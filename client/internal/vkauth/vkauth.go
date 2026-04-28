package vkauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	neturl "net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/cacggghp/vk-turn-proxy/client/internal/appcfg"
	"github.com/cacggghp/vk-turn-proxy/client/internal/appstate"
	"github.com/cacggghp/vk-turn-proxy/client/internal/captcha"
	"github.com/cacggghp/vk-turn-proxy/client/internal/dnsdial"
	prof "github.com/cacggghp/vk-turn-proxy/client/internal/profile"
	"github.com/google/uuid"
)

type VKCredentials struct {
	ClientID     string
	ClientSecret string
}

// Only client_ids that currently expose calls.getAnonymousToken.
// VKVIDEO_* and VK_ID_AUTH_APP started returning error_code:3 "Unknown method"
// (observed 2026-04-28) and only burn throttle budget if kept in rotation.
var vkCredentialsList = []VKCredentials{
	{ClientID: "6287487", ClientSecret: "QbYic1K3lEV5kTGiqlq2"}, // VK_WEB_APP_ID
	{ClientID: "7879029", ClientSecret: "aR5NKGmm03GYrCiNKsaw"}, // VK_MVK_APP_ID
}

type TurnCredentials struct {
	Username   string
	Password   string
	ServerAddr string
	ExpiresAt  time.Time
	Link       string
}

type StreamCredentialsCache struct {
	creds         TurnCredentials
	mutex         sync.RWMutex
	errorCount    atomic.Int32
	lastErrorTime atomic.Int64
}

const (
	credentialLifetime = 10 * time.Minute
	cacheSafetyMargin  = 60 * time.Second
	maxCacheErrors     = 3
	errorWindow        = 10 * time.Second
	streamsPerCache    = 1
	identityLifetime   = 8 * time.Minute
)

func getCacheID(streamID int) int {
	return streamID / streamsPerCache
}

func vkDelayRandom(minMs, maxMs int) {
	ms := minMs + rand.Intn(maxMs-minMs+1)
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

var credentialsStore = struct {
	mu     sync.RWMutex
	caches map[int]*StreamCredentialsCache
}{
	caches: make(map[int]*StreamCredentialsCache),
}

// ResetErrorCount clears the auth-error counter for the cache covering the
// given stream after a successful TURN allocation.
func ResetErrorCount(streamID int) {
	getStreamCache(streamID).errorCount.Store(0)
}

func getStreamCache(streamID int) *StreamCredentialsCache {
	cacheID := getCacheID(streamID)

	credentialsStore.mu.RLock()
	cache, exists := credentialsStore.caches[cacheID]
	credentialsStore.mu.RUnlock()

	if exists {
		return cache
	}

	credentialsStore.mu.Lock()
	defer credentialsStore.mu.Unlock()

	if cache, exists = credentialsStore.caches[cacheID]; exists {
		return cache
	}

	cache = &StreamCredentialsCache{}
	credentialsStore.caches[cacheID] = cache
	return cache
}

func IsAuthError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "Unauthorized") ||
		strings.Contains(errStr, "authentication") ||
		strings.Contains(errStr, "invalid credential") ||
		strings.Contains(errStr, "stale nonce")
}

func HandleAuthError(streamID int) bool {
	cache := getStreamCache(streamID)
	cacheID := getCacheID(streamID)

	now := time.Now().Unix()

	if now-cache.lastErrorTime.Load() > int64(errorWindow.Seconds()) {
		cache.errorCount.Store(0)
	}

	count := cache.errorCount.Add(1)
	cache.lastErrorTime.Store(now)

	log.Printf("[STREAM %d] Auth error (cache=%d, count=%d/%d)", streamID, cacheID, count, maxCacheErrors)

	if count >= maxCacheErrors {
		log.Printf("[VK Auth] Multiple auth errors detected (%d), invalidating cache %d for stream %d...", count, cacheID, streamID)
		cache.invalidate(streamID)
		return true
	}
	return false
}

func (c *StreamCredentialsCache) invalidate(streamID int) {
	c.mutex.Lock()
	c.creds = TurnCredentials{}
	c.mutex.Unlock()

	c.errorCount.Store(0)
	c.lastErrorTime.Store(0)

	log.Printf("[STREAM %d] [VK Auth] Credentials cache invalidated", streamID)
}

func GetCredsCached(ctx context.Context, link string, streamID int, cfg *appcfg.Config) (string, string, string, error) {
	cache := getStreamCache(streamID)
	cacheID := getCacheID(streamID)

	cache.mutex.RLock()
	if cache.creds.Link == link && time.Now().Before(cache.creds.ExpiresAt) {
		expires := time.Until(cache.creds.ExpiresAt)
		u, p, a := cache.creds.Username, cache.creds.Password, cache.creds.ServerAddr
		cache.mutex.RUnlock()
		if cfg.Debug {
			log.Printf("[STREAM %d] [VK Auth] Using cached credentials (cache=%d, expires in %v)", streamID, cacheID, expires)
		}
		return u, p, a, nil
	}
	cache.mutex.RUnlock()

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	// Double-check inside lock
	if cache.creds.Link == link && time.Now().Before(cache.creds.ExpiresAt) {
		return cache.creds.Username, cache.creds.Password, cache.creds.ServerAddr, nil
	}

	user, pass, addr, err := fetchVkCreds(ctx, link, streamID, cfg)
	if err != nil {
		return "", "", "", err
	}

	cache.creds = TurnCredentials{Username: user, Password: pass, ServerAddr: addr, ExpiresAt: time.Now().Add(credentialLifetime - cacheSafetyMargin), Link: link}
	return user, pass, addr, nil
}

var (
	vkRequestMu           sync.Mutex
	globalLastVkFetchTime time.Time
)

// vkIdentity caches the captcha-gated portion of a VK auth chain (steps 1-3:
// anonym_token + getCallPreview + getAnonymousToken). Once acquired it can be
// replayed via acquireVkTurnSlot to mint independent TURN credentials,
// each with a unique username — bypassing per-username throttling at the cost
// of a single captcha solve per (link, client_id) pair.
type vkIdentity struct {
	creds      VKCredentials
	profile    prof.Profile
	name       string
	token1     string
	token2     string
	client     tlsclient.HttpClient
	expiresAt  time.Time
	urlCounter atomic.Uint64 // round-robin index across turn_server.urls
}

type identityCacheKey struct {
	link     string
	clientID string
}

type identityEntry struct {
	mu    sync.Mutex
	ident *vkIdentity
}

var identityStore = struct {
	mu sync.Mutex
	m  map[identityCacheKey]*identityEntry
}{m: make(map[identityCacheKey]*identityEntry)}

func getOrAcquireIdentity(ctx context.Context, link string, streamID int, creds VKCredentials, cfg *appcfg.Config) (*vkIdentity, error) {
	key := identityCacheKey{link: link, clientID: creds.ClientID}

	identityStore.mu.Lock()
	entry, ok := identityStore.m[key]
	if !ok {
		entry = &identityEntry{}
		identityStore.m[key] = entry
	}
	identityStore.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.ident != nil && time.Now().Before(entry.ident.expiresAt) {
		return entry.ident, nil
	}

	ident, err := acquireVkIdentity(ctx, link, streamID, creds, cfg)
	if err != nil {
		return nil, err
	}
	entry.ident = ident
	return ident, nil
}

func invalidateIdentity(link, clientID string) {
	identityStore.mu.Lock()
	entry, ok := identityStore.m[identityCacheKey{link: link, clientID: clientID}]
	identityStore.mu.Unlock()
	if !ok {
		return
	}
	entry.mu.Lock()
	entry.ident = nil
	entry.mu.Unlock()
}

func fetchVkCreds(ctx context.Context, link string, streamID int, cfg *appcfg.Config) (string, string, string, error) {
	if time.Now().Unix() < appstate.GlobalCaptchaLockout.Load() {
		return "", "", "", fmt.Errorf("CAPTCHA_WAIT_REQUIRED: global lockout active")
	}

	n := len(vkCredentialsList)
	startIdx := streamID % n

	var lastErr error
	for offset := 0; offset < n; offset++ {
		creds := vkCredentialsList[(startIdx+offset)%n]
		log.Printf("[STREAM %d] [VK Auth] Trying credentials: client_id=%s", streamID, creds.ClientID)

		ident, err := getOrAcquireIdentity(ctx, link, streamID, creds, cfg)
		if err != nil {
			lastErr = err
			log.Printf("[STREAM %d] [VK Auth] identity acquire failed (client_id=%s): %v", streamID, creds.ClientID, err)
			if strings.Contains(err.Error(), "CAPTCHA_WAIT_REQUIRED") || strings.Contains(err.Error(), "FATAL_CAPTCHA") {
				return "", "", "", err
			}
			continue
		}

		user, pass, addr, err := acquireVkTurnSlot(ctx, link, streamID, ident, cfg)
		if err == nil {
			log.Printf("[STREAM %d] [VK Auth] Success with client_id=%s", streamID, creds.ClientID)
			return user, pass, addr, nil
		}

		lastErr = err
		log.Printf("[STREAM %d] [VK Auth] slot acquire failed (client_id=%s): %v", streamID, creds.ClientID, err)
		invalidateIdentity(link, creds.ClientID)

		if strings.Contains(err.Error(), "CAPTCHA_WAIT_REQUIRED") || strings.Contains(err.Error(), "FATAL_CAPTCHA") {
			return "", "", "", err
		}
		if strings.Contains(err.Error(), "error_code:29") || strings.Contains(err.Error(), "error_code: 29") || strings.Contains(err.Error(), "Rate limit") {
			log.Printf("[STREAM %d] [VK Auth] Rate limit detected, trying next credentials...", streamID)
		}
	}

	return "", "", "", fmt.Errorf("all VK credentials failed: %w", lastErr)
}

func vkDoRequest(ctx context.Context, client tlsclient.HttpClient, profile prof.Profile, data, url string) (map[string]interface{}, error) {
	parsedURL, err := neturl.Parse(url)
	if err != nil {
		return nil, fmt.Errorf("parse request URL: %w", err)
	}
	domain := parsedURL.Hostname()

	req, err := fhttp.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer([]byte(data)))
	if err != nil {
		return nil, err
	}

	req.Host = domain
	captcha.ApplyBrowserProfileFhttp(req, profile)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", "https://vk.ru")
	req.Header.Set("Referer", "https://vk.ru/")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Priority", "u=1, i")

	httpResp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := httpResp.Body.Close(); closeErr != nil {
			log.Printf("close response body: %s", closeErr)
		}
	}()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// acquireVkIdentity runs the heavy + captcha-gated portion of the VK auth chain
// (steps 1-3): get_anonym_token, calls.getCallPreview, calls.getAnonymousToken.
// The result is cached and reused across many TURN slot acquisitions.
//
// Globally serialised via vkRequestMu + a 3-6s cooldown to avoid VK API bans.
func acquireVkIdentity(ctx context.Context, link string, streamID int, creds VKCredentials, cfg *appcfg.Config) (*vkIdentity, error) {
	vkRequestMu.Lock()
	defer vkRequestMu.Unlock()

	minInterval := 3*time.Second + time.Duration(rand.Intn(3000))*time.Millisecond
	elapsed := time.Since(globalLastVkFetchTime)
	if !globalLastVkFetchTime.IsZero() && elapsed < minInterval {
		wait := minInterval - elapsed
		log.Printf("[STREAM %d] [VK Auth] Throttling: waiting %v to prevent rate limit...", streamID, wait.Truncate(time.Millisecond))
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	defer func() {
		globalLastVkFetchTime = time.Now()
	}()

	if time.Now().Unix() < appstate.GlobalCaptchaLockout.Load() {
		return nil, fmt.Errorf("CAPTCHA_WAIT_REQUIRED: global lockout active")
	}

	profile := prof.Profile{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Not(A:Brand";v="99", "Google Chrome";v="146", "Chromium";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	}

	jar := tlsclient.NewCookieJar()
	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(20),
		tlsclient.WithClientProfile(profiles.Chrome_146),
		tlsclient.WithCookieJar(jar),
		tlsclient.WithDialer(dnsdial.AppDialer(cfg.DNSMode)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize tls_client: %w", err)
	}

	name := prof.GenerateName()
	escapedName := neturl.QueryEscape(name)

	log.Printf("[STREAM %d] [VK Auth] Connecting Identity - Name: %s | client_id=%s", streamID, name, creds.ClientID)

	// Step 1: anonym_token
	data := fmt.Sprintf("client_id=%s&token_type=messages&client_secret=%s&version=1&app_id=%s", creds.ClientID, creds.ClientSecret, creds.ClientID)
	resp, err := vkDoRequest(ctx, client, profile, data, "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return nil, err
	}
	dataMap, ok := resp["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected anon token response: %v", resp)
	}
	token1, ok := dataMap["access_token"].(string)
	if !ok {
		return nil, fmt.Errorf("missing access_token in response: %v", resp)
	}

	vkDelayRandom(100, 150)

	// Step 2: getCallPreview (best-effort)
	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&fields=photo_200&access_token=%s", link, token1)
	_, err = vkDoRequest(ctx, client, profile, data, "https://api.vk.ru/method/calls.getCallPreview?v=5.275&client_id="+creds.ClientID)
	if err != nil {
		log.Printf("[STREAM %d] [VK Auth] Warning: getCallPreview failed: %v", streamID, err)
	}

	vkDelayRandom(200, 400)

	// Step 3: getAnonymousToken (captcha-gated)
	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s", link, escapedName, token1)
	urlAddr := fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id=%s", creds.ClientID)

	chain := captcha.BuildChain(cfg.ManualCaptcha, cfg.AutoCaptchaSliderPOC)
	deps := captcha.SolveDeps{Client: client, Profile: profile, StreamID: streamID, Cfg: cfg}

	exhausted := func() error {
		appstate.GlobalCaptchaLockout.Store(time.Now().Add(60 * time.Second).Unix())
		if appstate.ConnectedStreams.Load() == 0 {
			log.Printf("[STREAM %d] [FATAL] 0 connected streams and captcha solve modes exhausted.", streamID)
			return fmt.Errorf("FATAL_CAPTCHA_FAILED_NO_STREAMS")
		}
		return fmt.Errorf("CAPTCHA_WAIT_REQUIRED")
	}

	var token2 string
	for attempt := 0; ; attempt++ {
		resp, err = vkDoRequest(ctx, client, profile, data, urlAddr)
		if err != nil {
			return nil, err
		}

		if errObj, hasErr := resp["error"].(map[string]interface{}); hasErr {
			captchaErr := captcha.ParseVkCaptchaError(errObj)
			if captchaErr != nil && captchaErr.IsCaptchaError() {
				solver, ok := chain.Solver(attempt)
				if !ok {
					log.Printf("[STREAM %d] [Captcha] No more solve modes available (attempt %d)", streamID, attempt+1)
					return nil, exhausted()
				}

				res, solveErr := solver.Solve(ctx, captchaErr, deps)
				if solveErr != nil {
					log.Printf("[STREAM %d] [Captcha] %s failed (attempt %d): %v", streamID, solver.Label(), attempt+1, solveErr)
					if next, hasNext := chain.Solver(attempt + 1); hasNext {
						log.Printf("[STREAM %d] [Captcha] Falling back to %s...", streamID, next.Label())
						continue
					}
					return nil, exhausted()
				}

				if captchaErr.CaptchaAttempt == "0" || captchaErr.CaptchaAttempt == "" {
					captchaErr.CaptchaAttempt = "1"
				}

				if res.CaptchaKey != "" {
					data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&captcha_key=%s&captcha_sid=%s&access_token=%s",
						link, escapedName, neturl.QueryEscape(res.CaptchaKey), captchaErr.CaptchaSid, token1)
				} else {
					data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s&captcha_ts=%s&captcha_attempt=%s&access_token=%s",
						link, escapedName, captchaErr.CaptchaSid, neturl.QueryEscape(res.SuccessToken), captchaErr.CaptchaTs, captchaErr.CaptchaAttempt, token1)
				}
				continue
			}
			return nil, fmt.Errorf("VK API error: %v", errObj)
		}

		respMap, okLoop := resp["response"].(map[string]interface{})
		if !okLoop {
			return nil, fmt.Errorf("unexpected getAnonymousToken response: %v", resp)
		}
		token2, okLoop = respMap["token"].(string)
		if !okLoop {
			return nil, fmt.Errorf("missing token in response: %v", resp)
		}
		break
	}

	return &vkIdentity{
		creds:     creds,
		profile:   profile,
		name:      name,
		token1:    token1,
		token2:    token2,
		client:    client,
		expiresAt: time.Now().Add(identityLifetime),
	}, nil
}

// acquireVkTurnSlot runs the lightweight portion of the chain (steps 4-5):
// auth.anonymLogin (with a fresh device_id) followed by vchat.joinConversationByLink.
// Each call returns a distinct (username, password) pair from VK, which lets us
// run multiple parallel TURN allocations under the same identity — bypassing
// per-username throttling without re-solving captcha.
func acquireVkTurnSlot(ctx context.Context, link string, streamID int, ident *vkIdentity, cfg *appcfg.Config) (string, string, string, error) {
	// Step 4: auth.anonymLogin with fresh device_id → fresh session_key
	sessionData := fmt.Sprintf(`{"version":2,"device_id":"%s","client_version":1.1,"client_type":"SDK_JS"}`, uuid.New())
	data := fmt.Sprintf("session_data=%s&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA", neturl.QueryEscape(sessionData))
	resp, err := vkDoRequest(ctx, ident.client, ident.profile, data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", "", err
	}
	token3, ok := resp["session_key"].(string)
	if !ok {
		return "", "", "", fmt.Errorf("missing session_key in response: %v", resp)
	}

	vkDelayRandom(100, 150)

	// Step 5: vchat.joinConversationByLink → turn_server creds
	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&capabilities=2F7F&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", link, ident.token2, token3)
	resp, err = vkDoRequest(ctx, ident.client, ident.profile, data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", "", err
	}

	tsRaw, ok := resp["turn_server"].(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("missing turn_server in response: %v", resp)
	}
	user, ok := tsRaw["username"].(string)
	if !ok {
		return "", "", "", fmt.Errorf("missing username in turn_server")
	}
	pass, ok := tsRaw["credential"].(string)
	if !ok {
		return "", "", "", fmt.Errorf("missing credential in turn_server")
	}
	urlsRaw, ok := tsRaw["urls"].([]interface{})
	if !ok || len(urlsRaw) == 0 {
		return "", "", "", fmt.Errorf("missing or empty urls in turn_server")
	}
	if cfg.Debug {
		log.Printf("[STREAM %d] [VK Auth] turn_server urls: %v", streamID, urlsRaw)
	}

	// Prefer URLs whose transport matches the requested mode (cfg.UDP).
	// Per RFC 7065, "?transport=tcp" → TCP, missing or "transport=udp" → UDP.
	// Fall back to the full list if nothing matches — this preserves the
	// -port override path where the user intentionally dials a port not
	// advertised in the URL list (e.g. -port 443 -udp=false against a host
	// whose URL only advertises a UDP port).
	all := make([]string, 0, len(urlsRaw))
	preferred := make([]string, 0, len(urlsRaw))
	for _, raw := range urlsRaw {
		s, ok := raw.(string)
		if !ok {
			continue
		}
		all = append(all, s)
		isTCP := strings.Contains(s, "transport=tcp")
		if cfg.UDP == !isTCP {
			preferred = append(preferred, s)
		}
	}
	if len(all) == 0 {
		return "", "", "", fmt.Errorf("turn_server urls list contained no strings: %v", urlsRaw)
	}

	pool := preferred
	if len(pool) == 0 {
		pool = all
		log.Printf("[STREAM %d] [VK Auth] no urls match transport (udp=%v), falling back to full list (relying on -port override). urls=%v", streamID, cfg.UDP, all)
	}

	// Round-robin within the identity. Using streamID % len(pool) breaks
	// when shard sharding (variant C) puts every stream of an identity on
	// the same parity, collapsing all streams onto the same URL.
	urlIdx := int(ident.urlCounter.Add(1)-1) % len(pool)
	urlStr := pool[urlIdx]
	log.Printf("[STREAM %d] [VK Auth] turn_server urls=%d (preferred=%d), picked[%d]: %s", streamID, len(all), len(preferred), urlIdx, urlStr)

	clean := strings.Split(urlStr, "?")[0]
	address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

	return user, pass, address, nil
}
