package main

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"time"

	prof "github.com/cacggghp/vk-turn-proxy/client/internal/profile"
	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
)

type captchaSolveMode int

const (
	captchaSolveModeAuto captchaSolveMode = iota
	captchaSolveModeSliderPOC
	captchaSolveModeManual
)

func captchaSolveModeForAttempt(attempt int, manualOnly bool, enableSliderPOC bool) (captchaSolveMode, bool) {
	if manualOnly {
		return captchaSolveModeManual, attempt == 0
	}

	switch attempt {
	case 0:
		return captchaSolveModeAuto, true
	case 1:
		if enableSliderPOC {
			return captchaSolveModeSliderPOC, true
		}
		return captchaSolveModeManual, true
	case 2:
		if enableSliderPOC {
			return captchaSolveModeManual, true
		}
	}

	return 0, false
}

func captchaSolveModeLabel(mode captchaSolveMode) string {
	switch mode {
	case captchaSolveModeAuto:
		return "auto captcha"
	case captchaSolveModeSliderPOC:
		return "auto captcha slider POC"
	case captchaSolveModeManual:
		return "manual captcha"
	default:
		return "captcha"
	}
}

// applyBrowserProfile applies consistent User-Agent and Client Hints to bypass WAFs
func applyBrowserProfile(req *http.Request, profile prof.Profile) {
	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("sec-ch-ua", profile.SecChUa)
	req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
	req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("DNT", "1")
}

func applyBrowserProfileFhttp(req *fhttp.Request, profile prof.Profile) {
	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("sec-ch-ua", profile.SecChUa)
	req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
	req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("DNT", "1")
}

func generateBrowserFp(profile prof.Profile) string {
	// Fallback logic for generating a fingerprint if no saved profile is available.
	// This uses a simple MD5 hash of UA and a fixed resolution.
	data := profile.UserAgent + profile.SecChUa + "1536x864x24"
	h := md5.Sum([]byte(data))
	return hex.EncodeToString(h[:])
}

type VkCaptchaError struct {
	ErrorCode               int
	ErrorMsg                string
	CaptchaSid              string
	CaptchaImg              string
	RedirectURI             string
	IsSoundCaptchaAvailable bool
	SessionToken            string
	CaptchaTs               string
	CaptchaAttempt          string
}

func ParseVkCaptchaError(errData map[string]interface{}) *VkCaptchaError {
	// Extract error_code
	codeFloat, ok := errData["error_code"].(float64)
	if !ok {
		log.Printf("missing error_code in captcha error data")
		return nil
	}
	code := int(codeFloat)

	// Extract redirect_uri
	RedirectURI, ok := errData["redirect_uri"].(string)
	if !ok {
		log.Printf("missing redirect_uri in captcha error data")
		return nil
	}

	// Extract captcha_sid
	captchaSid, ok := errData["captcha_sid"].(string)
	if !ok {
		// try numeric
		if sidNum, ok2 := errData["captcha_sid"].(float64); ok2 {
			captchaSid = fmt.Sprintf("%.0f", sidNum)
		} else {
			log.Printf("missing captcha_sid in captcha error data")
			return nil
		}
	}

	// Extract captcha_img
	captchaImg, ok := errData["captcha_img"].(string)
	if !ok {
		log.Printf("missing captcha_img in captcha error data")
		return nil
	}

	// Extract error_msg
	errorMsg, ok := errData["error_msg"].(string)
	if !ok {
		log.Printf("missing error_msg in captcha error data")
		return nil
	}

	// Extract session token
	var sessionToken string
	if RedirectURI != "" {
		if parsed, err := neturl.Parse(RedirectURI); err == nil {
			sessionToken = parsed.Query().Get("session_token")
		} else {
			log.Printf("failed to parse redirect_uri: %v", err)
			return nil
		}
	}
	// Fallback to top-level session_token field if not in redirect_uri
	if sessionToken == "" {
		if st, stOk := errData["session_token"].(string); stOk {
			sessionToken = st
		}
	}

	// Extract is_sound_captcha_available
	isSound, ok := errData["is_sound_captcha_available"].(bool)
	if !ok {
		isSound = false
	}

	// Extract captcha_ts
	var captchaTs string
	if tsFloat, ok := errData["captcha_ts"].(float64); ok {
		captchaTs = fmt.Sprintf("%.0f", tsFloat)
	} else if tsStr, ok := errData["captcha_ts"].(string); ok {
		captchaTs = tsStr
	}

	// Extract captcha_attempt
	var captchaAttempt string
	if attFloat, ok := errData["captcha_attempt"].(float64); ok {
		captchaAttempt = fmt.Sprintf("%.0f", attFloat)
	} else if attStr, ok := errData["captcha_attempt"].(string); ok {
		captchaAttempt = attStr
	}

	// Build VkCaptchaError
	return &VkCaptchaError{
		ErrorCode:               code,
		ErrorMsg:                errorMsg,
		CaptchaSid:              captchaSid,
		CaptchaImg:              captchaImg,
		RedirectURI:             RedirectURI,
		IsSoundCaptchaAvailable: isSound,
		SessionToken:            sessionToken,
		CaptchaTs:               captchaTs,
		CaptchaAttempt:          captchaAttempt,
	}
}

func (e *VkCaptchaError) IsCaptchaError() bool {
	return e.ErrorCode == 14 && e.RedirectURI != "" && e.SessionToken != ""
}

func solveVkCaptcha(ctx context.Context, captchaErr *VkCaptchaError, streamID int, client tlsclient.HttpClient, profile prof.Profile, useSliderPOC bool) (string, error) {
	if useSliderPOC {
		log.Printf("[STREAM %d] [Captcha] Solving captcha with slider POC...", streamID)
	} else {
		log.Printf("[STREAM %d] [Captcha] Solving captcha...", streamID)
	}

	if captchaErr.SessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri for auto-solve")
	}
	if captchaErr.RedirectURI == "" {
		return "", fmt.Errorf("no redirect_uri for auto-solve")
	}

	// Try to load saved profile from disk
	var savedProfile *prof.SavedProfile
	if sp, err := prof.LoadProfileFromDisk(); err == nil {
		log.Printf("[STREAM %d] [Captcha] Using saved real browser profile", streamID)
		savedProfile = sp
		profile = sp.Profile // Use saved headers/UA
	}

	bootstrap, err := fetchCaptchaBootstrap(ctx, captchaErr.RedirectURI, client, profile)
	if err != nil {
		return "", fmt.Errorf("failed to fetch captcha bootstrap: %w", err)
	}

	log.Printf("[STREAM %d] [Captcha] PoW input: %s, difficulty: %d", streamID, bootstrap.PowInput, bootstrap.Difficulty)

	hash, err := solvePoW(bootstrap.PowInput, bootstrap.Difficulty)
	if err != nil {
		return "", fmt.Errorf("PoW: %w", err)
	}
	log.Printf("[STREAM %d] [Captcha] PoW solved: hash=%s", streamID, hash)

	var successToken string
	if useSliderPOC {
		successToken, err = callCaptchaNotRobotWithSliderPOC(
			ctx,
			captchaErr.SessionToken,
			hash,
			streamID,
			client,
			profile,
			bootstrap.Settings,
			savedProfile, // Pass savedProfile if available
		)
	} else {
		successToken, err = callCaptchaNotRobot(ctx, captchaErr.SessionToken, hash, streamID, client, profile, savedProfile)
	}
	if err != nil {
		return "", fmt.Errorf("captchaNotRobot API failed: %w", err)
	}

	log.Printf("[STREAM %d] [Captcha] Success! Got success_token", streamID)
	return successToken, nil
}

func fetchCaptchaBootstrap(ctx context.Context, redirectURI string, client tlsclient.HttpClient, profile prof.Profile) (*captchaBootstrap, error) {
	parsedURL, err := neturl.Parse(redirectURI)
	if err != nil {
		return nil, err
	}
	domain := parsedURL.Hostname()

	req, err := fhttp.NewRequestWithContext(ctx, "GET", redirectURI, nil)
	if err != nil {
		return nil, err
	}

	req.Host = domain
	applyBrowserProfileFhttp(req, profile)
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseCaptchaBootstrapHTML(string(body))
}

func solvePoW(powInput string, difficulty int) (string, error) {
	target := strings.Repeat("0", difficulty)
	for nonce := 1; nonce <= 10000000; nonce++ {
		data := powInput + strconv.Itoa(nonce)
		hash := sha256.Sum256([]byte(data))
		hexHash := hex.EncodeToString(hash[:])
		if strings.HasPrefix(hexHash, target) {
			return hexHash, nil
		}
	}
	return "", fmt.Errorf("PoW unsolved (difficulty=%d, tried 10M nonces)", difficulty)
}

func callCaptchaNotRobot(ctx context.Context, sessionToken, hash string, streamID int, client tlsclient.HttpClient, profile prof.Profile, savedProfile *prof.SavedProfile) (string, error) {
	vkReq := func(method string, postData string) (map[string]interface{}, error) {
		reqURL := "https://api.vk.ru/method/" + method + "?v=5.131"
		parsedURL, err := neturl.Parse(reqURL)
		if err != nil {
			return nil, fmt.Errorf("parse request URL: %w", err)
		}
		domain := parsedURL.Hostname()

		req, err := fhttp.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(postData))
		if err != nil {
			return nil, err
		}

		req.Host = domain
		applyBrowserProfileFhttp(req, profile)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Origin", "https://api.vk.ru")
		req.Header.Set("Referer", fmt.Sprintf("https://api.vk.ru/not_robot_captcha?domain=vk.com&session_token=%s&variant=popup&blank=1", sessionToken))
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(httpResp.Body)

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

	adFpBytes := make([]byte, 16)
	for i := range adFpBytes {
		adFpBytes[i] = byte(rand.Intn(256))
	}
	adFp := base64.RawURLEncoding.EncodeToString(adFpBytes)[:21]

	baseParams := fmt.Sprintf("session_token=%s&domain=vk.com&adFp=%s&access_token=", neturl.QueryEscape(sessionToken), neturl.QueryEscape(adFp))

	log.Printf("[STREAM %d] [Captcha] Step 1/4: settings", streamID)
	if _, err := vkReq("captchaNotRobot.settings", baseParams); err != nil {
		return "", fmt.Errorf("settings failed: %w", err)
	}

	time.Sleep(200 * time.Millisecond)

	log.Printf("[STREAM %d] [Captcha] Step 2/4: componentDone", streamID)
	browserFp := generateBrowserFp(profile)
	deviceJSON := buildCaptchaDeviceJSON(profile)
	if savedProfile != nil {
		browserFp = savedProfile.BrowserFp
		deviceJSON = savedProfile.DeviceJSON
	}
	componentDoneData := baseParams + fmt.Sprintf("&browser_fp=%s&device=%s", browserFp, neturl.QueryEscape(deviceJSON))

	if _, err := vkReq("captchaNotRobot.componentDone", componentDoneData); err != nil {
		return "", fmt.Errorf("componentDone failed: %w", err)
	}

	time.Sleep(200 * time.Millisecond)

	log.Printf("[STREAM %d] [Captcha] Step 3/4: check", streamID)
	// The real browser sends an empty array for cursor on the first check.
	cursorJSON := "[]"
	answer := base64.StdEncoding.EncodeToString([]byte("{}"))

	// debug_info must vary per-session — a hardcoded hash becomes a stable
	// fingerprint that VK uses to flag the bot path (status=BOT).
	debugInfoBytes := sha256.Sum256([]byte(profile.UserAgent + sessionToken + strconv.FormatInt(time.Now().UnixNano(), 10)))
	debugInfo := hex.EncodeToString(debugInfoBytes[:])

	// Realistic per-session jitter; static arrays were also a fingerprint.
	rttSamples := 4 + rand.Intn(4)
	rttBase := 40 + rand.Intn(120)
	rttVals := make([]string, rttSamples)
	for i := range rttVals {
		rttVals[i] = strconv.Itoa(rttBase + rand.Intn(40) - 20)
	}
	connectionRtt := "[" + strings.Join(rttVals, ",") + "]"

	dlSamples := 4 + rand.Intn(4)
	dlBase := 2.0 + rand.Float64()*8.0
	dlVals := make([]string, dlSamples)
	for i := range dlVals {
		dlVals[i] = strconv.FormatFloat(dlBase+(rand.Float64()-0.5)*0.4, 'f', 2, 64)
	}
	connectionDownlink := "[" + strings.Join(dlVals, ",") + "]"

	checkData := baseParams + fmt.Sprintf(
		"&accelerometer=%s&gyroscope=%s&motion=%s&cursor=%s&taps=%s&connectionRtt=%s&connectionDownlink=%s&browser_fp=%s&hash=%s&answer=%s&debug_info=%s",
		neturl.QueryEscape("[]"), neturl.QueryEscape("[]"), neturl.QueryEscape("[]"),
		neturl.QueryEscape(cursorJSON), neturl.QueryEscape("[]"), neturl.QueryEscape(connectionRtt),
		neturl.QueryEscape(connectionDownlink),
		browserFp, hash, answer, debugInfo,
	)

	checkResp, err := vkReq("captchaNotRobot.check", checkData)
	if err != nil {
		return "", fmt.Errorf("check failed: %w", err)
	}

	respObj, ok := checkResp["response"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid check response: %v", checkResp)
	}
	status, ok := respObj["status"].(string)
	if !ok || status != "OK" {
		return "", fmt.Errorf("check status: %s", status)
	}
	successToken, ok := respObj["success_token"].(string)
	if !ok || successToken == "" {
		return "", fmt.Errorf("success_token not found")
	}

	time.Sleep(200 * time.Millisecond)

	log.Printf("[STREAM %d] [Captcha] Step 4/4: endSession", streamID)
	_, err = vkReq("captchaNotRobot.endSession", baseParams)
	if err != nil {
		log.Printf("[STREAM %d] [Captcha] Warning: endSession failed: %v", streamID, err)
	}

	return successToken, nil
}
