package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/cacggghp/vk-turn-proxy/client/internal/appstate"
	"github.com/cacggghp/vk-turn-proxy/client/internal/dnsdial"
	prof "github.com/cacggghp/vk-turn-proxy/client/internal/profile"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

func getYandexCreds(link string) (string, string, string, error) {
	const telemostConfHost = "cloud-api.yandex.ru"
	telemostConfPath := fmt.Sprintf("%s%s%s", "/telemost_front/v2/telemost/conferences/https%3A%2F%2Ftelemost.yandex.ru%2Fj%2F", link, "/connection?next_gen_media_platform_allowed=false")

	profile := prof.GetRandomProfile()
	name := prof.GenerateName()

	type ConferenceResponse struct {
		URI                 string `json:"uri"`
		RoomID              string `json:"room_id"`
		PeerID              string `json:"peer_id"`
		ClientConfiguration struct {
			MediaServerURL string `json:"media_server_url"`
		} `json:"client_configuration"`
		Credentials string `json:"credentials"`
	}

	type PartMeta struct {
		Name        string `json:"name"`
		Role        string `json:"role"`
		Description string `json:"description"`
		SendAudio   bool   `json:"sendAudio"`
		SendVideo   bool   `json:"sendVideo"`
	}

	type PartAttrs struct {
		Name        string `json:"name"`
		Role        string `json:"role"`
		Description string `json:"description"`
	}

	type SdkInfo struct {
		Implementation string `json:"implementation"`
		Version        string `json:"version"`
		UserAgent      string `json:"userAgent"`
		HwConcurrency  int    `json:"hwConcurrency"`
	}

	type Capabilities struct {
		OfferAnswerMode             []string `json:"offerAnswerMode"`
		InitialSubscriberOffer      []string `json:"initialSubscriberOffer"`
		SlotsMode                   []string `json:"slotsMode"`
		SimulcastMode               []string `json:"simulcastMode"`
		SelfVadStatus               []string `json:"selfVadStatus"`
		DataChannelSharing          []string `json:"dataChannelSharing"`
		VideoEncoderConfig          []string `json:"videoEncoderConfig"`
		DataChannelVideoCodec       []string `json:"dataChannelVideoCodec"`
		BandwidthLimitationReason   []string `json:"bandwidthLimitationReason"`
		SdkDefaultDeviceManagement  []string `json:"sdkDefaultDeviceManagement"`
		JoinOrderLayout             []string `json:"joinOrderLayout"`
		PinLayout                   []string `json:"pinLayout"`
		SendSelfViewVideoSlot       []string `json:"sendSelfViewVideoSlot"`
		ServerLayoutTransition      []string `json:"serverLayoutTransition"`
		SdkPublisherOptimizeBitrate []string `json:"sdkPublisherOptimizeBitrate"`
		SdkNetworkLostDetection     []string `json:"sdkNetworkLostDetection"`
		SdkNetworkPathMonitor       []string `json:"sdkNetworkPathMonitor"`
		PublisherVp9                []string `json:"publisherVp9"`
		SvcMode                     []string `json:"svcMode"`
		SubscriberOfferAsyncAck     []string `json:"subscriberOfferAsyncAck"`
		SvcModes                    []string `json:"svcModes"`
		ReportTelemetryModes        []string `json:"reportTelemetryModes"`
		KeepDefaultDevicesModes     []string `json:"keepDefaultDevicesModes"`
	}

	type HelloPayload struct {
		ParticipantMeta        PartMeta     `json:"participantMeta"`
		ParticipantAttributes  PartAttrs    `json:"participantAttributes"`
		SendAudio              bool         `json:"sendAudio"`
		SendVideo              bool         `json:"sendVideo"`
		SendSharing            bool         `json:"sendSharing"`
		ParticipantID          string       `json:"participantId"`
		RoomID                 string       `json:"roomId"`
		ServiceName            string       `json:"serviceName"`
		Credentials            string       `json:"credentials"`
		CapabilitiesOffer      Capabilities `json:"capabilitiesOffer"`
		SdkInfo                SdkInfo      `json:"sdkInfo"`
		SdkInitializationID    string       `json:"sdkInitializationId"`
		DisablePublisher       bool         `json:"disablePublisher"`
		DisableSubscriber      bool         `json:"disableSubscriber"`
		DisableSubscriberAudio bool         `json:"disableSubscriberAudio"`
	}

	type HelloRequest struct {
		UID   string       `json:"uid"`
		Hello HelloPayload `json:"hello"`
	}

	type FlexUrls []string

	type WSSResponse struct {
		UID         string `json:"uid"`
		ServerHello struct {
			RtcConfiguration struct {
				IceServers []struct {
					Urls       FlexUrls `json:"urls"`
					Username   string   `json:"username,omitempty"`
					Credential string   `json:"credential,omitempty"`
				} `json:"iceServers"`
			} `json:"rtcConfiguration"`
		} `json:"serverHello"`
	}

	type WSSAck struct {
		UID string `json:"uid"`
		Ack struct {
			Status struct {
				Code string `json:"code"`
			} `json:"status"`
		} `json:"ack"`
	}

	type WSSData struct {
		ParticipantID string
		RoomID        string
		Credentials   string
		Wss           string
	}

	endpoint := "https://" + telemostConfHost + telemostConfPath
	appD := dnsdial.AppDialer()
	tr := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DialContext:         appD.DialContext,
	}
	client := &http.Client{
		Timeout:   20 * time.Second,
		Transport: tr,
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return "", "", "", err
	}

	applyBrowserProfile(req, profile)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", "https://telemost.yandex.ru/")
	req.Header.Set("Origin", "https://telemost.yandex.ru")
	req.Header.Set("Client-Instance-Id", uuid.New().String())

	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("close response body: %s", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		readBody, err2 := io.ReadAll(resp.Body)
		if err2 != nil {
			return "", "", "", fmt.Errorf("GetConference: status=%s (failed to read body: %v)", resp.Status, err2)
		}
		return "", "", "", fmt.Errorf("GetConference: status=%s body=%s", resp.Status, string(readBody))
	}

	var result ConferenceResponse
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", "", fmt.Errorf("decode conf: %v", err)
	}
	data := WSSData{
		ParticipantID: result.PeerID,
		RoomID:        result.RoomID,
		Credentials:   result.Credentials,
		Wss:           result.ClientConfiguration.MediaServerURL,
	}
	h := http.Header{}
	h.Set("Origin", "https://telemost.yandex.ru")
	h.Set("User-Agent", profile.UserAgent)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	wsAppD := dnsdial.AppDialer()
	dialer := websocket.Dialer{NetDialContext: wsAppD.DialContext}
	var conn *websocket.Conn
	conn, resp, err = dialer.DialContext(ctx, data.Wss, h)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return "", "", "", fmt.Errorf("ws dial: %w", err)
	}
	if resp != nil && resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			log.Printf("close websocket: %s", closeErr)
		}
	}()

	req1 := HelloRequest{
		UID: uuid.New().String(),
		Hello: HelloPayload{
			ParticipantMeta: PartMeta{
				Name:        name,
				Role:        "SPEAKER",
				Description: "",
				SendAudio:   false,
				SendVideo:   false,
			},
			ParticipantAttributes: PartAttrs{
				Name:        name,
				Role:        "SPEAKER",
				Description: "",
			},
			SendAudio:   false,
			SendVideo:   false,
			SendSharing: false,

			ParticipantID: data.ParticipantID,
			RoomID:        data.RoomID,
			ServiceName:   "telemost",
			Credentials:   data.Credentials,
			SdkInfo: SdkInfo{
				Implementation: "browser",
				Version:        "5.15.0",
				UserAgent:      profile.UserAgent,
				HwConcurrency:  4,
			},
			SdkInitializationID:    uuid.New().String(),
			DisablePublisher:       false,
			DisableSubscriber:      false,
			DisableSubscriberAudio: false,
			CapabilitiesOffer: Capabilities{
				OfferAnswerMode:             []string{"SEPARATE"},
				InitialSubscriberOffer:      []string{"ON_HELLO"},
				SlotsMode:                   []string{"FROM_CONTROLLER"},
				SimulcastMode:               []string{"DISABLED"},
				SelfVadStatus:               []string{"FROM_SERVER"},
				DataChannelSharing:          []string{"TO_RTP"},
				VideoEncoderConfig:          []string{"NO_CONFIG"},
				DataChannelVideoCodec:       []string{"VP8"},
				BandwidthLimitationReason:   []string{"BANDWIDTH_REASON_DISABLED"},
				SdkDefaultDeviceManagement:  []string{"SDK_DEFAULT_DEVICE_MANAGEMENT_DISABLED"},
				JoinOrderLayout:             []string{"JOIN_ORDER_LAYOUT_DISABLED"},
				PinLayout:                   []string{"PIN_LAYOUT_DISABLED"},
				SendSelfViewVideoSlot:       []string{"SEND_SELF_VIEW_VIDEO_SLOT_DISABLED"},
				ServerLayoutTransition:      []string{"SERVER_LAYOUT_TRANSITION_DISABLED"},
				SdkPublisherOptimizeBitrate: []string{"SDK_PUBLISHER_OPTIMIZE_BITRATE_DISABLED"},
				SdkNetworkLostDetection:     []string{"SDK_NETWORK_LOST_DETECTION_DISABLED"},
				SdkNetworkPathMonitor:       []string{"SDK_NETWORK_PATH_MONITOR_DISABLED"},
				PublisherVp9:                []string{"PUBLISH_VP9_DISABLED"},
				SvcMode:                     []string{"SVC_MODE_DISABLED"},
				SubscriberOfferAsyncAck:     []string{"SUBSCRIBER_OFFER_ASYNC_ACK_DISABLED"},
				SvcModes:                    []string{"FALSE"},
				ReportTelemetryModes:        []string{"TRUE"},
				KeepDefaultDevicesModes:     []string{"TRUE"},
			},
		},
	}

	if appstate.Debug {
		b, _ := json.MarshalIndent(req1, "", "  ")
		log.Printf("Sending HELLO:\n%s", string(b))
	}

	if err := conn.WriteJSON(req1); err != nil {
		return "", "", "", fmt.Errorf("ws write: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return "", "", "", fmt.Errorf("ws set read deadline: %w", err)
	}

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return "", "", "", fmt.Errorf("ws read: %w", err)
		}
		if appstate.Debug {
			s := string(msg)
			if len(s) > 800 {
				s = s[:800] + "...(truncated)"
			}
			log.Printf("WSS recv: %s", s)
		}

		var ack WSSAck
		if err := json.Unmarshal(msg, &ack); err == nil && ack.Ack.Status.Code != "" {
			continue
		}

		var resp WSSResponse
		if err := json.Unmarshal(msg, &resp); err == nil {
			ice := resp.ServerHello.RtcConfiguration.IceServers
			for _, s := range ice {
				for _, u := range s.Urls {
					if !strings.HasPrefix(u, "turn:") && !strings.HasPrefix(u, "turns:") {
						continue
					}
					if strings.Contains(u, "transport=tcp") {
						continue
					}
					clean := strings.Split(u, "?")[0]
					address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

					return s.Username, s.Credential, address, nil
				}
			}
		}
	}
}
