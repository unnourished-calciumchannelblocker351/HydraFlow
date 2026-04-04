// Package bypass provides the core DPI bypass engine for HydraFlow.
// This file implements Cloudflare WARP integration for outbound traffic.
// WARP routes outbound connections through Cloudflare's network, which
// makes the server's IP appear as a Cloudflare IP — useful for accessing
// services that block VPS/datacenter IPs (Netflix, ChatGPT, Spotify, etc).
//
// The integration works by:
//  1. Registering with Cloudflare's WARP API to get WireGuard credentials
//  2. Generating an xray-core WireGuard outbound configuration
//  3. Generating routing rules to send specific domains through WARP
//
// Inspired by 3x-ui's built-in WARP integration.
package bypass

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/curve25519"
)

// warpAPIBase is the Cloudflare WARP registration endpoint.
const warpAPIBase = "https://api.cloudflareclient.com/v0a2158/reg"

// WARPConfig holds the configuration for Cloudflare WARP integration.
type WARPConfig struct {
	// Enabled controls whether WARP outbound is active.
	Enabled bool `json:"enabled" yaml:"enabled"`

	// PrivateKey is the WireGuard private key (base64).
	PrivateKey string `json:"private_key" yaml:"private_key"`

	// PublicKey is the peer (Cloudflare) public key (base64).
	PublicKey string `json:"public_key" yaml:"public_key"`

	// ClientID is a 3-byte identifier encoded as base64.
	ClientID string `json:"client_id" yaml:"client_id"`

	// DeviceID is the registered device UUID from Cloudflare.
	DeviceID string `json:"device_id" yaml:"device_id"`

	// AccessToken is the bearer token for WARP API calls.
	AccessToken string `json:"access_token" yaml:"access_token"`

	// IPv4 is the assigned WARP IPv4 address (CIDR).
	IPv4 string `json:"ipv4" yaml:"ipv4"`

	// IPv6 is the assigned WARP IPv6 address (CIDR).
	IPv6 string `json:"ipv6" yaml:"ipv6"`

	// Endpoint is the Cloudflare WireGuard endpoint.
	Endpoint string `json:"endpoint" yaml:"endpoint"`

	// Reserved is the 3-byte reserved field for the WireGuard tunnel.
	Reserved [3]byte `json:"reserved" yaml:"reserved"`

	// RegisteredAt records when this WARP identity was registered.
	RegisteredAt time.Time `json:"registered_at" yaml:"registered_at"`
}

// warpRegRequest is the JSON body sent to the WARP registration API.
type warpRegRequest struct {
	Key       string `json:"key"`
	InstallID string `json:"install_id"`
	FCMToken  string `json:"fcm_token"`
	Type      string `json:"type"`
	Model     string `json:"model"`
	Locale    string `json:"locale"`
}

// warpRegResponse is the JSON response from the WARP registration API.
type warpRegResponse struct {
	ID      string `json:"id"`
	Account struct {
		ID string `json:"id"`
	} `json:"account"`
	Token  string `json:"token"`
	Config struct {
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
		ClientID string `json:"client_id"`
	} `json:"config"`
}

// generateWireGuardKeyPair generates a new Curve25519 key pair for WireGuard.
// Returns (privateKey, publicKey) as base64-encoded strings.
func generateWireGuardKeyPair() (string, string, error) {
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return "", "", fmt.Errorf("warp: generate random key: %w", err)
	}

	// Clamp the private key per Curve25519 convention.
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	privB64 := base64.StdEncoding.EncodeToString(privateKey[:])
	pubB64 := base64.StdEncoding.EncodeToString(publicKey[:])

	return privB64, pubB64, nil
}

// generateClientID creates a random 3-byte client identifier.
func generateClientID() ([3]byte, string, error) {
	var id [3]byte
	if _, err := rand.Read(id[:]); err != nil {
		return id, "", fmt.Errorf("warp: generate client id: %w", err)
	}
	return id, base64.StdEncoding.EncodeToString(id[:]), nil
}

// RegisterWARP registers a new device with Cloudflare's WARP API
// and returns a WARPConfig with all credentials needed for WireGuard.
//
// This calls Cloudflare's WARP client API, which is the same API
// used by the 1.1.1.1 app. The free tier provides unlimited bandwidth
// but routes only through Cloudflare's network (no WARP+ locations).
//
// The httpPost parameter is a function that performs HTTP POST requests,
// allowing tests to inject a mock. Its signature is:
//
//	func(url string, headers map[string]string, body []byte) ([]byte, error)
func RegisterWARP(httpPost func(url string, headers map[string]string, body []byte) ([]byte, error)) (*WARPConfig, error) {
	// Generate WireGuard key pair.
	privKey, pubKey, err := generateWireGuardKeyPair()
	if err != nil {
		return nil, err
	}

	// Generate client ID.
	reserved, _, err := generateClientID()
	if err != nil {
		return nil, err
	}

	// Build registration request.
	regReq := warpRegRequest{
		Key:       pubKey,
		InstallID: "", // empty is fine for free tier
		FCMToken:  "",
		Type:      "Linux",
		Model:     "HydraFlow",
		Locale:    "en_US",
	}

	reqBody, err := json.Marshal(regReq)
	if err != nil {
		return nil, fmt.Errorf("warp: marshal request: %w", err)
	}

	headers := map[string]string{
		"Content-Type":     "application/json",
		"User-Agent":       "HydraFlow/2.0",
		"CF-Client-Version": "a-6.11-2223",
	}

	respBody, err := httpPost(warpAPIBase, headers, reqBody)
	if err != nil {
		return nil, fmt.Errorf("warp: registration request failed: %w", err)
	}

	var resp warpRegResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("warp: parse response: %w", err)
	}

	if resp.ID == "" {
		return nil, fmt.Errorf("warp: registration returned empty device ID")
	}

	if len(resp.Config.Peers) == 0 {
		return nil, fmt.Errorf("warp: no peers in registration response")
	}

	peer := resp.Config.Peers[0]

	cfg := &WARPConfig{
		Enabled:      true,
		PrivateKey:   privKey,
		PublicKey:    peer.PublicKey,
		ClientID:     base64.StdEncoding.EncodeToString(reserved[:]),
		DeviceID:     resp.ID,
		AccessToken:  resp.Token,
		IPv4:         resp.Config.Interface.Addresses.V4,
		IPv6:         resp.Config.Interface.Addresses.V6,
		Endpoint:     peer.Endpoint.V4,
		Reserved:     reserved,
		RegisteredAt: time.Now().UTC(),
	}

	if cfg.Endpoint == "" {
		cfg.Endpoint = "engage.cloudflareclient.com:2408"
	}

	return cfg, nil
}

// StreamingDomains returns the list of domains that should be routed
// through WARP for streaming/AI service access.
var StreamingDomains = []string{
	// Netflix
	"domain:netflix.com",
	"domain:netflix.net",
	"domain:nflxvideo.net",
	"domain:nflximg.net",
	"domain:nflxso.net",
	"domain:nflxext.com",
	// ChatGPT / OpenAI
	"domain:openai.com",
	"domain:chatgpt.com",
	"domain:oaiusercontent.com",
	"domain:oaistatic.com",
	"domain:auth0.com",
	// Spotify
	"domain:spotify.com",
	"domain:spotifycdn.com",
	"domain:scdn.co",
	"domain:spotify.net",
	// Disney+
	"domain:disneyplus.com",
	"domain:disney-plus.net",
	"domain:dssott.com",
	"domain:bamgrid.com",
	// Hulu
	"domain:hulu.com",
	"domain:hulustream.com",
	"domain:huluim.com",
	// YouTube Premium (geo-restricted content)
	"domain:youtube.com",
	"domain:googlevideo.com",
	"domain:ytimg.com",
	// Claude / Anthropic
	"domain:anthropic.com",
	"domain:claude.ai",
	// Google Gemini
	"domain:gemini.google.com",
	"domain:bard.google.com",
}

// XrayWARPOutbound represents the xray-core WireGuard outbound config
// for routing traffic through Cloudflare WARP.
type XrayWARPOutbound struct {
	Tag      string                 `json:"tag"`
	Protocol string                 `json:"protocol"`
	Settings map[string]interface{} `json:"settings"`
}

// GenerateWARPOutbound creates an xray-core outbound configuration
// that routes traffic through the Cloudflare WARP WireGuard tunnel.
func GenerateWARPOutbound(cfg *WARPConfig) (*XrayWARPOutbound, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, fmt.Errorf("warp: config is nil or disabled")
	}
	if cfg.PrivateKey == "" || cfg.PublicKey == "" {
		return nil, fmt.Errorf("warp: missing WireGuard keys")
	}

	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "engage.cloudflareclient.com:2408"
	}

	reserved := make([]int, 3)
	reserved[0] = int(cfg.Reserved[0])
	reserved[1] = int(cfg.Reserved[1])
	reserved[2] = int(cfg.Reserved[2])

	outbound := &XrayWARPOutbound{
		Tag:      "warp-out",
		Protocol: "wireguard",
		Settings: map[string]interface{}{
			"secretKey": cfg.PrivateKey,
			"address": []string{
				cfg.IPv4,
				cfg.IPv6,
			},
			"peers": []map[string]interface{}{
				{
					"publicKey": cfg.PublicKey,
					"endpoint":  endpoint,
				},
			},
			"reserved": reserved,
			"mtu":      1280,
		},
	}

	return outbound, nil
}

// GenerateWARPRoutingRules creates xray-core routing rules that send
// streaming/AI service traffic through the WARP outbound.
func GenerateWARPRoutingRules() map[string]interface{} {
	return map[string]interface{}{
		"type":        "field",
		"outboundTag": "warp-out",
		"domain":      StreamingDomains,
	}
}

// GenerateFullXrayWARPConfig returns the complete set of xray config
// objects (outbound + routing rule) needed to enable WARP.
func GenerateFullXrayWARPConfig(cfg *WARPConfig) (outbound *XrayWARPOutbound, rule map[string]interface{}, err error) {
	outbound, err = GenerateWARPOutbound(cfg)
	if err != nil {
		return nil, nil, err
	}
	rule = GenerateWARPRoutingRules()
	return outbound, rule, nil
}
