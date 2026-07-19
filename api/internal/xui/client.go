// Package xui is a client for the 3x-ui panel API
// ({webBasePath}/panel/api/inbounds/*), authenticated with a Bearer API
// token (Settings → Security → API Token in the panel) rather than
// cookie-based login, to avoid session-expiry handling.
package xui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const inboundsPath = "/panel/api/inbounds"

// Panel is a client for one 3x-ui panel instance.
type Panel struct {
	// baseURL must already include the panel's webBasePath, e.g.
	// "https://host:port/xyzsecret" — every route is mounted under it,
	// including the API, so a base URL without it will 404 on every call.
	baseURL    string
	token      string
	httpClient *http.Client
}

func NewPanel(baseURL, token string) (*Panel, error) {
	if baseURL == "" {
		return nil, errors.New("xui: base URL is required")
	}
	if token == "" {
		return nil, errors.New("xui: API token is required")
	}

	return &Panel{
		baseURL:    strings.TrimSuffix(baseURL, "/"),
		token:      token,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}, nil
}

func (p *Panel) do(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, p.baseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("xui: unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var env envelope
	if err := json.Unmarshal(respBody, &env); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if !env.Success {
		return nil, fmt.Errorf("xui: %s", env.Msg)
	}

	return env.Obj, nil
}

func (p *Panel) ListInbounds(ctx context.Context) ([]Inbound, error) {
	obj, err := p.do(ctx, http.MethodGet, inboundsPath+"/list", nil)
	if err != nil {
		return nil, err
	}

	var inbounds []Inbound
	if err := json.Unmarshal(obj, &inbounds); err != nil {
		return nil, fmt.Errorf("decode inbounds: %w", err)
	}
	return inbounds, nil
}

func (p *Panel) GetInbound(ctx context.Context, id int) (*Inbound, error) {
	obj, err := p.do(ctx, http.MethodGet, fmt.Sprintf("%s/get/%d", inboundsPath, id), nil)
	if err != nil {
		return nil, err
	}

	var inbound Inbound
	if err := json.Unmarshal(obj, &inbound); err != nil {
		return nil, fmt.Errorf("decode inbound: %w", err)
	}
	return &inbound, nil
}

func (p *Panel) AddClient(ctx context.Context, inboundID int, client Client) error {
	settings, err := marshalClientSettings(client)
	if err != nil {
		return err
	}

	_, err = p.do(ctx, http.MethodPost, inboundsPath+"/addClient", addClientRequest{
		ID:       inboundID,
		Settings: settings,
	})
	return err
}

func (p *Panel) UpdateClient(ctx context.Context, inboundID int, clientUUID string, client Client) error {
	settings, err := marshalClientSettings(client)
	if err != nil {
		return err
	}

	path := fmt.Sprintf("%s/updateClient/%s", inboundsPath, url.PathEscape(clientUUID))
	_, err = p.do(ctx, http.MethodPost, path, addClientRequest{
		ID:       inboundID,
		Settings: settings,
	})
	return err
}

func (p *Panel) DeleteClient(ctx context.Context, inboundID int, clientUUID string) error {
	path := fmt.Sprintf("%s/%d/delClient/%s", inboundsPath, inboundID, url.PathEscape(clientUUID))
	_, err := p.do(ctx, http.MethodPost, path, nil)
	return err
}

// GetClientTraffics fetches usage/quota info by client email.
func (p *Panel) GetClientTraffics(ctx context.Context, email string) (*ClientTraffic, error) {
	path := fmt.Sprintf("%s/getClientTraffics/%s", inboundsPath, url.PathEscape(email))
	obj, err := p.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var traffic ClientTraffic
	if err := json.Unmarshal(obj, &traffic); err != nil {
		return nil, fmt.Errorf("decode client traffic: %w", err)
	}
	return &traffic, nil
}

// GetClientTrafficsByID fetches usage/quota info by client UUID. 3x-ui may
// return more than one entry if the UUID exists across multiple inbounds.
func (p *Panel) GetClientTrafficsByID(ctx context.Context, uuid string) ([]ClientTraffic, error) {
	path := fmt.Sprintf("%s/getClientTrafficsById/%s", inboundsPath, url.PathEscape(uuid))
	obj, err := p.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var traffics []ClientTraffic
	if err := json.Unmarshal(obj, &traffics); err != nil {
		return nil, fmt.Errorf("decode client traffics: %w", err)
	}
	return traffics, nil
}

func marshalClientSettings(client Client) (string, error) {
	b, err := json.Marshal(clientSettings{Clients: []Client{client}})
	if err != nil {
		return "", fmt.Errorf("marshal client settings: %w", err)
	}
	return string(b), nil
}
