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

const (
	inboundsPath = "/panel/api/inbounds"
	clientsPath  = "/panel/api/clients"
)

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

// AddClient creates a standalone client record and attaches it to
// inboundID. If client.ID is empty, the panel generates a fresh VLESS UUID
// server-side and ignores a client-supplied one silently on some builds —
// always pass an explicit ID when the caller (e.g. clients.Service) needs
// to control the credential value.
func (p *Panel) AddClient(ctx context.Context, inboundID int, client Client) error {
	_, err := p.do(ctx, http.MethodPost, clientsPath+"/add", addClientRequest{
		Client:     client,
		InboundIDs: []int{inboundID},
	})
	return err
}

// UpdateClient replaces the client record identified by email — this is a
// full overwrite, not a partial patch: any field left at its zero value
// (e.g. Enable omitted) is written as that zero value, silently disabling
// or clearing the field. Callers must always send the complete desired
// record. Inbound attachment is untouched by this call.
func (p *Panel) UpdateClient(ctx context.Context, email string, client Client) error {
	path := fmt.Sprintf("%s/update/%s", clientsPath, url.PathEscape(email))
	_, err := p.do(ctx, http.MethodPost, path, client)
	return err
}

// DeleteClient removes the client record identified by email.
func (p *Panel) DeleteClient(ctx context.Context, email string) error {
	path := fmt.Sprintf("%s/del/%s", clientsPath, url.PathEscape(email))
	_, err := p.do(ctx, http.MethodPost, path, nil)
	return err
}

// GetClientTraffics fetches usage/quota info by client email.
func (p *Panel) GetClientTraffics(ctx context.Context, email string) (*ClientTraffic, error) {
	path := fmt.Sprintf("%s/traffic/%s", clientsPath, url.PathEscape(email))
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
