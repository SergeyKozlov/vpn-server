package xui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewPanelValidation(t *testing.T) {
	if _, err := NewPanel("", "token"); err == nil {
		t.Fatalf("expected error for empty base URL")
	}
	if _, err := NewPanel("https://host/base", ""); err == nil {
		t.Fatalf("expected error for empty token")
	}
	if _, err := NewPanel("https://host/base", "token"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func newTestPanel(t *testing.T, handler http.HandlerFunc) (*Panel, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	p, err := NewPanel(srv.URL+"/base", "test-token")
	if err != nil {
		t.Fatalf("NewPanel: %v", err)
	}
	return p, srv
}

func TestAddClientRequestShape(t *testing.T) {
	var gotPath, gotMethod, gotAuth, gotContentType string
	var gotBody addClientRequest

	p, _ := newTestPanel(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(envelope{Success: true})
	})

	client := Client{
		ID:         "95e4e7bb-7f3e-4a1e-9d6a-0b2c3d4e5f60",
		Email:      "user_ab12cd",
		Flow:       "xtls-rprx-vision",
		Enable:     true,
		ExpiryTime: 1767225600000,
		LimitIP:    2,
		TotalGB:    107374182400,
		SubID:      "sub_ab12cd",
	}

	if err := p.AddClient(context.Background(), 1, client); err != nil {
		t.Fatalf("AddClient: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/base/panel/api/clients/add" {
		t.Errorf("path = %q, want /base/panel/api/clients/add", gotPath)
	}
	if gotAuth != "Bearer test-token" {
		t.Errorf("Authorization = %q, want Bearer test-token", gotAuth)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}

	// The client record is a flat JSON object under "client", not an
	// escaped-string "settings" blob — and the inbound association is
	// explicit via top-level "inboundIds".
	if gotBody.Client != client {
		t.Errorf("client = %+v, want %+v", gotBody.Client, client)
	}
	if len(gotBody.InboundIDs) != 1 || gotBody.InboundIDs[0] != 1 {
		t.Errorf("inboundIds = %v, want [1]", gotBody.InboundIDs)
	}
}

func TestUpdateAndDeleteClientPaths(t *testing.T) {
	var gotPaths []string

	p, _ := newTestPanel(t, func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(envelope{Success: true})
	})

	email := "user_ab12cd"
	uuid := "95e4e7bb-7f3e-4a1e-9d6a-0b2c3d4e5f60"

	if err := p.UpdateClient(context.Background(), email, Client{ID: uuid, Email: email}); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	if err := p.DeleteClient(context.Background(), email); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}

	want := []string{
		"/base/panel/api/clients/update/" + email,
		"/base/panel/api/clients/del/" + email,
	}
	if len(gotPaths) != len(want) {
		t.Fatalf("got %d requests, want %d", len(gotPaths), len(want))
	}
	for i, w := range want {
		if gotPaths[i] != w {
			t.Errorf("request %d path = %q, want %q", i, gotPaths[i], w)
		}
	}
}

func TestUpdateClientSendsFlatClientBody(t *testing.T) {
	var gotBody Client

	p, _ := newTestPanel(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(envelope{Success: true})
	})

	client := Client{ID: "uuid-1", Email: "user_ab12cd", Enable: true, LimitIP: 3}
	if err := p.UpdateClient(context.Background(), client.Email, client); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}

	if gotBody != client {
		t.Errorf("request body = %+v, want %+v", gotBody, client)
	}
}

func TestGetClientTraffics(t *testing.T) {
	p, _ := newTestPanel(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/base/panel/api/clients/traffic/user_ab12cd" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(envelope{
			Success: true,
			Obj:     json.RawMessage(`{"id":1,"inboundId":1,"enable":true,"email":"user_ab12cd","up":524288000,"down":1048576000,"total":107374182400,"expiryTime":1767225600000,"reset":0}`),
		})
	})

	traffic, err := p.GetClientTraffics(context.Background(), "user_ab12cd")
	if err != nil {
		t.Fatalf("GetClientTraffics: %v", err)
	}
	if traffic.Email != "user_ab12cd" || traffic.Up != 524288000 || traffic.Down != 1048576000 {
		t.Errorf("unexpected traffic: %+v", traffic)
	}
}

func TestErrorEnvelopeReturnsError(t *testing.T) {
	p, _ := newTestPanel(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(envelope{Success: false, Msg: "client already exists"})
	})

	err := p.AddClient(context.Background(), 1, Client{ID: "x", Email: "y"})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestNonOKStatusReturnsError(t *testing.T) {
	p, _ := newTestPanel(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("unauthorized"))
	})

	_, err := p.GetClientTraffics(context.Background(), "user_ab12cd")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestListAndGetInbound(t *testing.T) {
	p, _ := newTestPanel(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		switch r.URL.Path {
		case "/base/panel/api/inbounds/list":
			json.NewEncoder(w).Encode(envelope{
				Success: true,
				Obj:     json.RawMessage(`[{"id":1,"remark":"vless-reality","enable":true,"port":443,"protocol":"vless","settings":"{}"}]`),
			})
		case "/base/panel/api/inbounds/get/1":
			json.NewEncoder(w).Encode(envelope{
				Success: true,
				Obj:     json.RawMessage(`{"id":1,"remark":"vless-reality","enable":true,"port":443,"protocol":"vless","settings":"{}"}`),
			})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	inbounds, err := p.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("ListInbounds: %v", err)
	}
	if len(inbounds) != 1 || inbounds[0].ID != 1 || inbounds[0].Protocol != "vless" {
		t.Errorf("unexpected inbounds: %+v", inbounds)
	}

	inbound, err := p.GetInbound(context.Background(), 1)
	if err != nil {
		t.Fatalf("GetInbound: %v", err)
	}
	if inbound.Port != 443 {
		t.Errorf("unexpected inbound: %+v", inbound)
	}
}
