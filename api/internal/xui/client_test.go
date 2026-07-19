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
	if gotPath != "/base/panel/api/inbounds/addClient" {
		t.Errorf("path = %q, want /base/panel/api/inbounds/addClient", gotPath)
	}
	if gotAuth != "Bearer test-token" {
		t.Errorf("Authorization = %q, want Bearer test-token", gotAuth)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
	if gotBody.ID != 1 {
		t.Errorf("id = %d, want 1", gotBody.ID)
	}

	// settings must be a *string* containing JSON, not a nested object.
	var settings clientSettings
	if err := json.Unmarshal([]byte(gotBody.Settings), &settings); err != nil {
		t.Fatalf("settings is not valid JSON: %v", err)
	}
	if len(settings.Clients) != 1 || settings.Clients[0].ID != client.ID {
		t.Errorf("settings.clients = %+v, want [%+v]", settings.Clients, client)
	}
}

func TestUpdateAndDeleteClientPaths(t *testing.T) {
	var gotPaths []string

	p, _ := newTestPanel(t, func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(envelope{Success: true})
	})

	uuid := "95e4e7bb-7f3e-4a1e-9d6a-0b2c3d4e5f60"

	if err := p.UpdateClient(context.Background(), 1, uuid, Client{ID: uuid}); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	if err := p.DeleteClient(context.Background(), 1, uuid); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}

	want := []string{
		"/base/panel/api/inbounds/updateClient/" + uuid,
		"/base/panel/api/inbounds/1/delClient/" + uuid,
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

func TestGetClientTraffics(t *testing.T) {
	p, _ := newTestPanel(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/base/panel/api/inbounds/getClientTraffics/user_ab12cd" {
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
