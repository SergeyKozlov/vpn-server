package xui

import "encoding/json"

// envelope is the standard response shape of every /panel/api/* handler.
type envelope struct {
	Success bool            `json:"success"`
	Msg     string          `json:"msg"`
	Obj     json.RawMessage `json:"obj"`
}

// Client is a single VLESS client entry, as sent to/read from the
// /panel/api/clients/* endpoints (standalone client records since 3x-ui
// v3.5.0 — no longer nested inside an inbound's "settings" JSON).
type Client struct {
	ID         string `json:"id,omitempty"`   // VLESS UUID; server-generated if omitted on add
	Email      string `json:"email"`          // unique across the whole panel; primary identifier
	Flow       string `json:"flow,omitempty"` // "xtls-rprx-vision" for VLESS Reality Vision
	Enable     bool   `json:"enable"`
	ExpiryTime int64  `json:"expiryTime"` // epoch milliseconds, 0 = never
	LimitIP    int    `json:"limitIp"`    // max concurrent IPs, 0 = unlimited
	TotalGB    int64  `json:"totalGB"`    // bytes, 0 = unlimited
	TgID       int64  `json:"tgId"`       // must be numeric; a "" string 400s on v3.5.0
	SubID      string `json:"subId,omitempty"`
	Comment    string `json:"comment,omitempty"`
	Reset      int    `json:"reset"` // traffic reset period in days, 0 = never
}

// addClientRequest is the /panel/api/clients/add body: the client record
// plus which inbound(s) to attach it to (a client is no longer embedded in
// one inbound's settings, so the association is explicit).
type addClientRequest struct {
	Client     Client `json:"client"`
	InboundIDs []int  `json:"inboundIds"`
}

// ClientTraffic is per-client usage/quota info, as returned by
// /panel/api/clients/traffic/{email} and embedded in Inbound.ClientStats.
type ClientTraffic struct {
	ID         int    `json:"id"`
	InboundID  int    `json:"inboundId"`
	Enable     bool   `json:"enable"`
	Email      string `json:"email"`
	Up         int64  `json:"up"`   // bytes uploaded
	Down       int64  `json:"down"` // bytes downloaded
	Total      int64  `json:"total"`
	ExpiryTime int64  `json:"expiryTime"`
	Reset      int    `json:"reset"`
}

// Inbound is a 3x-ui inbound entry. Settings is a stringified JSON blob
// (contains the clients array); unmarshal it separately if needed.
type Inbound struct {
	ID          int             `json:"id"`
	Remark      string          `json:"remark"`
	Enable      bool            `json:"enable"`
	Port        int             `json:"port"`
	Protocol    string          `json:"protocol"`
	Settings    string          `json:"settings"`
	ClientStats []ClientTraffic `json:"clientStats"`
}
