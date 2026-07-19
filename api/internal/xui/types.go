package xui

import "encoding/json"

// envelope is the standard response shape of every /panel/api/* handler.
type envelope struct {
	Success bool            `json:"success"`
	Msg     string          `json:"msg"`
	Obj     json.RawMessage `json:"obj"`
}

// Client is a single VLESS client entry, as sent to/read from the
// addClient/updateClient/inbound "settings" JSON.
type Client struct {
	ID         string `json:"id"`             // VLESS UUID
	Email      string `json:"email"`          // unique identifier, not a real email
	Flow       string `json:"flow,omitempty"` // "xtls-rprx-vision" for VLESS Reality Vision
	Enable     bool   `json:"enable"`
	ExpiryTime int64  `json:"expiryTime"` // epoch milliseconds, 0 = never
	LimitIP    int    `json:"limitIp"`    // max concurrent IPs, 0 = unlimited
	TotalGB    int64  `json:"totalGB"`    // bytes, 0 = unlimited
	TgID       string `json:"tgId,omitempty"`
	SubID      string `json:"subId,omitempty"`
	Reset      int    `json:"reset"` // traffic reset period in days, 0 = never
}

// clientSettings is marshaled to a string and sent as the "settings" field
// of addClient/updateClient requests — 3x-ui expects stringified JSON there,
// not a nested object.
type clientSettings struct {
	Clients []Client `json:"clients"`
}

type addClientRequest struct {
	ID       int    `json:"id"`
	Settings string `json:"settings"`
}

// ClientTraffic is per-client usage/quota info, as returned by
// getClientTraffics/getClientTrafficsById and embedded in Inbound.ClientStats.
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
