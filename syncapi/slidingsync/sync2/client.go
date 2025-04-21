package sync2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/element-hq/dendrite/syncapi/sync"
	"github.com/element-hq/dendrite/syncapi/types"
	userapi "github.com/element-hq/dendrite/userapi/api"
)

const AccountDataGlobalRoom = ""

type Client interface {
	// // Versions fetches and parses the list of Matrix versions that the homeserver
	// // advertises itself as supporting.
	// Versions(ctx context.Context) (version []string, err error)
	// // WhoAmI asks the homeserver to lookup the access token using the CSAPI /whoami
	// // endpoint. The response must contain a device ID (meaning that we assume the
	// // homeserver supports Matrix >= 1.1.)
	// WhoAmI(ctx context.Context, accessToken string) (userID, deviceID string, err error)
	DoSyncV2(ctx context.Context, userID, deviceID, since string, isFirst bool, toDeviceOnly bool) (*types.Response, error)
}

// PseudoClient is a temporary replacement of the original HTTP client. Since sliding sync proxy is now a part of dendrite,
// there is no need to send http requests to the main server. Instead we call handlers directly.
// Obviously, this a minimum sufficient solution and is acceptable for the first iteration of merging, however it must be removed
// in the further iterations.
type PseudoClient struct {
	rp *sync.RequestPool
}

func NewPseudoClient(rp *sync.RequestPool) *PseudoClient {
	return &PseudoClient{
		rp: rp,
	}
}

func (p *PseudoClient) DoSyncV2(ctx context.Context, userID, deviceID, since string, isFirst bool, toDeviceOnly bool) (*types.Response, error) {
	syncURL := p.createSyncURL(since, isFirst, toDeviceOnly)
	req, _ := http.NewRequestWithContext(ctx, "GET", syncURL, nil)
	device := userapi.Device{
		ID:     deviceID,
		UserID: userID,
	}
	jsonResponse := p.rp.OnIncomingSyncRequest(req, &device)
	if !jsonResponse.Is2xx() {
		return nil, fmt.Errorf("DoSyncV2: OnIncomingSyncRequest failed")
	}
	resp, ok := jsonResponse.JSON.(*types.Response)
	if !ok {
		return nil, fmt.Errorf("DoSyncV2: OnIncomingSyncRequest returned unknown Response")
	}
	return resp, nil
}

func (p *PseudoClient) createSyncURL(since string, isFirst, toDeviceOnly bool) string {
	qps := "?"
	if isFirst { // first time polling for v2-sync in this process
		qps += "timeout=0"
	} else {
		qps += "timeout=30000"
	}
	if since != "" {
		qps += "&since=" + url.QueryEscape(since)
	}

	// Set presence to offline, this potentially reduces CPU load on upstream homeservers
	qps += "&set_presence=offline"

	// To reduce the likelihood of a gappy v2 sync, ask for a large timeline by default.
	// Synapse's default is 10; 50 is the maximum allowed, by my reading of
	// https://github.com/matrix-org/synapse/blob/89a71e73905ffa1c97ae8be27d521cd2ef3f3a0c/synapse/handlers/sync.py#L576-L577
	// NB: this is a stopgap to reduce the likelihood of hitting
	// https://github.com/matrix-org/sliding-sync/issues/18
	timelineLimit := 50
	if since == "" {
		// First time the poller has sync v2-ed for this user
		timelineLimit = 1
	}
	room := map[string]interface{}{}
	room["timeline"] = map[string]interface{}{"limit": timelineLimit}

	if toDeviceOnly {
		// no rooms match this filter, so we get everything but room data
		room["rooms"] = []string{}
	}
	filter := map[string]interface{}{
		"room": room,
		// filter out all presence events (remove this once/if the proxy handles presence)
		"presence": map[string]interface{}{"not_types": []string{"*"}},
	}
	filterJSON, _ := json.Marshal(filter)
	qps += "&filter=" + url.QueryEscape(string(filterJSON))

	return "/sync" + qps
}

type SyncResponse struct {
	NextBatch   string         `json:"next_batch"`
	AccountData EventsResponse `json:"account_data"`
	Presence    struct {
		Events []json.RawMessage `json:"events,omitempty"`
	} `json:"presence"`
	Rooms       SyncRoomsResponse `json:"rooms"`
	ToDevice    EventsResponse    `json:"to_device"`
	DeviceLists struct {
		Changed []string `json:"changed,omitempty"`
		Left    []string `json:"left,omitempty"`
	} `json:"device_lists"`
	DeviceListsOTKCount          map[string]int `json:"device_one_time_keys_count,omitempty"`
	DeviceUnusedFallbackKeyTypes []string       `json:"device_unused_fallback_key_types,omitempty"`
}

type SyncRoomsResponse struct {
	Join   map[string]SyncV2JoinResponse   `json:"join"`
	Invite map[string]SyncV2InviteResponse `json:"invite"`
	Leave  map[string]SyncV2LeaveResponse  `json:"leave"`
}

// JoinResponse represents a /sync response for a room which is under the 'join' or 'peek' key.
type SyncV2JoinResponse struct {
	State               EventsResponse      `json:"state"`
	Timeline            TimelineResponse    `json:"timeline"`
	Ephemeral           EventsResponse      `json:"ephemeral"`
	AccountData         EventsResponse      `json:"account_data"`
	UnreadNotifications UnreadNotifications `json:"unread_notifications"`
}

type UnreadNotifications struct {
	HighlightCount    *int `json:"highlight_count,omitempty"`
	NotificationCount *int `json:"notification_count,omitempty"`
}

type TimelineResponse struct {
	Events    []json.RawMessage `json:"events"`
	Limited   bool              `json:"limited"`
	PrevBatch string            `json:"prev_batch,omitempty"`
}

type EventsResponse struct {
	Events []json.RawMessage `json:"events"`
}

// InviteResponse represents a /sync response for a room which is under the 'invite' key.
type SyncV2InviteResponse struct {
	InviteState EventsResponse `json:"invite_state"`
}

// LeaveResponse represents a /sync response for a room which is under the 'leave' key.
type SyncV2LeaveResponse struct {
	State struct {
		Events []json.RawMessage `json:"events"`
	} `json:"state"`
	Timeline struct {
		Events    []json.RawMessage `json:"events"`
		Limited   bool              `json:"limited"`
		PrevBatch string            `json:"prev_batch,omitempty"`
	} `json:"timeline"`
}
