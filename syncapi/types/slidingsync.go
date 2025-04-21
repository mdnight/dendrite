package types

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/gjson"
)

type SlidingSyncRoomInfo struct {
	ID                string
	IsEncrypted       bool
	UpgradedRoomID    *string // from the most recent valid tombstone event, or NULL
	PredecessorRoomID *string // from the create event
	Type              *string
}

type SlidingSyncAccountData struct {
	ID     int64
	UserID string
	RoomID string
	Type   string
	Data   []byte
}

type SlidingSyncEvent struct {
	NID        int64
	Type       string
	StateKey   string
	Membership string
	// whether this was part of a v2 state response and hence not part of the timeline
	IsState bool
	// This is a snapshot ID which corresponds to some room state BEFORE this event has been applied.
	BeforeStateSnapshotID int64
	ReplacesNID           int64
	ID                    string
	RoomID                string
	// not all events include a prev batch (e.g if it was part of state not timeline, and only the first
	// event in a timeline has a prev_batch attached), but we'll look for the 'closest' prev batch
	// when returning these tokens to the caller (closest = next newest, assume clients de-dupe)
	PrevBatch sql.NullString
	// stripped events will be missing this field
	JSON []byte
	// MissingPrevious is true iff the previous timeline event is not known to the proxy.
	MissingPrevious bool
	Unsigned        []byte
}

type SlidingSyncStrippedEvents []SlidingSyncEvent

func (se SlidingSyncStrippedEvents) NIDs() (membershipNIDs, otherNIDs []int64) {
	for _, s := range se {
		if s.Type == spec.MRoomMember {
			membershipNIDs = append(membershipNIDs, s.NID)
		} else {
			otherNIDs = append(otherNIDs, s.NID)
		}
	}
	return
}

func (ev *SlidingSyncEvent) EnsureFieldsSetOnEvent() error {
	evJSON := gjson.ParseBytes(ev.JSON)
	unsignedJSON := gjson.ParseBytes(ev.Unsigned)
	if ev.RoomID == "" {
		roomIDResult := evJSON.Get("room_id")
		if !roomIDResult.Exists() || roomIDResult.Str == "" {
			return fmt.Errorf("event missing room_id key")
		}
		ev.RoomID = roomIDResult.Str
	}
	if ev.ID == "" {
		eventIDResult := evJSON.Get("event_id")
		if !eventIDResult.Exists() || eventIDResult.Str == "" {
			return fmt.Errorf("event JSON missing event_id key")
		}
		ev.ID = eventIDResult.Str
	}
	if ev.Type == "" {
		typeResult := evJSON.Get("type")
		if !typeResult.Exists() || typeResult.Type != gjson.String { // empty strings for 'type' are valid apparently
			return fmt.Errorf("event JSON missing type key")
		}
		ev.Type = typeResult.Str
	}
	if ev.StateKey == "" {
		// valid for this to be "" on message events
		ev.StateKey = evJSON.Get("state_key").Str
	}
	if ev.StateKey != "" && ev.Type == spec.MRoomMember {
		membershipResult := evJSON.Get("membership")
		if !membershipResult.Exists() || membershipResult.Str == "" {
			return fmt.Errorf("membership event missing membership key")
		}
		// genuine changes mark the membership event
		if isMembershipChange(evJSON, unsignedJSON) {
			ev.Membership = membershipResult.Str
		} else {
			// profile changes have _ prefix.
			ev.Membership = "_" + membershipResult.Str
		}
	}
	return nil
}

func isMembershipChange(eventJSON gjson.Result, unsignedJSON gjson.Result) bool {
	// membership event possibly, make sure the membership has changed else
	// things like display name changes will count as membership events :(
	prevMembership := spec.Leave
	pm := unsignedJSON.Get("prev_content.membership")
	if pm.Exists() && pm.Str != "" {
		prevMembership = pm.Str
	}
	currMembership := spec.Leave
	cm := eventJSON.Get("membership")
	if cm.Exists() && cm.Str != "" {
		currMembership = cm.Str
	}
	return prevMembership != currMembership // membership was changed
}

type SlidingSyncSpaceRelation struct {
	Relation    int
	IsSuggested bool
	Parent      string
	Child       string
	Ordering    string
}

func (sr *SlidingSyncSpaceRelation) Key() string {
	return strings.Join([]string{sr.Parent, sr.Child, strconv.Itoa(sr.Relation)}, "-")
}

type SlidingSyncSnapshotRow struct {
	SnapshotID       int64
	RoomID           string
	OtherEvents      []int64
	MembershipEvents []int64
}

type SlidingSyncReceipt struct {
	TS        int64
	IsPrivate bool
	RoomID    string
	EventID   string
	UserID    string
	ThreadID  string
}

type SlidingSyncReceiptEDU struct {
	Type    string                               `json:"type"`
	Content map[string]SlidingSyncReceiptContent `json:"content"`
}

type SlidingSyncReceiptContent struct {
	Read        map[string]SlidingSyncReceiptInfo `json:"m.read,omitempty"`
	ReadPrivate map[string]SlidingSyncReceiptInfo `json:"m.read.private,omitempty"`
}

type SlidingSyncReceiptInfo struct {
	TS       int64  `json:"ts"`
	ThreadID string `json:"thread_id,omitempty"`
}

const (
	SlidingSyncDeviceListChanged = 1
	SlidingSyncDeviceListLeft    = 2
)

type SlidingSyncMapStringInt map[string]int

// Value implements driver.Valuer
func (dl SlidingSyncMapStringInt) Value() (driver.Value, error) {
	if len(dl) == 0 {
		return "{}", nil
	}
	v, err := json.Marshal(dl)
	return v, err
}

const (
	bitOTKCount int = iota
	bitFallbackKeyTypes
)

func setBit(n int, bit int) int {
	n |= (1 << bit)
	return n
}
func isBitSet(n int, bit int) bool {
	val := n & (1 << bit)
	return val > 0
}

// SlidingSyncDeviceData contains useful data for this user's device.
type SlidingSyncDeviceData struct {
	SlidingSyncDeviceListChanges
	SlidingSyncDeviceKeyData
	UserID   string
	DeviceID string
}

// This is calculated from device_lists table
type SlidingSyncDeviceListChanges struct {
	DeviceListChanged []string
	DeviceListLeft    []string
}

// This gets serialised as CBOR in device_data table
type SlidingSyncDeviceKeyData struct {
	// Contains the latest device_one_time_keys_count values.
	// Set whenever this field arrives down the v2 poller, and it replaces what was previously there.
	OTKCounts SlidingSyncMapStringInt `json:"otk"`
	// Contains the latest device_unused_fallback_key_types value
	// Set whenever this field arrives down the v2 poller, and it replaces what was previously there.
	// If this is a nil slice this means no change. If this is an empty slice then this means the fallback key was used up.
	FallbackKeyTypes []string `json:"fallback"`
	// bitset for which device data changes are present. They accumulate until they get swapped over
	// when they get reset
	ChangedBits int `json:"c"`
}

func (dd *SlidingSyncDeviceKeyData) SetOTKCountChanged() {
	dd.ChangedBits = setBit(dd.ChangedBits, bitOTKCount)
}

func (dd *SlidingSyncDeviceKeyData) SetFallbackKeysChanged() {
	dd.ChangedBits = setBit(dd.ChangedBits, bitFallbackKeyTypes)
}

func (dd *SlidingSyncDeviceKeyData) OTKCountChanged() bool {
	return isBitSet(dd.ChangedBits, bitOTKCount)
}
func (dd *SlidingSyncDeviceKeyData) FallbackKeysChanged() bool {
	return isBitSet(dd.ChangedBits, bitFallbackKeyTypes)
}

type SlidingSyncDevice struct {
	UserID   string
	DeviceID string
	Since    string
}
