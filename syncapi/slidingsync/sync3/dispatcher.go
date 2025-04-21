package sync3

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/element-hq/dendrite/syncapi/slidingsync/internal"
	"github.com/element-hq/dendrite/syncapi/slidingsync/sync3/caches"
	"github.com/element-hq/dendrite/syncapi/types"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/matrix-org/util"
	"github.com/tidwall/gjson"
)

var logger = util.GetLogger(context.Background())

const DispatcherAllUsers = "-"

// Receiver represents the callbacks that a Dispatcher may fire.
type Receiver interface {
	OnNewEvent(ctx context.Context, event *caches.EventData)
	OnReceipt(ctx context.Context, receipt types.SlidingSyncReceipt)
	OnEphemeralEvent(ctx context.Context, roomID string, ephType string, ephEvent json.RawMessage)
	// OnRegistered is called after a successful call to Dispatcher.Register
	OnRegistered(ctx context.Context) error
}

// Dispatches live events to caches
type Dispatcher struct {
	jrt              *JoinedRoomsTracker
	userToReceiver   map[string]Receiver
	userToReceiverMu *sync.RWMutex
}

func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		jrt:              NewJoinedRoomsTracker(),
		userToReceiver:   make(map[string]Receiver),
		userToReceiverMu: &sync.RWMutex{},
	}
}

func (d *Dispatcher) IsUserJoined(userID, roomID string) bool {
	return d.jrt.IsUserJoined(userID, roomID)
}

// Load joined members into the dispatcher.
// MUST BE CALLED BEFORE V2 POLL LOOPS START.
func (d *Dispatcher) Startup(roomToJoinedUsers map[string][]string) error {
	// populate joined rooms tracker
	d.jrt.Startup(roomToJoinedUsers)
	return nil
}

func (d *Dispatcher) Unregister(userID string) {
	d.userToReceiverMu.Lock()
	defer d.userToReceiverMu.Unlock()
	delete(d.userToReceiver, userID)
}

// UnregisterBulk accepts a slice of user IDs to unregister. The given users need not
// already be registered (in which case unregistering them is a no-op). Returns the
// list of users that were unregistered.
func (d *Dispatcher) UnregisterBulk(userIDs []string) []string {
	d.userToReceiverMu.Lock()
	defer d.userToReceiverMu.Unlock()

	unregistered := make([]string, 0)
	for _, userID := range userIDs {
		_, exists := d.userToReceiver[userID]
		if exists {
			delete(d.userToReceiver, userID)
			unregistered = append(unregistered, userID)
		}
	}
	return unregistered
}

func (d *Dispatcher) Register(ctx context.Context, userID string, r Receiver) error {
	d.userToReceiverMu.Lock()
	defer d.userToReceiverMu.Unlock()
	if _, ok := d.userToReceiver[userID]; ok {
		logger.WithField("user", userID).Warn("Dispatcher.Register: receiver already registered")
	}
	d.userToReceiver[userID] = r
	return r.OnRegistered(ctx)
}

func (d *Dispatcher) ReceiverForUser(userID string) Receiver {
	d.userToReceiverMu.RLock()
	defer d.userToReceiverMu.RUnlock()
	return d.userToReceiver[userID]
}

func (d *Dispatcher) newEventData(event json.RawMessage, roomID string, latestPos int64) *caches.EventData {
	// parse the event to pull out fields we care about
	var stateKey *string
	ev := gjson.ParseBytes(event)
	if sk := ev.Get("state_key"); sk.Exists() {
		stateKey = &sk.Str
	}
	eventType := ev.Get("type").Str

	return &caches.EventData{
		Event:         event,
		RoomID:        roomID,
		EventType:     eventType,
		StateKey:      stateKey,
		Content:       ev.Get("content"),
		NID:           latestPos,
		Timestamp:     ev.Get("origin_server_ts").Uint(),
		Sender:        ev.Get("sender").Str,
		TransactionID: ev.Get("unsigned.transaction_id").Str,
	}
}

// Called by v2 pollers when we receive an initial state block. Very similar to OnNewEvents but
// done in bulk for speed.
func (d *Dispatcher) OnNewInitialRoomState(ctx context.Context, roomID string, state []json.RawMessage) {
	// sanity check
	if _, jc := d.jrt.JoinedUsersForRoom(roomID, nil); jc > 0 {
		logger.WithField("join_count", jc).WithField("room", roomID).WithField("num_state", len(state)).Warn(
			"OnNewInitialRoomState but have entries in JoinedRoomsTracker already, this should be impossible. Degrading to live events",
		)
		for _, s := range state {
			d.OnNewEvent(ctx, roomID, s, 0)
		}
		return
	}
	// create event datas for state
	eventDatas := make([]*caches.EventData, len(state))
	var joined, invited []string
	for i, event := range state {
		ed := d.newEventData(event, roomID, 0)
		eventDatas[i] = ed
		if ed.EventType == spec.MRoomMember && ed.StateKey != nil {
			membership := ed.Content.Get("membership").Str
			switch membership {
			case spec.Invite:
				invited = append(invited, *ed.StateKey)
			case spec.Join:
				joined = append(joined, *ed.StateKey)
			}
		}
	}
	// bulk update joined room tracker
	forceInitial := d.jrt.UsersJoinedRoom(joined, roomID)
	d.jrt.UsersInvitedToRoom(invited, roomID)
	inviteCount := d.jrt.NumInvitedUsersForRoom(roomID)

	// work out who to notify
	userIDs, joinCount := d.jrt.JoinedUsersForRoom(roomID, func(userID string) bool {
		if userID == DispatcherAllUsers {
			return false // safety guard to prevent dupe global callbacks
		}
		return d.ReceiverForUser(userID) != nil
	})

	// notify listeners
	for _, ed := range eventDatas {
		ed.InviteCount = inviteCount
		ed.JoinCount = joinCount
		d.notifyListeners(ctx, ed, userIDs, "", forceInitial, "")
	}
}

func (d *Dispatcher) OnNewEvent(
	ctx context.Context, roomID string, event json.RawMessage, nid int64,
) {
	ed := d.newEventData(event, roomID, nid)

	// update the tracker
	targetUser := ""
	membership := ""
	shouldForceInitial := false
	leaveAfterJoinOrInvite := false
	if ed.EventType == spec.MRoomMember && ed.StateKey != nil {
		targetUser = *ed.StateKey
		membership = ed.Content.Get("membership").Str
		switch membership {
		case spec.Invite:
			// we only do this to track invite counts correctly.
			d.jrt.UsersInvitedToRoom([]string{targetUser}, ed.RoomID)
		case spec.Join:
			if d.jrt.UserJoinedRoom(targetUser, ed.RoomID) {
				shouldForceInitial = true
			}
		case spec.Ban:
			fallthrough
		case spec.Leave:
			leaveAfterJoinOrInvite = d.jrt.UserLeftRoom(targetUser, ed.RoomID)
		}
		ed.InviteCount = d.jrt.NumInvitedUsersForRoom(ed.RoomID)
	}

	// notify all people in this room
	userIDs, joinCount := d.jrt.JoinedUsersForRoom(ed.RoomID, func(userID string) bool {
		if userID == DispatcherAllUsers {
			return false // safety guard to prevent dupe global callbacks
		}
		return d.ReceiverForUser(userID) != nil
	})
	ed.JoinCount = joinCount
	if leaveAfterJoinOrInvite {
		// Only tell the target user about a leave if they were previously aware of the
		// room. This prevents us from leaking pre-emptive bans.
		userIDs = append(userIDs, targetUser)
	}
	d.notifyListeners(ctx, ed, userIDs, targetUser, shouldForceInitial, membership)
}

func (d *Dispatcher) OnEphemeralEvent(ctx context.Context, roomID string, ephType string, ephEvent json.RawMessage) {
	notifyUserIDs, _ := d.jrt.JoinedUsersForRoom(roomID, func(userID string) bool {
		if userID == DispatcherAllUsers {
			return false // safety guard to prevent dupe global callbacks
		}
		return d.ReceiverForUser(userID) != nil
	})

	d.userToReceiverMu.RLock()
	defer d.userToReceiverMu.RUnlock()

	// global listeners (invoke before per-user listeners so caches can update)
	listener := d.userToReceiver[DispatcherAllUsers]
	if listener != nil {
		listener.OnEphemeralEvent(ctx, roomID, ephType, ephEvent)
	}

	// poke user caches OnEphemeralEvent which then pokes ConnState
	for _, userID := range notifyUserIDs {
		l := d.userToReceiver[userID]
		if l == nil {
			continue
		}
		l.OnEphemeralEvent(ctx, roomID, ephType, ephEvent)
	}
}

func (d *Dispatcher) OnReceipt(ctx context.Context, receipt types.SlidingSyncReceipt) {
	notifyUserIDs, _ := d.jrt.JoinedUsersForRoom(receipt.RoomID, func(userID string) bool {
		if userID == DispatcherAllUsers {
			return false // safety guard to prevent dupe global callbacks
		}
		return d.ReceiverForUser(userID) != nil
	})

	d.userToReceiverMu.RLock()
	defer d.userToReceiverMu.RUnlock()

	// global listeners (invoke before per-user listeners so caches can update)
	listener := d.userToReceiver[DispatcherAllUsers]
	if listener != nil {
		listener.OnReceipt(ctx, receipt) // FIXME: redundant, it doesn't care about receipts
	}

	// poke user caches OnReceipt which then pokes ConnState
	for _, userID := range notifyUserIDs {
		l := d.userToReceiver[userID]
		if l == nil {
			continue
		}
		l.OnReceipt(ctx, receipt)
	}
}

func (d *Dispatcher) notifyListeners(ctx context.Context, ed *caches.EventData, userIDs []string, targetUser string, shouldForceInitial bool, membership string) {
	internal.Logf(ctx, "dispatcher", "%s: notify %d users (nid=%d,join_count=%d)", ed.RoomID, len(userIDs), ed.NID, ed.JoinCount)
	// invoke listeners
	d.userToReceiverMu.RLock()
	defer d.userToReceiverMu.RUnlock()

	// global listeners (invoke before per-user listeners so caches can update)
	listener := d.userToReceiver[DispatcherAllUsers]
	if listener != nil {
		listener.OnNewEvent(ctx, ed)
	}

	// per-user listeners
	for _, userID := range userIDs {
		l := d.userToReceiver[userID]
		if l != nil {
			edd := *ed
			if targetUser == userID {
				if shouldForceInitial {
					edd.ForceInitial = true
				}
			}
			l.OnNewEvent(ctx, &edd)
		}
	}
}

func (d *Dispatcher) OnInvalidateRoom(roomID string, joins, invites []string) {
	// Reset the joined room tracker.
	d.jrt.ReloadMembershipsForRoom(roomID, joins, invites)
}
