package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/exp/slices"

	"github.com/element-hq/dendrite/syncapi/storage/shared"
	"github.com/element-hq/dendrite/syncapi/storage/tables"
	"github.com/element-hq/dendrite/syncapi/synctypes"
	"github.com/element-hq/dendrite/syncapi/types"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/matrix-org/util"

	"github.com/getsentry/sentry-go"
	"github.com/lib/pq"

	"github.com/element-hq/dendrite/syncapi/slidingsync/internal"
	"github.com/element-hq/dendrite/syncapi/slidingsync/sqlutil"
	"github.com/tidwall/gjson"
)

var logger = util.GetLogger(context.Background())

// Max number of parameters in a single SQL command
const MaxPostgresParameters = 65535

const AccountDataGlobalRoom = ""

const (
	RelationMSpaceParent = 1
	RelationMSpaceChild  = 2
)

// StartupSnapshot represents a snapshot of startup data for the sliding sync HTTP API instances
type StartupSnapshot struct {
	GlobalMetadata   map[string]internal.RoomMetadata // room_id -> metadata
	AllJoinedMembers map[string][]string              // room_id -> [user_id]
}

type LatestEvents struct {
	Timeline  []json.RawMessage
	PrevBatch string
	LatestNID int64
}

// DiscardIgnoredMessages modifies the struct in-place, replacing the Timeline with
// a copy that has all ignored events omitted. The order of timelines is preserved.
func (e *LatestEvents) DiscardIgnoredMessages(shouldIgnore func(sender string) bool) {
	// A little bit sad to be effectively doing a copy here---most of the time there
	// won't be any messages to ignore (and the timeline is likely short). But that copy
	// is unlikely to be a bottleneck.
	newTimeline := make([]json.RawMessage, 0, len(e.Timeline))
	for _, ev := range e.Timeline {
		parsed := gjson.ParseBytes(ev)
		if parsed.Get("state_key").Exists() || !shouldIgnore(parsed.Get("sender").Str) {
			newTimeline = append(newTimeline, ev)
		}
	}
	e.Timeline = newTimeline
}

type Storage struct {
	DB                *sql.DB
	Accumulator       Accumulator
	AccountDataTable  tables.SlidingSyncAccountData
	EventsTable       tables.SlidingSyncEvent
	RoomsTable        tables.SlidingSyncRooms
	TransactionsTable tables.SlidingSyncTxn
	InvitesTable      tables.SlidingSyncInvites
	DeviceDataTable   tables.SlidingSyncDeviceData
	UnreadTable       tables.SlidingSyncUnread
	ReceiptTable      tables.SlidingSyncReceipt
	ToDeviceTable     tables.SlidingSyncToDevice
	Devices           tables.SlidingSyncDevices
	MaxTimelineLimit  int
	shutdownCh        chan struct{}
	shutdown          bool
}

func NewStorageWithDB(database *shared.Database, addPrometheusMetrics bool) *Storage {
	return &Storage{
		DB: database.DB,
		Accumulator: Accumulator{
			database:      database,
			db:            database.DB,
			roomsTable:    database.SlidingSyncRooms,
			eventsTable:   database.SlidingSyncEvent,
			snapshotTable: database.SlidingSyncSnapthot,
			spacesTable:   database.SlidingSyncSpaces,
			invitesTable:  database.SlidingSyncInvites,
		},
		AccountDataTable:  database.SlidingSyncAccountData,
		EventsTable:       database.SlidingSyncEvent,
		RoomsTable:        database.SlidingSyncRooms,
		TransactionsTable: database.SlidingSyncTxn,
		InvitesTable:      database.SlidingSyncInvites,
		DeviceDataTable:   database.SlidingSyncDeviceData,
		UnreadTable:       database.SlidingSyncUnread,
		ReceiptTable:      database.SlidingSyncReceipt,
		ToDeviceTable:     database.SlidingSyncToDevice,
		Devices:           database.SlidingSyncDevice,
		MaxTimelineLimit:  50,
		shutdownCh:        make(chan struct{}),
	}
}

func (s *Storage) LatestEventNID(ctx context.Context) (int64, error) {
	return s.Accumulator.eventsTable.SelectHighestNID(ctx)
}

func (s *Storage) AccountData(ctx context.Context, userID, roomID string, eventTypes []string) (data []types.SlidingSyncAccountData, err error) {
	err = sqlutil.WithTransaction(s.Accumulator.db, func(txn *sql.Tx) error {
		data, err = s.AccountDataTable.Select(ctx, txn, userID, eventTypes, roomID)
		return err
	})
	return
}

func (s *Storage) RoomAccountDatasWithType(ctx context.Context, userID, eventType string) (data []types.SlidingSyncAccountData, err error) {
	err = sqlutil.WithTransaction(s.Accumulator.db, func(txn *sql.Tx) error {
		data, err = s.AccountDataTable.SelectWithType(ctx, txn, userID, eventType)
		return err
	})
	return
}

// Pull out all account data for this user. If roomIDs is empty, global account data is returned.
// If roomIDs is non-empty, all account data for these rooms are extracted.
func (s *Storage) AccountDatas(ctx context.Context, userID string, roomIDs ...string) (datas []types.SlidingSyncAccountData, err error) {
	err = sqlutil.WithTransaction(s.Accumulator.db, func(txn *sql.Tx) error {
		datas, err = s.AccountDataTable.SelectMany(ctx, txn, userID, roomIDs)
		return err
	})
	return
}

func (s *Storage) InsertAccountData(ctx context.Context, userID, roomID string, events []json.RawMessage) (data []types.SlidingSyncAccountData, err error) {
	data = make([]types.SlidingSyncAccountData, len(events))
	for i := range events {
		data[i] = types.SlidingSyncAccountData{
			UserID: userID,
			RoomID: roomID,
			Data:   events[i],
			Type:   gjson.ParseBytes(events[i]).Get("type").Str,
		}
	}
	err = sqlutil.WithTransaction(s.Accumulator.db, func(txn *sql.Tx) error {
		data, err = s.AccountDataTable.Insert(ctx, txn, data)
		return err
	})
	return data, err
}

// Prepare a snapshot of the database for calling snapshot functions.
func (s *Storage) PrepareSnapshot(txn *sql.Tx) (tableName string, err error) {
	// create a temporary table with all the membership nids for the current snapshots for all rooms.
	// A temporary table will be deleted when the postgres session ends (this process quits).
	// We insert these into a temporary table to let the query planner make better decisions. In practice,
	// if we instead nest this SELECT as a subselect, we see very poor query times for large tables as
	// each event NID is queried using a btree index, rather than doing a seq scan as this query will pull
	// out ~50% of the rows in syncv3_events.
	tempTableName := "temp_snapshot"
	_, err = txn.Exec(
		`SELECT UNNEST(membership_events) AS membership_nid INTO TEMP ` + tempTableName + ` FROM syncv3_snapshots
		JOIN syncv3_rooms ON syncv3_snapshots.snapshot_id = syncv3_rooms.current_snapshot_id`,
	)
	return tempTableName, err
}

// GlobalSnapshot snapshots the entire database for the purposes of initialising
// a sliding sync instance. It will atomically grab metadata for all rooms and all joined members
// in a single transaction.
func (s *Storage) GlobalSnapshot(ctx context.Context) (ss StartupSnapshot, err error) {
	err = sqlutil.WithTransaction(s.Accumulator.db, func(txn *sql.Tx) error {
		tempTableName, err := s.PrepareSnapshot(txn)
		if err != nil {
			err = fmt.Errorf("GlobalSnapshot: failed to call PrepareSnapshot: %w", err)
			sentry.CaptureException(err)
			return err
		}
		var metadata map[string]internal.RoomMetadata
		ss.AllJoinedMembers, metadata, err = s.AllJoinedMembers(ctx, txn, tempTableName)
		if err != nil {
			err = fmt.Errorf("GlobalSnapshot: failed to call AllJoinedMembers: %w", err)
			sentry.CaptureException(err)
			return err
		}
		err = s.MetadataForAllRooms(ctx, txn, tempTableName, metadata)
		if err != nil {
			err = fmt.Errorf("GlobalSnapshot: failed to call MetadataForAllRooms: %w", err)
			sentry.CaptureException(err)
			return err
		}
		ss.GlobalMetadata = metadata
		return err
	})
	return
}

// Extract hero info for all rooms. Requires a prepared snapshot in order to be called.
func (s *Storage) MetadataForAllRooms(ctx context.Context, txn *sql.Tx, tempTableName string, result map[string]internal.RoomMetadata) error {
	loadMetadata := func(roomID string) internal.RoomMetadata {
		metadata, ok := result[roomID]
		if !ok {
			metadata = *internal.NewRoomMetadata(roomID)
		}
		return metadata
	}

	// work out latest timestamps
	events, err := s.Accumulator.eventsTable.SelectLatestEventByTypeInAllRooms(ctx, txn)
	if err != nil {
		return err
	}
	for _, ev := range events {
		metadata := loadMetadata(ev.RoomID)

		// For a given room, we'll see many events (one for each event type in the
		// room's state). We need to pick the largest of these events' timestamps here.
		ts := gjson.ParseBytes(ev.JSON).Get("origin_server_ts").Uint()
		if ts > metadata.LastMessageTimestamp {
			metadata.LastMessageTimestamp = ts
		}
		parsed := gjson.ParseBytes(ev.JSON)
		eventMetadata := internal.EventMetadata{
			NID:       ev.NID,
			Timestamp: parsed.Get("origin_server_ts").Uint(),
		}
		metadata.LatestEventsByType[parsed.Get("type").Str] = eventMetadata
		// it's possible the latest event is a brand new room not caught by the first SELECT for joined
		// rooms e.g when you're invited to a room so we need to make sure to set the metadata again here
		// TODO: is the comment above now that we explicitly call NewRoomMetadata above
		//       when handling invites?
		metadata.RoomID = ev.RoomID
		result[ev.RoomID] = metadata
	}

	// Select the name / canonical alias for all rooms
	roomIDToStateEvents, err := s.currentNotMembershipStateEventsInAllRooms(ctx, txn, []string{
		spec.MRoomName, spec.MRoomCanonicalAlias, spec.MRoomAvatar,
	})
	if err != nil {
		return fmt.Errorf("failed to load state events for all rooms: %s", err)
	}
	for roomID, stateEvents := range roomIDToStateEvents {
		metadata := loadMetadata(roomID)
		for _, ev := range stateEvents {
			if ev.Type == spec.MRoomName && ev.StateKey == "" {
				metadata.NameEvent = gjson.ParseBytes(ev.JSON).Get("name").Str
			} else if ev.Type == spec.MRoomCanonicalAlias && ev.StateKey == "" {
				metadata.CanonicalAlias = gjson.ParseBytes(ev.JSON).Get("alias").Str
			} else if ev.Type == spec.MRoomAvatar && ev.StateKey == "" {
				metadata.AvatarEvent = gjson.ParseBytes(ev.JSON).Get("url").Str
			}
		}
		result[roomID] = metadata
	}

	roomInfos, err := s.Accumulator.roomsTable.SelectRoomInfos(ctx, txn)
	if err != nil {
		return fmt.Errorf("failed to select room infos: %s", err)
	}
	var spaceRoomIDs []string
	for _, info := range roomInfos {
		metadata := loadMetadata(info.ID)
		metadata.Encrypted = info.IsEncrypted
		metadata.UpgradedRoomID = info.UpgradedRoomID
		metadata.PredecessorRoomID = info.PredecessorRoomID
		metadata.RoomType = info.Type
		result[info.ID] = metadata
		if metadata.IsSpace() {
			spaceRoomIDs = append(spaceRoomIDs, info.ID)
		}
	}

	// select space children
	spaceRoomToRelations, err := s.Accumulator.spacesTable.SelectChildren(ctx, txn, spaceRoomIDs)
	if err != nil {
		return fmt.Errorf("failed to select space children: %s", err)
	}
	for roomID, relations := range spaceRoomToRelations {
		if _, exists := result[roomID]; !exists {
			// this can happen when you join a space (so it populates the spaces table) then leave the space,
			// so there are no joined members in the space so result doesn't include the room. In this case,
			// we don't want to have a stub metadata with just the space children, so skip it.
			continue
		}
		metadata := loadMetadata(roomID)
		metadata.ChildSpaceRooms = make(map[string]struct{}, len(relations))
		for _, r := range relations {
			// For now we only honour child state events, but we store all the mappings just in case.
			if r.Relation == RelationMSpaceChild {
				metadata.ChildSpaceRooms[r.Child] = struct{}{}
			}
		}
		result[roomID] = metadata
	}
	return nil
}

// ResetMetadataState updates the given metadata in-place to reflect the current state
// of the room. This is only safe to call from the subscriber goroutine; it is not safe
// to call from the connection goroutines.
// TODO: could have this create a new RoomMetadata and get the caller to assign it.
func (s *Storage) ResetMetadataState(ctx context.Context, metadata *internal.RoomMetadata) error {
	var events []types.SlidingSyncEvent
	rows, err := s.Accumulator.db.QueryContext(ctx, `
	WITH snapshot(events, membership_events) AS (
        SELECT events, membership_events
        FROM syncv3_snapshots
            JOIN syncv3_rooms ON snapshot_id = current_snapshot_id
        WHERE syncv3_rooms.room_id = $1
    )
	SELECT event_id, event_type, state_key, event, membership
	FROM syncv3_events JOIN snapshot ON (
		event_nid = ANY (ARRAY_CAT(events, membership_events))
	)
	WHERE (event_type IN ('m.room.name', 'm.room.avatar', 'm.room.canonical_alias', 'm.room.encryption') AND state_key = '')
	   OR (event_type = 'm.room.member' AND membership IN ('join', '_join', 'invite', '_invite'))
	ORDER BY event_nid ASC;`, metadata.RoomID)
	if err != nil {
		return fmt.Errorf("ResetMetadataState[%s]: %w", metadata.RoomID, err)
	}
	defer rows.Close()

	for rows.Next() {
		events = append(events, types.SlidingSyncEvent{})
		last := len(events) - 1
		err := rows.Scan(
			&events[last].ID,
			&events[last].Type,
			&events[last].StateKey,
			&events[last].JSON,
			&events[last].Membership,
		)
		if err != nil {
			return fmt.Errorf("ResetMetadataState[%s]: %w", metadata.RoomID, err)
		}
	}

	heroMemberships := circularSlice[*types.SlidingSyncEvent]{max: 6}
	metadata.JoinCount = 0
	metadata.InviteCount = 0
	metadata.ChildSpaceRooms = make(map[string]struct{})

	for i, ev := range events {
		switch ev.Type {
		case spec.MRoomName:
			metadata.NameEvent = gjson.GetBytes(ev.JSON, "name").Str
		case spec.MRoomAvatar:
			metadata.AvatarEvent = gjson.GetBytes(ev.JSON, "url").Str
		case spec.MRoomCanonicalAlias:
			metadata.CanonicalAlias = gjson.GetBytes(ev.JSON, "alias").Str
		case spec.MRoomEncryption:
			metadata.Encrypted = true
		case spec.MRoomMember:
			heroMemberships.append(&events[i])
			switch ev.Membership {
			case spec.Join:
				fallthrough
			case "_join":
				metadata.JoinCount++
			case spec.Invite:
				fallthrough
			case "_invite":
				metadata.InviteCount++
			}
		case spec.MSpaceChild:
			metadata.ChildSpaceRooms[ev.StateKey] = struct{}{}
		}
	}

	metadata.Heroes = make([]internal.Hero, 0, len(heroMemberships.vals))
	for _, ev := range heroMemberships.vals {
		parsed := gjson.ParseBytes(ev.JSON)
		hero := internal.Hero{
			ID:     ev.StateKey,
			Name:   parsed.Get("displayname").Str,
			Avatar: parsed.Get("avatar_url").Str,
		}
		metadata.Heroes = append(metadata.Heroes, hero)
	}

	// For now, don't bother reloading PredecessorID and UpgradedRoomID.
	// These shouldn't be changing during a room's lifetime in normal operation.

	// We haven't updated LatestEventsByType because that's not part of the timeline.
	return nil
}

// FetchMemberships looks up the latest snapshot for the given room and determines the
// latest membership events in the room. Returns
//   - the list of joined members,
//   - the list of invited members, and then
//   - the list of all other memberships. (This is called "leaves", but includes bans. It
//     also includes knocks, but the proxy doesn't support those.)
//
// Each lists' members are arranged in no particular order.
//
// TODO: there is a very similar query in ResetMetadataState which also selects events
// events row for memberships. It is a shame to have to do this twice---can we query
// once and pass the data around?
func (s *Storage) FetchMemberships(ctx context.Context, roomID string) (joins, invites, leaves []string, err error) {
	var events []types.SlidingSyncEvent
	rows, err := s.Accumulator.db.QueryContext(ctx, `
	WITH snapshot(membership_nids) AS (
        SELECT membership_events
        FROM syncv3_snapshots
            JOIN syncv3_rooms ON snapshot_id = current_snapshot_id
        WHERE syncv3_rooms.room_id = $1
	)
	SELECT state_key, membership
	FROM syncv3_events JOIN snapshot ON (
		event_nid = ANY( membership_nids )
	)
	`, roomID)
	if err != nil {
		return nil, nil, nil, err
	}
	defer rows.Close()

	for rows.Next() {
		events = append(events, types.SlidingSyncEvent{})
		last := len(events) - 1
		err := rows.Scan(
			events[last].StateKey,
			events[last].Membership,
		)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("FetchMemberships[%s]: %w", roomID, err)
		}
	}

	joins = make([]string, 0, len(events))
	invites = make([]string, 0, len(events))
	leaves = make([]string, 0, len(events))

	for _, e := range events {
		switch e.Membership {
		case "_join":
			fallthrough
		case spec.Join:
			joins = append(joins, e.StateKey)
		case "_invite":
			fallthrough
		case spec.Invite:
			invites = append(invites, e.StateKey)
		default:
			leaves = append(leaves, e.StateKey)
		}
	}
	return
}

// Returns all current NOT MEMBERSHIP state events matching the event types given in all rooms. Returns a map of
// room ID to events in that room.
func (s *Storage) currentNotMembershipStateEventsInAllRooms(ctx context.Context, txn *sql.Tx, eventTypes []string) (map[string][]types.SlidingSyncEvent, error) {
	rows, err := txn.QueryContext(ctx,
		`SELECT syncv3_events.room_id, syncv3_events.event_type, syncv3_events.state_key, syncv3_events.event FROM syncv3_events
		WHERE syncv3_events.event_type = ANY($1)
		AND syncv3_events.event_nid IN (
			SELECT UNNEST(events) FROM syncv3_snapshots WHERE syncv3_snapshots.snapshot_id IN (SELECT current_snapshot_id FROM syncv3_rooms)
		)`,
		pq.StringArray(eventTypes),
	)
	if err != nil {
		return nil, fmt.Errorf("currentNotMembershipStateEventsInAllRooms: %w", err)
	}
	defer rows.Close()
	result := make(map[string][]types.SlidingSyncEvent)
	for rows.Next() {
		var ev types.SlidingSyncEvent
		if err := rows.Scan(&ev.RoomID, &ev.Type, &ev.StateKey, &ev.JSON); err != nil {
			return nil, err
		}
		result[ev.RoomID] = append(result[ev.RoomID], ev)
	}
	return result, nil
}

func (s *Storage) Accumulate(userID, roomID string, timeline types.Timeline) (result AccumulateResult, err error) {
	if len(timeline.Events) == 0 {
		return AccumulateResult{}, nil
	}
	err = sqlutil.WithTransaction(s.Accumulator.db, func(txn *sql.Tx) error {
		result, err = s.Accumulator.Accumulate(txn, userID, roomID, timeline)
		return err
	})
	return result, err
}

func (s *Storage) Initialise(roomID string, state []synctypes.ClientEvent) (InitialiseResult, error) {
	return s.Accumulator.Initialise(roomID, state)
}

// EventNIDs fetches the raw JSON form of events given a slice of eventNIDs. The events
// are returned in ascending NID order; the order of eventNIDs is ignored.
func (s *Storage) EventNIDs(ctx context.Context, eventNIDs []int64) ([]json.RawMessage, error) {
	// TODO: this selects a bunch of rows from the DB, but we only use the raw JSON
	// itself.
	events, err := s.EventsTable.SelectByNIDs(ctx, nil, true, eventNIDs)
	if err != nil {
		return nil, err
	}
	e := make([]json.RawMessage, len(events))
	for i := range events {
		e[i] = events[i].JSON
	}
	return e, nil
}

func (s *Storage) StateSnapshot(ctx context.Context, snapID int64) (state []json.RawMessage, err error) {
	err = sqlutil.WithTransaction(s.Accumulator.db, func(txn *sql.Tx) error {
		snapshotRow, err := s.Accumulator.snapshotTable.Select(ctx, txn, snapID)
		if err != nil {
			return err
		}
		events, err := s.Accumulator.eventsTable.SelectByNIDs(ctx, txn, true, append(snapshotRow.MembershipEvents, snapshotRow.OtherEvents...))
		if err != nil {
			return fmt.Errorf("failed to select state snapshot %v: %s", snapID, err)
		}
		state = make([]json.RawMessage, len(events))
		for i := range events {
			state[i] = events[i].JSON
		}
		return nil
	})
	return
}

// Look up room state after the given event position and no further. eventTypesToStateKeys is a map of event type to a list of state keys for that event type.
// If the list of state keys is empty then all events matching that event type will be returned. If the map is empty entirely, then all room state
// will be returned.
func (s *Storage) RoomStateAfterEventPosition(ctx context.Context, roomIDs []string, pos int64, eventTypesToStateKeys map[string][]string) (roomToEvents map[string][]types.SlidingSyncEvent, err error) {
	_, span := internal.StartSpan(ctx, "RoomStateAfterEventPosition")
	defer span.End()
	roomToEvents = make(map[string][]types.SlidingSyncEvent, len(roomIDs))
	roomIndex := make(map[string]int, len(roomIDs))
	err = sqlutil.WithTransaction(s.Accumulator.db, func(txn *sql.Tx) error {
		// we have 2 ways to pull the latest events:
		//  - superfast rooms table (which races as it can be updated before the new state hits the dispatcher)
		//  - slower events table query
		// we will try to fulfill as many rooms as possible with the rooms table, only using the slower events table
		// query if we can prove we have races. We can prove this because the latest NIDs will be > pos, meaning the
		// database state is ahead of the in-memory state (which is normal as we update the DB first). This should
		// happen infrequently though, so we will warn about this behaviour.
		roomToLatestNIDs, err := s.Accumulator.roomsTable.SelectLatestNIDs(ctx, txn, roomIDs)
		if err != nil {
			return err
		}
		fastNIDs := make([]int64, 0, len(roomToLatestNIDs))
		var slowRooms []string
		for roomID, latestNID := range roomToLatestNIDs {
			if latestNID > pos {
				slowRooms = append(slowRooms, roomID)
			} else {
				fastNIDs = append(fastNIDs, latestNID)
			}
		}
		latestEvents, err := s.Accumulator.eventsTable.SelectByNIDs(ctx, txn, true, fastNIDs)
		if err != nil {
			return fmt.Errorf("failed to select latest nids in rooms %v: %s", roomIDs, err)
		}
		if len(slowRooms) > 0 {
			logger.WithField("slow_rooms", len(slowRooms)).Warn("RoomStateAfterEventPosition: pos value provided is far behind the database copy, performance degraded")
			latestSlowEvents, err := s.Accumulator.eventsTable.LatestEventInRooms(ctx, txn, slowRooms, pos)
			if err != nil {
				return err
			}
			latestEvents = append(latestEvents, latestSlowEvents...)
		}
		for i, ev := range latestEvents {
			roomIndex[ev.RoomID] = i
			if ev.BeforeStateSnapshotID == 0 {
				// if there is no before snapshot then this last event NID is _part of_ the initial state,
				// ergo the state after this == the current state and we can safely ignore the lastEventNID
				ev.BeforeStateSnapshotID = 0
				ev.BeforeStateSnapshotID, err = s.Accumulator.roomsTable.SelectCurrentAfterSnapshotID(ctx, txn, ev.RoomID)
				if err != nil {
					return err
				}
				latestEvents[i] = ev
			}
		}

		if len(eventTypesToStateKeys) == 0 {
			for _, ev := range latestEvents {
				snapshotRow, err := s.Accumulator.snapshotTable.Select(ctx, txn, ev.BeforeStateSnapshotID)
				if err != nil {
					return err
				}
				allStateEventNIDs := append(snapshotRow.MembershipEvents, snapshotRow.OtherEvents...)
				// we need to roll forward if this event is state
				if gjson.ParseBytes(ev.JSON).Get("state_key").Exists() {
					if ev.ReplacesNID != 0 {
						// we determined at insert time of this event that this event replaces a nid in the snapshot.
						// find it and replace it
						for j := range allStateEventNIDs {
							if allStateEventNIDs[j] == ev.ReplacesNID {
								allStateEventNIDs[j] = ev.NID
								break
							}
						}
					} else {
						// the event is still state, but it doesn't replace anything, so just add it onto the snapshot,
						// but only if we haven't already
						alreadyExists := false
						for _, nid := range allStateEventNIDs {
							if nid == ev.NID {
								alreadyExists = true
								break
							}
						}
						if !alreadyExists {
							allStateEventNIDs = append(allStateEventNIDs, ev.NID)
						}
					}
				}
				events, err := s.Accumulator.eventsTable.SelectByNIDs(ctx, txn, true, allStateEventNIDs)
				if err != nil {
					return fmt.Errorf("failed to select state snapshot %v for room %v: %s", ev.BeforeStateSnapshotID, ev.RoomID, err)
				}
				roomToEvents[ev.RoomID] = events
			}
		} else {
			// do an optimised query to pull out only the event types and state keys we care about.
			var args []any // event type, state key, event type, state key, ....

			snapIDs := make([]int64, len(latestEvents))
			for i := range latestEvents {
				snapIDs[i] = latestEvents[i].BeforeStateSnapshotID
			}
			args = append(args, pq.Int64Array(snapIDs))

			var wheres []string
			hasMembershipFilter := false
			hasOtherFilter := false

			// figure out which state events to look at - if there is no m.room.member filter we can be super fast
			nidcols := "array_cat(events, membership_events)"
			if hasMembershipFilter && !hasOtherFilter {
				nidcols = "membership_events"
			} else if !hasMembershipFilter && hasOtherFilter {
				nidcols = "events"
			}

			var query strings.Builder
			query.WriteString("WITH nids AS ( SELECT ")
			query.WriteString(nidcols)
			query.WriteString(" AS allNids FROM syncv3_snapshots WHERE syncv3_snapshots.snapshot_id = ANY($1) ) ")
			query.WriteString(" SELECT syncv3_events.event_nid, syncv3_events.room_id, syncv3_events.event_type, syncv3_events.state_key, syncv3_events.event FROM syncv3_events, nids ")
			query.WriteString("WHERE (")

			n := 1
			for evType, skeys := range eventTypesToStateKeys {
				if evType == spec.MRoomMember {
					hasMembershipFilter = true
				} else {
					hasOtherFilter = true
				}
				for _, skey := range skeys {
					args = append(args, evType, skey)
					wheres = append(wheres, strings.Join([]string{
						"(syncv3_events.event_type = $",
						strconv.Itoa(n + 1),
						" AND syncv3_events.state_key = $",
						strconv.Itoa(n + 2),
						")",
					}, ""))
					n += 2
				}
				if len(skeys) == 0 {
					args = append(args, evType)
					wheres = append(wheres, strings.Join([]string{"syncv3_events.event_type = $", strconv.Itoa(n + 1)}, ""))
					n += 1
				}
			}

			query.WriteString(strings.Join(wheres, " OR "))
			query.WriteString(") AND syncv3_events.event_nid = ANY(nids.allNids) ORDER BY syncv3_events.event_nid ASC")

			// it's not possible for there to be no membership filter and no other filter, we wouldn't be executing this code
			// it is possible to have both, so neither if will execute.

			// Similar to CurrentStateEventsInAllRooms
			// We're using a CTE here, since unnestting the nids is quite expensive. Using the array as is
			// and using ANY() instead performs quite well (e.g. 86k membership events and 130ms execution time, vs
			// the previous query with unnest took 2.5s)
			rows, err := txn.QueryContext(ctx, query.String(), args...)
			if err != nil {
				return fmt.Errorf("failed to execute query: %s", err)
			}
			defer rows.Close()
			for rows.Next() {
				var ev types.SlidingSyncEvent
				if err := rows.Scan(&ev.NID, &ev.RoomID, &ev.Type, &ev.StateKey, &ev.JSON); err != nil {
					return err
				}
				i := roomIndex[ev.RoomID]
				if latestEvents[i].ReplacesNID == ev.NID {
					// this event is replaced by the last event
					ev = latestEvents[i]
				}
				roomToEvents[ev.RoomID] = append(roomToEvents[ev.RoomID], ev)
			}
			// handle the most recent events which won't be in the snapshot but may need to be.
			// we handle the replace case but don't handle brand new state events
			for i := range latestEvents {
				if latestEvents[i].ReplacesNID == 0 {
					// check if we should include it
					for evType, stateKeys := range eventTypesToStateKeys {
						if evType != latestEvents[i].Type {
							continue
						}
						if len(stateKeys) == 0 {
							roomToEvents[latestEvents[i].RoomID] = append(roomToEvents[latestEvents[i].RoomID], latestEvents[i])
						} else {
							for _, skey := range stateKeys {
								if skey == latestEvents[i].StateKey {
									roomToEvents[latestEvents[i].RoomID] = append(roomToEvents[latestEvents[i].RoomID], latestEvents[i])
									break
								}
							}
						}
					}
				}
			}
		}
		return nil
	})
	return
}

// LatestEventsInRooms returns the most recent events
// - in the given rooms
// - that the user has permission to see
// - with NIDs <= `to`.
// Up to `limit` events are chosen per room. This limit be itself be limited according to MaxTimelineLimit.
func (s *Storage) LatestEventsInRooms(ctx context.Context, userID string, roomIDs []string, to int64, limit int) (map[string]*LatestEvents, error) {
	roomIDToRange, err := s.visibleEventNIDsBetweenForRooms(ctx, userID, roomIDs, 0, to)
	if err != nil {
		return nil, err
	}
	if s.MaxTimelineLimit != 0 && limit > s.MaxTimelineLimit {
		limit = s.MaxTimelineLimit
	}
	result := make(map[string]*LatestEvents, len(roomIDs))
	err = sqlutil.WithTransaction(s.Accumulator.db, func(txn *sql.Tx) error {
		for roomID, r := range roomIDToRange {
			var earliestEventNID int64
			var latestEventNID int64
			var roomEvents []json.RawMessage
			// the most recent event will be first
			events, err := s.EventsTable.SelectLatestEventsBetween(ctx, txn, roomID, r[0]-1, r[1], limit)
			if err != nil {
				return fmt.Errorf("room %s failed to SelectEventsBetween: %s", roomID, err)
			}
			for _, ev := range events {
				if latestEventNID == 0 { // set first time and never again
					latestEventNID = ev.NID
				}
				roomEvents = append(roomEvents, ev.JSON)
				earliestEventNID = ev.NID
				if len(roomEvents) >= limit {
					break
				}
			}
			// we want the most recent event to be last, so reverse the slice now in-place.
			slices.Reverse(roomEvents)
			latestEvents := LatestEvents{
				LatestNID: latestEventNID,
				Timeline:  roomEvents,
			}
			if earliestEventNID != 0 {
				// the oldest event needs a prev batch token, so find one now
				prevBatch, err := s.EventsTable.SelectClosestPrevBatch(ctx, txn, roomID, earliestEventNID)
				if err != nil {
					return fmt.Errorf("failed to select prev_batch for room %s : %s", roomID, err)
				}
				latestEvents.PrevBatch = prevBatch
			}
			result[roomID] = &latestEvents
		}
		return nil
	})
	return result, err
}

// Remove state snapshots which cannot be accessed by clients. The latest MaxTimelineEvents
// snapshots must be kept, +1 for the current state. This handles the worst case where all
// MaxTimelineEvents are state events and hence each event makes a new snapshot. We can safely
// delete all snapshots older than this, as it's not possible to reach this snapshot as the proxy
// does not handle historical state (deferring to the homeserver for that).
func (s *Storage) RemoveInaccessibleStateSnapshots() error {
	numToKeep := s.MaxTimelineLimit + 1
	// Create a CTE which ranks each snapshot so we can figure out which snapshots to delete
	// then execute the delete using the CTE.
	//
	// A per-room version of this query:
	// WITH ranked_snapshots AS (
	//   SELECT
	//     snapshot_id,
	//     room_id,
	//     ROW_NUMBER() OVER (PARTITION BY room_id ORDER BY snapshot_id DESC) AS row_num
	//   FROM syncv3_snapshots
	// )
	// DELETE FROM syncv3_snapshots WHERE snapshot_id IN(
	//   SELECT snapshot_id FROM ranked_snapshots WHERE row_num > 51 AND room_id='!....'
	// );
	awfulQuery := fmt.Sprintf(`WITH ranked_snapshots AS (
		SELECT
		  snapshot_id,
		  room_id,
		  ROW_NUMBER() OVER (PARTITION BY room_id ORDER BY snapshot_id DESC) AS row_num
		FROM
		  syncv3_snapshots
	  )
	  DELETE FROM syncv3_snapshots USING ranked_snapshots
	  WHERE syncv3_snapshots.snapshot_id = ranked_snapshots.snapshot_id
	  AND ranked_snapshots.row_num > %d;`, numToKeep)

	result, err := s.Accumulator.db.Exec(awfulQuery)
	if err != nil {
		return fmt.Errorf("failed to RemoveInaccessibleStateSnapshots: Exec %s", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err == nil {
		logger.WithField("rows_affected", rowsAffected).Info("RemoveInaccessibleStateSnapshots: deleted rows")
	}
	return nil
}

func (s *Storage) GetClosestPrevBatch(ctx context.Context, roomID string, eventNID int64) (prevBatch string) {
	var err error
	sqlutil.WithTransaction(s.Accumulator.db, func(txn *sql.Tx) error {
		// discard the error, we don't care if we fail as it's best effort
		prevBatch, err = s.EventsTable.SelectClosestPrevBatch(ctx, txn, roomID, eventNID)
		return err
	})
	return
}

// visibleEventNIDsBetweenForRooms determines which events a given user has permission to see.
// It accepts a nid range [from, to]. For each given room, it calculates the NID range
// [A1, B1] within [from, to] in which the user has permission to see events.
func (s *Storage) visibleEventNIDsBetweenForRooms(ctx context.Context, userID string, roomIDs []string, from, to int64) (map[string][2]int64, error) {
	// load *THESE* joined rooms for this user at from (inclusive)
	var membershipEvents []types.SlidingSyncEvent
	var err error
	if from != 0 {
		// if from==0 then this query will return nothing, so optimise it out
		membershipEvents, err = s.Accumulator.eventsTable.SelectEventsWithTypeStateKeyInRooms(ctx, nil, roomIDs, spec.MRoomMember, userID, 0, from)
		if err != nil {
			return nil, fmt.Errorf("VisibleEventNIDsBetweenForRooms.SelectEventsWithTypeStateKeyInRooms: %s", err)
		}
	}
	joinTimingsAtFromByRoomID, err := s.determineJoinedRoomsFromMemberships(membershipEvents)
	if err != nil {
		return nil, fmt.Errorf("failed to work out joined rooms for %s at pos %d: %s", userID, from, err)
	}

	// load membership deltas for *THESE* rooms for this user
	membershipEvents, err = s.Accumulator.eventsTable.SelectEventsWithTypeStateKeyInRooms(ctx, nil, roomIDs, spec.MRoomMember, userID, from, to)
	if err != nil {
		return nil, fmt.Errorf("failed to load membership events: %s", err)
	}

	return s.visibleEventNIDsWithData(joinTimingsAtFromByRoomID, membershipEvents, userID, from, to)
}

// Work out the NID ranges to pull events from for this user. Given a from and to event nid stream position,
// this function returns a map of room ID to a 2-element from|to positions. These positions are
// all INCLUSIVE, and the client should be informed of these events at some point. For example:
//
//	                  Stream Positions
//	        1     2   3    4   5   6   7   8   9   10
//	Room A  Maj   E   E                E
//	Room B                 E   Maj E
//	Room C                                 E   Mal E   (a already joined to this room at position 0)
//
//	E=message event, M=membership event, followed by user letter, followed by 'i' or 'j' or 'l' for invite|join|leave
//
//	- For Room A: from=1, to=10, returns { RoomA: [ 1,10 ]}  (tests events in joined room)
//	- For Room B: from=1, to=10, returns { RoomB: [ 5,10 ]}  (tests joining a room starts events)
//	- For Room C: from=1, to=10, returns { RoomC: [ 0,9 ]}  (tests leaving a room stops events)
//
// In cases where a user joins/leaves a room multiple times in the nid range, only the last range is returned.
// This is critical to ensure we don't skip out timeline events due to history visibility (which the proxy defers
// to the upstream HS for). See https://github.com/element-hq/dendrite/syncapi/slidingsync/issues/365 for what happens if we returned
// all ranges.
//
//	                   Stream Positions
//	         1     2   3    4   5   6   7   8   9   10  11  12  13  14  15
//	 Room D  Maj                E   Mal E   Maj E   Mal E
//	 Room E        E   Mai  E                               E   Maj E   E
//
//	- For Room D: from=1, to=15 returns { RoomD: [ 8,10 ] } (tests multi-join/leave)
//	- For Room E: from=1, to=15 returns { RoomE: [ 13,15 ] } (tests invites)
func (s *Storage) VisibleEventNIDsBetween(ctx context.Context, userID string, from, to int64) (map[string][2]int64, error) {
	// load *ALL* joined rooms for this user at from (inclusive)
	joinTimingsAtFromByRoomID, err := s.JoinedRoomsAfterPosition(ctx, userID, from)
	if err != nil {
		return nil, fmt.Errorf("failed to work out joined rooms for %s at pos %d: %s", userID, from, err)
	}

	// load *ALL* membership deltas for all rooms for this user
	membershipEvents, err := s.Accumulator.eventsTable.SelectEventsWithTypeStateKey(ctx, nil, spec.MRoomMember, userID, from, to)
	if err != nil {
		return nil, fmt.Errorf("failed to load membership events: %s", err)
	}

	return s.visibleEventNIDsWithData(joinTimingsAtFromByRoomID, membershipEvents, userID, from, to)
}

type membershipEvent struct {
	types.SlidingSyncEvent
	StateKey   string
	Membership string
}

func (s *Storage) visibleEventNIDsWithData(joinTimingsAtFromByRoomID map[string]internal.EventMetadata, membershipEvents []types.SlidingSyncEvent, userID string, from, to int64) (map[string][2]int64, error) {
	// load membership events in order and bucket based on room ID
	roomIDToLogs := make(map[string][]membershipEvent)
	for _, ev := range membershipEvents {
		evJSON := gjson.ParseBytes(ev.JSON)
		roomIDToLogs[ev.RoomID] = append(roomIDToLogs[ev.RoomID], membershipEvent{
			SlidingSyncEvent: ev,
			StateKey:         evJSON.Get("state_key").Str,
			Membership:       evJSON.Get("membership").Str,
		})
	}

	// Performs the algorithm
	calculateVisibleEventNIDs := func(isJoined bool, fromIncl, toIncl int64, logs []membershipEvent) [2]int64 {
		// short circuit when there are no membership deltas
		if len(logs) == 0 {
			return [2]int64{
				fromIncl, toIncl, // TODO: is this actually valid? Surely omitting it is the right answer?
			}
		}
		var result [][2]int64
		var startIndex int64 = -1
		if isJoined {
			startIndex = fromIncl
		}
		for _, memEvent := range logs {
			// check for a valid transition (join->leave|ban or leave|invite->join) - we won't always get valid transitions
			// e.g logs will be there for things like leave->ban which we don't care about
			isValidTransition := false
			if isJoined && (memEvent.Membership == spec.Leave || memEvent.Membership == spec.Ban) {
				isValidTransition = true
			} else if !isJoined && memEvent.Membership == spec.Join {
				isValidTransition = true
			} else if !isJoined && memEvent.Membership == spec.Invite {
				// short-circuit: invites are sent on their own and don't affect ranges
				result = append(result, [2]int64{memEvent.NID, memEvent.NID})
				continue
			}
			if !isValidTransition {
				continue
			}
			if isJoined {
				// transitioning to leave, we get all events up to and including the leave event
				result = append(result, [2]int64{startIndex, memEvent.NID})
				isJoined = false
			} else {
				// transitioning to joined, we will get the join and some more events in a bit
				startIndex = memEvent.NID
				isJoined = true
			}
		}
		// if we are still joined to the room at this point, grab all events up to toIncl
		if isJoined {
			result = append(result, [2]int64{startIndex, toIncl})
		}
		if len(result) == 0 {
			return [2]int64{}
		}
		// we only care about the LAST nid range, otherwise we can end up with gaps being returned in the
		// timeline. See https://github.com/element-hq/dendrite/syncapi/slidingsync/issues/365
		return result[len(result)-1]
	}

	// For each joined room, perform the algorithm and delete the logs afterwards
	result := make(map[string][2]int64)
	for joinedRoomID, _ := range joinTimingsAtFromByRoomID {
		roomResult := calculateVisibleEventNIDs(true, from, to, roomIDToLogs[joinedRoomID])
		result[joinedRoomID] = roomResult
		delete(roomIDToLogs, joinedRoomID)
	}

	// Handle rooms which we are not joined to but have logs for
	for roomID, logs := range roomIDToLogs {
		roomResult := calculateVisibleEventNIDs(false, from, to, logs)
		result[roomID] = roomResult
	}

	return result, nil
}

func (s *Storage) RoomMembershipDelta(ctx context.Context, roomID string, from, to int64, limit int) (eventJSON []json.RawMessage, upTo int64, err error) {
	err = sqlutil.WithTransaction(s.Accumulator.db, func(txn *sql.Tx) error {
		nids, err := s.Accumulator.eventsTable.SelectEventNIDsWithTypeInRoom(ctx, txn, spec.MRoomMember, limit, roomID, from, to)
		if err != nil {
			return err
		}
		if len(nids) == 0 {
			return nil
		}
		upTo = nids[len(nids)-1]
		events, err := s.Accumulator.eventsTable.SelectByNIDs(ctx, txn, true, nids)
		if err != nil {
			return err
		}
		eventJSON = make([]json.RawMessage, len(events))
		for i := range events {
			eventJSON[i] = events[i].JSON
		}
		return nil
	})
	return
}

// Extract all rooms with joined members, and include the joined user list. Requires a prepared snapshot in order to be called.
// Populates the join/invite count and heroes for the returned metadata.
func (s *Storage) AllJoinedMembers(ctx context.Context, txn *sql.Tx, tempTableName string) (joinedMembers map[string][]string, metadata map[string]internal.RoomMetadata, err error) {
	// Select the most recent members for each room to serve as Heroes. The spec is ambiguous here:
	// "This should be the first 5 members of the room, ordered by stream ordering, which are joined or invited."
	// Unclear if this is the first 5 *most recent* (backwards) or forwards. For now we'll use the most recent
	// ones, and select 6 of them so we can always use 5 no matter who is requesting the room name.
	rows, err := txn.Query(
		`SELECT membership_nid, room_id, state_key, membership FROM ` + tempTableName + ` INNER JOIN syncv3_events
		on membership_nid = event_nid WHERE membership='join' OR membership='_join' OR membership='invite' OR membership='_invite' ORDER BY event_nid ASC`,
	)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	joinedMembers = make(map[string][]string)
	inviteCounts := make(map[string]int)
	heroNIDs := make(map[string]*circularSlice[int64])
	var stateKey string
	var membership string
	var roomID string
	var nid int64
	for rows.Next() {
		if err := rows.Scan(&nid, &roomID, &stateKey, &membership); err != nil {
			return nil, nil, err
		}
		heroes := heroNIDs[roomID]
		if heroes == nil {
			heroes = &circularSlice[int64]{max: 6}
			heroNIDs[roomID] = heroes
		}
		switch membership {
		case spec.Join:
			fallthrough
		case "_join":
			users := joinedMembers[roomID]
			users = append(users, stateKey)
			joinedMembers[roomID] = users
			heroes.append(nid)
		case spec.Invite:
			fallthrough
		case "_invite":
			inviteCounts[roomID] = inviteCounts[roomID] + 1
			heroes.append(nid)
		}
	}

	// now select the membership events for the heroes
	var allHeroNIDs []int64
	for _, nids := range heroNIDs {
		allHeroNIDs = append(allHeroNIDs, nids.vals...)
	}
	heroEvents, err := s.EventsTable.SelectByNIDs(ctx, txn, true, allHeroNIDs)
	if err != nil {
		return nil, nil, err
	}
	heroes := make(map[string][]internal.Hero)
	// loop backwards so the most recent hero is first in the hero list
	for i := len(heroEvents) - 1; i >= 0; i-- {
		ev := heroEvents[i]
		evJSON := gjson.ParseBytes(ev.JSON)
		roomHeroes := heroes[ev.RoomID]
		roomHeroes = append(roomHeroes, internal.Hero{
			ID:     ev.StateKey,
			Name:   evJSON.Get("displayname").Str,
			Avatar: evJSON.Get("avatar_url").Str,
		})
		heroes[ev.RoomID] = roomHeroes
	}

	metadata = make(map[string]internal.RoomMetadata)
	for roomID, members := range joinedMembers {
		m := internal.NewRoomMetadata(roomID)
		m.JoinCount = len(members)
		m.InviteCount = inviteCounts[roomID]
		m.Heroes = heroes[roomID]
		metadata[roomID] = *m
	}
	return joinedMembers, metadata, nil
}

func (s *Storage) Cleaner(ctx context.Context, n time.Duration) {
Loop:
	for {
		select {
		case <-time.After(n):
			now := time.Now()
			boundaryTime := now.Add(-1 * n)
			if n < time.Hour {
				boundaryTime = now.Add(-1 * time.Hour)
			}
			logger.WithField("boundaryTime", boundaryTime).Info("Cleaner running")
			err := s.TransactionsTable.Clean(ctx, nil, boundaryTime)
			if err != nil {
				logger.WithError(err).Warn("failed to clean txn ID table")
				sentry.CaptureException(err)
			}
			// we also want to clean up stale state snapshots which are inaccessible, to
			// keep the size of the syncv3_snapshots table low.
			if err = s.RemoveInaccessibleStateSnapshots(); err != nil {
				logger.WithError(err).Warn("failed to remove inaccessible state snapshots")
				sentry.CaptureException(err)
			}
		case <-s.shutdownCh:
			break Loop
		}
	}
}

func (s *Storage) LatestEventNIDInRooms(ctx context.Context, roomIDs []string, highestNID int64) (roomToNID map[string]int64, err error) {
	roomToNID = make(map[string]int64)
	err = sqlutil.WithTransaction(s.Accumulator.db, func(txn *sql.Tx) error {
		// Pull out the latest nids for all the rooms. If they are < highestNID then use them, else we need to query the
		// events table (slow) for the latest nid in this room which is < highestNID.
		fastRoomToLatestNIDs, err := s.Accumulator.roomsTable.SelectLatestNIDs(ctx, txn, roomIDs)
		if err != nil {
			return err
		}
		var slowRooms []string
		for _, roomID := range roomIDs {
			nid := fastRoomToLatestNIDs[roomID]
			if nid > 0 && nid <= highestNID {
				roomToNID[roomID] = nid
			} else {
				// we need to do a slow query for this
				slowRooms = append(slowRooms, roomID)
			}
		}

		if len(slowRooms) == 0 {
			return nil // no work to do
		}
		logger.WithField("slow_rooms", len(slowRooms)).Warn("LatestEventNIDInRooms: pos value provided is far behind the database copy, performance degraded")

		slowRoomToLatestNIDs, err := s.EventsTable.LatestEventNIDInRooms(ctx, txn, slowRooms, highestNID)
		if err != nil {
			return err
		}
		for roomID, nid := range slowRoomToLatestNIDs {
			roomToNID[roomID] = nid
		}
		return nil
	})
	return roomToNID, err
}

// Returns a map from joined room IDs to EventMetadata, which is nil iff a non-nil error
// is returned.
func (s *Storage) JoinedRoomsAfterPosition(ctx context.Context, userID string, pos int64) (
	joinTimingByRoomID map[string]internal.EventMetadata, err error,
) {
	// fetch all the membership events up to and including pos
	membershipEvents, err := s.Accumulator.eventsTable.SelectEventsWithTypeStateKey(ctx, nil, spec.MRoomMember, userID, 0, pos)
	if err != nil {
		return nil, fmt.Errorf("JoinedRoomsAfterPosition.SelectEventsWithTypeStateKey: %s", err)
	}
	return s.determineJoinedRoomsFromMemberships(membershipEvents)
}

// determineJoinedRoomsFromMemberships scans a slice of membership events from multiple
// rooms, to determine which rooms a user is currently joined to. Those events MUST be
// - sorted by ascending NIDs, and
// - only memberships for the given user;
// neither of these preconditions are checked by this function.
//
// Returns a map from joined room IDs to EventMetadata, which is nil iff a non-nil error
// is returned.
func (s *Storage) determineJoinedRoomsFromMemberships(membershipEvents []types.SlidingSyncEvent) (
	joinTimingByRoomID map[string]internal.EventMetadata, err error,
) {
	joinTimingByRoomID = make(map[string]internal.EventMetadata, len(membershipEvents))
	for _, ev := range membershipEvents {
		parsed := gjson.ParseBytes(ev.JSON)
		membership := parsed.Get("membership").Str
		switch membership {
		// These are "join" and the only memberships that you can transition to after
		// a join: see e.g. the transition diagram in
		// https://spec.matrix.org/v1.7/client-server-api/#room-membership
		case spec.Join:
			// Only remember a join NID if we are not joined to this room according to
			// the state before ev.
			if _, currentlyJoined := joinTimingByRoomID[ev.RoomID]; !currentlyJoined {
				joinTimingByRoomID[ev.RoomID] = internal.EventMetadata{
					NID:       ev.NID,
					Timestamp: parsed.Get("origin_server_ts").Uint(),
				}
			}
		case spec.Ban:
			fallthrough
		case spec.Leave:
			delete(joinTimingByRoomID, ev.RoomID)
		}
	}

	return joinTimingByRoomID, nil
}

func (s *Storage) Teardown() {
	if !s.shutdown {
		s.shutdown = true
		close(s.shutdownCh)
	}

	err := s.Accumulator.db.Close()
	if err != nil {
		panic("Storage.Teardown: " + err.Error())
	}
}

// circularSlice is a slice which can be appended to which will wraparound at `max`.
// Mostly useful for lazily calculating heroes. The values returned aren't sorted.
type circularSlice[T any] struct {
	i    int
	vals []T
	max  int
}

func (s *circularSlice[T]) append(val T) {
	if len(s.vals) < s.max {
		// populate up to max
		s.vals = append(s.vals, val)
		s.i++
		return
	}
	// wraparound
	if s.i == s.max {
		s.i = 0
	}
	// replace this entry
	s.vals[s.i] = val
	s.i++
}

// PackReceiptsIntoEDU bundles all the receipts into a single m.receipt EDU, suitable for sending down
// client connections.
func PackReceiptsIntoEDU(receipts []types.SlidingSyncReceipt) (json.RawMessage, error) {
	newReceiptEDU := types.SlidingSyncReceiptEDU{
		Type:    spec.MReceipt,
		Content: make(map[string]types.SlidingSyncReceiptContent),
	}
	for _, r := range receipts {
		thisReceiptIsUnthreaded := r.ThreadID == ""
		receiptsForEvent := newReceiptEDU.Content[r.EventID]
		if r.IsPrivate {
			if receiptsForEvent.ReadPrivate == nil {
				receiptsForEvent.ReadPrivate = make(map[string]types.SlidingSyncReceiptInfo)
			}
			// MSC4102: always replace threaded receipts with unthreaded ones if there is a clash
			_, receiptAlreadyExists := receiptsForEvent.ReadPrivate[r.UserID]
			if !receiptAlreadyExists || (receiptAlreadyExists && thisReceiptIsUnthreaded) {
				receiptsForEvent.ReadPrivate[r.UserID] = types.SlidingSyncReceiptInfo{
					TS:       r.TS,
					ThreadID: r.ThreadID,
				}
			}
		} else {
			if receiptsForEvent.Read == nil {
				receiptsForEvent.Read = make(map[string]types.SlidingSyncReceiptInfo)
			}
			// MSC4102: always replace threaded receipts with unthreaded ones if there is a clash
			_, receiptAlreadyExists := receiptsForEvent.Read[r.UserID]
			if !receiptAlreadyExists || (receiptAlreadyExists && thisReceiptIsUnthreaded) {
				receiptsForEvent.Read[r.UserID] = types.SlidingSyncReceiptInfo{
					TS:       r.TS,
					ThreadID: r.ThreadID,
				}
			}
		}
		newReceiptEDU.Content[r.EventID] = receiptsForEvent
	}
	return json.Marshal(newReceiptEDU)
}

func UnpackReceiptsFromEDU(roomID string, ephEvent json.RawMessage) (readReceipts, privateReceipts []types.SlidingSyncReceipt, err error) {
	// unpack the receipts, of the form:
	//  {
	//		"content": {
	//		  "$1435641916114394fHBLK:matrix.org": {
	//			"m.read": {
	//			  "@rikj:jki.re": {
	//				"ts": 1436451550453,
	//  			"thread_id": "$aaabbbccc"
	//			  }
	//			},
	//			"m.read.private": {
	//			  "@self:example.org": {
	//				"ts": 1661384801651
	//			  }
	//			}
	//		  }
	//		},
	//		"type": "m.receipt"
	//  }
	var edu types.SlidingSyncReceiptEDU
	if err := json.Unmarshal(ephEvent, &edu); err != nil {
		return nil, nil, err
	}
	if edu.Type != spec.MReceipt {
		return
	}
	for eventID, content := range edu.Content {
		for userID, val := range content.Read {
			readReceipts = append(readReceipts, types.SlidingSyncReceipt{
				UserID:   userID,
				RoomID:   roomID,
				EventID:  eventID,
				TS:       val.TS,
				ThreadID: val.ThreadID,
			})
		}
		for userID, val := range content.ReadPrivate {
			privateReceipts = append(privateReceipts, types.SlidingSyncReceipt{
				UserID:    userID,
				RoomID:    roomID,
				EventID:   eventID,
				TS:        val.TS,
				ThreadID:  val.ThreadID,
				IsPrivate: true,
			})
		}
	}
	return readReceipts, privateReceipts, nil
}
