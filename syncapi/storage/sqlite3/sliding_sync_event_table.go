package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"

	"github.com/element-hq/dendrite/internal"
	"github.com/element-hq/dendrite/internal/sqlutil"
	"github.com/element-hq/dendrite/syncapi/storage/tables"
	"github.com/element-hq/dendrite/syncapi/types"
	"github.com/lib/pq"
	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/util"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const eventSchema = `
CREATE SEQUENCE IF NOT EXISTS syncv3_event_nids_seq;
	CREATE TABLE IF NOT EXISTS syncv3_events (
		event_nid BIGINT PRIMARY KEY NOT NULL DEFAULT nextval('syncv3_event_nids_seq'),
		event_id TEXT NOT NULL UNIQUE,
		before_state_snapshot_id BIGINT NOT NULL DEFAULT 0,
		-- which nid gets replaced in the snapshot with event_nid
		event_replaces_nid BIGINT NOT NULL DEFAULT 0,
		room_id TEXT NOT NULL,
		event_type TEXT NOT NULL,
		state_key TEXT NOT NULL,
		prev_batch TEXT,
		membership TEXT,
		is_state BOOLEAN NOT NULL, -- is this event part of the v2 state response?
		event BYTEA NOT NULL,
		-- True iff this event was seen at the start of the timeline in a limited sync
		-- (i.e. the preceding timeline event was not known to the proxy).
		missing_previous BOOLEAN NOT NULL DEFAULT FALSE
	);

	-- index for querying all joined rooms for a given user
	CREATE INDEX IF NOT EXISTS syncv3_events_type_sk_idx ON syncv3_events(event_type, state_key);
	-- index for querying membership deltas in particular rooms
	CREATE INDEX IF NOT EXISTS syncv3_events_type_room_nid_idx ON syncv3_events(event_type, room_id, event_nid);
	-- index for querying events in a given room
	CREATE INDEX IF NOT EXISTS syncv3_nid_room_state_idx ON syncv3_events(room_id, event_nid, is_state);

	CREATE UNIQUE INDEX IF NOT EXISTS syncv3_events_room_event_nid_type_skey_idx ON syncv3_events(event_nid, event_type, state_key);
`

const (
	EventsStart = -1
	EventsEnd   = math.MaxInt64 - 1
)

const slidingSyncSelectHighestNIDSQL = `SELECT MAX(event_NID) as e from syncv3_events;`

const slidingSyncInsertEventSQL = ``

const slidingSyncSelectByNIDsSQL = `
	SELECT event_nid, event_id, event, event_type, state_key, room_id, before_state_snapshot_id, membership, event_replaces_nid, missing_previous 
	FROM syncv3_events
	WHERE event_nid = ANY ($1) ORDER BY event_nid ASC;
`

const slidingSyncSelectByIDsSQL = `
	SELECT event_nid, event_id, event, event_type, state_key, room_id, before_state_snapshot_id, membership, missing_previous 
	FROM syncv3_events
	WHERE event_id = ANY ($1) ORDER BY event_nid ASC;
`

const slidingSyncSelectNIDsByIDsSQL = `
	SELECT event_nid, event_id, event, event_type, state_key, room_id, before_state_snapshot_id, membership, missing_previous 
	FROM syncv3_events
	WHERE event_id = ANY ($1) ORDER BY event_nid ASC;
`
const slidingSyncSelectStrippedEventsByNIDsSQL = `
	SELECT event_nid, event_id, event_type, state_key, room_id, before_state_snapshot_id 
	FROM syncv3_events
	WHERE event_nid = ANY ($1) ORDER BY event_nid ASC;
`

const slidingSyncSelectStrippedEventsByIDsSQL = `
	SELECT event_nid, event_id, event_type, state_key, room_id, before_state_snapshot_id 
	FROM syncv3_events
	WHERE event_id = ANY ($1) ORDER BY event_nid ASC;
`

const slidingSyncSelectUnknownEventIDsSQL = `
	WITH maybe_unknown_events(event_id) AS (SELECT unnest($1::text[]))
	SELECT event_id
	FROM maybe_unknown_events LEFT JOIN syncv3_events USING(event_id)
	WHERE event_nid IS NULL;
`

const slidingSyncUpdateBeforeSnapshotIDSQL = `UPDATE syncv3_events SET before_state_snapshot_id=$1, event_replaces_nid=$2 WHERE event_nid = $3;`

const slidingSyncLatestEventInRoomsSQL = `
	WITH room_ids AS (
		select unnest($1::text[]) AS room_id
	),
	max_ev_nid AS (
		SELECT * 
		FROM room_ids,
			LATERAL (
				SELECT max(event_nid) FROM syncv3_events e WHERE e.room_id = room_ids.room_id AND event_nid <= $2
				) AS x)
	SELECT evs.*
	FROM room_ids,
		max_ev_nid,
		LATERAL (
			SELECT event_nid, room_id, event_replaces_nid, before_state_snapshot_id, event_type, state_key, event
			FROM syncv3_events e
			WHERE e.event_nid = max_ev_nid.max AND room_ids.room_id = e.room_id
			) AS evs;
`
const slidingSyncLatestEventNIDInRoomsSQL = `
	WITH room_ids AS (
		select unnest($1::text[]) AS room_id
	)
	SELECT evs.event_nid, room_id
	FROM room_ids, 
		LATERAL (
				SELECT max(event_nid) event_nid FROM syncv3_events e WHERE e.room_id = room_ids.room_id AND event_nid <= $2
				) AS evs WHERE event_nid IS NOT NULL;
`

const slidingSyncRedactSQL = `
	UPDATE syncv3_events SET event=$1 WHERE event_id=$2;
`

const slidingSyncSelectLatestEventsBetweenSQL = `
	SELECT event_nid, event, missing_previous 
	FROM syncv3_events 
	WHERE event_nid > $1 AND event_nid <= $2 AND room_id = $3 AND is_state=FALSE 
	ORDER BY event_nid DESC LIMIT $4;
`
const slidingSyncSelectLatestEventByTypeInAllRoomsSQL = `
	WITH event_types AS (
		WITH RECURSIVE t AS (
			(SELECT event_type FROM syncv3_events ORDER BY event_type LIMIT 1)  -- parentheses required
			UNION ALL
			SELECT (SELECT event_type FROM syncv3_events WHERE event_type > t.event_type ORDER BY event_type LIMIT 1)
			FROM t
			WHERE t.event_type IS NOT NULL
		)
		SELECT event_type FROM t WHERE event_type IS NOT NULL
	), room_ids AS (
		SELECT DISTINCT room_id FROM syncv3_rooms
	), max_by_ev_type AS (
		SELECT m.max FROM event_types, room_ids,
		LATERAL ( SELECT max(event_nid) as max FROM syncv3_events e WHERE e.room_id = room_ids.room_id AND e.event_type = event_types.event_type ) AS m
	)
	SELECT room_id, event_nid, event FROM syncv3_events, max_by_ev_type WHERE event_nid = max_by_ev_type.max;
`
const slidingSyncSelectEventsWithTypeStateKeySQL = `
	SELECT event_nid, room_id, event FROM syncv3_events
	WHERE event_nid > $1 AND event_nid <= $2 AND event_type = $3 AND state_key = $4
	ORDER BY event_nid ASC;
`
const slidingSyncSelectEventWithTypeStateKeyInRoomsSQL = `
	SELECT event_nid, room_id, event FROM syncv3_events
	WHERE event_nid > $1 AND event_nid <= $2 AND event_type = $3 AND state_key = $4 AND room_id IN ($5)
	ORDER BY event_nid ASC;
`
const slidingSyncSelectEventNIDsWithTypeInRoomsSQL = `
	SELECT event_nid FROM syncv3_events WHERE event_nid > $1 AND event_nid <= $2 AND event_type = $3 AND room_id = $4 ORDER BY event_nid ASC LIMIT $5
`
const slidingSyncSelectClosestPrevBatchByIDSQL = `
	SELECT prev_batch FROM syncv3_events WHERE prev_batch IS NOT NULL AND room_id=$1 AND event_nid >= (
		SELECT event_nid FROM syncv3_events WHERE event_id = $2
	) LIMIT 1;
`
const slidingSyncSelectClosestPrevBatchSQL = `
	SELECT prev_batch FROM syncv3_events WHERE prev_batch IS NOT NULL AND room_id=$1 AND event_nid >= $2 LIMIT 1;
`
const slidingSyncSelectCreateEventSQL = `
	SELECT event FROM syncv3_events WHERE room_id=$1 AND event_type='m.room.create' AND state_key='';
`

const slidingSyncCountCurrentStateRedactionsSQL = `
	SELECT COUNT(*)
	FROM syncv3_events
	JOIN syncv3_snapshots ON event_nid = ANY (ARRAY_CAT(events, membership_events))
	WHERE snapshot_id = $1 AND event_id = ANY($2);
`

func NewSqliteSlidingSyncEventTable(db *sql.DB) (tables.SlidingSyncEvent, error) {
	s := &slidingSyncEventStatements{}
	_, err := db.Exec(eventSchema)
	if err != nil {
		return nil, err
	}
	return s, sqlutil.StatementList{
		{&s.selectHighestNIDStmt, slidingSyncSelectHighestNIDSQL},
		{&s.insertEventStmt, slidingSyncInsertEventSQL},
		{&s.selectByNIDStmt, slidingSyncSelectByNIDsSQL},
		{&s.selectByIDsStmt, slidingSyncSelectByIDsSQL},
		{&s.selectNIDByIDsStmt, slidingSyncSelectNIDsByIDsSQL},
		{&s.selectStrippedEventsByNIDsStmt, slidingSyncSelectStrippedEventsByNIDsSQL},
		{&s.selectStrippedEventsByIDsStmt, slidingSyncSelectStrippedEventsByIDsSQL},
		{&s.selectUnknownEventIDsStmt, slidingSyncSelectUnknownEventIDsSQL},
		{&s.updateBeforeSnapshotIDStmt, slidingSyncUpdateBeforeSnapshotIDSQL},
		{&s.latestEventInRoomsStmt, slidingSyncLatestEventInRoomsSQL},
		{&s.latestEventNIDInRoomsStmt, slidingSyncLatestEventNIDInRoomsSQL},
		{&s.redactStmt, slidingSyncRedactSQL},
		{&s.selectLatestEventsBetweenStmt, slidingSyncSelectLatestEventsBetweenSQL},
		{&s.selectLatestEventByTypeInAllRoomsStmt, slidingSyncSelectLatestEventByTypeInAllRoomsSQL},
		{&s.selectEventsWithTypeStateKeyStmt, slidingSyncSelectEventsWithTypeStateKeySQL},
		{&s.selectEventWithTypeStateKeyInRoomsStmt, slidingSyncSelectEventWithTypeStateKeyInRoomsSQL},
		{&s.selectEventNIDsWithTypeInRoomsStmt, slidingSyncSelectEventNIDsWithTypeInRoomsSQL},
		{&s.selectClosestPrevBatchByIDStmt, slidingSyncSelectClosestPrevBatchByIDSQL},
		{&s.selectClosestPrevBatchStmt, slidingSyncSelectClosestPrevBatchSQL},
		{&s.selectCreateEventStmt, slidingSyncSelectCreateEventSQL},
		{&s.countCurrentStateRedactionsStmt, slidingSyncCountCurrentStateRedactionsSQL},
	}.Prepare(db)
}

type slidingSyncEventStatements struct {
	selectHighestNIDStmt                   *sql.Stmt
	insertEventStmt                        *sql.Stmt
	selectByNIDStmt                        *sql.Stmt
	selectByIDsStmt                        *sql.Stmt
	selectNIDByIDsStmt                     *sql.Stmt
	selectStrippedEventsByNIDsStmt         *sql.Stmt
	selectStrippedEventsByIDsStmt          *sql.Stmt
	selectUnknownEventIDsStmt              *sql.Stmt
	updateBeforeSnapshotIDStmt             *sql.Stmt
	latestEventInRoomsStmt                 *sql.Stmt
	latestEventNIDInRoomsStmt              *sql.Stmt
	redactStmt                             *sql.Stmt
	selectLatestEventsBetweenStmt          *sql.Stmt
	selectLatestEventByTypeInAllRoomsStmt  *sql.Stmt
	selectEventsWithTypeStateKeyStmt       *sql.Stmt
	selectEventWithTypeStateKeyInRoomsStmt *sql.Stmt
	selectEventNIDsWithTypeInRoomsStmt     *sql.Stmt
	selectClosestPrevBatchByIDStmt         *sql.Stmt
	selectClosestPrevBatchStmt             *sql.Stmt
	selectCreateEventStmt                  *sql.Stmt
	countCurrentStateRedactionsStmt        *sql.Stmt
}

func (s *slidingSyncEventStatements) SelectHighestNID(ctx context.Context) (int64, error) {
	var result sql.NullInt64
	err := s.selectHighestNIDStmt.QueryRowContext(ctx).Scan(&result)
	if err != nil {
		util.GetLogger(ctx).Error("selectHighestNIDStmt failed", err)
		return 0, err
	}
	if result.Valid {
		return result.Int64, nil
	}
	return 0, nil
}

func (s *slidingSyncEventStatements) Insert(ctx context.Context, txn *sql.Tx, events []types.SlidingSyncEvent, checkFields bool) (map[string]int64, error) {
	if checkFields {
		events = filterAndEnsureFieldsSet(ctx, events)
	}
	result := make(map[string]int64, len(events))
	for i := range events {
		if !gjson.GetBytes(events[i].JSON, "unsigned.txn_id").Exists() {
			continue
		}
		js, err := sjson.DeleteBytes(events[i].JSON, "unsigned.txn_id")
		if err != nil {
			return nil, err
		}
		events[i].JSON = js
	}

	stmt, err := txn.PrepareContext(ctx, pq.CopyIn("syncv3_events", "event_id", "before_state_snapshot_id", "event_replaces_nid", "room_id", "event_type", "state_key", "prev_batch", "membership", "is_state", "event", "missing_previous"))
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("txn.Prepare failed")
		return nil, err
	}

	for i := range events {
		if _, err = stmt.ExecContext(ctx, events[i].ID, events[i].BeforeStateSnapshotID, events[i].ReplacesNID, events[i].RoomID, events[i].Type, events[i].StateKey, events[i].PrevBatch, events[i].Membership, events[i].IsState, events[i].JSON, events[i].MissingPrevious); err != nil {
			util.GetLogger(ctx).WithError(err).Error("stmt.Exec failed")
			return nil, err
		}
		result[events[i].ID] = events[i].NID
	}

	if _, err = stmt.ExecContext(ctx); err != nil {
		util.GetLogger(ctx).WithError(err).Error("stmt.Exec failed")
		return nil, err
	}

	return result, nil
}

func (s *slidingSyncEventStatements) SelectByNIDs(ctx context.Context, txn *sql.Tx, verifyAll bool, nids []int64) ([]types.SlidingSyncEvent, error) {
	numWanted := 0
	if verifyAll {
		numWanted = len(nids)
	}

	events := make([]types.SlidingSyncEvent, 0, len(nids))
	rows, err := sqlutil.TxStmtContext(ctx, txn, s.selectByNIDStmt).QueryContext(ctx, pq.Int64Array(nids))
	if err != nil && err != sql.ErrNoRows {
		util.GetLogger(ctx).WithError(err).Error("selectByNIDStmt: QueryContext failed")
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "SelectByNIDs: rows.close() failed")

	for rows.Next() {
		var event types.SlidingSyncEvent
		if err := rows.Scan(
			&event.NID,
			&event.ID,
			&event.JSON,
			&event.Type,
			&event.StateKey,
			&event.RoomID,
			&event.BeforeStateSnapshotID,
			&event.Membership,
			&event.ReplacesNID,
			&event.MissingPrevious,
		); err != nil {
			util.GetLogger(ctx).WithError(err).Error("selectByNIDStmt: rows.Scan failed")
			return nil, err
		}
		events = append(events, event)
	}

	if numWanted > 0 && len(events) != numWanted {
		return nil, internal.NewDataError("events table query got %d events wanted %d", len(events), numWanted)
	}

	return events, nil
}

func (s *slidingSyncEventStatements) SelectByIDs(ctx context.Context, txn *sql.Tx, verifyAll bool, ids []string) ([]types.SlidingSyncEvent, error) {
	numWanted := 0
	if verifyAll {
		numWanted = len(ids)
	}

	events := make([]types.SlidingSyncEvent, 0, len(ids))
	rows, err := sqlutil.TxStmtContext(ctx, txn, s.selectByIDsStmt).QueryContext(ctx, pq.StringArray(ids))
	if err != nil && err != sql.ErrNoRows {
		util.GetLogger(ctx).WithError(err).Error("selectByIDsStmt: QueryContext failed")
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "SelectByIDs: rows.close() failed")

	for rows.Next() {
		var event types.SlidingSyncEvent
		if err := rows.Scan(
			&event.NID,
			&event.ID,
			&event.JSON,
			&event.Type,
			&event.StateKey,
			&event.RoomID,
			&event.BeforeStateSnapshotID,
			&event.Membership,
			&event.MissingPrevious,
		); err != nil {
			util.GetLogger(ctx).WithError(err).Error("selectByIDsStmt: rows.Scan failed")
			return nil, err
		}
		events = append(events, event)
	}

	if numWanted > 0 && len(events) != numWanted {
		return nil, internal.NewDataError("events table query got %d events wanted %d", len(events), numWanted)
	}

	return events, nil
}

// SelectNIDsByIDs does just that. Returns a map from event ID to nid, with a key-value
// pair for every event_id that was found in the database.
func (s *slidingSyncEventStatements) SelectNIDsByIDs(ctx context.Context, txn *sql.Tx, ids []string) (map[string]int64, error) {
	// Select NIDs using a single parameter which is a string array
	// https://stackoverflow.com/questions/52712022/what-is-the-most-performant-way-to-rewrite-a-large-in-clause
	result := make(map[string]int64, len(ids))
	rows, err := sqlutil.TxStmtContext(ctx, txn, s.selectNIDByIDsStmt).QueryContext(ctx, pq.StringArray(ids))
	if err != nil && err != sql.ErrNoRows {
		util.GetLogger(ctx).WithError(err).Error("selectNIDByIDsStmt: QueryContext failed")
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "SelectNIDsByIDs: rows.close() failed")

	for rows.Next() {
		var (
			NID int64
			ID  string
		)
		if err := rows.Scan(&NID, &ID); err != nil {
			util.GetLogger(ctx).WithError(err).Error("selectNIDByIDsStmt: rows.Scan failed")
			return nil, err
		}
		result[ID] = NID
	}
	return result, nil
}

func (s *slidingSyncEventStatements) SelectStrippedEventsByNIDs(ctx context.Context, txn *sql.Tx, verifyAll bool, nids []int64) (types.SlidingSyncStrippedEvents, error) {
	numWanted := 0
	if verifyAll {
		numWanted = len(nids)
	}

	events := make(types.SlidingSyncStrippedEvents, 0, len(nids))
	rows, err := sqlutil.TxStmtContext(ctx, txn, s.selectStrippedEventsByNIDsStmt).QueryContext(ctx, pq.Int64Array(nids))
	if err != nil && err != sql.ErrNoRows {
		util.GetLogger(ctx).WithError(err).Error("selectStrippedEventsByNIDsStmt: QueryContext failed")
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "SelectStrippedEventsByNIDs: rows.close() failed")

	for rows.Next() {
		var event types.SlidingSyncEvent
		if err := rows.Scan(
			&event.NID,
			&event.ID,
			&event.Type,
			&event.StateKey,
			&event.RoomID,
			&event.BeforeStateSnapshotID,
		); err != nil {
			util.GetLogger(ctx).WithError(err).Error("selectStrippedEventsByNIDsStmt: rows.Scan failed")
			return nil, err
		}
		events = append(events, event)
	}

	if numWanted > 0 && len(nids) != numWanted {
		return nil, internal.NewDataError("events table query selectStrippedEventsByNIDsStmt got %d events wanted %d. err=%s", len(events), numWanted, err)
	}

	return events, nil
}

func (s *slidingSyncEventStatements) SelectStrippedEventsByIDs(ctx context.Context, txn *sql.Tx, verifyAll bool, ids []string) (types.SlidingSyncStrippedEvents, error) {
	numWanted := 0
	if verifyAll {
		numWanted = len(ids)
	}

	events := make([]types.SlidingSyncEvent, 0, len(ids))
	rows, err := sqlutil.TxStmtContext(ctx, txn, s.selectStrippedEventsByIDsStmt).QueryContext(ctx, pq.StringArray(ids))
	if err != nil && err != sql.ErrNoRows {
		util.GetLogger(ctx).WithError(err).Error("selectStrippedEventsByIDsStmt: QueryContext failed")
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "SelectStrippedEventsByIDs: rows.close() failed")

	for rows.Next() {
		var event types.SlidingSyncEvent
		if err := rows.Scan(
			&event.NID,
			&event.ID,
			&event.Type,
			&event.StateKey,
			&event.RoomID,
			&event.BeforeStateSnapshotID,
		); err != nil {
			util.GetLogger(ctx).WithError(err).Error("selectStrippedEventsByIDsStmt: rows.Scan failed")
			return nil, err
		}
		events = append(events, event)
	}

	if numWanted > 0 && len(ids) != numWanted {
		return nil, internal.NewDataError("events table query selectStrippedEventsByIDsStmt got %d events wanted %d. err=%s", len(events), numWanted, err)
	}

	return events, nil
}

func (s *slidingSyncEventStatements) SelectUnknownEventIDs(ctx context.Context, txn *sql.Tx, maybeUnknownEventIDs []string) (map[string]struct{}, error) {
	var unknownEventIDs []string
	rows, err := sqlutil.TxStmtContext(ctx, txn, s.selectUnknownEventIDsStmt).QueryContext(ctx, pq.StringArray(maybeUnknownEventIDs))
	if err != nil && err != sql.ErrNoRows {
		util.GetLogger(ctx).WithError(err).Error("selectUnknownEventIDsStmt: QueryContext failed")
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "SelectUnknownEventIDs: rows.close() failed")
	for rows.Next() {
		var eventID string
		if err := rows.Scan(&eventID); err != nil {
			util.GetLogger(ctx).WithError(err).Error("selectUnknownEventIDsStmt: rows.Scan failed")
			return nil, err
		}
		unknownEventIDs = append(unknownEventIDs, eventID)
	}
	unknownMap := make(map[string]struct{}, len(unknownEventIDs))
	for _, eventID := range unknownEventIDs {
		unknownMap[eventID] = struct{}{}
	}
	return unknownMap, nil
}

func (s *slidingSyncEventStatements) UpdateBeforeSnapshotID(ctx context.Context, txn *sql.Tx, eventNID, snapID, replacesNID int64) error {
	stmt := sqlutil.TxStmtContext(ctx, txn, s.updateBeforeSnapshotIDStmt)
	_, err := stmt.ExecContext(ctx, snapID, replacesNID, eventNID)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("updateBeforeSnapshotIDStmt: ExecContext failed")
		return err
	}
	return nil
}

func (s *slidingSyncEventStatements) LatestEventInRooms(ctx context.Context, txn *sql.Tx, roomIDs []string, highestNID int64) ([]types.SlidingSyncEvent, error) {
	rows, err := sqlutil.TxStmtContext(ctx, txn, s.latestEventInRoomsStmt).QueryContext(ctx, pq.StringArray(roomIDs), highestNID)
	if err != nil && err != sql.ErrNoRows {
		util.GetLogger(ctx).WithError(err).Error("latestEventInRoomsStmt: QueryContext failed")
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "LatestEventInRooms: rows.close() failed")

	events := make([]types.SlidingSyncEvent, 0, len(roomIDs))
	for rows.Next() {
		var event types.SlidingSyncEvent
		if err := rows.Scan(
			&event.NID,
			&event.RoomID,
			&event.ReplacesNID,
			&event.BeforeStateSnapshotID,
			&event.Type,
			&event.StateKey,
			&event.JSON,
		); err != nil {
			util.GetLogger(ctx).WithError(err).Error("latestEventInRoomsStmt: rows.Scan failed")
			return nil, err
		}
		events = append(events, event)
	}
	return events, nil
}

func (s *slidingSyncEventStatements) LatestEventNIDInRooms(ctx context.Context, txn *sql.Tx, roomIDs []string, highestNID int64) (map[string]int64, error) {
	rows, err := sqlutil.TxStmtContext(ctx, txn, s.latestEventNIDInRoomsStmt).QueryContext(ctx, pq.StringArray(roomIDs), highestNID)
	if err != nil && err != sql.ErrNoRows {
		util.GetLogger(ctx).WithError(err).Error("latestEventNIDInRoomsStmt: QueryContext failed")
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "LatestEventNIDInRooms: rows.close() failed")

	events := make(map[string]int64, len(roomIDs))
	for rows.Next() {
		var event types.SlidingSyncEvent
		if err := rows.Scan(
			&event.NID,
			&event.RoomID,
		); err != nil {
			util.GetLogger(ctx).WithError(err).Error("latestEventNIDInRoomsStmt: rows.Scan failed")
			return nil, err
		}
		events[event.RoomID] = event.NID
	}
	return events, nil
}

func (s *slidingSyncEventStatements) Redact(ctx context.Context, txn *sql.Tx, roomVer string, redacteeEventIDToRedactEvent map[string]*types.SlidingSyncEvent) error {
	eventIDs := make([]string, 0, len(redacteeEventIDToRedactEvent))
	for eventID := range redacteeEventIDToRedactEvent {
		eventIDs = append(eventIDs, eventID)
	}

	// verifyAll=false so if we are asked to redact an event we don't have we don't fall over.
	eventsToRedact, err := s.SelectByIDs(ctx, txn, false, eventIDs)
	if err != nil {
		util.GetLogger(ctx).WithError(err).WithField("eventIDs", eventIDs).Errorf("Redact: SelectByIDs failed")
		return err
	}

	rv, err := gomatrixserverlib.GetRoomVersion(gomatrixserverlib.RoomVersion(roomVer))
	if err != nil {
		util.GetLogger(ctx).WithError(err).WithField("roomVer", roomVer).Errorf("Redact: GetRoomVersion failed")
		return err
	}

	for i := range eventsToRedact {
		eventsToRedact[i].JSON, err = rv.RedactEventJSON(eventsToRedact[i].JSON)
		if err != nil {
			util.GetLogger(ctx).WithError(err).WithField("eventID", eventsToRedact[i].ID).Errorf("Redact: RedactEventJSON failed")
			return err
		}
		// also set unsigned.redacted_because as EX relies on it
		eventsToRedact[i].JSON, err = sjson.SetBytes(eventsToRedact[i].JSON, "unsigned.redacted_because", json.RawMessage(redacteeEventIDToRedactEvent[eventsToRedact[i].ID].JSON))
		if err != nil {
			util.GetLogger(ctx).WithError(err).WithField("eventID", eventsToRedact[i].ID).Errorf("Redact: setting redacted_because failed")
			return err
		}
		_, err = sqlutil.TxStmtContext(ctx, txn, s.redactStmt).ExecContext(ctx, eventsToRedact[i].JSON, eventsToRedact[i].ID)
		if err != nil {
			util.GetLogger(ctx).WithError(err).WithField("eventID", eventsToRedact[i].ID).Errorf("Redact: ExecContext failed")
			return err
		}
	}
	return nil
}

func (s *slidingSyncEventStatements) SelectLatestEventsBetween(ctx context.Context, txn *sql.Tx, roomID string, lowerExclusive, upperInclusive int64, limit int) ([]types.SlidingSyncEvent, error) {
	rows, err := sqlutil.TxStmtContext(ctx, txn, s.selectLatestEventsBetweenStmt).QueryContext(ctx, lowerExclusive, upperInclusive, roomID, limit)
	if err != nil && err != sql.ErrNoRows {
		util.GetLogger(ctx).WithError(err).Error("selectLatestEventsBetweenStmt: QueryContext failed")
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "SelectLatestEventsBetween: rows.close() failed")

	events := make([]types.SlidingSyncEvent, 0, limit)
	for rows.Next() {
		var event types.SlidingSyncEvent
		if err := rows.Scan(
			&event.NID,
			&event.JSON,
			&event.MissingPrevious,
		); err != nil {
			util.GetLogger(ctx).WithError(err).Error("selectLatestEventsBetweenStmt: rows.Scan failed")
			return nil, err
		}
		events = append(events, event)
	}

	// Look to see if there is an event missing its predecessor in the timeline.
	// Note: events[0] is the newest event, as the query is ORDERed BY event_nid DESC.
	for i, ev := range events {
		if ev.MissingPrevious {
			events = events[:i+1]
			break
		}
	}

	return events, nil
}

func (s *slidingSyncEventStatements) SelectEventsWithTypeStateKey(ctx context.Context, txn *sql.Tx, eventType, stateKey string, lowerExclusive, upperInclusive int64) ([]types.SlidingSyncEvent, error) {
	var events []types.SlidingSyncEvent
	rows, err := sqlutil.TxStmtContext(ctx, txn, s.selectEventsWithTypeStateKeyStmt).QueryContext(ctx, lowerExclusive, upperInclusive, eventType, stateKey)
	if err != nil && err != sql.ErrNoRows {
		util.GetLogger(ctx).WithError(err).Error("selectEventsWithTypeStateKeyStmt: QueryContext failed")
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "SelectEventsWithTypeStateKey: rows.close() failed")
	for rows.Next() {
		var event types.SlidingSyncEvent
		if err := rows.Scan(
			&event.NID,
			&event.RoomID,
			&event.JSON,
		); err != nil {
			util.GetLogger(ctx).WithError(err).Error("selectEventsWithTypeStateKeyStmt: rows.Scan failed")
			return nil, err
		}
		events = append(events, event)
	}
	return events, nil
}

func (s *slidingSyncEventStatements) SelectEventsWithTypeStateKeyInRooms(ctx context.Context, txn *sql.Tx, roomIDs []string, eventType, stateKey string, lowerExclusive, upperInclusive int64) ([]types.SlidingSyncEvent, error) {
	var events []types.SlidingSyncEvent
	rows, err := sqlutil.TxStmtContext(ctx, txn, s.selectEventWithTypeStateKeyInRoomsStmt).QueryContext(ctx, lowerExclusive, upperInclusive, eventType, stateKey, pq.StringArray(roomIDs))
	if err != nil && err != sql.ErrNoRows {
		util.GetLogger(ctx).WithError(err).Error("selectEventWithTypeStateKeyInRoomsStmt: QueryContext failed")
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "SelectEventsWithTypeStateKeyInRooms: rows.close() failed")
	for rows.Next() {
		var event types.SlidingSyncEvent
		if err := rows.Scan(
			&event.NID,
			&event.RoomID,
			&event.JSON,
		); err != nil {
			util.GetLogger(ctx).WithError(err).Error("selectEventWithTypeStateKeyInRoomsStmt: rows.Scan failed")
			return nil, err
		}
		events = append(events, event)
	}
	return events, nil
}

func (s *slidingSyncEventStatements) SelectEventNIDsWithTypeInRoom(ctx context.Context, txn *sql.Tx, eventType string, limit int, targetRoom string, lowerExclusive, upperInclusive int64) ([]int64, error) {
	rows, err := sqlutil.TxStmtContext(ctx, txn, s.selectEventNIDsWithTypeInRoomsStmt).QueryContext(ctx, lowerExclusive, upperInclusive, eventType, targetRoom, limit)
	if err != nil && err != sql.ErrNoRows {
		util.GetLogger(ctx).WithError(err).Error("selectEventNIDsWithTypeInRoomsStmt: QueryContext failed")
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "SelectEventNIDsWithTypeInRoom: rows.close() failed")

	nids := make([]int64, 0, limit)
	for rows.Next() {
		var nid int64
		if err := rows.Scan(&nid); err != nil {
			util.GetLogger(ctx).WithError(err).Error("selectEventNIDsWithTypeInRoomsStmt: rows.Scan failed")
			return nil, err
		}
		nids = append(nids, nid)
	}
	return nids, nil
}

func (s *slidingSyncEventStatements) SelectClosestPrevBatchByID(ctx context.Context, txn *sql.Tx, roomID string, eventID string) (string, error) {
	row := sqlutil.TxStmtContext(ctx, txn, s.selectClosestPrevBatchByIDStmt).QueryRowContext(ctx, roomID, eventID)
	var prevBatch sql.NullString
	if err := row.Scan(&prevBatch); err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		util.GetLogger(ctx).WithError(err).Error("selectClosestPrevBatchByIDStmt: row.Scan failed")
		return "", err
	}
	if prevBatch.Valid {
		return prevBatch.String, nil
	}
	return "", nil
}

func (s *slidingSyncEventStatements) SelectClosestPrevBatch(ctx context.Context, txn *sql.Tx, roomID string, eventNID int64) (string, error) {
	row := sqlutil.TxStmtContext(ctx, txn, s.selectClosestPrevBatchStmt).QueryRowContext(ctx, roomID, eventNID)
	var prevBatch sql.NullString
	if err := row.Scan(&prevBatch); err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		util.GetLogger(ctx).WithError(err).Error("selectClosestPrevBatchStmt: row.Scan failed")
		return "", err
	}
	if prevBatch.Valid {
		return prevBatch.String, nil
	}
	return "", nil
}

func (s *slidingSyncEventStatements) SelectCreateEvent(ctx context.Context, txn *sql.Tx, roomID string) (json.RawMessage, error) {
	row := sqlutil.TxStmtContext(ctx, txn, s.selectCreateEventStmt).QueryRowContext(ctx, roomID)
	var createEvent sql.NullString
	if err := row.Scan(&createEvent); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		util.GetLogger(ctx).WithError(err).Error("selectCreateEventStmt: row.Scan failed")
		return nil, err
	}
	if createEvent.Valid {
		return json.RawMessage(createEvent.String), nil
	}
	return nil, nil
}

func (s *slidingSyncEventStatements) CountCurrentStateRedactions(ctx context.Context, txn *sql.Tx, snapshotID int64, eventIDs []string) (int64, error) {
	var count sql.NullInt64
	row := sqlutil.TxStmtContext(ctx, txn, s.countCurrentStateRedactionsStmt).QueryRowContext(ctx, snapshotID, pq.StringArray(eventIDs))
	if err := row.Scan(&count); err != nil {
		util.GetLogger(ctx).WithError(err).Error("countCurrentStateRedactionsStmt: row.Scan failed")
		return 0, err
	}
	if count.Valid {
		return count.Int64, nil
	}
	return 0, nil
}

func (s *slidingSyncEventStatements) SelectLatestEventByTypeInAllRooms(ctx context.Context, txn *sql.Tx) ([]types.SlidingSyncEvent, error) {
	result := []types.SlidingSyncEvent{}
	// What the following query does:
	//	1. Gets all event types from a recursive CTE as the `event_types` CTE
	//	2. Gets all rooms as the `room_ids` CTE
	// 	3. Gets the latest event_nid for each event_type and room as the `max_by_ev_type` CTE
	//	4. Queries the required data using the event_nids provided by the `max_by_ev_type` CTE
	rows, err := sqlutil.TxStmtContext(ctx, txn, s.selectLatestEventByTypeInAllRoomsStmt).QueryContext(ctx)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("selectLatestEventByTypeInAllRoomsStmt: QueryContext failed")
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "SelectLatestEventByTypeInAllRooms: rows.close() failed")
	n := 0
	for rows.Next() {
		result = append(result, types.SlidingSyncEvent{})
		if err := rows.Scan(&result[n].RoomID, &result[n].NID, &result[n].JSON); err != nil {
			return nil, err
		}
		n++
	}
	return result, nil
}

func filterAndEnsureFieldsSet(ctx context.Context, events []types.SlidingSyncEvent) []types.SlidingSyncEvent {
	result := make([]types.SlidingSyncEvent, 0, len(events))
	// ensure fields are set
	for i := range events {
		ev := &events[i]
		if err := ev.EnsureFieldsSetOnEvent(); err != nil {
			util.GetLogger(ctx).WithError(err).WithField("event_id", ev.ID).Warn(
				"filterAndEnsureFieldsSet: failed to parse event, ignoring",
			)
			continue
		}
		result = append(result, *ev)
	}
	return result
}
