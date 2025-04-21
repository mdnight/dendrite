package postgres

import (
	"context"
	"database/sql"
	"strconv"
	"strings"

	"github.com/element-hq/dendrite/internal"
	"github.com/element-hq/dendrite/internal/sqlutil"
	"github.com/element-hq/dendrite/syncapi/storage/tables"
	"github.com/element-hq/dendrite/syncapi/types"
	"github.com/lib/pq"
	"github.com/matrix-org/util"
)

const roomsSchema = `
CREATE TABLE IF NOT EXISTS syncv3_rooms (
	room_id TEXT NOT NULL PRIMARY KEY,
	current_snapshot_id BIGINT NOT NULL,
	is_encrypted BOOL NOT NULL DEFAULT FALSE,
	upgraded_room_id TEXT,
	predecessor_room_id TEXT,
	latest_nid BIGINT NOT NULL DEFAULT 0,
	type TEXT -- nullable
);
`

const selectRoomInfosCountSQL = `
SELECT COUNT(*) as count FROM syncv3_rooms
`

const selectRoomInfosSQL = `
SELECT room_id, is_encrypted, upgraded_room_id, predecessor_room_id, type FROM syncv3_rooms
`

const latestNIDsSQL = `
SELECT room_id, latest_nid FROM syncv3_rooms WHERE room_id = ANY($1)
`

const currentAfterSnapshotIDSQL = `
SELECT current_snapshot_id FROM syncv3_rooms WHERE room_id = $1
`

type roomsStatements struct {
	selectRoomInfosCountStmt         *sql.Stmt
	selectRoomInfosStmt              *sql.Stmt
	selectLatestNIDsStmt             *sql.Stmt
	selectCurrentAfterSnapshotIDStmt *sql.Stmt
}

func NewPostgresSlidingSyncRoomsTable(db *sql.DB) (tables.SlidingSyncRooms, error) {
	s := &roomsStatements{}
	_, err := db.Exec(roomsSchema)
	if err != nil {
		return nil, err
	}
	return s, sqlutil.StatementList{
		{&s.selectRoomInfosCountStmt, selectRoomInfosCountSQL},
		{&s.selectRoomInfosStmt, selectRoomInfosSQL},
		{&s.selectLatestNIDsStmt, latestNIDsSQL},
		{&s.selectCurrentAfterSnapshotIDStmt, currentAfterSnapshotIDSQL},
	}.Prepare(db)
}

func (s *roomsStatements) SelectRoomInfos(ctx context.Context, txn *sql.Tx) ([]types.SlidingSyncRoomInfo, error) {
	stmt := sqlutil.TxStmtContext(ctx, txn, s.selectRoomInfosCountStmt)
	var count int
	if err := stmt.QueryRowContext(ctx).Scan(&count); err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	stmt = sqlutil.TxStmtContext(ctx, txn, s.selectRoomInfosStmt)
	row, err := stmt.QueryContext(ctx)
	if err != nil {
		return nil, err
	}
	defer row.Close()
	roomInfos := make([]types.SlidingSyncRoomInfo, 0, count)
	for row.Next() {
		var roomInfo types.SlidingSyncRoomInfo
		if err := row.Scan(
			&roomInfo.ID,
			&roomInfo.IsEncrypted,
			&roomInfo.UpgradedRoomID,
			&roomInfo.PredecessorRoomID,
			&roomInfo.Type,
		); err != nil {
			return nil, err
		}
		roomInfos = append(roomInfos, roomInfo)
	}
	return roomInfos, nil
}

func (s *roomsStatements) SelectLatestNIDs(
	ctx context.Context, txn *sql.Tx, roomIDs []string,
) (latestNIDs map[string]int64, err error) {
	stmt := sqlutil.TxStmtContext(ctx, txn, s.selectLatestNIDsStmt)
	rows, err := stmt.QueryContext(ctx, pq.StringArray(roomIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	latestNIDs = make(map[string]int64)
	for rows.Next() {
		var roomID string
		var latestNID int64
		if err = rows.Scan(&roomID, &latestNID); err != nil {
			return nil, err
		}
		latestNIDs[roomID] = latestNID
	}
	return latestNIDs, nil
}

func (s *roomsStatements) SelectCurrentAfterSnapshotID(
	ctx context.Context, txn *sql.Tx, roomID string,
) (snapshotID int64, err error) {
	stmt := sqlutil.TxStmtContext(ctx, txn, s.selectCurrentAfterSnapshotIDStmt)
	err = stmt.QueryRowContext(ctx, roomID).Scan(&snapshotID)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	return snapshotID, nil
}

func (s *roomsStatements) Upsert(ctx context.Context, txn *sql.Tx, info types.SlidingSyncRoomInfo, snapshotID, latestNID int64) error {
	// This is a bit of a wonky query to ensure that you cannot set is_encrypted=false after it has been
	// set to true.

	insertCols := []string{"room_id", "current_snapshot_id", "latest_nid"}
	insertVals := []string{"$1", "$2", "$3"}
	n := 4
	updateCols := []string{"current_snapshot_id", "latest_nid"}
	updateVals := []string{"$2", "$3"}
	if info.IsEncrypted {
		insertCols = append(insertCols, "is_encrypted")
		insertVals = append(insertVals, "true")
		updateCols = append(updateCols, "is_encrypted")
		updateVals = append(updateVals, "true") // flip it to true.
	}

	if info.UpgradedRoomID != nil {
		val := strings.Join([]string{"$", strconv.Itoa(n)}, "")
		insertCols = append(insertCols, "upgraded_room_id")
		insertVals = append(insertVals, val)
		updateCols = append(updateCols, "upgraded_room_id")
		updateVals = append(updateVals, val)
		n++
	}

	if info.Type != nil {
		// by default we insert NULL which means no type, so we only need to set it when this is non-nil.
		// This also neatly handles the case where we issue updates which will have the Type set to nil
		// as we don't pull out the create event for incremental updates.
		val := strings.Join([]string{"$", strconv.Itoa(n)}, "")
		insertCols = append(insertCols, "type")
		insertVals = append(insertVals, val)
		updateCols = append(updateCols, "type")
		updateVals = append(updateVals, val)
		n++
	}

	if info.PredecessorRoomID != nil {
		val := strings.Join([]string{"$", strconv.Itoa(n)}, "")
		insertCols = append(insertCols, "predecessor_room_id")
		insertVals = append(insertVals, val)
		updateCols = append(updateCols, "predecessor_room_id")
		updateVals = append(updateVals, val)
		n++
	}

	// Build the query
	var query strings.Builder
	query.WriteString("INSERT INTO syncv3_rooms (")
	query.WriteString(strings.Join(insertCols, ", "))
	query.WriteString(") ")
	query.WriteString("VALUES (")
	query.WriteString(strings.Join(insertVals, ", "))
	query.WriteString(") ON CONFLICT (room_id) DO UPDATE SET ")
	for i := range updateCols {
		query.WriteString(updateCols[i])
		query.WriteString(" = ")
		query.WriteString(updateVals[i])
		if i < len(updateCols)-1 {
			query.WriteString(", ")
		}
	}

	stmt, err := txn.PrepareContext(ctx, query.String())
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("roomsStatements.Upsert: txn.PrepareContext failed")
		return err
	}
	defer internal.CloseAndLogIfError(ctx, stmt, "roomsStatements.Upsert: stmt.close() failed")

	args := []interface{}{info.ID, snapshotID, latestNID}
	if info.UpgradedRoomID != nil {
		args = append(args, info.UpgradedRoomID)
	}
	if info.Type != nil {
		args = append(args, info.Type)
	}
	if info.PredecessorRoomID != nil {
		args = append(args, *info.PredecessorRoomID)
	}

	if _, err = stmt.ExecContext(ctx, args...); err != nil {
		util.GetLogger(ctx).WithError(err).Error("roomsStatements.Upsert: stmt.ExecContext failed")
		return err
	}
	return nil
}
