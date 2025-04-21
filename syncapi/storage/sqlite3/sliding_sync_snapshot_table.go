package sqlite3

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/element-hq/dendrite/internal"
	"github.com/element-hq/dendrite/internal/sqlutil"
	"github.com/element-hq/dendrite/syncapi/storage/tables"
	"github.com/element-hq/dendrite/syncapi/types"
	"github.com/lib/pq"
	"github.com/matrix-org/util"
)

const slidingSyncSnapshotSchema = `
	CREATE SEQUENCE IF NOT EXISTS syncv3_snapshots_seq;
	CREATE TABLE IF NOT EXISTS syncv3_snapshots (
		snapshot_id BIGINT PRIMARY KEY DEFAULT nextval('syncv3_snapshots_seq'),
		room_id TEXT NOT NULL,
		events BIGINT[] NOT NULL,
		membership_events BIGINT[] NOT NULL,
		UNIQUE(snapshot_id, room_id)
	);
`

const currentSnapshotSQL = `SELECT syncv3_rooms.room_id, events, membership_events FROM syncv3_snapshots JOIN syncv3_rooms ON syncv3_snapshots.snapshot_id = syncv3_rooms.current_snapshot_id`

const selectSnapshotSQL = `SELECT snapshot_id, room_id, events, membership_events FROM syncv3_snapshots WHERE snapshot_id = $1`

const insertSnapshotSQL = `INSERT INTO syncv3_snapshots(room_id, events, membership_events) VALUES($1, $2, $3) RETURNING snapshot_id`

const deleteSnapshotSQL = `DELETE FROM syncv3_snapshots WHERE snapshot_id = ANY($1)`

type slidingSyncSnapshotStmts struct {
	currentSnapshotStmt *sql.Stmt
	selectSnapshotStmt  *sql.Stmt
	insertSnapshotStmt  *sql.Stmt
	deleteSnapshotStmt  *sql.Stmt
}

func NewSqliteSlidingSyncSnapshotTable(db *sql.DB) (tables.SlidingSyncSnapshot, error) {
	s := &slidingSyncSnapshotStmts{}
	_, err := db.Exec(slidingSyncSnapshotSchema)
	if err != nil {
		return nil, err
	}
	return s, sqlutil.StatementList{
		{&s.currentSnapshotStmt, currentSnapshotSQL},
		{&s.selectSnapshotStmt, selectSnapshotSQL},
		{&s.insertSnapshotStmt, insertSnapshotSQL},
		{&s.deleteSnapshotStmt, deleteSnapshotSQL},
	}.Prepare(db)
}

func (s *slidingSyncSnapshotStmts) CurrentSnapshots(ctx context.Context, txn *sql.Tx) (map[string][]int64, error) {
	rows, err := sqlutil.TxStmtContext(ctx, txn, s.currentSnapshotStmt).QueryContext(ctx)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("CurrentSnapshots: query failed")
		return nil, err
	}
	defer internal.CloseAndLogIfError(context.Background(), rows, "CurrentSnapshots: rows.Close() failed")
	result := make(map[string][]int64)
	for rows.Next() {
		var eventNIDs, memberEventNIDs pq.Int64Array
		var roomID string
		if err = rows.Scan(&roomID, &eventNIDs, &memberEventNIDs); err != nil {
			util.GetLogger(ctx).WithError(err).Error("CurrentSnapshots: scan failed")
			return nil, err
		}
		result[roomID] = append(result[roomID], eventNIDs...)
	}
	return result, nil
}

func (s *slidingSyncSnapshotStmts) Select(ctx context.Context, txn *sql.Tx, snapshotID int64) (row types.SlidingSyncSnapshotRow, err error) {
	if snapshotID == 0 {
		err = fmt.Errorf("SlidingSyncSnapshotTable.Select: snapshotID")
		return
	}
	err = sqlutil.TxStmtContext(ctx, txn, s.selectSnapshotStmt).QueryRowContext(ctx, snapshotID).Scan(&row.SnapshotID, &row.RoomID, &row.OtherEvents, &row.MembershipEvents)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("SlidingSyncSnapshotTable.Select: query failed")
	}
	return
}

func (s *slidingSyncSnapshotStmts) Insert(ctx context.Context, txn *sql.Tx, row *types.SlidingSyncSnapshotRow) error {
	var id int64
	if row.MembershipEvents == nil {
		row.MembershipEvents = make([]int64, 0)
	}
	if row.OtherEvents == nil {
		row.OtherEvents = make([]int64, 0)
	}
	err := sqlutil.TxStmtContext(ctx, txn, s.insertSnapshotStmt).QueryRowContext(ctx, row.RoomID, pq.Int64Array(row.OtherEvents), pq.Int64Array(row.MembershipEvents)).Scan(&id)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("SlidingSyncSnapshotTable.Insert: query failed")
	}
	row.SnapshotID = id
	return err
}

func (s *slidingSyncSnapshotStmts) Delete(ctx context.Context, txn *sql.Tx, snapshotIDs []int64) error {
	_, err := sqlutil.TxStmtContext(ctx, txn, s.deleteSnapshotStmt).ExecContext(ctx, pq.Int64Array(snapshotIDs))
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("SlidingSyncSnapshotTable.Delete: query failed")
	}
	return err
}
