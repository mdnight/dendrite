package sqlite3

import (
	"context"
	"database/sql"

	"github.com/element-hq/dendrite/internal"
	"github.com/element-hq/dendrite/internal/sqlutil"
	"github.com/element-hq/dendrite/syncapi/storage/tables"
	"github.com/matrix-org/util"
)

const slidingSyncUnreadTableSchema = `
	CREATE TABLE IF NOT EXISTS syncv3_unread (
		room_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		notification_count BIGINT NOT NULL DEFAULT 0,
		highlight_count BIGINT NOT NULL DEFAULT 0,
		UNIQUE(user_id, room_id)
	);
`

const selectAllNonZeroCountsForUserSQL = `SELECT room_id, notification_count, highlight_count FROM syncv3_unread WHERE user_id=$1 AND (notification_count > 0 OR highlight_count > 0)`

const selectUnreadCountersSQL = `SELECT notification_count, highlight_count FROM syncv3_unread WHERE user_id=$1 AND room_id=$2`

const updateUnreadCounters1SQL = `UPDATE syncv3_unread SET notification_count=$1, highlight_count=$2 WHERE user_id=$3 AND room_id=$4`

const updateUnreadCounters2SQL = `INSERT INTO syncv3_unread(room_id, user_id, highlight_count) VALUES($1, $2, $3) ON CONFLICT (room_id, user_id) DO UPDATE SET highlight_count = $3`

const updateUnreadCounters3SQL = `INSERT INTO syncv3_unread(room_id, user_id, notification_count) VALUES($1, $2, $3) ON CONFLICT (room_id, user_id) DO UPDATE SET notification_count = $3`

type slidingSyncUnreadStatements struct {
	selectAllNonZeroCountsForUserStmt *sql.Stmt
	selectUnreadCountersStmt          *sql.Stmt
	updateUnreadCounters1Stmt         *sql.Stmt
	updateUnreadCounters2Stmt         *sql.Stmt
	updateUnreadCounters3Stmt         *sql.Stmt
}

func NewSqliteSlidingSyncUnreadTable(db *sql.DB) (tables.SlidingSyncUnread, error) {
	s := &slidingSyncUnreadStatements{}
	_, err := db.Exec(slidingSyncUnreadTableSchema)
	if err != nil {
		return nil, err
	}
	return s, sqlutil.StatementList{
		{&s.selectAllNonZeroCountsForUserStmt, selectAllNonZeroCountsForUserSQL},
		{&s.selectUnreadCountersStmt, selectUnreadCountersSQL},
		{&s.updateUnreadCounters1Stmt, updateUnreadCounters1SQL},
		{&s.updateUnreadCounters2Stmt, updateUnreadCounters2SQL},
		{&s.updateUnreadCounters3Stmt, updateUnreadCounters3SQL},
	}.Prepare(db)
}

func (s *slidingSyncUnreadStatements) SelectAllNonZeroCountsForUser(ctx context.Context, txn *sql.Tx, userID string, callback func(roomID string, highlightCount, notificationCount int)) error {
	stmt := sqlutil.TxStmtContext(ctx, txn, s.selectAllNonZeroCountsForUserStmt)
	rows, err := stmt.QueryContext(ctx, userID)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("SelectAllNonZeroCountsForUser: failed to query unread counts")
		return err
	}
	defer internal.CloseAndLogIfError(ctx, stmt, "roomsStatements.Upsert: stmt.close() failed")

	for rows.Next() {
		var roomID string
		var highlightCount, notificationCount int
		if err := rows.Scan(&roomID, &notificationCount, &highlightCount); err != nil {
			util.GetLogger(ctx).WithError(err).Error("SelectAllNonZeroCountsForUser: failed to scan unread counts")
			return err
		}
		callback(roomID, highlightCount, notificationCount)
	}
	return nil
}

func (s *slidingSyncUnreadStatements) SelectUnreadCounters(ctx context.Context, txn *sql.Tx, userID, roomID string) (highlightCount, notificationCount int, err error) {
	stmt := sqlutil.TxStmtContext(ctx, txn, s.selectUnreadCountersStmt)
	err = stmt.QueryRowContext(ctx, userID, roomID).Scan(&notificationCount, &highlightCount)
	if err != nil && err != sql.ErrNoRows {
		util.GetLogger(ctx).WithError(err).Error("SelectUnreadCounters: failed to query unread counts")
		return 0, 0, err
	}
	return highlightCount, notificationCount, nil
}

func (s *slidingSyncUnreadStatements) UpdateUnreadCounters(ctx context.Context, txn *sql.Tx, userID, roomID string, highlightCount, notificationCount *int) error {
	var err error
	if highlightCount != nil && notificationCount != nil {
		stmt := sqlutil.TxStmtContext(ctx, txn, s.updateUnreadCounters1Stmt)
		_, err = stmt.ExecContext(ctx, *notificationCount, *highlightCount, userID, roomID)
	} else if highlightCount != nil {
		stmt := sqlutil.TxStmtContext(ctx, txn, s.updateUnreadCounters2Stmt)
		_, err = stmt.ExecContext(ctx, roomID, userID, *highlightCount)
	} else if notificationCount != nil {
		stmt := sqlutil.TxStmtContext(ctx, txn, s.updateUnreadCounters3Stmt)
		_, err = stmt.ExecContext(ctx, roomID, userID, *notificationCount)
	}
	return err
}
