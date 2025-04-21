package postgres

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"

	"github.com/element-hq/dendrite/internal"
	"github.com/element-hq/dendrite/internal/sqlutil"
	"github.com/element-hq/dendrite/syncapi/storage/tables"
	"github.com/lib/pq"
	"github.com/matrix-org/util"
)

const slidingSyncTxnSchema = `
	CREATE TABLE IF NOT EXISTS syncv3_txns (
		user_id TEXT NOT NULL,
		device_id TEXT NOT NULL,
		event_id TEXT NOT NULL,
		txn_id TEXT NOT NULL,
		ts BIGINT NOT NULL,
		UNIQUE(user_id, device_id, event_id)
	);
`

const insertTxnSQL = `INSERT INTO syncv3_txns (user_id, device_id, event_id, txn_id, ts) VALUES ($1, $2, $3, $4, $5)`

const deleteTxnSQL = `DELETE FROM syncv3_txns WHERE ts <= $1`

const selectTxnSQL = `SELECT event_id, txn_id FROM syncv3_txns WHERE user_id=$1 AND device_id=$2 and event_id=ANY($3)`

type slidingSyncTxnStatements struct {
	insertTxnStmt *sql.Stmt
	deleteTxnStmt *sql.Stmt
	selectTxnStmt *sql.Stmt
}

func NewPostgresSlidingSyncTxnTable(db *sql.DB) (tables.SlidingSyncTxn, error) {
	s := &slidingSyncTxnStatements{}
	_, err := db.Exec(slidingSyncTxnSchema)
	if err != nil {
		return nil, err
	}
	return s, sqlutil.StatementList{
		{&s.insertTxnStmt, insertTxnSQL},
		{&s.deleteTxnStmt, deleteTxnSQL},
		{&s.selectTxnStmt, selectTxnSQL},
	}.Prepare(db)
}

func (s *slidingSyncTxnStatements) Insert(ctx context.Context, txn *sql.Tx, userID, deviceID string, eventIDToTxnID map[string]string) error {
	ts := time.Now()
	valueArgs := make([]any, 0, len(eventIDToTxnID)*5)
	var query strings.Builder
	n := 0
	query.WriteString("INSERT INTO syncv3_txns (user_id, device_id, event_id, txn_id, ts) VALUES ")
	for eventID, txnID := range eventIDToTxnID {
		query.WriteString("(")
		query.WriteString(strings.Join([]string{
			strings.Join([]string{"$", strconv.Itoa(n + 1)}, ""), // user_id
			strings.Join([]string{"$", strconv.Itoa(n + 2)}, ""), // device_id
			strings.Join([]string{"$", strconv.Itoa(n + 3)}, ""), // event_id
			strings.Join([]string{"$", strconv.Itoa(n + 4)}, ""), // txn_id
			strings.Join([]string{"$", strconv.Itoa(n + 5)}, ""), // ts
		}, ", "))
		n += 5
		if n < len(eventIDToTxnID)*5 {
			query.WriteString("), ")
		} else {
			query.WriteString(") ")
		}
		valueArgs = append(valueArgs,
			userID,
			deviceID,
			eventID,
			txnID,
			ts.UnixMilli(),
		)
	}
	_, err := txn.ExecContext(ctx, query.String(), valueArgs...)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("slidingSyncTxnStatements.Insert: failed to execute statement")
		return err
	}
	return nil
}

func (s *slidingSyncTxnStatements) Select(ctx context.Context, txn *sql.Tx, userID, deviceID string, eventIDs []string) (map[string]string, error) {
	rows, err := sqlutil.TxStmtContext(ctx, txn, s.selectTxnStmt).QueryContext(ctx, userID, deviceID, pq.Array(eventIDs))
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("slidingSyncTxnStatements.Select: failed to execute statement")
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "slidingSyncTxnStatements.Select: rows.close() failed")
	result := make(map[string]string, len(eventIDs))
	var eventID, txnID string
	for rows.Next() {
		if err := rows.Scan(&eventID, &txnID); err != nil {
			util.GetLogger(ctx).WithError(err).Error("slidingSyncTxnStatements.Select: failed to scan row")
			return nil, err
		}
		result[eventID] = txnID
	}

	return result, nil
}

func (s *slidingSyncTxnStatements) Clean(ctx context.Context, txn *sql.Tx, boundaryTime time.Time) error {
	_, err := sqlutil.TxStmtContext(ctx, txn, s.deleteTxnStmt).ExecContext(ctx, boundaryTime.UnixMilli())
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("slidingSyncTxnStatements.Clean: failed to execute statement")
	}
	return err
}
