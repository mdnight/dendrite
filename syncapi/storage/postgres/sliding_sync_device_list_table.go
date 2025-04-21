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
	"github.com/matrix-org/util"
)

const (
	BucketNew  = 1
	BucketSent = 2
)

const slidingSyncDeviceListSchema = `
	CREATE TABLE IF NOT EXISTS syncv3_device_list_updates (
		user_id TEXT NOT NULL,
		device_id TEXT NOT NULL,
		target_user_id TEXT NOT NULL,
		target_state SMALLINT NOT NULL,
		bucket SMALLINT NOT NULL,
		UNIQUE(user_id, device_id, target_user_id, bucket)
	);
	-- make an index so selecting all the rows is faster
	CREATE INDEX IF NOT EXISTS syncv3_device_list_updates_bucket_idx ON syncv3_device_list_updates(user_id, device_id, bucket);
	-- Set the fillfactor to 90%, to allow for HOT updates (e.g. we only
	-- change the data, not anything indexed like the id)
	ALTER TABLE syncv3_device_list_updates SET (fillfactor = 90);
`

const selectDeviceListChangesInBucketSQL = `SELECT target_user_id, target_state FROM syncv3_device_list_updates WHERE user_id=$1 AND device_id=$2 AND bucket=$3`

const deleteDeviceListChangesInBucketSQL = `DELETE FROM syncv3_device_list_updates WHERE user_id=$1 AND device_id=$2 AND bucket=$3`

const updateDeviceListChangesInBucketSQL = `UPDATE syncv3_device_list_updates SET bucket=$1 WHERE user_id=$2 AND device_id=$3 AND bucket=$4 RETURNING target_user_id, target_state`

type slidingSyncDeviceListStmts struct {
	selectDeviceListChangesInBucketStmt *sql.Stmt
	deleteDeviceListChangesInBucketStmt *sql.Stmt
	updateDeviceListChangesInBucketStmt *sql.Stmt
}

func NewPostgresSlidingSyncDeviceListTable(db *sql.DB) (tables.SlidingSyncDeviceList, error) {
	s := &slidingSyncDeviceListStmts{}
	_, err := db.Exec(slidingSyncDeviceListSchema)
	if err != nil {
		return nil, err
	}
	return s, sqlutil.StatementList{
		{&s.selectDeviceListChangesInBucketStmt, selectDeviceListChangesInBucketSQL},
		{&s.deleteDeviceListChangesInBucketStmt, deleteDeviceListChangesInBucketSQL},
		{&s.updateDeviceListChangesInBucketStmt, updateDeviceListChangesInBucketSQL},
	}.Prepare(db)
}

func (s *slidingSyncDeviceListStmts) Select(ctx context.Context, txn *sql.Tx, userID, deviceID string, swap bool) (result types.SlidingSyncMapStringInt, err error) {
	if !swap {
		// read only view, just return what we previously sent and don't do anything else.
		return s.selectDeviceListChangesInBucket(ctx, txn, userID, deviceID, BucketSent)
	}

	// delete the now acknowledged 'sent' data
	_, err = sqlutil.TxStmtContext(ctx, txn, s.deleteDeviceListChangesInBucketStmt).ExecContext(ctx, userID, deviceID, BucketSent)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("selectDeviceListChangesInBucket: delete failed")
		return nil, err
	}
	// grab any 'new' updates and atomically mark these as 'sent'.
	// NB: we must not SELECT then UPDATE, because a 'new' row could be inserted after the SELECT and before the UPDATE, which
	// would then be incorrectly moved to 'sent' without being returned to the client, dropping the data. This happens because
	// the default transaction level is 'read committed', which /allows/ nonrepeatable reads which is:
	//  > A transaction re-reads data it has previously read and finds that data has been modified by another transaction (that committed since the initial read).
	// We could change the isolation level but this incurs extra performance costs in addition to serialisation errors which
	// need to be handled. It's easier to just use UPDATE .. RETURNING. Note that we don't require UPDATE .. RETURNING to be
	// atomic in any way, it's just that we need to guarantee each things SELECTed is also UPDATEd (so in the scenario above,
	// we don't care if the SELECT includes or excludes the 'new' row, but if it is SELECTed it MUST be UPDATEd).
	rows, err := sqlutil.TxStmtContext(ctx, txn, s.updateDeviceListChangesInBucketStmt).QueryContext(ctx, BucketSent, userID, deviceID, BucketNew)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("selectDeviceListChangesInBucket: update failed")
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "selectDeviceListChangesInBucket: rows.close() failed")
	var targetUserID string
	var targetState int
	result = make(types.SlidingSyncMapStringInt)
	for rows.Next() {
		if err = rows.Scan(&targetUserID, &targetState); err != nil {
			util.GetLogger(ctx).WithError(err).Error("selectDeviceListChangesInBucket: scan failed")
			return nil, err
		}
		result[targetUserID] = targetState
	}
	// TODO do we want to call sentry here?
	return result, rows.Err()
}

func (s *slidingSyncDeviceListStmts) Upsert(ctx context.Context, txn *sql.Tx, userID, deviceID string, deviceListChanges map[string]int) (err error) {
	if len(deviceListChanges) == 0 {
		return nil
	}
	var query strings.Builder
	argVals := make([]any, 0, len(deviceListChanges)*5)
	query.WriteString("INSERT INTO syncv3_device_list_updates(user_id, device_id, target_user_id, target_state, bucket) VALUES ")
	n := 0
	maxN := 5 * len(deviceListChanges)
	for targetUserID, targetState := range deviceListChanges {
		query.WriteString("(")
		query.WriteString(strings.Join([]string{
			strings.Join([]string{"$", strconv.Itoa(n + 1)}, ""), // user_id
			strings.Join([]string{"$", strconv.Itoa(n + 2)}, ""), // device_id
			strings.Join([]string{"$", strconv.Itoa(n + 3)}, ""), // target_user_id
			strings.Join([]string{"$", strconv.Itoa(n + 4)}, ""), // target_state
			strings.Join([]string{"$", strconv.Itoa(n + 5)}, ""), // bucket
		}, ", "))
		query.WriteString(")")
		n += 5
		if n < maxN {
			query.WriteString(", ")
		} else {
			query.WriteString(" ")
		}
		argVals = append(argVals, userID, deviceID, targetUserID, targetState, BucketNew)
	}
	query.WriteString("ON CONFLICT (user_id, device_id, target_user_id, bucket) DO UPDATE SET target_state = EXCLUDED.target_state")
	_, err = txn.ExecContext(ctx, query.String(), argVals...)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("Upsert: failed to insert device list changes")
	}
	// TODO do we want to call sentry here?
	return err
}

func (s *slidingSyncDeviceListStmts) selectDeviceListChangesInBucket(ctx context.Context, txn *sql.Tx, userID, deviceID string, bucket int) (types.SlidingSyncMapStringInt, error) {
	stmt := sqlutil.TxStmtContext(ctx, txn, s.selectDeviceListChangesInBucketStmt)
	rows, err := stmt.QueryContext(ctx, userID, deviceID, bucket)
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "selectDeviceListChangesInBucket: rows.close() failed")
	result := make(types.SlidingSyncMapStringInt)
	for rows.Next() {
		var targetUserID string
		var targetState int
		if err = rows.Scan(&targetUserID, &targetState); err != nil {
			util.GetLogger(ctx).WithError(err).Error("selectDeviceListChangesInBucket: scan failed")
			return nil, err
		}
		result[targetUserID] = targetState
	}
	return result, nil
}
