package sqlite3

import (
	"context"
	"database/sql"
	"time"

	"github.com/element-hq/dendrite/internal"
	"github.com/element-hq/dendrite/internal/sqlutil"
	"github.com/element-hq/dendrite/syncapi/storage/tables"
	"github.com/element-hq/dendrite/syncapi/types"
	"github.com/matrix-org/util"
)

const slidingSyncDevicesSchema = `
	CREATE TABLE IF NOT EXISTS syncv3_sync2_devices (
		user_id TEXT NOT NULL,
		device_id TEXT NOT NULL,
		PRIMARY KEY (user_id, device_id),
		since TEXT NOT NULL
	);
`

const insertDeviceSQL = `INSERT INTO syncv3_sync2_devices(user_id, device_id, since) VALUES($1,$2,$3) ON CONFLICT (user_id, device_id) DO NOTHING;`

const updateDeviceSinceSQL = `UPDATE syncv3_sync2_devices SET since = $1 WHERE user_id = $2 AND device_id = $3;`

const findOldDevicesSQL = `
	SELECT user_id, device_id
	FROM syncv3_sync2_devices JOIN syncv3_sync2_tokens USING(user_id, device_id)
	GROUP BY (user_id, device_id)
	HAVING MAX(last_seen) < $1;
`

const selectSinceSQL = `SELECT since FROM syncv3_sync2_devices WHERE user_id = $1 AND device_id = $2;`

type slidingSyncDevicesStmts struct {
	insertDeviceStmt      *sql.Stmt
	updateDeviceSinceStmt *sql.Stmt
	findOldDevicesStmt    *sql.Stmt
	selectSinceStmt       *sql.Stmt
}

func NewSqliteSlidingSyncDevicesTable(db *sql.DB) (tables.SlidingSyncDevices, error) {
	s := &slidingSyncDevicesStmts{}
	_, err := db.Exec(slidingSyncDevicesSchema)
	if err != nil {
		return nil, err
	}
	return s, sqlutil.StatementList{
		{&s.insertDeviceStmt, insertDeviceSQL},
		{&s.updateDeviceSinceStmt, updateDeviceSinceSQL},
		{&s.findOldDevicesStmt, findOldDevicesSQL},
		{&s.selectSinceStmt, selectSinceSQL},
	}.Prepare(db)
}

// InsertDevice creates a new devices row with a blank since token if no such row
// exists. Otherwise, it does nothing.
func (s *slidingSyncDevicesStmts) InsertDevice(ctx context.Context, txn *sql.Tx, userID, deviceID string) error {
	_, err := sqlutil.TxStmtContext(ctx, txn, s.insertDeviceStmt).ExecContext(ctx, userID, deviceID, "")
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("SlidingSyncDeviceTable.InsertDevice: ExecContext failed")
	}
	return err
}

func (s *slidingSyncDevicesStmts) UpdateDeviceSince(ctx context.Context, txn *sql.Tx, userID, deviceID, since string) error {
	_, err := sqlutil.TxStmtContext(ctx, txn, s.updateDeviceSinceStmt).ExecContext(ctx, since, userID, deviceID)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("SlidingSyncDeviceTable.UpdateDeviceSince: ExecContext failed")
	}
	return err
}

// FindOldDevices fetches the user_id and device_id of all devices which haven't /synced
// for at least as long as the given inactivityPeriod. Such devices are returned in
// no particular order.
//
// This is determined using the syncv3_sync2_tokens.last_seen column, which is updated
// at most once per day to save DB throughtput (see TokensTable.MaybeUpdateLastSeen).
// The caller should therefore use an inactivityPeriod of at least two days to avoid
// considering a recently-used device as old.
func (s *slidingSyncDevicesStmts) FindOldDevices(ctx context.Context, txn *sql.Tx, inactivityPeriod time.Duration) (devices []types.SlidingSyncDevice, err error) {
	rows, err := sqlutil.TxStmtContext(ctx, txn, s.findOldDevicesStmt).QueryContext(ctx, time.Now().Add(-inactivityPeriod))
	if err != nil && err != sql.ErrNoRows {
		util.GetLogger(ctx).WithError(err).Error("SlidingSyncDeviceTable.FindOldDevices: QueryContext failed")
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "SlidingSyncDeviceTable.FindOldDevices: rows.close() failed")
	var userID, deviceID string
	for rows.Next() {
		if err = rows.Scan(&userID, &deviceID); err != nil {
			util.GetLogger(ctx).WithError(err).Error("SlidingSyncDeviceTable.FindOldDevices: rows.Scan failed")
			return nil, err
		}
		devices = append(
			devices,
			types.SlidingSyncDevice{
				UserID:   userID,
				DeviceID: deviceID,
			},
		)
	}
	return
}

func (s *slidingSyncDevicesStmts) SelectSince(ctx context.Context, txn *sql.Tx, userID, deviceID string) (since string, err error) {
	err = sqlutil.TxStmtContext(ctx, txn, s.selectSinceStmt).QueryRowContext(ctx, userID, deviceID).Scan(&since)
	if err != nil && err != sql.ErrNoRows {
		util.GetLogger(ctx).WithError(err).Error("SlidingSyncDeviceTable.SelectSince: QueryRowContext failed")
	}
	return
}
