package sqlite3

import (
	"context"
	"database/sql"
	"reflect"

	"github.com/element-hq/dendrite/internal/sqlutil"
	"github.com/element-hq/dendrite/syncapi/storage/tables"
	"github.com/element-hq/dendrite/syncapi/types"
	"github.com/fxamacker/cbor/v2"
	"github.com/matrix-org/util"
)

const slidingSyncDeviceDataSchema = `
	CREATE TABLE IF NOT EXISTS syncv3_device_data (
		user_id TEXT NOT NULL,
		device_id TEXT NOT NULL,
		data BYTEA NOT NULL,
		UNIQUE(user_id, device_id)
	);
	-- Set the fillfactor to 90%, to allow for HOT updates (e.g. we only
	-- change the data, not anything indexed like the id)
	ALTER TABLE syncv3_device_data SET (fillfactor = 90);
`

const selectDeviceDataForUpdateSQL = `SELECT data FROM syncv3_device_data WHERE user_id=$1 AND device_id=$2 FOR UPDATE`

const updateDeviceDataSQL = `UPDATE syncv3_device_data SET data=$1 WHERE user_id=$2 AND device_id=$3`

const insertDeviceDataSQL = `INSERT INTO syncv3_device_data(user_id, device_id, data) VALUES($1,$2,$3) ON CONFLICT (user_id, device_id) DO UPDATE SET data=$3`

type slidingSyncDeviceDataStmts struct {
	deviceListTable               tables.SlidingSyncDeviceList
	selectDeviceDataForUpdateStmt *sql.Stmt
	updateDeviceDataStmt          *sql.Stmt
	insertDeviceDataStmt          *sql.Stmt
}

func NewSqliteSlidingSyncDeviceDataTable(db *sql.DB, deviceList tables.SlidingSyncDeviceList) (tables.SlidingSyncDeviceData, error) {
	s := &slidingSyncDeviceDataStmts{
		deviceListTable: deviceList,
	}
	_, err := db.Exec(slidingSyncDeviceDataSchema)
	if err != nil {
		return nil, err
	}
	return s, sqlutil.StatementList{
		{&s.selectDeviceDataForUpdateStmt, selectDeviceDataForUpdateSQL},
		{&s.updateDeviceDataStmt, updateDeviceDataSQL},
		{&s.insertDeviceDataStmt, insertDeviceDataSQL},
	}.Prepare(db)
}

type DeviceDataRow struct {
	ID       int64
	UserID   string
	DeviceID string
	// This will contain internal.DeviceKeyData serialised as JSON. It's stored in a single column as we don't
	// need to perform searches on this data.
	KeyData []byte
}

// Atomically select the device data for this user|device and then swap DeviceLists around if set.
// This should only be called by the v3 HTTP APIs when servicing an E2EE extension request.
func (s *slidingSyncDeviceDataStmts) Select(ctx context.Context, txn *sql.Tx, userID, deviceID string, swap bool) (result *types.SlidingSyncDeviceData, err error) {
	// grab otk counts and fallback key types
	var row DeviceDataRow
	r := sqlutil.TxStmtContext(ctx, txn, s.selectDeviceDataForUpdateStmt).QueryRowContext(ctx, userID, deviceID)
	err = r.Scan(&row.UserID, &row.DeviceID, &row.KeyData)
	if err != nil && err != sql.ErrNoRows {
		util.GetLogger(ctx).WithError(err).Error("SlidingSyncDeviceData.Select: query failed")
		return nil, err
	}
	result = &types.SlidingSyncDeviceData{}
	var keyData *types.SlidingSyncDeviceKeyData
	// unmarshal to swap
	if err = cbor.Unmarshal(row.KeyData, &keyData); err != nil {
		return nil, err
	}
	result.UserID = userID
	result.DeviceID = deviceID
	if keyData != nil {
		result.SlidingSyncDeviceKeyData = *keyData
	}

	deviceListChanges, err := s.deviceListTable.Select(ctx, txn, userID, deviceID, swap)
	if err != nil {
		return nil, err
	}
	for targetUserID, targetState := range deviceListChanges {
		switch targetState {
		case types.SlidingSyncDeviceListChanged:
			result.DeviceListChanged = append(result.DeviceListChanged, targetUserID)
		case types.SlidingSyncDeviceListLeft:
			result.DeviceListLeft = append(result.DeviceListLeft, targetUserID)
		}
	}
	if !swap {
		return // don't swap
	}
	// swap over the fields
	writeBack := *keyData
	writeBack.ChangedBits = 0

	if reflect.DeepEqual(keyData, &writeBack) {
		// The update to the DB would be a no-op; don't bother with it.
		// This helps reduce write usage and the contention on the unique index for
		// the device_data table.
		return
	}
	// re-marshal and write
	data, err := cbor.Marshal(writeBack)
	if err != nil {
		return nil, err
	}
	_, err = sqlutil.TxStmtContext(ctx, txn, s.updateDeviceDataStmt).ExecContext(ctx, data, userID, deviceID)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("SlidingSyncDeviceData.Select: update failed")
	}
	return
}

// Upsert combines what is in the database for this user|device with the partial entry `dd`
func (s *slidingSyncDeviceDataStmts) Upsert(ctx context.Context, txn *sql.Tx, userID, deviceID string, keys types.SlidingSyncDeviceKeyData, deviceListChanges map[string]int) (err error) {
	// Update device lists
	err = s.deviceListTable.Upsert(ctx, txn, userID, deviceID, deviceListChanges)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("SlidingSyncDeviceData.Upsert: device list update failed")
		return err
	}
	// select what already exists
	var row DeviceDataRow
	// select what already exists
	r := sqlutil.TxStmtContext(ctx, txn, s.selectDeviceDataForUpdateStmt).QueryRowContext(ctx, userID, deviceID)
	err = r.Scan(&row.KeyData)
	if err != nil && err != sql.ErrNoRows {
		util.GetLogger(ctx).WithError(err).Error("SlidingSyncDeviceData.Upsert: query failed")
		return err
	}
	// unmarshal and combine
	var keyData types.SlidingSyncDeviceKeyData
	if len(row.KeyData) > 0 {
		if err = cbor.Unmarshal(row.KeyData, &keyData); err != nil {
			return err
		}
	}
	if keys.FallbackKeyTypes != nil {
		keyData.FallbackKeyTypes = keys.FallbackKeyTypes
		keyData.SetFallbackKeysChanged()
	}
	if keys.OTKCounts != nil {
		keyData.OTKCounts = keys.OTKCounts
		keyData.SetOTKCountChanged()
	}
	data, err := cbor.Marshal(keyData)
	if err != nil {
		return err
	}
	_, err = sqlutil.TxStmtContext(ctx, txn, s.insertDeviceDataStmt).ExecContext(ctx, userID, deviceID, data)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("SlidingSyncDeviceData.Upsert: insert failed")
	}

	// TODO do we want to call sentry here?
	return err
}
