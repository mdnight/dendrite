package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/element-hq/dendrite/internal"
	"github.com/element-hq/dendrite/internal/sqlutil"
	"github.com/element-hq/dendrite/syncapi/storage/tables"
	"github.com/lib/pq"
	"github.com/matrix-org/util"
	"github.com/tidwall/gjson"
)

const (
	ActionRequest = 1
	ActionCancel  = 2
)

const slidingSyncToDeviceSchema = `
CREATE SEQUENCE IF NOT EXISTS syncv3_to_device_messages_seq;
	CREATE TABLE IF NOT EXISTS syncv3_to_device_messages (
		position BIGINT NOT NULL PRIMARY KEY DEFAULT nextval('syncv3_to_device_messages_seq'),
		user_id TEXT NOT NULL,
		device_id TEXT NOT NULL,
		event_type TEXT NOT NULL,
		sender TEXT NOT NULL,
		message TEXT NOT NULL,
		-- nullable as these fields are not on all to-device events
		unique_key TEXT,
		action SMALLINT DEFAULT 0 -- 0 means unknown
	);
	CREATE TABLE IF NOT EXISTS syncv3_to_device_ack_pos (
		user_id TEXT NOT NULL,
		device_id TEXT NOT NULL,
		PRIMARY KEY (user_id, device_id),
		unack_pos BIGINT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS syncv3_to_device_messages_device_idx ON syncv3_to_device_messages(device_id);
	CREATE INDEX IF NOT EXISTS syncv3_to_device_messages_ukey_idx ON syncv3_to_device_messages(unique_key, device_id);
	CREATE INDEX IF NOT EXISTS syncv3_to_device_messages_pos_device_idx ON syncv3_to_device_messages(position, device_id);
`

const setUnackedPositionSQL = `INSERT INTO syncv3_to_device_ack_pos(user_id, device_id, unack_pos) VALUES($1,$2,$3) ON CONFLICT (user_id, device_id)
	DO UPDATE SET unack_pos=excluded.unack_pos;`

const deleteMessagesUpToAndIncludingSQL = `DELETE FROM syncv3_to_device_messages WHERE user_id = $1 AND device_id = $2 AND position <= $3;`

const deleteMessagesForDeviceSQL = `DELETE FROM syncv3_to_device_messages WHERE user_id = $1 AND device_id = $2;`

const deleteAckPositionForDeviceSQL = `DELETE FROM syncv3_to_device_ack_pos WHERE user_id = $1 AND device_id = $2;`

const selectMessagesSQL = `SELECT position, message FROM syncv3_to_device_messages WHERE user_id = $1 AND device_id = $2 AND position > $3 ORDER BY position ASC LIMIT $4;`

const selectUnackedPositionSQL = `SELECT unack_pos FROM syncv3_to_device_ack_pos WHERE user_id=$1 AND device_id=$2;`

const deleteMessagesByUniqueKeysSQL = `DELETE FROM syncv3_to_device_messages WHERE unique_key = ANY($1) AND user_id = $2 AND device_id = $3 AND position > $4 RETURNING unique_key;`

type slidingSyncToDeviceStmt struct {
	setUnackedPositionStmt             *sql.Stmt
	deleteMessagesUpToAndIncludingStmt *sql.Stmt
	deleteMessagesForDeviceStmt        *sql.Stmt
	deleteAckPositionForDeviceStmt     *sql.Stmt
	selectMessagesStmt                 *sql.Stmt
	selectUnackedPositionStmt          *sql.Stmt
	deleteMessagesByUniqueKeysStmt     *sql.Stmt
}

func NewSqliteSlidingSyncToDeviceTable(db *sql.DB) (tables.SlidingSyncToDevice, error) {
	s := &slidingSyncToDeviceStmt{}
	_, err := db.Exec(slidingSyncToDeviceSchema)
	if err != nil {
		return nil, err
	}
	return s, sqlutil.StatementList{
		{&s.setUnackedPositionStmt, setUnackedPositionSQL},
		{&s.deleteMessagesUpToAndIncludingStmt, deleteMessagesUpToAndIncludingSQL},
		{&s.deleteMessagesForDeviceStmt, deleteMessagesForDeviceSQL},
		{&s.deleteAckPositionForDeviceStmt, deleteAckPositionForDeviceSQL},
		{&s.selectMessagesStmt, selectMessagesSQL},
		{&s.selectUnackedPositionStmt, selectUnackedPositionSQL},
		{&s.deleteMessagesByUniqueKeysStmt, deleteMessagesByUniqueKeysSQL},
	}.Prepare(db)
}

func (s *slidingSyncToDeviceStmt) SetUnackedPosition(ctx context.Context, txn *sql.Tx, userID, deviceID string, pos int64) error {
	_, err := sqlutil.TxStmtContext(ctx, txn, s.setUnackedPositionStmt).ExecContext(ctx, userID, deviceID, pos)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("SetUnackedPosition: exec failed")
	}
	return err
}

func (s *slidingSyncToDeviceStmt) DeleteMessagesUpToAndIncluding(ctx context.Context, txn *sql.Tx, userID, deviceID string, toIncl int64) error {
	_, err := sqlutil.TxStmtContext(ctx, txn, s.deleteMessagesUpToAndIncludingStmt).ExecContext(ctx, userID, deviceID, toIncl)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("DeleteMessagesUpToAndIncluding: exec failed")
	}
	return err
}

func (s *slidingSyncToDeviceStmt) DeleteAllMessagesForDevice(ctx context.Context, txn *sql.Tx, userID, deviceID string) error {
	_, err := sqlutil.TxStmtContext(ctx, txn, s.deleteMessagesForDeviceStmt).ExecContext(ctx, userID, deviceID)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("DeleteAllMessagesForDevice: deleteMessagesForDeviceStmt exec failed")
		return err
	}

	_, err = sqlutil.TxStmtContext(ctx, txn, s.deleteAckPositionForDeviceStmt).ExecContext(ctx, userID, deviceID)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("DeleteAllMessagesForDevice: deleteAckPositionForDeviceStmt exec failed")
		return err
	}

	return nil
}

// Messages fetches up to `limit` to-device messages for this device, starting from and excluding `from`.
// Returns the fetches messages ordered by ascending position, as well as the position of the last to-device message
// fetched.
func (s *slidingSyncToDeviceStmt) Messages(ctx context.Context, txn *sql.Tx, userID, deviceID string, from, limit int64) (msgs []json.RawMessage, upTo int64, err error) {
	upTo = from
	sqlRows, err := sqlutil.TxStmtContext(ctx, txn, s.selectMessagesStmt).QueryContext(ctx, userID, deviceID, from, limit)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("Messages: query failed")
		return nil, 0, err
	}
	defer internal.CloseAndLogIfError(ctx, sqlRows, "slidingSyncTxnStatements.Select: sqlRows.close() failed")
	msgs = make([]json.RawMessage, 0, limit)
	var pos int64
	var msg string
	for sqlRows.Next() {
		if err = sqlRows.Scan(&pos, &msg); err != nil {
			util.GetLogger(ctx).WithError(err).Error("Messages: scan failed")
			return nil, 0, err
		}
		m := gjson.Parse(msg)
		msgId := m.Get(`content.org\.matrix\.msgid`).Str
		if msgId != "" {
			util.GetLogger(ctx).WithField("msgId", msgId).WithField("user", userID).WithField("device", deviceID).Debug("ToDeviceTable.Messages")
		}
	}
	upTo = pos
	return
}

type ToDeviceRow struct {
	Position  int64
	UserID    string
	DeviceID  string
	Message   string
	Type      string
	Sender    string
	UniqueKey *string
	Action    int
}

func (s *slidingSyncToDeviceStmt) InsertMessages(ctx context.Context, txn *sql.Tx, userID, deviceID string, msgs []json.RawMessage) (pos int64, err error) {
	var lastPos int64
	var unackPos int64
	err = sqlutil.TxStmtContext(ctx, txn, s.selectUnackedPositionStmt).QueryRowContext(ctx, userID, deviceID).Scan(&unackPos)
	if err != nil && err != sql.ErrNoRows {
		util.GetLogger(ctx).WithError(err).Error("InsertMessages: selectUnackedPositionStmt unable to select unacked pos")
		return 0, err
	}

	// Some of these events may be "cancel" actions. If we find events for the unique key of this event, then delete them
	// and ignore the "cancel" action.
	cancels := []string{}
	allRequests := make(map[string]struct{})
	allCancels := make(map[string]struct{})

	rows := make([]ToDeviceRow, 0, len(msgs))
	for i := range msgs {
		m := gjson.ParseBytes(msgs[i])
		rows = append(rows, ToDeviceRow{
			UserID:   userID,
			DeviceID: deviceID,
			Message:  string(msgs[i]),
			Type:     m.Get("type").Str,
			Sender:   m.Get("sender").Str,
		})
		msgId := m.Get(`org\.matrix\.msgid`).Str
		if msgId != "" {
			util.GetLogger(ctx).WithField("msgId", msgId).WithField("user", userID).WithField("device", deviceID).Debug("ToDeviceTable.InsertMessages")
		}
		switch rows[i].Type {
		case "m.room_key_request":
			action := m.Get("action").Str
			if action == "request" {
				rows[i].Action = ActionRequest
			} else if action == "request_cancellation" {
				rows[i].Action = ActionCancel
			}
			// "the same request_id and requesting_device_id fields, sent by the same user."
			key := strings.Join([]string{
				rows[i].Type,
				rows[i].Sender,
				m.Get("requesting_device_id").Str,
				m.Get("request_id").Str,
			}, "-")
			rows[i].UniqueKey = &key
		}
		if rows[i].Action == ActionCancel && rows[i].UniqueKey != nil {
			cancels = append(cancels, *rows[i].UniqueKey)
			allCancels[*rows[i].UniqueKey] = struct{}{}
		} else if rows[i].Action == ActionRequest && rows[i].UniqueKey != nil {
			allRequests[*rows[i].UniqueKey] = struct{}{}
		}
	}
	if len(cancels) > 1 {
		// delete action: request events which have the same unique key, for this device inbox, only if they are not sent to the client already (unacked)
		sqlDeleteRows, err := sqlutil.TxStmtContext(ctx, txn, s.deleteMessagesByUniqueKeysStmt).QueryContext(ctx, pq.StringArray(cancels), userID, deviceID, unackPos)
		if err != nil {
			util.GetLogger(ctx).WithError(err).Error("InsertMessages: deleteMessagesByUniqueKeysStmt failed to delete cancelled events")
			return 0, err
		}
		defer internal.CloseAndLogIfError(ctx, sqlDeleteRows, "InsertMessages: sqlDeleteRows.close() failed")
		cancelledInDBSet := make(map[string]struct{})
		for sqlDeleteRows.Next() {
			var uniqueKey string
			if err = sqlDeleteRows.Scan(&uniqueKey); err != nil {
				util.GetLogger(ctx).WithError(err).Error("InsertMessages: deleteMessagesByUniqueKeysStmt failed to scan unique key")
				return 0, err
			}
			cancelledInDBSet[uniqueKey] = struct{}{}
		}
		// do not insert the cancelled unique keys
		newRows := make([]ToDeviceRow, 0, len(rows))
		for i := range rows {
			if rows[i].UniqueKey != nil {
				ukey := *rows[i].UniqueKey
				if _, exists := cancelledInDBSet[ukey]; exists {
					continue // the request was deleted so don't insert the cancel
				}
				// we may be requesting and cancelling in one go, check it and ignore if so
				_, reqExists := allRequests[ukey]
				_, cancelExists := allCancels[ukey]
				if reqExists && cancelExists {
					continue
				}
			}
			newRows = append(newRows, rows[i])
		}
		rows = newRows
	}
	// we may have nothing to do if the entire set of events were cancellations
	if len(rows) == 0 {
		return
	}

	valueArgs := make([]any, 0, len(rows)*7)
	var query strings.Builder
	query.WriteString("INSERT INTO syncv3_to_device_messages (user_id, device_id, message, event_type, sender, action, unique_key) VALUES ")
	for i := range rows {
		query.WriteString("(")
		query.WriteString(strings.Join([]string{
			strings.Join([]string{"$", strconv.Itoa(i*7 + 1)}, ""), // user_id
			strings.Join([]string{"$", strconv.Itoa(i*7 + 2)}, ""), // device_id
			strings.Join([]string{"$", strconv.Itoa(i*7 + 3)}, ""), // message
			strings.Join([]string{"$", strconv.Itoa(i*7 + 4)}, ""), // event_type
			strings.Join([]string{"$", strconv.Itoa(i*7 + 5)}, ""), // sender
			strings.Join([]string{"$", strconv.Itoa(i*7 + 6)}, ""), // action
			strings.Join([]string{"$", strconv.Itoa(i*7 + 7)}, ""), // unique_key
		}, ", "))
		if i < len(rows)-1 {
			query.WriteString("), ")
		} else {
			query.WriteString(") ")
		}
		valueArgs = append(valueArgs,
			rows[i].UserID,
			rows[i].DeviceID,
			rows[i].Message,
			rows[i].Type,
			rows[i].Sender,
			rows[i].Action,
			rows[i].UniqueKey,
		)
	}
	query.WriteString("RETURNING position")
	sqlInsertRows, err := txn.QueryContext(ctx, query.String(), valueArgs...)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("InsertMessages: query failed")
		return 0, err
	}
	defer internal.CloseAndLogIfError(ctx, sqlInsertRows, "InsertMessages: sqlInsertRows.close() failed")
	for sqlInsertRows.Next() {
		if err = sqlInsertRows.Scan(&lastPos); err != nil {
			util.GetLogger(ctx).WithError(err).Error("InsertMessages: sqlInsertRows scan failed")
			return 0, err
		}
	}

	return lastPos, err
}
