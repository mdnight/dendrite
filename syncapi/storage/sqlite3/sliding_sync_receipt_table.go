package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/element-hq/dendrite/internal"
	"github.com/element-hq/dendrite/internal/sqlutil"
	"github.com/element-hq/dendrite/syncapi/storage/tables"
	"github.com/element-hq/dendrite/syncapi/types"
	"github.com/lib/pq"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/matrix-org/util"
)

const slidingSyncReceiptSchema = `
	CREATE TABLE IF NOT EXISTS %s (
		room_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		thread_id TEXT NOT NULL,
		event_id TEXT NOT NULL,
		ts BIGINT NOT NULL,
		UNIQUE(room_id, user_id, thread_id)
	);
	-- for querying by events in the timeline, need to search by event id
	CREATE INDEX IF NOT EXISTS %s_by_event_idx ON %s(room_id, event_id);
	-- for querying all receipts for a user in a room, need to search by user id
	CREATE INDEX IF NOT EXISTS %s_by_user_idx ON %s(room_id, user_id);
`

const selectReceiptsForEventsSQL = `SELECT room_id, event_id, user_id, ts, thread_id FROM syncv3_receipts WHERE room_id=$1 AND event_id = ANY($2)`

const selectReceiptsForUserSQL = `SELECT room_id, event_id, user_id, ts, thread_id FROM syncv3_receipts WHERE room_id=ANY($1) AND user_id = $2`

const selectReceiptsForUserPrivateSQL = `SELECT room_id, event_id, user_id, ts, thread_id FROM syncv3_receipts_private WHERE room_id=ANY($1) AND user_id = $2`

type slidingSyncReceiptStmts struct {
	selectReceiptsForEventsStmt      *sql.Stmt
	selectReceiptsForUserStmt        *sql.Stmt
	selectReceiptsForUserPrivateStmt *sql.Stmt
}

func NewSqliteSlidingSyncReceiptTable(db *sql.DB) (tables.SlidingSyncReceipt, error) {
	// we make 2 tables here to reduce the compound key size to be just room/user/thread and not
	// room/user/thread/receipt_type. This should help performance somewhat when querying. Other than
	// that, the tables are identical.
	tableNames := []string{
		"syncv3_receipts", "syncv3_receipts_private",
	}

	for _, tableName := range tableNames {
		_, err := db.Exec(fmt.Sprintf(slidingSyncReceiptSchema, tableName, tableName, tableName, tableName, tableName))
		if err != nil {
			return nil, err
		}
	}

	s := &slidingSyncReceiptStmts{}
	return s, sqlutil.StatementList{
		{&s.selectReceiptsForEventsStmt, selectReceiptsForEventsSQL},
		{&s.selectReceiptsForUserStmt, selectReceiptsForUserSQL},
		{&s.selectReceiptsForUserPrivateStmt, selectReceiptsForUserPrivateSQL},
	}.Prepare(db)
}

func (s *slidingSyncReceiptStmts) Insert(ctx context.Context, txn *sql.Tx, roomID string, ephEvent json.RawMessage) (receipts []types.SlidingSyncReceipt, err error) {
	readReceipts, privateReceipts, err := UnpackReceiptsFromEDU(roomID, ephEvent)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("UnpackReceiptsFromEDU: failed to unpack receipts")
		return nil, err
	}
	if len(readReceipts) == 0 && len(privateReceipts) == 0 {
		return nil, nil
	}
	readReceipts, err = s.bulkInsert(ctx, txn, "syncv3_receipts", readReceipts)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("bulkInsert: failed to insert receipts")
		return nil, err
	}
	privateReceipts, err = s.bulkInsert(ctx, txn, "syncv3_receipts_private", privateReceipts)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("bulkInsert: failed to insert private receipts")
		return nil, err
	}
	// no new receipts
	if len(readReceipts) == 0 && len(privateReceipts) == 0 {
		return nil, nil
	}
	// combine together new receipts
	return append(readReceipts, privateReceipts...), nil
}

// Select all non-private receipts for the event IDs given. Events must be in the room ID given.
// The parsed receipts are returned so callers can use information in the receipts in further queries
// e.g to pull out profile information for users read receipts. Call PackReceiptsIntoEDU when sending to clients.
func (s *slidingSyncReceiptStmts) SelectReceiptsForEvents(ctx context.Context, txn *sql.Tx, roomID string, eventIDs []string) (receipts []types.SlidingSyncReceipt, err error) {
	rows, err := sqlutil.TxStmtContext(ctx, txn, s.selectReceiptsForEventsStmt).QueryContext(ctx, roomID, pq.Array(eventIDs))
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("SelectReceiptsForEvents: query failed")
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "SelectReceiptsForEvents: rows.Close() failed")
	receipts = make([]types.SlidingSyncReceipt, 0, len(eventIDs))
	var userID, eventID, threadID string
	var ts int64
	for rows.Next() {
		if err = rows.Scan(&roomID, &eventID, &userID, &ts, &threadID); err != nil {
			util.GetLogger(ctx).WithError(err).Error("SelectReceiptsForEvents: scan failed")
			return nil, err
		}
		receipts = append(receipts, types.SlidingSyncReceipt{
			UserID:   userID,
			RoomID:   roomID,
			EventID:  eventID,
			TS:       ts,
			ThreadID: threadID,
		})
	}
	return
}

// Select all (including private) receipts for this user in these rooms.
func (s *slidingSyncReceiptStmts) SelectReceiptsForUser(ctx context.Context, txn *sql.Tx, roomIDs []string, userID string) (receiptsByRoom map[string][]types.SlidingSyncReceipt, err error) {
	var receipts []types.SlidingSyncReceipt
	rows, err := sqlutil.TxStmtContext(ctx, txn, s.selectReceiptsForUserStmt).QueryContext(ctx, pq.StringArray(roomIDs), userID)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("SelectReceiptsForUser: query failed")
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "SelectReceiptsForUser: rows.Close() failed")
	var roomID, eventID, threadID string
	var ts int64
	for rows.Next() {
		if err = rows.Scan(&roomID, &eventID, &userID, &ts, &threadID); err != nil {
			util.GetLogger(ctx).WithError(err).Error("SelectReceiptsForUser: scan failed")
			return nil, err
		}
		receipts = append(receipts, types.SlidingSyncReceipt{
			UserID:   userID,
			RoomID:   roomID,
			EventID:  eventID,
			TS:       ts,
			ThreadID: threadID,
		})
	}

	privRows, err := sqlutil.TxStmtContext(ctx, txn, s.selectReceiptsForUserPrivateStmt).QueryContext(ctx, pq.StringArray(roomIDs), userID)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("SelectReceiptsForUser: query failed")
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, privRows, "SelectReceiptsForUser: rows.Close() failed")

	for privRows.Next() {
		if err = privRows.Scan(&roomID, &eventID, &userID, &ts, &threadID); err != nil {
			util.GetLogger(ctx).WithError(err).Error("SelectReceiptsForUser: scan failed")
			return nil, err
		}
		receipts = append(receipts, types.SlidingSyncReceipt{
			UserID:    userID,
			RoomID:    roomID,
			EventID:   eventID,
			TS:        ts,
			ThreadID:  threadID,
			IsPrivate: true,
		})
	}
	receiptsByRoom = make(map[string][]types.SlidingSyncReceipt, len(roomIDs))
	for i := range receipts {
		receiptsByRoom[receipts[i].RoomID] = append(receiptsByRoom[receipts[i].RoomID], receipts[i])
	}
	return receiptsByRoom, nil
}

func (s *slidingSyncReceiptStmts) bulkInsert(ctx context.Context, txn *sql.Tx, tableName string, receipts []types.SlidingSyncReceipt) (newReceipts []types.SlidingSyncReceipt, err error) {
	if len(receipts) == 0 {
		return nil, nil
	}
	var query strings.Builder
	query.WriteString("INSERT INTO ")
	query.WriteString(tableName)
	query.WriteString(" (room_id, event_id, user_id, ts, thread_id) VALUES ")
	valueArgs := make([]any, 0, len(receipts)*5)
	for i := range receipts {
		query.WriteString("(")
		query.WriteString(strings.Join(
			[]string{
				strings.Join([]string{"$", strconv.Itoa(i*5 + 1)}, ""), // room_id
				strings.Join([]string{"$", strconv.Itoa(i*5 + 2)}, ""), // event_id
				strings.Join([]string{"$", strconv.Itoa(i*5 + 3)}, ""), // user_id
				strings.Join([]string{"$", strconv.Itoa(i*5 + 4)}, ""), // ts
				strings.Join([]string{"$", strconv.Itoa(i*5 + 5)}, ""), // thread_id
			}, ", "))
		if i < len(receipts)-1 {
			query.WriteString("), ")
		} else {
			query.WriteString(") ")
		}
		valueArgs = append(
			valueArgs,
			receipts[i].RoomID,
			receipts[i].EventID,
			receipts[i].UserID,
			receipts[i].TS,
			receipts[i].ThreadID,
		)
	}
	query.WriteString("ON CONFLICT (room_id, user_id, thread_id) DO UPDATE SET event_id=excluded.event_id, ts=excluded.ts WHERE old.event_id <> excluded.event_id RETURNING room_id, user_id, thread_id, event_id, ts")
	rows, err := txn.QueryContext(ctx, query.String(), valueArgs...)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("bulkInsert: failed to insert receipts")
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "bulkInsert: rows.Close() failed")
	newReceipts = make([]types.SlidingSyncReceipt, 0, len(receipts))
	var roomID, userID, eventID, threadID string
	var ts int64
	for rows.Next() {
		if err = rows.Scan(&roomID, &userID, &threadID, &eventID, &ts); err != nil {
			util.GetLogger(ctx).WithError(err).Error("bulkInsert: scan failed")
			return nil, err
		}
		newReceipts = append(newReceipts, types.SlidingSyncReceipt{
			RoomID:   roomID,
			UserID:   userID,
			EventID:  eventID,
			TS:       ts,
			ThreadID: threadID,
		})
	}
	return
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
