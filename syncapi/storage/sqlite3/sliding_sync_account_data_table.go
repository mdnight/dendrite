// Copyright 2025 New Vector Ltd.
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

package sqlite3

import (
	"context"
	"database/sql"
	"strconv"
	"strings"

	"github.com/element-hq/dendrite/internal/sqlutil"
	"github.com/element-hq/dendrite/syncapi/storage/tables"
	"github.com/element-hq/dendrite/syncapi/types"
	"github.com/lib/pq"
	"github.com/matrix-org/util"
)

const AccountDataGlobalRoom = ""

const slidingSyncAccountDataSchema = `
CREATE SEQUENCE IF NOT EXISTS syncv3_account_data_seq;
CREATE TABLE IF NOT EXISTS syncv3_account_data (
	id BIGINT NOT NULL DEFAULT nextval('syncv3_account_data_seq'),
	user_id TEXT NOT NULL,
	room_id TEXT NOT NULL, -- optional if global
	type TEXT NOT NULL,
	data BYTEA NOT NULL,
	UNIQUE(user_id, room_id, type)
);
`

const insertSlidingSyncAccountDataSQL = `
INSERT INTO syncv3_account_data (user_id, room_id, type, data)
VALUES ($1, $2, $3, $4) ON CONFLICT (user_id, room_id, type)
ON CONFLICT (user_id, room_id, type)
DO UPDATE SET data = EXCLUDED.data, id = nextval('syncv3_account_data_seq')
RETURNING id
`

const selectSlidingSyncAccountDataSQL = `
SELECT id, user_id, room_id, type, data FROM syncv3_account_data
WHERE user_id = $1 AND type = ANY($2) AND room_id = $3
`

const selectSlidingSyncAccountDataWithTypeSQL = `
SELECT id, user_id, room_id, type, data FROM syncv3_account_data
WHERE user_id = $1 AND type = $2 AND room_id != ''
`

const selectManySlidingSyncAccountDataSQL = `
SELECT id, user_id, room_id, type, data FROM syncv3_account_data
WHERE user_id = $1 AND room_id = ANY($2)
`

type slidingSyncAccountDataStatements struct {
	insertStmt         *sql.Stmt
	selectStmt         *sql.Stmt
	selectWithTypeStmt *sql.Stmt
	selectManyStmt     *sql.Stmt
}

func NewSqliteSlidingSyncAccountDataTable(db *sql.DB) (tables.SlidingSyncAccountData, error) {
	s := &slidingSyncAccountDataStatements{}
	_, err := db.Exec(slidingSyncAccountDataSchema)
	if err != nil {
		return nil, err
	}
	return s, sqlutil.StatementList{
		{&s.insertStmt, insertSlidingSyncAccountDataSQL},
		{&s.selectStmt, selectSlidingSyncAccountDataSQL},
		{&s.selectWithTypeStmt, selectSlidingSyncAccountDataWithTypeSQL},
		{&s.selectManyStmt, selectManySlidingSyncAccountDataSQL},
	}.Prepare(db)
}

func (s *slidingSyncAccountDataStatements) Insert(ctx context.Context, txn *sql.Tx, accDatas []types.SlidingSyncAccountData) ([]types.SlidingSyncAccountData, error) {
	// fold duplicates into one as we A: don't care about historical data, B: cannot use EXCLUDED if the
	// accDatas list has the same unique key twice in the same transaction.
	keys := map[string]*types.SlidingSyncAccountData{}
	dedupedAccountData := make([]types.SlidingSyncAccountData, 0, len(accDatas))
	for i := range accDatas {
		key := strings.Join([]string{accDatas[i].UserID, accDatas[i].RoomID, accDatas[i].Type}, " ")
		// later data always wins as it is more recent
		keys[key] = &accDatas[i]
	}

	// now make a new account data list with keys de-duped. This will resort the events but that's
	// fine as this is an atomic operation anyway.
	for _, ad := range keys {
		dedupedAccountData = append(dedupedAccountData, *ad)
	}

	valueArgs := make([]any, 0, len(dedupedAccountData)*4)
	var query strings.Builder
	query.WriteString("INSERT INTO syncv3_account_data (user_id, room_id, type, data) VALUES ")
	for i := range dedupedAccountData {
		query.WriteString("(")
		query.WriteString(strings.Join([]string{
			strings.Join([]string{"$", strconv.Itoa(i*4 + 1)}, ""), // user_id
			strings.Join([]string{"$", strconv.Itoa(i*4 + 2)}, ""), // room_id
			strings.Join([]string{"$", strconv.Itoa(i*4 + 3)}, ""), // type
			strings.Join([]string{"$", strconv.Itoa(i*4 + 4)}, ""), // data
		}, ", "))
		query.WriteString(")")
		if i == len(dedupedAccountData)-1 {
			query.WriteString(" ")
		} else {
			query.WriteString(", ")
		}
		valueArgs = append(valueArgs,
			dedupedAccountData[i].UserID,
			dedupedAccountData[i].RoomID,
			dedupedAccountData[i].Type,
			dedupedAccountData[i].Data,
		)
	}
	query.WriteString("ON CONFLICT (user_id, room_id, type) DO UPDATE SET data = EXCLUDED.data, id = nextval('syncv3_account_data_seq')")

	if _, err := txn.ExecContext(ctx, query.String(), valueArgs...); err != nil {
		util.GetLogger(ctx).WithError(err).Error("Insert failed")
		return nil, err
	}

	return dedupedAccountData, nil
}

func (s *slidingSyncAccountDataStatements) Select(
	ctx context.Context, txn *sql.Tx, userID string, eventTypes []string, roomID string,
) (datas []types.SlidingSyncAccountData, err error) {
	rows, err := sqlutil.TxStmt(txn, s.selectStmt).QueryContext(ctx, userID, pq.StringArray(eventTypes), roomID)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("QueryContext failed")
		return
	}
	defer rows.Close()
	for rows.Next() {
		var data types.SlidingSyncAccountData
		if err = rows.Scan(&data.ID, &data.UserID, &data.RoomID, &data.Type, &data.Data); err != nil {
			util.GetLogger(ctx).WithError(err).Error("rows.Scan failed")
			return
		}
		datas = append(datas, data)
	}
	return
}

func (s *slidingSyncAccountDataStatements) SelectWithType(
	ctx context.Context, txn *sql.Tx, userID, dataType string,
) (datas []types.SlidingSyncAccountData, err error) {
	rows, err := sqlutil.TxStmt(txn, s.selectWithTypeStmt).QueryContext(ctx, userID, dataType)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("QueryContext failed")
		return
	}
	defer rows.Close()
	for rows.Next() {
		var data types.SlidingSyncAccountData
		if err = rows.Scan(&data.ID, &data.UserID, &data.RoomID, &data.Type, &data.Data); err != nil {
			util.GetLogger(ctx).WithError(err).Error("rows.Scan failed")
			return
		}
		datas = append(datas, data)
	}
	return
}

func (s *slidingSyncAccountDataStatements) SelectMany(
	ctx context.Context, txn *sql.Tx, userID string, roomIDs []string,
) (datas []types.SlidingSyncAccountData, err error) {
	rows, err := sqlutil.TxStmt(txn, s.selectManyStmt).QueryContext(ctx, userID, pq.StringArray(roomIDs))
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var data types.SlidingSyncAccountData
		if err = rows.Scan(&data.ID, &data.UserID, &data.RoomID, &data.Type, &data.Data); err != nil {
			util.GetLogger(ctx).WithError(err).Error("rows.Scan failed")
			return
		}
		datas = append(datas, data)
	}
	return
}
