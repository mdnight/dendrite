package postgres

import (
	"context"
	"database/sql"

	"github.com/element-hq/dendrite/internal/sqlutil"
	"github.com/element-hq/dendrite/syncapi/storage/tables"
	"github.com/lib/pq"
)

const slidingSyncTypingSchema = `
	CREATE SEQUENCE IF NOT EXISTS syncv3_typing_seq;
	CREATE TABLE IF NOT EXISTS syncv3_typing (
		stream_id BIGINT NOT NULL DEFAULT nextval('syncv3_typing_seq'),
		room_id TEXT NOT NULL PRIMARY KEY,
		user_ids TEXT[] NOT NULL
	);
`

const selectHighesIDSQL = `SELECT MAX(stream_id) FROM syncv3_typing;`

const insertTypingSQL = `INSERT INTO syncv3_typing(room_id, user_ids) VALUES($1, $2)
		ON CONFLICT (room_id) DO UPDATE SET user_ids = $2, stream_id = nextval('syncv3_typing_seq') RETURNING stream_id;`

const selectTypingSQL = `SELECT stream_id, user_ids FROM syncv3_typing WHERE room_id=$1 AND stream_id > $2 AND stream_id <= $3`

type slidingSyncTypingStatements struct {
	insertTypingStmt    *sql.Stmt
	selectHighestIDStmt *sql.Stmt
	selectTypingStmt    *sql.Stmt
}

func NewPostgresSlidingSyncTypingTable(db *sql.DB) (tables.SlidingSyncTyping, error) {
	s := &slidingSyncTypingStatements{}
	_, err := db.Exec(slidingSyncTypingSchema)
	if err != nil {
		return nil, err
	}
	return s, sqlutil.StatementList{
		{&s.insertTypingStmt, insertTypingSQL},
		{&s.selectHighestIDStmt, selectHighesIDSQL},
		{&s.selectTypingStmt, selectTypingSQL},
	}.Prepare(db)
}

func (s *slidingSyncTypingStatements) SelectHighestID(ctx context.Context, txn *sql.Tx) (id int64, err error) {
	var result sql.NullInt64
	if err = sqlutil.TxStmtContext(ctx, txn, s.selectHighestIDStmt).QueryRowContext(ctx).Scan(&result); err != nil {
		return
	}
	if result.Valid {
		id = result.Int64
	}
	return
}

func (s *slidingSyncTypingStatements) SetTyping(ctx context.Context, txn *sql.Tx, roomID string, userIDs []string) (position int64, err error) {
	if userIDs == nil {
		userIDs = []string{}
	}
	err = sqlutil.TxStmtContext(ctx, txn, s.insertTypingStmt).QueryRowContext(ctx, roomID, pq.Array(userIDs)).Scan(&position)
	return
}

func (s *slidingSyncTypingStatements) Typing(ctx context.Context, txn *sql.Tx, roomID string, fromStreamIDExcl, toStreamIDIncl int64) (userIDs []string, latest int64, err error) {
	var userIDsArray pq.StringArray
	err = sqlutil.TxStmtContext(ctx, txn, s.selectTypingStmt).QueryRowContext(ctx, roomID, fromStreamIDExcl, toStreamIDIncl).Scan(&latest, &userIDsArray)
	if err == sql.ErrNoRows {
		err = nil
	}
	return userIDsArray, latest, err
}
