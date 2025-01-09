// Copyright 2024 New Vector Ltd.
// Copyright 2021 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/element-hq/dendrite/internal"
	"github.com/element-hq/dendrite/internal/sqlutil"
	"github.com/element-hq/dendrite/userapi/storage/tables"
	"github.com/element-hq/dendrite/userapi/types"
	"github.com/matrix-org/gomatrixserverlib/fclient"
	"github.com/matrix-org/gomatrixserverlib/spec"
)

var crossSigningKeysSchema = `
CREATE TABLE IF NOT EXISTS keyserver_cross_signing_keys (
    user_id TEXT NOT NULL,
	key_type SMALLINT NOT NULL,
	key_data TEXT NOT NULL,
    updatable_without_uia_before_ms BIGINT DEFAULT NULL,
	PRIMARY KEY (user_id, key_type)
);
`

const selectCrossSigningKeysForUserSQL = "" +
	"SELECT key_type, key_data, updatable_without_uia_before_ms FROM keyserver_cross_signing_keys" +
	" WHERE user_id = $1"

const selectCrossSigningKeysForUserAndKeyTypeSQL = "" +
	"SELECT key_type, key_data, updatable_without_uia_before_ms FROM keyserver_cross_signing_keys" +
	" WHERE user_id = $1 AND key_type = $2"

const upsertCrossSigningKeysForUserSQL = "" +
	"INSERT INTO keyserver_cross_signing_keys (user_id, key_type, key_data, updatable_without_uia_before_ms)" +
	" VALUES($1, $2, $3, $4)" +
	" ON CONFLICT (user_id, key_type) DO UPDATE SET key_data = $3"

const updateMasterCrossSigningKeyAllowReplacementWithoutUiaSQL = "" +
	"UPDATE keyserver_cross_signing_keys" +
	" SET updatable_without_uia_before_ms = $1" +
	" WHERE user_id = $2 AND key_type = $3"

type crossSigningKeysStatements struct {
	db                                                        *sql.DB
	selectCrossSigningKeysForUserStmt                         *sql.Stmt
	selectCrossSigningKeysForUserAndKeyTypeStmt               *sql.Stmt
	upsertCrossSigningKeysForUserStmt                         *sql.Stmt
	updateMasterCrossSigningKeyAllowReplacementWithoutUiaStmt *sql.Stmt
}

func NewPostgresCrossSigningKeysTable(db *sql.DB) (tables.CrossSigningKeys, error) {
	s := &crossSigningKeysStatements{
		db: db,
	}
	_, err := db.Exec(crossSigningKeysSchema)
	if err != nil {
		return nil, err
	}
	return s, sqlutil.StatementList{
		{&s.selectCrossSigningKeysForUserStmt, selectCrossSigningKeysForUserSQL},
		{&s.selectCrossSigningKeysForUserAndKeyTypeStmt, selectCrossSigningKeysForUserAndKeyTypeSQL},
		{&s.upsertCrossSigningKeysForUserStmt, upsertCrossSigningKeysForUserSQL},
		{&s.updateMasterCrossSigningKeyAllowReplacementWithoutUiaStmt, updateMasterCrossSigningKeyAllowReplacementWithoutUiaSQL},
	}.Prepare(db)
}

func (s *crossSigningKeysStatements) SelectCrossSigningKeysForUser(
	ctx context.Context, txn *sql.Tx, userID string,
) (r types.CrossSigningKeyMap, err error) {
	rows, err := sqlutil.TxStmt(txn, s.selectCrossSigningKeysForUserStmt).QueryContext(ctx, userID)
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "selectCrossSigningKeysForUserStmt: rows.close() failed")
	r = types.CrossSigningKeyMap{}
	for rows.Next() {
		var keyTypeInt int16
		var keyData spec.Base64Bytes
		var updatableWithoutUIABeforeMs *int64
		if err = rows.Scan(&keyTypeInt, &keyData, &updatableWithoutUIABeforeMs); err != nil {
			return nil, err
		}
		keyType, ok := types.KeyTypeIntToPurpose[keyTypeInt]
		if !ok {
			return nil, fmt.Errorf("unknown key purpose int %d", keyTypeInt)
		}
		r[keyType] = types.CrossSigningKey{
			UpdatableWithoutUIABeforeMs: updatableWithoutUIABeforeMs,
			KeyData:                     keyData,
		}
	}
	err = rows.Err()
	return
}

func (s *crossSigningKeysStatements) SelectCrossSigningKeysForUserAndKeyType(
	ctx context.Context, txn *sql.Tx, userID string, keyType fclient.CrossSigningKeyPurpose,
) (r types.CrossSigningKeyMap, err error) {
	keyTypeInt, ok := types.KeyTypePurposeToInt[keyType]
	if !ok {
		return nil, fmt.Errorf("unknown key purpose %q", keyType)
	}
	rows, err := sqlutil.TxStmt(txn, s.selectCrossSigningKeysForUserAndKeyTypeStmt).QueryContext(ctx, userID, keyTypeInt)
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "SelectCrossSigningKeysForUserAndKeyType: rows.close() failed")
	r = types.CrossSigningKeyMap{}
	for rows.Next() {
		var keyTypeInt int16
		var keyData spec.Base64Bytes
		var updatableWithoutUIABeforeMs *int64
		if err = rows.Scan(&keyTypeInt, &keyData, &updatableWithoutUIABeforeMs); err != nil {
			return nil, err
		}
		keyType, ok := types.KeyTypeIntToPurpose[keyTypeInt]
		if !ok {
			return nil, fmt.Errorf("unknown key purpose int %d", keyTypeInt)
		}
		r[keyType] = types.CrossSigningKey{
			UpdatableWithoutUIABeforeMs: updatableWithoutUIABeforeMs,
			KeyData:                     keyData,
		}
	}
	err = rows.Err()
	return
}

func (s *crossSigningKeysStatements) UpsertCrossSigningKeysForUser(
	ctx context.Context, txn *sql.Tx, userID string, keyType fclient.CrossSigningKeyPurpose, keyData spec.Base64Bytes, updatableWithoutUIABeforeMs *int64,
) error {
	keyTypeInt, ok := types.KeyTypePurposeToInt[keyType]
	if !ok {
		return fmt.Errorf("unknown key purpose %q", keyType)
	}
	if _, err := sqlutil.TxStmt(txn, s.upsertCrossSigningKeysForUserStmt).ExecContext(ctx, userID, keyTypeInt, keyData, updatableWithoutUIABeforeMs); err != nil {
		return fmt.Errorf("s.upsertCrossSigningKeysForUserStmt: %w", err)
	}
	return nil
}

func (s *crossSigningKeysStatements) UpdateMasterCrossSigningKeyAllowReplacementWithoutUIA(ctx context.Context, txn *sql.Tx, userID string, duration time.Duration) (int64, error) {
	keyTypeInt := types.KeyTypePurposeToInt[fclient.CrossSigningKeyPurposeMaster]
	ts := time.Now().Add(duration).UnixMilli()
	result, err := sqlutil.TxStmt(txn, s.updateMasterCrossSigningKeyAllowReplacementWithoutUiaStmt).ExecContext(ctx, ts, userID, keyTypeInt)
	if err != nil {
		return -1, err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return -1, sql.ErrNoRows
	}
	return ts, nil
}
