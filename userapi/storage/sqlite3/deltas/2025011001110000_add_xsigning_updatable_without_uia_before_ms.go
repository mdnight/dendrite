package deltas

import (
	"context"
	"database/sql"
	"fmt"
)

func UpAddXSigningUpdatableWithoutUIABeforeMs(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `ALTER TABLE keyserver_cross_signing_keys ADD COLUMN updatable_without_uia_before_ms BIGINT DEFAULT NULL;`)
	if err != nil {
		return fmt.Errorf("failed to execute upgrade: %w", err)
	}
	return nil
}

func DownAddXSigningUpdatableWithoutUIABeforeMs(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `ALTER TABLE keyserver_cross_signing_keys DROP COLUMN updatable_without_uia_before_ms;`)
	if err != nil {
		return fmt.Errorf("failed to execute downgrade: %w", err)
	}
	return nil
}
