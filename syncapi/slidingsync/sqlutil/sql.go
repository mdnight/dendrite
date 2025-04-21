package sqlutil

import (
	"context"
	"database/sql"
	"fmt"
	"runtime/debug"

	"github.com/element-hq/dendrite/syncapi/slidingsync/internal"
	"github.com/matrix-org/util"
)

var logger = util.GetLogger(context.Background())

// WithTransaction runs a block of code passing in an SQL transaction
// If the code returns an error or panics then the transactions is rolled back
// Otherwise the transaction is committed.
func WithTransaction(db *sql.DB, fn func(txn *sql.Tx) error) (err error) {
	txn, err := db.Begin()
	if err != nil {
		return fmt.Errorf("WithTransaction.Begin: %w", err)
	}

	defer func() {
		panicErr := recover()
		if err == nil && panicErr != nil {
			// TODO: thread a context through to here?
			ctx := context.Background()
			logger.WithError(err).Error(string(debug.Stack()))
			internal.GetSentryHubFromContextOrDefault(ctx).RecoverWithContext(ctx, panicErr)
			err = fmt.Errorf("panic: %v", panicErr)
		}
		var txnErr error
		if err != nil {
			txnErr = txn.Rollback()
		} else {
			txnErr = txn.Commit()
		}
		if txnErr != nil && err == nil {
			err = fmt.Errorf("WithTransaction failed to commit/rollback: %w", txnErr)
		}
	}()

	err = fn(txn)
	return
}
