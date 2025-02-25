// Copyright 2024 New Vector Ltd.
// Copyright 2020 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//go:build !wasm && !cgo
// +build !wasm,!cgo

package sqlutil

import (
	"github.com/lib/pq"
	"modernc.org/sqlite"
	lib "modernc.org/sqlite/lib"
)

// IsUniqueConstraintViolationErr returns true if the error is an unique_violation error
func IsUniqueConstraintViolationErr(err error) bool {
	switch e := err.(type) {
	case *pq.Error:
		return e.Code == "23505"
	case *sqlite.Error:
		return e.Code() == lib.SQLITE_CONSTRAINT
	}
	return false
}
