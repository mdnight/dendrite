// Copyright 2024 New Vector Ltd.
// Copyright 2019, 2020 The Matrix.org Foundation C.I.C.
// Copyright 2017, 2018 New Vector Ltd
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

package postgres

import (
	"context"
	"database/sql"

	// Import the postgres database driver.
	"github.com/element-hq/dendrite/internal/sqlutil"
	"github.com/element-hq/dendrite/setup/config"
	"github.com/element-hq/dendrite/syncapi/storage/postgres/deltas"
	"github.com/element-hq/dendrite/syncapi/storage/shared"
	_ "github.com/lib/pq"
)

// SyncServerDatasource represents a sync server datasource which manages
// both the database for PDUs and caches for EDUs.
type SyncServerDatasource struct {
	shared.Database
	db     *sql.DB
	writer sqlutil.Writer
}

// NewDatabase creates a new sync server database
func NewDatabase(ctx context.Context, cm *sqlutil.Connections, dbProperties *config.DatabaseOptions) (*SyncServerDatasource, error) {
	var d SyncServerDatasource
	var err error
	if d.db, d.writer, err = cm.Connection(dbProperties); err != nil {
		return nil, err
	}
	accountData, err := NewPostgresAccountDataTable(d.db)
	if err != nil {
		return nil, err
	}
	events, err := NewPostgresEventsTable(d.db)
	if err != nil {
		return nil, err
	}
	currState, err := NewPostgresCurrentRoomStateTable(d.db)
	if err != nil {
		return nil, err
	}
	invites, err := NewPostgresInvitesTable(d.db)
	if err != nil {
		return nil, err
	}
	peeks, err := NewPostgresPeeksTable(d.db)
	if err != nil {
		return nil, err
	}
	topology, err := NewPostgresTopologyTable(d.db)
	if err != nil {
		return nil, err
	}
	backwardExtremities, err := NewPostgresBackwardsExtremitiesTable(d.db)
	if err != nil {
		return nil, err
	}
	sendToDevice, err := NewPostgresSendToDeviceTable(d.db)
	if err != nil {
		return nil, err
	}
	filter, err := NewPostgresFilterTable(d.db)
	if err != nil {
		return nil, err
	}
	receipts, err := NewPostgresReceiptsTable(d.db)
	if err != nil {
		return nil, err
	}
	memberships, err := NewPostgresMembershipsTable(d.db)
	if err != nil {
		return nil, err
	}
	notificationData, err := NewPostgresNotificationDataTable(d.db)
	if err != nil {
		return nil, err
	}
	ignores, err := NewPostgresIgnoresTable(d.db)
	if err != nil {
		return nil, err
	}
	presence, err := NewPostgresPresenceTable(d.db)
	if err != nil {
		return nil, err
	}
	relations, err := NewPostgresRelationsTable(d.db)
	if err != nil {
		return nil, err
	}
	slidingSyncAccountData, err := NewPostgresSlidingSyncAccountDataTable(d.db)
	if err != nil {
		return nil, err
	}
	slidingSyncRooms, err := NewPostgresSlidingSyncRoomsTable(d.db)
	if err != nil {
		return nil, err
	}
	slidingSyncUnread, err := NewPostgresSlidingSyncUnreadTable(d.db)
	if err != nil {
		return nil, err
	}
	slidingSyncSnapshot, err := NewPostgresSlidingSyncSnapshotTable(d.db)
	if err != nil {
		return nil, err
	}
	slidingSyncInvites, err := NewPostgresSlidingSyncInvitesTable(d.db)
	if err != nil {
		return nil, err
	}
	slidingSyncTyping, err := NewPostgresSlidingSyncTypingTable(d.db)
	if err != nil {
		return nil, err
	}
	slidingSyncEvent, err := NewPostgresSlidingSyncEventTable(d.db)
	if err != nil {
		return nil, err
	}
	slidingSyncTxn, err := NewPostgresSlidingSyncTxnTable(d.db)
	if err != nil {
		return nil, err
	}
	slidingSyncToDevice, err := NewPostgresSlidingSyncToDeviceTable(d.db)
	if err != nil {
		return nil, err
	}
	slidingSyncSpaces, err := NewPostgresSlidingSyncSpacesTable(d.db)
	if err != nil {
		return nil, err
	}
	slidingSyncReceipt, err := NewPostgresSlidingSyncReceiptTable(d.db)
	if err != nil {
		return nil, err
	}
	slidingSyncDeviceList, err := NewPostgresSlidingSyncDeviceListTable(d.db)
	if err != nil {
		return nil, err
	}
	slidingSyncDeviceData, err := NewPostgresSlidingSyncDeviceDataTable(d.db, slidingSyncDeviceList)
	if err != nil {
		return nil, err
	}
	slidingSyncDevice, err := NewPostgresSlidingSyncDevicesTable(d.db)
	if err != nil {
		return nil, err
	}

	// apply migrations which need multiple tables
	m := sqlutil.NewMigrator(d.db)
	m.AddMigrations(
		sqlutil.Migration{
			Version: "syncapi: set history visibility for existing events",
			Up:      deltas.UpSetHistoryVisibility, // Requires current_room_state and output_room_events to be created.
		},
	)
	err = m.Up(ctx)
	if err != nil {
		return nil, err
	}

	d.Database = shared.Database{
		DB:                     d.db,
		Writer:                 d.writer,
		Invites:                invites,
		Peeks:                  peeks,
		AccountData:            accountData,
		OutputEvents:           events,
		Topology:               topology,
		CurrentRoomState:       currState,
		BackwardExtremities:    backwardExtremities,
		Filter:                 filter,
		SendToDevice:           sendToDevice,
		Receipts:               receipts,
		Memberships:            memberships,
		NotificationData:       notificationData,
		Ignores:                ignores,
		Presence:               presence,
		Relations:              relations,
		SlidingSyncAccountData: slidingSyncAccountData,
		SlidingSyncRooms:       slidingSyncRooms,
		SlidingSyncUnread:      slidingSyncUnread,
		SlidingSyncInvites:     slidingSyncInvites,
		SlidingSyncTyping:      slidingSyncTyping,
		SlidingSyncEvent:       slidingSyncEvent,
		SlidingSyncTxn:         slidingSyncTxn,
		SlidingSyncToDevice:    slidingSyncToDevice,
		SlidingSyncSpaces:      slidingSyncSpaces,
		SlidingSyncSnapthot:    slidingSyncSnapshot,
		SlidingSyncReceipt:     slidingSyncReceipt,
		SlidingSyncDeviceList:  slidingSyncDeviceList,
		SlidingSyncDeviceData:  slidingSyncDeviceData,
		SlidingSyncDevice:      slidingSyncDevice,
	}
	return &d, nil
}
