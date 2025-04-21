package sqlite3

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/element-hq/dendrite/internal"
	"github.com/element-hq/dendrite/internal/sqlutil"
	"github.com/element-hq/dendrite/syncapi/storage/tables"
	"github.com/element-hq/dendrite/syncapi/types"
	"github.com/lib/pq"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/matrix-org/util"
)

const invitesSchema = `
CREATE TABLE IF NOT EXISTS syncv3_invites (
	room_id TEXT NOT NULL,
	user_id TEXT NOT NULL,
	-- JSON array. The contents of 'rooms.invite.$room_id.invite_state.events'
	invite_state BYTEA NOT NULL,
	UNIQUE(user_id, room_id)
);
`

const insertInviteSQL = `INSERT INTO syncv3_invites(user_id, room_id, invite_state) VALUES($1,$2,$3) ON CONFLICT (user_id, room_id) DO UPDATE SET invite_state = $3;`

const removeInviteSQL = `DELETE FROM syncv3_invites WHERE user_id = $1 AND room_id = $2;`

const removeSupersededInvitesSQL = `DELETE FROM syncv3_invites WHERE user_id = ANY($1) AND room_id = $2;`

const selectInviteStateSQL = `SELECT invite_state FROM syncv3_invites WHERE user_id=$1 AND room_id=$2;`

const selectAllInvitesForUserSQL = `SELECT room_id, invite_state FROM syncv3_invites WHERE user_id = $1;`

// InvitesTable stores invites for each user.
// Originally, invites were stored with the main events in a room. We ignored stripped state and
// just kept the m.room.member invite event. This had many problems though:
//   - The room would be initialised by the invite event, causing the room to not populate with state
//     correctly when the user joined the room.
//   - The user could read room data in the room without being joined to the room e.g could pull
//     `required_state` and `timeline` as they would be authorised by the invite to see this data.
//
// Instead, we now completely split out invites from the normal event flow. This fixes the issues
// outlined above but introduce more problems:
//   - How do you sort the invite with rooms?
//   - How do you calculate the room name when you lack heroes?
//
// For now, we say that invites:
//   - are treated as a highlightable event for the purposes of sorting by highlight count.
//   - are given the timestamp of when the invite arrived.
//   - calculate the room name on a best-effort basis given the lack of heroes (same as element-web).
//
// When an invite is rejected, it appears in the `leave` section which then causes the invite to be
// removed from this table.
func NewSqliteSlidingSyncInvitesTable(db *sql.DB) (tables.SlidingSyncInvites, error) {
	s := &slidingSyncInvitesStatements{}
	_, err := db.Exec(invitesSchema)
	if err != nil {
		return nil, err
	}
	return s, sqlutil.StatementList{
		{&s.insertInviteStmt, insertInviteSQL},
		{&s.removeInviteStmt, removeInviteSQL},
		{&s.removeSupersededInvitesStmt, removeSupersededInvitesSQL},
		{&s.selectInviteStateStmt, selectInviteStateSQL},
		{&s.selectAllInvitesForUserStmt, selectAllInvitesForUserSQL},
	}.Prepare(db)
}

type slidingSyncInvitesStatements struct {
	removeInviteStmt            *sql.Stmt
	removeSupersededInvitesStmt *sql.Stmt
	insertInviteStmt            *sql.Stmt
	selectInviteStateStmt       *sql.Stmt
	selectAllInvitesForUserStmt *sql.Stmt
}

func (s *slidingSyncInvitesStatements) RemoveInvite(ctx context.Context, txn *sql.Tx, userID, roomID string) error {
	_, err := sqlutil.TxStmt(txn, s.removeInviteStmt).ExecContext(ctx, userID, roomID)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("RemoveInvite failed")
	}
	return err
}

// RemoveSupersededInvites accepts a list of events in the given room. The events should
// either
//   - contain at most one membership event per user, or else
//   - be in timeline order (most recent last)
//
// (corresponding to an Accumulate and an Initialise call, respectively).
//
// The events are scanned in order for membership changes, to determine the "final"
// memberships. Users who final membership is not "invite" have their outstanding
// invites to this room deleted.
func (s *slidingSyncInvitesStatements) RemoveSupersededInvites(ctx context.Context, txn *sql.Tx, roomID string, newEvents []types.SlidingSyncEvent) error {
	memberships := make(map[string]string)
	for _, event := range newEvents {
		if event.Type != spec.MRoomMember {
			continue
		}
		memberships[event.StateKey] = event.Membership
	}

	usersToRemove := make([]string, 0, len(memberships)/2)
	for userID, membership := range memberships {
		if membership != spec.Invite && membership != "_invite" {
			usersToRemove = append(usersToRemove, userID)
		}
	}

	if len(usersToRemove) == 0 {
		return nil
	}

	_, err := sqlutil.TxStmtContext(ctx, txn, s.removeSupersededInvitesStmt).ExecContext(ctx, pq.StringArray(usersToRemove), roomID)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("RemoveSupersededInvites failed")
	}
	return err
}

func (s *slidingSyncInvitesStatements) InsertInvite(ctx context.Context, txn *sql.Tx, userID, roomID string, inviteRoomState []json.RawMessage) error {
	blob, err := json.Marshal(inviteRoomState)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("InsertInvite failed")
		return err
	}
	_, err = sqlutil.TxStmtContext(ctx, txn, s.insertInviteStmt).ExecContext(ctx, userID, roomID, blob)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("InsertInvite failed")
	}
	return err
}

func (s *slidingSyncInvitesStatements) SelectInviteState(ctx context.Context, txn *sql.Tx, userID, roomID string) ([]json.RawMessage, error) {
	var blob json.RawMessage
	err := sqlutil.TxStmtContext(ctx, txn, s.selectInviteStateStmt).QueryRowContext(ctx, userID, roomID).Scan(&blob)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("SelectInviteState failed")
		return nil, err
	}

	var inviteState []json.RawMessage
	err = json.Unmarshal(blob, &inviteState)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("SelectInviteState failed")
		return nil, err
	}
	return inviteState, nil
}

func (s *slidingSyncInvitesStatements) SelectAllInvitesForUser(ctx context.Context, txn *sql.Tx, userID string) (map[string][]json.RawMessage, error) {
	rows, err := sqlutil.TxStmtContext(ctx, txn, s.selectAllInvitesForUserStmt).QueryContext(ctx, userID)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("SelectAllInvitesForUser failed")
		return nil, err
	}
	defer internal.CloseAndLogIfError(ctx, rows, "SelectAllInvitesForUser: rows.close() failed")

	invites := make(map[string][]json.RawMessage)
	for rows.Next() {
		var roomID string
		var blob json.RawMessage
		err = rows.Scan(&roomID, &blob)
		if err != nil {
			util.GetLogger(ctx).WithError(err).Error("SelectAllInvitesForUser failed")
			return nil, err
		}
		var inviteState []json.RawMessage
		err = json.Unmarshal(blob, &inviteState)
		if err != nil {
			util.GetLogger(ctx).WithError(err).Error("SelectAllInvitesForUser failed")
			return nil, err
		}
		invites[roomID] = inviteState
	}
	return invites, nil
}
