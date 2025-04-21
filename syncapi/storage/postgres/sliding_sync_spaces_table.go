package postgres

import (
	"context"
	"database/sql"
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
	"github.com/tidwall/gjson"
)

const (
	RelationMSpaceParent = 1
	RelationMSpaceChild  = 2
)

const slidingSyncSpacesSchema = `
	CREATE TABLE IF NOT EXISTS syncv3_spaces (
		parent TEXT NOT NULL,
		child TEXT NOT NULL,
		relation SMALLINT NOT NULL,
		suggested BOOL NOT NULL,
		ordering TEXT NOT NULL, -- "" for unset
		UNIQUE(parent, child, relation)
	);
`

const upsertSpaceSQL = `
	INSERT INTO syncv3_spaces (parent, child, relation, ordering, suggested) 
	VALUES ($1, $2, $3, $4, $5) 
	ON CONFLICT (parent, child, relation) DO 
	UPDATE SET ordering = EXCLUDED.ordering, suggested = EXCLUDED.suggested
`

const deleteSpaceSQL = `DELETE FROM syncv3_spaces WHERE parent=$1 AND child=$2 AND relation=$3`

const selectChildrenSQL = `SELECT parent, child, relation, ordering, suggested FROM syncv3_spaces WHERE parent = ANY($1)`

type slidingSyncSpacesStmts struct {
	upsertSpaceStmt    *sql.Stmt
	deleteSpaceStmt    *sql.Stmt
	selectChildrenStmt *sql.Stmt
}

func NewPostgresSlidingSyncSpacesTable(db *sql.DB) (tables.SlidingSyncSpaces, error) {
	s := &slidingSyncSpacesStmts{}
	_, err := db.Exec(slidingSyncSpacesSchema)
	if err != nil {
		return nil, err
	}
	return s, sqlutil.StatementList{
		{&s.upsertSpaceStmt, upsertSpaceSQL},
		{&s.deleteSpaceStmt, deleteSpaceSQL},
		{&s.selectChildrenStmt, selectChildrenSQL},
	}.Prepare(db)
}

func (s *slidingSyncSpacesStmts) BulkInsert(ctx context.Context, txn *sql.Tx, relations []types.SlidingSyncSpaceRelation) error {
	if len(relations) == 0 {
		return nil
	}
	var query strings.Builder
	query.WriteString("	INSERT INTO syncv3_spaces (parent, child, relation, ordering, suggested) VALUES ")
	valueArgs := make([]any, 0, len(relations)*5)
	for i := range relations {
		query.WriteString(strings.Join(
			[]string{
				strings.Join([]string{"$", strconv.Itoa(i*5 + 1)}, ""), // parent
				strings.Join([]string{"$", strconv.Itoa(i*5 + 2)}, ""), // child
				strings.Join([]string{"$", strconv.Itoa(i*5 + 3)}, ""), // relation
				strings.Join([]string{"$", strconv.Itoa(i*5 + 4)}, ""), // ordering
				strings.Join([]string{"$", strconv.Itoa(i*5 + 5)}, ""), // suggested
			}, ", "))
		if i < len(relations)-1 {
			query.WriteString(", ")
		}
		valueArgs = append(
			valueArgs,
			relations[i].Parent,
			relations[i].Child,
			relations[i].Relation,
			relations[i].Ordering,
			relations[i].IsSuggested,
		)
	}
	query.WriteString(" ON CONFLICT (parent, child, relation) DO UPDATE SET ordering = EXCLUDED.ordering, suggested = EXCLUDED.suggested")
	_, err := txn.ExecContext(ctx, query.String(), valueArgs...)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("slidingSyncSpacesStmts.BulkInsert: failed to insert space relation")
		return err
	}
	return nil
}

func (s *slidingSyncSpacesStmts) BulkDelete(ctx context.Context, txn *sql.Tx, relations []types.SlidingSyncSpaceRelation) error {
	stmt := sqlutil.TxStmtContext(ctx, txn, s.deleteSpaceStmt)
	for i := range relations {
		_, err := stmt.ExecContext(ctx, relations[i].Parent, relations[i].Child, relations[i].Relation)
		if err != nil {
			util.GetLogger(ctx).WithError(err).Error("slidingSyncSpacesStmts.BulkDelete: failed to delete space relation")
			return err
		}
	}
	return nil
}

func (s *slidingSyncSpacesStmts) SelectChildren(ctx context.Context, txn *sql.Tx, spaces []string) (map[string][]types.SlidingSyncSpaceRelation, error) {
	result := make(map[string][]types.SlidingSyncSpaceRelation)
	rows, err := sqlutil.TxStmtContext(ctx, txn, s.selectChildrenStmt).QueryContext(ctx, pq.StringArray(spaces))
	if err != nil {
		defer internal.CloseAndLogIfError(ctx, rows, "slidingSyncSpacesStmts.SelectChildren: rows.close() failed")
		for rows.Next() {
			var parent, child, ordering string
			var relation int
			var suggested bool
			if err = rows.Scan(&parent, &child, &relation, &ordering, &suggested); err != nil {
				util.GetLogger(ctx).WithError(err).Error("slidingSyncSpacesStmts.SelectChildren: failed to scan row")
				return nil, err
			}
			result[parent] = append(
				result[parent],
				types.SlidingSyncSpaceRelation{
					Parent:      parent,
					Child:       child,
					Relation:    relation,
					IsSuggested: suggested,
					Ordering:    ordering,
				},
			)
		}
	}
	return result, nil
}

func (s *slidingSyncSpacesStmts) HandleSpaceUpdates(ctx context.Context, txn *sql.Tx, events []types.SlidingSyncEvent) error {
	// pull out relations, and bucket them so the last event wins to ensure we always use the latest
	// values in case someone repeatedly adds/removes the same space
	relations := make(map[string]struct {
		relation  *types.SlidingSyncSpaceRelation
		isDeleted bool
	})
	for _, ev := range events {
		r, isDeleted := NewSpaceRelationFromEvent(ev)
		if r != nil {
			relations[r.Key()] = struct {
				relation  *types.SlidingSyncSpaceRelation
				isDeleted bool
			}{
				relation:  r,
				isDeleted: isDeleted,
			}
		}
	}

	// now bucket by add/remove for bulk operations
	var added, removed []types.SlidingSyncSpaceRelation
	for _, r := range relations {
		if r.isDeleted {
			removed = append(removed, *r.relation)
		} else {
			added = append(added, *r.relation)
		}
	}
	// update the database
	if err := s.BulkInsert(ctx, txn, added); err != nil {
		return fmt.Errorf("failed to BulkInsert: %s", err)
	}
	if err := s.BulkDelete(ctx, txn, removed); err != nil {
		return fmt.Errorf("failed to BulkDelete: %s", err)
	}

	return nil
}

// Returns a space relation from a compatible event, else nil.
func NewSpaceRelationFromEvent(ev types.SlidingSyncEvent) (sr *types.SlidingSyncSpaceRelation, isDeleted bool) {
	event := gjson.ParseBytes(ev.JSON)
	if !event.Get("state_key").Exists() {
		return nil, false
	}
	switch ev.Type {
	case spec.MSpaceChild:
		return &types.SlidingSyncSpaceRelation{
			Parent:      ev.RoomID,
			Child:       ev.StateKey,
			Relation:    RelationMSpaceChild,
			Ordering:    event.Get("ordering").Str,
			IsSuggested: event.Get("suggested").Bool(),
		}, !event.Get("via").IsArray()
	case spec.MSpaceParent:
		return &types.SlidingSyncSpaceRelation{
			Parent:   ev.StateKey,
			Child:    ev.RoomID,
			Relation: RelationMSpaceParent,
			// parent events have a Canonical field but we don't care?
		}, !event.Get("via").IsArray()
	default:
		return nil, false
	}
}
