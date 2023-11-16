package permission

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DB interface {
	GetConn() *pgxpool.Pool
}

type permissionRepository struct {
	db DB
}

func NewPermissionRepository(db DB) *permissionRepository {
	return &permissionRepository{
		db: db,
	}
}

func (pr *permissionRepository) GetNotifications(
	ctx context.Context,
	userID uint64,
	status int,
	direction int,
) ([]Notification, error) {
	var notifications []Notification
	var err error

	stmt := `
		SELECT
				id, 
				source_user_id,
				target_user_id,
				status
		 FROM notifications 
		 WHERE 1=1
		 AND
		 `

	ctr := 1
	var args []any

	if status != 3 {
		stmt += fmt.Sprintf(" status = $%v AND ", ctr)
		args = append(args, status)
		ctr++
	}

	if direction == 0 {
		stmt += fmt.Sprintf(" source_user_id = $%v", ctr)
	} else {
		stmt += fmt.Sprintf(" target_user_id = $%v", ctr)
	}

	args = append(args, userID)

	rows, err := pr.db.GetConn().Query(ctx, stmt, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var n Notification
		err := rows.Scan(
			&n.ID,
			&n.SourceUserID,
			&n.TargetUserID,
			&n.Status,
		)
		if err != nil {
			return nil, err
		}

		notifications = append(notifications, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return notifications, nil
}
