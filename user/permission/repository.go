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
				n.id, 
				n.source_user_id,
				u1.username,
				n.target_user_id,
				u2.username,
				n.status
		 FROM 
		 	notifications n
		 LEFT JOIN
		 	users u1 ON n.source_user_id = u1.id
		LEFT JOIN 
		 	users u2 ON n.target_user_id = u2.id
		 WHERE 1=1
		 AND
		 `

	ctr := 1
	var args []any

	if status != 3 {
		stmt += fmt.Sprintf(" n.status = $%v AND ", ctr)
		args = append(args, status)
		ctr++
	}

	if direction == 0 {
		stmt += fmt.Sprintf(" n.source_user_id = $%v", ctr)
	} else {
		stmt += fmt.Sprintf(" n.target_user_id = $%v", ctr)
	}

	fmt.Println(stmt)

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
			&n.SourceUser.Username,
			&n.TargetUserID,
			&n.TargetUser.Username,
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
func (pr *permissionRepository) GetLastestNotification(
	ctx context.Context,
	sourceUserID uint64,
	targetUserID uint64,
) (*Notification, error) {
	var notification Notification

	stmt := `
		SELECT
			id,
			source_user_id,
			target_user_id,
			status
		FROM notifications
		WHERE
			source_user_id = $1 AND
			target_user_id = $2
		ORDER BY id DESC
		LIMIT 1
	`

	err := pr.db.GetConn().QueryRow(
		ctx,
		stmt,
		sourceUserID,
		targetUserID,
	).Scan(
		&notification.ID,
		&notification.SourceUserID,
		&notification.TargetUserID,
		&notification.Status,
	)
	if err != nil {
		return nil, err
	}

	return &notification, nil
}

func (pr *permissionRepository) CreateNotification(ctx context.Context, notification Notification) error {
	stmt := `
		INSERT INTO
			notifications (
				source_user_id,
				target_user_id,
				status
			)
		VALUES (
			$1,
			$2,
			$3
		)
	`

	_, err := pr.db.GetConn().Exec(
		ctx,
		stmt,
		notification.SourceUserID,
		notification.TargetUserID,
		notification.Status,
	)
	if err != nil {
		return err
	}

	return nil
}

func (pr *permissionRepository) GetPermissionByUserId(ctx context.Context, sourceUserID uint64, targetUserID uint64) (*Permission, error) {
	var permission Permission

	stmt := `
		SELECT
			id,
			source_user_id,
			target_user_id,
			key,
			key_reference
		FROM permissions
		WHERE
			source_user_id = $1 AND
			target_user_id = $2
	`

	err := pr.db.GetConn().QueryRow(
		ctx,
		stmt,
		sourceUserID,
		targetUserID,
	).Scan(
		&permission.ID,
		&permission.SourceUserID,
		&permission.TargetUserID,
		&permission.Key,
		&permission.KeyReference,
	)
	if err != nil {
		return nil, err
	}

	return &permission, nil
}

