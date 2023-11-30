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

func (pr *permissionRepository) GetProfileNotifications(
	ctx context.Context,
	userID uint64,
	status int,
	direction int,
) ([]ProfileNotification, error) {
	var notifications []ProfileNotification
	var err error

	stmt := `
		SELECT
				pn.id,
				pn.source_user_id,
				u1.username,
				pn.target_user_id,
				u2.username,
				pn.status
		FROM
			profile_notifications pn
		LEFT JOIN
		 	users u1 ON pn.source_user_id = u1.id
		LEFT JOIN
		 	users u2 ON pn.target_user_id = u2.id
		WHERE 1=1
		AND
		`

	ctr := 1
	var args []any

	if status != 3 {
		stmt += fmt.Sprintf(" pn.status = $%v AND ", ctr)
		args = append(args, status)
		ctr++
	}

	if direction == 0 {
		stmt += fmt.Sprintf(" pn.source_user_id = $%v", ctr)
	} else {
		stmt += fmt.Sprintf(" pn.target_user_id = $%v", ctr)
	}

	args = append(args, userID)

	fmt.Println(stmt)
	rows, err := pr.db.GetConn().Query(ctx, stmt, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var n ProfileNotification
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

func (pr *permissionRepository) GetProfileNotificationById(
	ctx context.Context,
	notificationID uint64,
) (*ProfileNotification, error) {
	var notification ProfileNotification

	stmt := `
		SELECT
			id,
			source_user_id,
			target_user_id,
			status
		FROM profile_notifications
		WHERE
			id = $1
	`

	err := pr.db.GetConn().QueryRow(
		ctx,
		stmt,
		notificationID,
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

func (pr *permissionRepository) GetProfileNotificationByUserId(
	ctx context.Context,
	sourceUserID uint64,
	targetUserID uint64,
) (*ProfileNotification, error) {
	var notification ProfileNotification

	stmt := `
		SELECT
			id,
			source_user_id,
			target_user_id,
			status
		FROM profile_notifications
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

func (pr *permissionRepository) CreateProfileNotification(ctx context.Context, notification ProfileNotification) error {
	stmt := `
		INSERT INTO
			profile_notifications (
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

func (pr *permissionRepository) UpdateProfileNotification(ctx context.Context, notification ProfileNotification) error {
	stmt := `
		UPDATE
			profile_notifications SET
				source_user_id = $2,
				target_user_id = $3,
				status = $4
		WHERE id = $1
	`

	_, err := pr.db.GetConn().Exec(
		ctx,
		stmt,
		notification.ID,
		notification.SourceUserID,
		notification.TargetUserID,
		notification.Status,
	)
	if err != nil {
		return err
	}

	return nil
}

func (pr *permissionRepository) GetFileNotifications(
	ctx context.Context,
	userID uint64,
	status int,
	direction int,
) ([]FileNotification, error) {
	var notifications []FileNotification
	var err error

	stmt := `
		SELECT
				fn.id, 
				fn.source_user_id,
				u1.username,
				fn.target_user_id,
				u2.username,
				fn.status,
				fn.file_id
		 FROM 
		 	file_notifications fn
		 LEFT JOIN
		 	users u1 ON fn.source_user_id = u1.id
		LEFT JOIN 
		 	users u2 ON fn.target_user_id = u2.id
		 WHERE 1=1
		 AND
		 `

	ctr := 1
	var args []any

	if status != 3 {
		stmt += fmt.Sprintf(" fn.status = $%v AND ", ctr)
		args = append(args, status)
		ctr++
	}

	if direction == 0 {
		stmt += fmt.Sprintf(" fn.source_user_id = $%v", ctr)
	} else {
		stmt += fmt.Sprintf(" fn.target_user_id = $%v", ctr)
	}

	args = append(args, userID)

	rows, err := pr.db.GetConn().Query(ctx, stmt, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var n FileNotification
		err := rows.Scan(
			&n.ID,
			&n.SourceUserID,
			&n.SourceUser.Username,
			&n.TargetUserID,
			&n.TargetUser.Username,
			&n.Status,
			&n.FileID,
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

func (pr *permissionRepository) GetFileNotificationById(ctx context.Context, notifcationID uint64) (*FileNotification, error) {
	var notification FileNotification

	stmt := `
		SELECT
			id,
			source_user_id,
			target_user_id,
			status,
			file_id
		FROM file_notifications
		WHERE
			id = $1
	`

	err := pr.db.GetConn().QueryRow(
		ctx,
		stmt,
		notifcationID,
	).Scan(
		&notification.ID,
		&notification.SourceUserID,
		&notification.TargetUserID,
		&notification.Status,
		&notification.FileID,
	)
	if err != nil {
		return nil, err
	}

	return &notification, nil
}

func (pr *permissionRepository) GetFileNotificationByUserIdAndFileId(
	ctx context.Context,
	sourceUserID uint64,
	targetUserID uint64,
	fileID int,
) (*FileNotification, error) {
	var notification FileNotification

	stmt := `
		SELECT
			id,
			source_user_id,
			target_user_id,
			status,
			file_id
		FROM file_notifications
		WHERE
			source_user_id = $1 AND
			target_user_id = $2 AND
			file_id = $3
	`

	err := pr.db.GetConn().QueryRow(
		ctx,
		stmt,
		sourceUserID,
		targetUserID,
		fileID,
	).Scan(
		&notification.ID,
		&notification.SourceUserID,
		&notification.TargetUserID,
		&notification.Status,
		&notification.FileID,
	)
	if err != nil {
		return nil, err
	}

	return &notification, nil
}

func (pr *permissionRepository) CreateFileNotification(ctx context.Context, notification FileNotification) error {
	stmt := `
		INSERT INTO
			file_notifications (
				source_user_id,
				target_user_id,
				file_id,
				status
			)
		VALUES (
			$1,
			$2,
			$3,
			$4
		)
	`

	_, err := pr.db.GetConn().Exec(
		ctx,
		stmt,
		notification.SourceUserID,
		notification.TargetUserID,
		notification.FileID,
		notification.Status,
	)
	if err != nil {
		return err
	}

	return nil
}

func (pr *permissionRepository) UpdateFileNotification(ctx context.Context, notification FileNotification) error {
	stmt := `
		UPDATE
			file_notifications SET
				source_user_id = $2,
				target_user_id = $3,
				status = $4
		WHERE id = $1
	`

	_, err := pr.db.GetConn().Exec(
		ctx,
		stmt,
		notification.ID,
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

func (pr *permissionRepository) CreatePermission(ctx context.Context, permission Permission) error {
	stmt := `
		INSERT INTO
			permissions (
				source_user_id,
				target_user_id,
				key,
				key_reference
			)
		VALUES (
			$1,
			$2,
			$3,
			$4
		)
	`

	_, err := pr.db.GetConn().Exec(
		ctx,
		stmt,
		permission.SourceUserID,
		permission.TargetUserID,
		permission.Key,
		permission.KeyReference,
	)
	if err != nil {
		return err
	}

	return nil
}
