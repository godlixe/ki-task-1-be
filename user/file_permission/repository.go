package filepermission

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DB interface {
	GetConn() *pgxpool.Pool
}

type filePermissionRepository struct {
	db DB
}

func NewPermissionRepository(db DB) *filePermissionRepository {
	return &filePermissionRepository{
		db: db,
	}
}

func (fpr *filePermissionRepository) GetByPermissionID(
	ctx context.Context,
	permissionID uint64,
) ([]FilePermission, error) {
	var filePermissions []FilePermission
	var err error

	stmt := `
		SELECT
				fp.id,
				fp.filepath,
				fp.permission_id,
				f.id,
				f.user_id,
				f.filename,
				f.type,
				f.filepath,
		 FROM 
		 	file_permissions fp
		 LEFT JOIN
		 	files f ON fp.file_id = f.id
		 WHERE permission_id = $1
		 `

	rows, err := fpr.db.GetConn().Query(ctx, stmt, permissionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var fp FilePermission
		err := rows.Scan(
			&fp.ID,
			&fp.Filepath,
			&fp.PermissionID,
			&fp.File.ID,
			&fp.File.UserID,
			&fp.File.Filename,
			&fp.File.Type,
			&fp.File.Filepath,
		)
		if err != nil {
			return nil, err
		}

		filePermissions = append(filePermissions, fp)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return filePermissions, nil
}

func (fpr *filePermissionRepository) GetByID(
	ctx context.Context,
	filePermissionID uint64,
) (FilePermission, error) {
	var fp FilePermission

	stmt := `
		SELECT
				fp.id,
				fp.filepath,
				fp.permission_id,
				f.id,
				f.user_id,
				f.filename,
				f.type,
				f.filepath,
		 FROM 
		 	file_permissions fp
		 LEFT JOIN
		 	files f ON fp.file_id = f.id
		 WHERE id = $1
		 `

	err := fpr.db.GetConn().QueryRow(
		ctx,
		stmt,
		filePermissionID,
	).Scan(
		&fp.ID,
		&fp.Filepath,
		&fp.PermissionID,
		&fp.File.ID,
		&fp.File.UserID,
		&fp.File.Filename,
		&fp.File.Type,
		&fp.File.Filepath,
	)
	if err != nil {
		return FilePermission{}, err
	}

	return fp, nil
}

func (fpr *filePermissionRepository) GetByUserFilePermission(
	ctx context.Context,
	sourceUserID uint64,
	targetUserID uint64,
	fileID uint64,
) (FilePermission, error) {
	var fp FilePermission
	var err error

	stmt := `
		SELECT
				fp.id,
				fp.filepath,
				fp.permission_id,
				f.id,
				f.user_id,
				f.filename,
				f.type,
				f.filepath,
				p.key,
				p.key_reference
		 FROM 
		 	file_permissions fp
		 LEFT JOIN
		 	files f ON fp.file_id = f.id
		 LEFT JOIN
			permissions p ON fp.permission_id= p.id  	
		 WHERE p.source_user_id = $1
		 	AND
		p.target_user_id = $2
			AND
		f.id = $3
		 `

	err = fpr.db.GetConn().QueryRow(
		ctx,
		stmt,
		sourceUserID,
		targetUserID,
		fileID,
	).Scan(
		&fp.ID,
		&fp.Filepath,
		&fp.PermissionID,
		&fp.File.ID,
		&fp.File.UserID,
		&fp.File.Filename,
		&fp.File.Type,
		&fp.File.Filepath,
		&fp.Permission.Key,
		&fp.Permission.KeyReference,
	)
	if err != nil {
		return FilePermission{}, err
	}

	return fp, nil
}

func (fpr *filePermissionRepository) ListByUserFilePermission(
	ctx context.Context,
	sourceUserID uint64,
	targetUserID uint64,
) ([]FilePermission, error) {
	var filePermissions []FilePermission
	var err error

	stmt := `
		SELECT
				fp.id,
				fp.filepath,
				fp.permission_id,
				f.id,
				f.user_id,
				f.filename,
				f.type,
				f.filepath
		 FROM 
		 	file_permissions fp
		 LEFT JOIN
		 	files f ON fp.file_id = f.id
		 LEFT JOIN
			permissions p ON fp.permission_id= p.id  	
		 WHERE p.source_user_id = $1
		 	AND
		p.target_user_id = $2
		 `

	rows, err := fpr.db.GetConn().Query(ctx, stmt, sourceUserID, targetUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var fp FilePermission
		err := rows.Scan(
			&fp.ID,
			&fp.Filepath,
			&fp.PermissionID,
			&fp.File.ID,
			&fp.File.UserID,
			&fp.File.Filename,
			&fp.File.Type,
			&fp.File.Filepath,
		)
		if err != nil {
			return nil, err
		}

		filePermissions = append(filePermissions, fp)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return filePermissions, nil
}

func (fpr *filePermissionRepository) CreateFilePermission(
	ctx context.Context,
	filePermission FilePermission,
) error {

	stmt := `
		INSERT INTO
			file_permissions (
				filepath,
				permission_id,
				file_id
			)
		VALUES (
			$1,
			$2,
			$3
		)
	`

	_, err := fpr.db.GetConn().Exec(
		ctx,
		stmt,
		filePermission.Filepath,
		filePermission.PermissionID,
		filePermission.FileID,
	)
	if err != nil {
		return err
	}

	return nil
}
