package file

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DB interface {
	GetConn() *pgxpool.Pool
}

type fileRepository struct {
	db DB
}

func NewFileRepository(db DB) *fileRepository {
	return &fileRepository{
		db: db,
	}
}

func (fr *fileRepository) Create(ctx context.Context, file File) error {
	var err error

	stmt := `
	INSERT INTO
		files (
			user_id,
			filename,
			type,
			filepath,
			key_reference
		)
	VALUES (
		$1,
		$2,
		$3,
		$4,
		$5
	)
	`
	_, err = fr.db.GetConn().Exec(
		ctx,
		stmt,
		file.UserID,
		file.Filename,
		file.Type,
		file.Filepath,
		file.KeyReference,
	)
	if err != nil {
		return err
	}

	return nil
}

func (fr *fileRepository) Get(ctx context.Context, id uint64) (File, error) {
	var file File
	var err error

	stmt := `
	SELECT
	 		id, 
			user_id,
			filename,
			filepath,
			is_signed,
			key_reference 
	 FROM files 
	 WHERE id = $1
	 `

	err = fr.db.GetConn().QueryRow(ctx, stmt, id).Scan(
		&file.ID,
		&file.UserID,
		&file.Filename,
		&file.Filepath,
		&file.IsSigned,
		&file.KeyReference,
	)
	if err != nil {
		return File{}, err
	}

	return file, nil
}

func (fr *fileRepository) List(ctx context.Context, userID uint64, fileType string) ([]File, error) {
	var files []File
	var err error

	stmt := `
		SELECT
				id, 
				filename,
				type,
				is_signed
		 FROM files 
		 WHERE type = $1
		 AND user_id = $2
		 `

	rows, err := fr.db.GetConn().Query(ctx, stmt, fileType, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var f File
		err := rows.Scan(
			&f.ID,
			&f.Filename,
			&f.Type,
			&f.IsSigned,
		)
		if err != nil {
			return nil, err
		}

		files = append(files, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return files, nil
}

func (fr *fileRepository) UpdateSignedStatus(ctx context.Context, file File) error {
	stmt := `
	UPDATE
		files SET
			is_signed = $2
	WHERE id = $1
	`

	_, err := fr.db.GetConn().Exec(
		ctx,
		stmt,
		file.ID,
		file.IsSigned,
	)
	if err != nil {
		return err
	}

	return nil
}

func (fr *fileRepository) Delete(ctx context.Context, id uint64) error {
	var err error

	stmt := `
	DELETE  
	 FROM files 
	 WHERE id = $1
	 `

	_, err = fr.db.GetConn().Exec(ctx, stmt, id)
	if err != nil {
		return err
	}

	return nil

}
