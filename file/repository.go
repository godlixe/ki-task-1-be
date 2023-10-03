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
			filename,
			filepath,
			metadata
		)
	VALUES (
		$1,
		$2,
		$3
	)
	`
	_, err = fr.db.GetConn().Exec(
		ctx,
		stmt,
		file.Filename,
		file.Filepath,
		file.Metadata,
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
			filename,
			filepath,
			metadata 
	 FROM files 
	 WHERE id = $1
	 `

	err = fr.db.GetConn().QueryRow(ctx, stmt, id).Scan(
		&file.ID,
		&file.Filename,
		&file.Filepath,
		&file.Metadata,
	)
	if err != nil {
		return File{}, err
	}

	return file, nil

}
