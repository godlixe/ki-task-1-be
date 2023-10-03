package guard

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DB interface {
	GetConn() *pgxpool.Pool
}

type guardRepository struct {
	db DB
}

func NewGuardRepository(db DB) *guardRepository {
	return &guardRepository{
		db: db,
	}
}

// GetKey gets a key from table in the key database
func (r *guardRepository) GetKey(ctx context.Context, table string, id uint64) (Key, error) {
	var key Key
	var err error

	stmt := fmt.Sprintf(`SELECT id, key FROM %v WHERE id = $1`, table)

	err = r.db.GetConn().QueryRow(ctx, stmt, id).Scan(
		&key.id,
		&key.PlainKey,
	)
	if err != nil {
		return Key{}, err
	}

	return key, nil

}

// GetKey gets a key from table in the key database
func (r *guardRepository) StoreKey(ctx context.Context, table string, key Key) (Key, error) {
	var err error

	stmt := fmt.Sprintf(
		`
	INSERT INTO
		%v (
			key
		)
	VALUES (
		$1
	)
	RETURNING id;
	`,
		table,
	)
	err = r.db.GetConn().QueryRow(
		ctx,
		stmt,
		key.PlainKey,
	).Scan(&key.id)
	if err != nil {
		return Key{}, err
	}

	return key, nil
}
