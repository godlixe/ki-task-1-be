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

func (r *guardRepository) GetMultipleKeys(ctx context.Context, table string, ids []uint64) ([]Key, error) {
	var keys []Key
	var err error

	stmt := fmt.Sprintf(`SELECT id, key FROM %v WHERE id IN (`, table)

	var args []any

	ctr := 1
	for _, id := range ids {
		stmt += fmt.Sprintf("$%v, ", ctr)
		args = append(args, id)
		ctr++
	}

	stmt += "NULL)"

	rows, err := r.db.GetConn().Query(ctx, stmt, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var k Key
		err := rows.Scan(
			&k.id,
			&k.PlainKey,
		)
		if err != nil {
			return nil, err
		}

		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return keys, nil

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
