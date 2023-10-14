package user

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DB interface {
	GetConn() *pgxpool.Pool
}

type userRepository struct {
	db DB
}

func NewUserRepository(db DB) *userRepository {
	return &userRepository{
		db: db,
	}
}

func (fr *userRepository) GetByUsername(ctx context.Context, username string) (*User, error) {
	var user User

	stmt := `
	SELECT
		id,
		username,
		password,
		name,
		phone_number,
		gender,
		religion,
		nationality,
		address,
		birth_info,
		key_reference
	FROM users
	WHERE username = $1
	`

	err := fr.db.GetConn().QueryRow(ctx, stmt, username).Scan(
		&user.ID,
		&user.Username,
		&user.Password,
		&user.Name,
		&user.PhoneNumber,
		&user.Gender,
		&user.Religion,
		&user.Nationality,
		&user.Address,
		&user.BirthInfo,
		&user.KeyReference,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (fr *userRepository) Create(ctx context.Context, user User) error {
	stmt := `
	INSERT INTO
		users (
			username,
			password,
			name,
			phone_number,
			gender,
			religion,
			nationality,
			address,
			birth_info,
			key_reference
		)
	VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
	)
	`
	_, err := fr.db.GetConn().Exec(
		ctx,
		stmt,
		user.Username,
		user.Password,
		user.Name,
		user.PhoneNumber,
		user.Gender,
		user.Religion,
		user.Nationality,
		user.Address,
		user.BirthInfo,
		user.KeyReference,
	)
	if err != nil {
		return err
	}

	return nil
}
