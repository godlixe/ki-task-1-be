package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultConnectionAttempts = 3
	defaultConnectionTimeout  = 5 * time.Second
)

type DatabaseCredentials struct {
	Host     string
	User     string
	Password string
	Port     string
	DBName   string
}

type postgresClient struct {
	connAttempts int
	connTimeout  time.Duration

	Conn *pgxpool.Pool
}

func NewPostgresClient(
	creds DatabaseCredentials,
) (*postgresClient, error) {
	pg := &postgresClient{
		connAttempts: defaultConnectionAttempts,
		connTimeout:  defaultConnectionTimeout,
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		pg.connTimeout)

	defer cancel()

	var dbpool *pgxpool.Pool
	var err error
	for pg.connAttempts > 0 {
		dbpool, err = pgxpool.New(ctx, fmt.Sprintf(
			"postgres://%v:%v@%v:%v/%v",
			creds.User,
			creds.Password,
			creds.Host,
			creds.Port,
			creds.DBName,
		))
		if err == nil {
			pg.Conn = dbpool
			return pg, nil
		}

		fmt.Printf("Connection attempt %d failed: %v\n", pg.connAttempts, err)

		time.Sleep(pg.connTimeout)
		pg.connAttempts--
	}

	return nil, err
}

func (p *postgresClient) GetConn() *pgxpool.Pool {
	return p.Conn
}
