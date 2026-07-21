// Command createadmin inserts a single admin row into the admins table. Run
// once, manually, on the server — there is no public registration
// endpoint. Requires the same DATABASE_URL as the api service, and expects
// migrations to have already been applied (run the api service at least
// once first).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"vpn-api/internal/password"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	username := flag.String("u", "", "admin username (required)")
	pw := flag.String("p", "", "admin password (required)")
	flag.Parse()

	if *username == "" || *pw == "" {
		return errors.New("both -u and -p are required")
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("DATABASE_URL is required")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()

	hash, err := password.Hash(*pw)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	_, err = pool.Exec(ctx, `INSERT INTO admins (username, password_hash) VALUES ($1, $2)`, *username, hash)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("user %q already exists", *username)
		}
		return fmt.Errorf("insert admin: %w", err)
	}

	fmt.Printf("created admin user %q\n", *username)
	return nil
}
