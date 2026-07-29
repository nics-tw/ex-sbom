package db

import (
	"context"
	"database/sql"
	"embed"
	"io/fs"
	"log/slog"

	gorm_duckdb "github.com/alifiroozi80/duckdb"
	_ "github.com/marcboeker/go-duckdb"
	"github.com/pressly/goose/v3"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// migrationsFS holds the goose SQL migrations, embedded so the binary is
// self-contained and migrations run automatically at startup.
//
// The migrations directory must live alongside this file (internal/db/migrations)
// because //go:embed cannot reference parent directories (no "../" is allowed).
// Moving it to the repository root would break this embed; if that layout is ever
// desired, the embed declaration must move to a Go file in that same root directory.
//
//go:embed migrations/*.sql
var migrationsFS embed.FS

var (
	DB     *sql.DB
	GormDB *gorm.DB
)

func Init(path string) error {
	db, err := sql.Open("duckdb", path)
	if err != nil {
		return err
	}

	if err := db.Ping(); err != nil {
		return err
	}

	DB = db
	if err := migrate(db); err != nil {
		return err
	}

	gdb, err := gorm.Open(gorm_duckdb.New(gorm_duckdb.Config{Conn: db}), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return err
	}

	GormDB = gdb

	slog.Info("DuckDB initialized", "path", path)
	return nil
}

// migrate applies all pending goose migrations from the embedded migrations
// directory. goose has no built-in DuckDB dialect, so a custom store
// (duckDBStore) tracks applied versions in a DuckDB-compatible version table.
func migrate(db *sql.DB) error {
	subFS, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}

	provider, err := goose.NewProvider(
		goose.DialectCustom, db, subFS,
		goose.WithStore(newDuckDBStore("goose_db_version")),
	)
	if err != nil {
		return err
	}

	if _, err := provider.Up(context.Background()); err != nil {
		return err
	}
	return nil
}

func Close() {
	if DB != nil {
		if err := DB.Close(); err != nil {
			slog.Error("Failed to close DB", "error", err)
		}
	}
}
