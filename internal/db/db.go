package db

import (
	"database/sql"
	"log/slog"

	gorm_duckdb "github.com/alifiroozi80/duckdb"
	"github.com/google/uuid"
	_ "github.com/marcboeker/go-duckdb"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *sql.DB
var GormDB *gorm.DB

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

	gdb, err := gorm.Open(gorm_duckdb.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return err
	}

	GormDB = gdb

	slog.Info("DuckDB initialized", "path", path)
	return nil
}

// migrate creates tables and seeds default data.
// todo: should apply with db migration
func migrate(db *sql.DB) error {
	_, err := db.Exec(`CREATE SEQUENCE IF NOT EXISTS projects_id_seq START 1`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`CREATE SEQUENCE IF NOT EXISTS sbom_records_id_seq START 1`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS projects (
			id           INTEGER DEFAULT nextval('projects_id_seq') PRIMARY KEY,
			project_name VARCHAR NOT NULL,
			uuid         VARCHAR,
			created_at   TIMESTAMP NOT NULL DEFAULT current_timestamp,
			updated_at   TIMESTAMP,
			UNIQUE (uuid)
		)
	`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS sbom_records (
			id             INTEGER DEFAULT nextval('sbom_records_id_seq') PRIMARY KEY,
			project_id     INTEGER NOT NULL REFERENCES projects(id),
			version        VARCHAR NOT NULL,
			bom_result_json JSON,
			bom_result_md5  VARCHAR,
			created_at      TIMESTAMP NOT NULL DEFAULT current_timestamp,
			updated_at      TIMESTAMP,
			bom_timestamp   TIMESTAMP,
			UNIQUE (project_id, version)
		)
	`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		INSERT INTO projects (project_name, uuid)
		SELECT 'default', ? WHERE NOT EXISTS (
			SELECT 1 FROM projects WHERE project_name = 'default'
		)
	`, uuid.New().String())
	return err
}

func Close() {
	if DB != nil {
		DB.Close()
	}
}
