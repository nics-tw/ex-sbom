// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/pressly/goose/v3/database"
)

// duckDBStore is a goose database.Store implementation for DuckDB.
//
// goose has no built-in DuckDB dialect: the postgres store uses SERIAL and the
// sqlite3 store uses AUTOINCREMENT for the version-table id, neither of which
// DuckDB supports. This store mirrors the sqlite3 queries but creates the id
// column from a DuckDB sequence and uses a native BOOLEAN for is_applied.
type duckDBStore struct {
	table string
}

var _ database.Store = (*duckDBStore)(nil)

// newDuckDBStore returns a goose Store backed by the given version table name.
func newDuckDBStore(table string) *duckDBStore {
	return &duckDBStore{table: table}
}

func (s *duckDBStore) Tablename() string { return s.table }

func (s *duckDBStore) CreateVersionTable(ctx context.Context, db database.DBTxConn) error {
	if _, err := db.ExecContext(ctx, fmt.Sprintf(
		`CREATE SEQUENCE IF NOT EXISTS %s_id_seq START 1`, s.table,
	)); err != nil {
		return err
	}
	_, err := db.ExecContext(ctx, fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id         INTEGER DEFAULT nextval('%s_id_seq') PRIMARY KEY,
			version_id BIGINT NOT NULL,
			is_applied BOOLEAN NOT NULL,
			tstamp     TIMESTAMP DEFAULT current_timestamp
		)`, s.table, s.table,
	))
	return err
}

func (s *duckDBStore) Insert(ctx context.Context, db database.DBTxConn, req database.InsertRequest) error {
	_, err := db.ExecContext(ctx, fmt.Sprintf(
		`INSERT INTO %s (version_id, is_applied) VALUES (?, ?)`, s.table,
	), req.Version, true)
	return err
}

func (s *duckDBStore) Delete(ctx context.Context, db database.DBTxConn, version int64) error {
	_, err := db.ExecContext(ctx, fmt.Sprintf(
		`DELETE FROM %s WHERE version_id=?`, s.table,
	), version)
	return err
}

func (s *duckDBStore) GetMigration(ctx context.Context, db database.DBTxConn, version int64) (*database.GetMigrationResult, error) {
	var result database.GetMigrationResult
	err := db.QueryRowContext(ctx, fmt.Sprintf(
		`SELECT tstamp, is_applied FROM %s WHERE version_id=? ORDER BY tstamp DESC LIMIT 1`, s.table,
	), version).Scan(&result.Timestamp, &result.IsApplied)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, database.ErrVersionNotFound
	}
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *duckDBStore) GetLatestVersion(ctx context.Context, db database.DBTxConn) (int64, error) {
	var version sql.NullInt64
	if err := db.QueryRowContext(ctx, fmt.Sprintf(
		`SELECT MAX(version_id) FROM %s`, s.table,
	)).Scan(&version); err != nil {
		return -1, err
	}
	if !version.Valid {
		return -1, database.ErrVersionNotFound
	}
	return version.Int64, nil
}

func (s *duckDBStore) ListMigrations(ctx context.Context, db database.DBTxConn) ([]*database.ListMigrationsResult, error) {
	rows, err := db.QueryContext(ctx, fmt.Sprintf(
		`SELECT version_id, is_applied FROM %s ORDER BY id DESC`, s.table,
	))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var migrations []*database.ListMigrationsResult
	for rows.Next() {
		var m database.ListMigrationsResult
		if err := rows.Scan(&m.Version, &m.IsApplied); err != nil {
			return nil, err
		}
		migrations = append(migrations, &m)
	}
	return migrations, rows.Err()
}
