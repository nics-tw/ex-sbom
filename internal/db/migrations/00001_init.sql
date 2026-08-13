-- +goose Up
CREATE SEQUENCE IF NOT EXISTS projects_id_seq START 1;
CREATE SEQUENCE IF NOT EXISTS sbom_records_id_seq START 1;

CREATE TABLE IF NOT EXISTS projects (
    id           INTEGER DEFAULT nextval('projects_id_seq') PRIMARY KEY,
    project_name VARCHAR NOT NULL,
    uuid         VARCHAR,
    created_at   TIMESTAMP NOT NULL DEFAULT current_timestamp,
    updated_at   TIMESTAMP,
    UNIQUE (uuid)
);

CREATE TABLE IF NOT EXISTS sbom_records (
    id             INTEGER DEFAULT nextval('sbom_records_id_seq') PRIMARY KEY,
    project_id     INTEGER NOT NULL REFERENCES projects(id),
    version        VARCHAR NOT NULL,
    bom_result_json JSON,
    bom_result_sha256 VARCHAR,
    created_at      TIMESTAMP NOT NULL DEFAULT current_timestamp,
    updated_at      TIMESTAMP,
    bom_timestamp   TIMESTAMP,
    UNIQUE (project_id, version)
);

INSERT INTO projects (project_name, uuid)
SELECT 'default', CAST(uuid() AS VARCHAR)
WHERE NOT EXISTS (SELECT 1 FROM projects WHERE project_name = 'default');

-- +goose Down
DROP TABLE IF EXISTS sbom_records;
DROP TABLE IF EXISTS projects;
DROP SEQUENCE IF EXISTS sbom_records_id_seq;
DROP SEQUENCE IF EXISTS projects_id_seq;
