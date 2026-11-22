-- +goose Up
ALTER TABLE projects ADD COLUMN deleted_at TIMESTAMP;
