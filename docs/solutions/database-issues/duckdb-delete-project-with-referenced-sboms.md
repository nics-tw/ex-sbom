---
module: "SBOM project persistence"
date: 2026-11-21
problem_type: database_issue
component: database
severity: high
symptoms:
  - "A failed project delete could leave the project visible after its SBOM rows were removed."
  - "DuckDB rejected deleting the child rows and parent row in one transaction."
root_cause: data_integrity
resolution_type: code_fix
tags: [duckdb, foreign-keys, project-deletion]
---

# Delete DuckDB projects without losing SBOM rows on failure

## Problem

PR #15 originally deleted `sbom_records` and then `projects` in separate statements. If the parent delete failed, the API returned an error after the child delete had committed.

## What Didn't Work

Using the PR's DuckDB driver, a direct SQL transaction accepted the child delete and rejected the subsequent parent delete because the foreign key still reported a reference. The same driver also rejected the `ON DELETE CASCADE` schema. Wrapping the two deletes in a GORM transaction would encounter the same database constraint.

## Solution

Update the project's `deleted_at` timestamp in one statement in `internal/repository/workspace.go`. Scope project and SBOM queries to active projects and clear in-memory SBOM state only after a successful update. The stored SBOM rows retain their foreign key and remain on disk. There is no restore action in the app.

## Prevention

Keep the read-only DuckDB delete regression in `internal/repository/sbom_integration_test.go`. It verifies that failure leaves both project and SBOM data intact. Before replacing logical deletion with hard deletion, verify the alternative against the actual DuckDB driver and test both success and rollback.
