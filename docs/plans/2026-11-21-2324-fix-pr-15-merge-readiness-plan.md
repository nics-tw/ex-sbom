---
title: "PR #15 Merge Readiness - Plan"
type: fix
date: 2026-11-21
artifact_contract: ce-unified-plan/v1
---

# PR #15 Merge Readiness - Plan

## Goal Capsule

**Objective.** Reviewers can verify that project and SBOM workflows preserve data and project ownership, and can review and merge the PR once CI and repository rules are satisfied.

**Delivery.** One update to the existing PR branch. The maintainers retain approval and merge authority.

## Product Contract

### Summary

Make the existing version-control PR ready for maintainer review by fixing its cross-platform CI failure, preserving SBOM data, binding operations to the selected project, and addressing applicable GitHub security findings.

### Problem Frame

Ubuntu CI fails on the favicon response. Project deletion can remove SBOM rows before returning a failure. Delayed browser operations can update the wrong project, and the save API cannot tell whether a result came from its preview. The PR also selects dependencies covered by open GitHub alerts.

### Requirements

- R1. The existing favicon URL serves the embedded image with the correct MIME type across platforms.
- R2. Failed project deletion preserves data. A successfully deleted project and its SBOMs disappear from app and API reads. Document database retention and allow name reuse. Existing projects are available after restart.
- R3. Delayed version list, rename, delete, or save responses cannot alter the selected project’s UI. A save must carry a preview issued by the server for that project and result.
- R4. Address applicable Dependabot and Code Scanning findings. Record evidence for any unresolved upstream module. Strix is outside the merge criteria.

## Planning Contract

- KTD1. Store project deletion as one timestamp update. DuckDB rejects both a child-then-parent delete inside one transaction and foreign-key cascade in the current driver. Keep the foreign key and filter deleted projects from repository operations.
- KTD2. Sign the project ID, result checksum, and timestamp with a per-process key. Continue checking the result checksum on save. The API client repeats preview after server restart.
- KTD3. Upgrade the existing OSV Scanner dependency and affected indirect modules. Verify the resolved graph and package imports separately. Treat a GitHub alert as open until the service reports its disposition.

### Assumptions

- The app is a local single-user tool. Server startup accepts loopback IP addresses only.
- GitHub's main-branch alerts can remain open while fixes are on the PR branch. Verify each remaining affected module against the PR graph and report the exact residual alert to maintainers.

## Implementation Units

### U1. Serve favicon consistently

**Requirements.** R1. **Files.** `main.go`, `main_test.go`.
**Approach.** Serve PNG bytes and content type explicitly at the existing URL.
**Test and verify.** SSR route tests and Ubuntu CI assert the same content type.

### U2. Preserve project data and load it on restart

**Requirements.** R2. **Files.** `internal/db/migrations/`, `internal/repository/`, `internal/service/workspace/`, `main.go`, `main_startup_test.go`, both READMEs.
**Approach.** Implement KTD1 and hydrate each active project at startup.
**Test and verify.** Exercise failed deletion, name reuse, old-ID isolation, conflicting rename rollback, and two projects after reopening DuckDB.

### U3. Keep SBOM actions within their project

**Requirements.** R3. **Files.** `static/js/app.js`, `tests/js/`, `internal/handler/sbom/`, `ex-sbom.postman_collection.json`.
**Approach.** Capture project identity through asynchronous operations and verify KTD2 at save.
**Test and verify.** Switch A to B while A’s history is pending, use the same version name in both, and verify late responses cannot modify B. Exercise invalid and valid preview tokens and the frontend JSON contract.

### U4. Update the dependency graph and log handling

**Requirements.** R4. **Files.** `go.mod`, `go.sum`, `internal/service/sbom/`, `main.go`.
**Approach.** Apply KTD3, adapt to the scanner type changes, sanitize remaining raw log fields, and enforce loopback for the local server.
**Test and verify.** Build, test, vet, verify modules, compare alert ranges, and check GitHub CodeQL on the updated head.

## Verification Contract

- Run `go build ./...`, `go test -count=1 -tags "unit integration" ./...`, `go vet -tags "unit integration" ./...`, `go mod verify`, and `node --test "tests/js/*.test.mjs"`.
- Check the updated PR’s Ubuntu CI and CodeQL. Compare Dependabot advisory ranges to the selected module versions and distinguish build reachability from entries that still appear in the module graph.

## Definition of Done

- U1–U4 pass local verification and the existing PR contains the verified commits.
- GitHub CI and CodeQL complete on that head. Reviewers resolve applicable threads and complete required approval before merge.
