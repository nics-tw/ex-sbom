package domain

import (
	"encoding/json"
	"time"
)

type (
	ProjectID     = int64  // unique identifier for a project
	SBOMID        = int64  // unique identifier for an SBOM record
	ProjectName   = string // name of a project
	UUID          = string // universally unique identifier string
	Version       = string // user-supplied version label for an SBOM snapshot
	BomResultJSON = string // JSON-serialised SBOM result stored in the database
	SHA256        = string // SHA-256 checksum of an SBOM file
)

// ProjectInfo holds a project's id, uuid and name.
type ProjectInfo struct {
	ID   ProjectID
	UUID UUID
	Name ProjectName
}

// SBOMEntry holds raw SBOM data as read from the database.
type SBOMEntry struct {
	Version   Version
	BomResult json.RawMessage
	SHA256    string
}

// VersionInfo holds summary metadata for a stored SBOM version.
type VersionInfo struct {
	Version   Version   `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}
