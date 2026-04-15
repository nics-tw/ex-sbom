package domain

import (
	"encoding/json"
	"time"
)

// ProjectID is the unique identifier for a project.
type ProjectID = int64

// SBOMID is the unique identifier for an SBOM record.
type SBOMID = int64

// ProjectName is the name of a project.
type ProjectName = string

// UUID is a universally unique identifier string.
type UUID = string

// Version is the user-supplied version label for an SBOM snapshot.
type Version = string

// BomResultJSON is the JSON-serialised SBOM result stored in the database.
type BomResultJSON = string

// SHA256 is the SHA-256 checksum of an SBOM file.
type SHA256 = string

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
