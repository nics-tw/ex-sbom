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

// Md5 is the MD5 checksum of an SBOM file.
type Md5 = string

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
	Md5       string
}

// VersionInfo holds summary metadata for a stored SBOM version.
type VersionInfo struct {
	Version   Version   `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}
