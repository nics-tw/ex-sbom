package domain

import "encoding/json"

// WorkspaceID is the unique identifier for a workspace.
type WorkspaceID = int64

// WorkspaceName is the name of a workspace.
type WorkspaceName = string

// Filename is the name of an SBOM file.
type Filename = string

// WorkspaceInfo holds a workspace's id, uuid and name.
type WorkspaceInfo struct {
	ID   WorkspaceID
	UUID string
	Name WorkspaceName
}

// SBOMEntry holds raw SBOM data as read from the database.
type SBOMEntry struct {
	Filename  Filename
	BomResult json.RawMessage
	Md5       string
}