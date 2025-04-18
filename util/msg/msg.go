package msg

const (
	RespMsg  = "msg"
	RespErr  = "error"
	RespData = "data"

	ErrInvalidSBOM = "Unknown SBOM"
	ErrSBOMNotFound = "SBOM not found"

	ErrParsingJson = "Error parsing JSON:"
	ErrParsingSPDX = "Error parsing SPDX SBOM"

	ErrMissingParam = "Missing required parameter: %s"
)
