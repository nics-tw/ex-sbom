package sscan

import (
	"fmt"
	"os"
)

var (
	filenames = []string{}
)

func GetFilePath(fileName string) string {
	for _, name := range filenames {
		if name == fileName {
			return name
		}
	}

	return ""
}

func CreateTempFile(bom []byte) (string, error) {
	tmpFile, err := os.CreateTemp("", "sbom-*.json")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.Write(bom); err != nil {
		return "", fmt.Errorf("failed to write to temp file: %w", err)
	}

	filenames = append(filenames, tmpFile.Name())

	return tmpFile.Name(), nil
}

func DeleteTempFile(fileName string) error {
	if err := os.Remove(fileName); err != nil {
		return fmt.Errorf("failed to delete temp file: %w", err)
	}

	for i, name := range filenames {
		if name == fileName {
			filenames = append(filenames[:i], filenames[i+1:]...)
			break
		}
	}

	return nil
}
