package file

import "os"

const (
	// Currently the file naming pattern that consumed by the scalibre is limited,
	// here apply the most acceptble name for both spdx and cyclonedx sbom file.
	DefaultName = "bom.json"

	defaultPermissions = 0644
)

func CopyAndCreate(input []byte) (string, error) {
	if err := os.WriteFile(DefaultName, input, defaultPermissions); err != nil {
		return "", err
	}

	return DefaultName, nil
}

func Delete(name string) error {
	if err := os.Remove(name); err != nil {
		return err
	}

	return nil
}
