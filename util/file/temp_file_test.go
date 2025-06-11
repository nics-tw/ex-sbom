//go:build unit

package file

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCopyAndCreate(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "file_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir) // Clean up when done

	// Save current working directory
	originalWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}

	// Change to temp directory for the test
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}
	defer os.Chdir(originalWd) // Restore working directory when done

	tests := []struct {
		name            string
		input           FileInput
		expectedPath    string
		expectedError   bool
		expectedContent []byte
	}{
		{
			name: "CDX file",
			input: FileInput{
				Name:  "custom.json",
				IsCDX: true,
				Data:  []byte(`{"name":"test-cdx"}`),
			},
			expectedPath:    DefaultName, // Should use DefaultName (bom.json)
			expectedError:   false,
			expectedContent: []byte(`{"name":"test-cdx"}`),
		},
		{
			name: "SPDX file",
			input: FileInput{
				Name:  "spdx-test.json",
				IsCDX: false,
				Data:  []byte(`{"name":"test-spdx"}`),
			},
			expectedPath:    "spdx-test.json", // Should use input.Name
			expectedError:   false,
			expectedContent: []byte(`{"name":"test-spdx"}`),
		},
		{
			name: "Empty data",
			input: FileInput{
				Name:  "empty.json",
				IsCDX: false,
				Data:  []byte{},
			},
			expectedPath:    "empty.json",
			expectedError:   false,
			expectedContent: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up any previous test files with the same name
			_ = os.Remove(tt.expectedPath)

			// Call the function we're testing
			path, err := CopyAndCreate(tt.input)

			// Check error state
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Check returned path
			assert.Equal(t, tt.expectedPath, path)

			// Verify file existence and content
			if !tt.expectedError {
				// Check if file exists
				info, err := os.Stat(tt.expectedPath)
				assert.NoError(t, err)
				assert.NotNil(t, info)

				// Check file permissions
				assert.Equal(t, os.FileMode(defaultPermissions), info.Mode().Perm())

				// Read content and verify
				content, err := os.ReadFile(tt.expectedPath)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedContent, content)
			}

			// Clean up
			_ = os.Remove(tt.expectedPath)
		})
	}

	// Test permission error case with a read-only directory
	t.Run("permission error", func(t *testing.T) {
		// Create a read-only directory
		readOnlyDir := filepath.Join(tempDir, "readonly")
		if err := os.Mkdir(readOnlyDir, 0500); err != nil {
			t.Fatalf("Failed to create read-only directory: %v", err)
		}

		// Change to the read-only directory
		if err := os.Chdir(readOnlyDir); err != nil {
			t.Fatalf("Failed to change to read-only directory: %v", err)
		}
		defer os.Chdir(tempDir) // Return to temp dir

		// Try to create a file in the read-only directory
		input := FileInput{
			Name:  "test.json",
			IsCDX: false,
			Data:  []byte(`{"test":"data"}`),
		}

		_, err := CopyAndCreate(input)
		assert.Error(t, err)
	})
}
