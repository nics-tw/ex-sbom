// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

//go:build unit

package file

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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
				IsCDX: true,
				Data:  []byte(`{"name":"test-cdx"}`),
			},
			expectedPath:    DefaultCDXName,
			expectedError:   false,
			expectedContent: []byte(`{"name":"test-cdx"}`),
		},
		{
			name: "SPDX file",
			input: FileInput{
				IsCDX: false,
				Data:  []byte(`{"name":"test-spdx"}`),
			},
			expectedPath:    DefaultSPDXName,
			expectedError:   false,
			expectedContent: []byte(`{"name":"test-spdx"}`),
		},
		{
			name: "Empty data",
			input: FileInput{
				IsCDX: false,
				Data:  []byte{},
			},
			expectedPath:    DefaultSPDXName,
			expectedError:   false,
			expectedContent: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Call the function we're testing
			path, err := CopyAndCreate(tt.input)

			// Check error state
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Check returned path: canonical filename inside a unique temp dir
			assert.Equal(t, tt.expectedPath, filepath.Base(path))
			assert.True(t, strings.HasPrefix(filepath.Base(filepath.Dir(path)), tempDirPrefix),
				"file must live in a per-request scan directory")

			// Verify file existence and content
			if !tt.expectedError {
				// Check if file exists
				info, err := os.Stat(path)
				assert.NoError(t, err)
				assert.NotNil(t, info)

				// Check file permissions
				assert.Equal(t, os.FileMode(defaultPermissions), info.Mode().Perm())

				// Read content and verify
				content, err := os.ReadFile(path)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedContent, content)
			}

			// Clean up
			assert.NoError(t, Delete(path))
		})
	}

	// Test error case: temp dir creation fails when TMPDIR is unusable
	t.Run("temp dir creation error", func(t *testing.T) {
		t.Setenv("TMPDIR", filepath.Join(tempDir, "does-not-exist"))

		input := FileInput{
			IsCDX: false,
			Data:  []byte(`{"test":"data"}`),
		}

		_, err := CopyAndCreate(input)
		assert.Error(t, err)
	})
}

func TestDelete(t *testing.T) {
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
		name        string
		fileName    string
		setup       func(string) error
		expectError bool
	}{
		{
			name:        "delete existing file",
			fileName:    "test.txt",
			setup:       func(name string) error { return os.WriteFile(name, []byte("test content"), 0644) },
			expectError: false,
		},
		{
			name:        "delete non-existent file",
			fileName:    "non-existent-file.txt",
			setup:       func(name string) error { return nil }, // No setup needed
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			if err := tt.setup(tt.fileName); err != nil {
				t.Fatalf("Setup failed: %v", err)
			}

			// Call the function we're testing
			err := Delete(tt.fileName)

			// Check results
			if tt.expectError {
				assert.Error(t, err)
				assert.True(t, os.IsNotExist(err), "Expected 'file not exist' error")
			} else {
				assert.NoError(t, err)

				// Verify file was deleted
				_, statErr := os.Stat(tt.fileName)
				assert.True(t, os.IsNotExist(statErr), "File should no longer exist after deletion")
			}
		})
	}

	// Test permission error case
	t.Run("delete file without permission", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Skipping permission test on Windows")
		}

		// Create a read-only directory
		readOnlyDir := filepath.Join(tempDir, "readonly")
		if err := os.Mkdir(readOnlyDir, 0700); err != nil {
			t.Fatalf("Failed to create directory: %v", err)
		}

		// Create a file in the directory
		testFile := filepath.Join(readOnlyDir, "test.txt")
		if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		// Make the directory read-only after creating the file
		if err := os.Chmod(readOnlyDir, 0500); err != nil {
			t.Fatalf("Failed to change directory permissions: %v", err)
		}

		// Try to delete the file (should fail on Unix systems)
		err := Delete(testFile)

		// On some systems this may still succeed, so we check conditionally
		if err != nil {
			// We got an error as expected
			assert.Error(t, err)
			assert.False(t, os.IsNotExist(err), "Should be a permission error, not 'not exist' error")
		}

		// Restore permissions for cleanup
		_ = os.Chmod(readOnlyDir, 0700)
	})
}

// TestCopyAndCreate_ConcurrentSameFormat: two concurrent previews of the same
// format must get isolated files — neither may see the other's content.
func TestCopyAndCreate_ConcurrentSameFormat(t *testing.T) {
	type result struct {
		path string
		err  error
	}

	payloads := [][]byte{
		[]byte(`{"request":"one"}`),
		[]byte(`{"request":"two"}`),
	}

	results := make([]result, len(payloads))
	var wg sync.WaitGroup
	for i, data := range payloads {
		wg.Add(1)
		go func(i int, data []byte) {
			defer wg.Done()
			path, err := CopyAndCreate(FileInput{IsCDX: true, Data: data})
			results[i] = result{path: path, err: err}
		}(i, data)
	}
	wg.Wait()

	for i, r := range results {
		assert.NoError(t, r.err)
		content, err := os.ReadFile(r.path)
		assert.NoError(t, err)
		assert.Equal(t, payloads[i], content, "request %d must read back its own content", i)
	}
	assert.NotEqual(t, results[0].path, results[1].path, "concurrent requests must not share a path")

	for _, r := range results {
		assert.NoError(t, Delete(r.path))
	}
}

// TestDelete_ConcurrentRequestsDoNotAffectEachOther: one request finishing and
// cleaning up must not remove a still-running request's file.
func TestDelete_ConcurrentRequestsDoNotAffectEachOther(t *testing.T) {
	pathA, err := CopyAndCreate(FileInput{IsCDX: true, Data: []byte(`{"request":"a"}`)})
	assert.NoError(t, err)
	pathB, err := CopyAndCreate(FileInput{IsCDX: true, Data: []byte(`{"request":"b"}`)})
	assert.NoError(t, err)

	// request A finishes first and cleans up its own path
	assert.NoError(t, Delete(pathA))

	// request B's file must still be intact and readable by the scanner
	content, err := os.ReadFile(pathB)
	assert.NoError(t, err)
	assert.Equal(t, []byte(`{"request":"b"}`), content)

	assert.NoError(t, Delete(pathB))
	_, statErr := os.Stat(filepath.Dir(pathB))
	assert.True(t, os.IsNotExist(statErr), "per-request scan directory must be removed after Delete")
}
