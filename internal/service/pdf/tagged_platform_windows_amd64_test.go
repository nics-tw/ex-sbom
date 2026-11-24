// SPDX-License-Identifier: MIT
//go:build unit && taggedpdf

package pdf

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestTaggedWindowsCacheRejectsWritableParent(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "shared")
	require.NoError(t, os.Mkdir(parent, 0700))
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	require.NoError(t, err)
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;BU)")
	require.NoError(t, err)
	acl, _, err := descriptor.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil))

	cache := filepath.Join(parent, "cache")
	t.Setenv("EX_SBOM_PDF_CACHE_DIR", cache)
	_, err = taggedExecutable()
	require.ErrorContains(t, err, "must have a private ACL")
	require.NoDirExists(t, cache)
}

func TestTaggedWindowsCacheRejectsJunction(t *testing.T) {
	parent := t.TempDir()
	cache := filepath.Join(parent, "cache")
	target := t.TempDir()
	cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"))
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: "cmd.exe /d /v:off /c mklink /J \"" + cache + "\" \"" + target + "\""}
	result, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", result)

	t.Setenv("EX_SBOM_PDF_CACHE_DIR", cache)
	_, err = taggedExecutable()
	require.ErrorContains(t, err, "no reparse point")
	entries, err := os.ReadDir(target)
	require.NoError(t, err)
	require.Empty(t, entries)
}
