// SPDX-License-Identifier: MIT
//go:build taggedpdf

package pdf

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	taggedExecutableSuffix = ".exe"
	taggedExecutableMode   = 0700
	fileDeleteChild        = 0x0040
	trustedInstallerSID    = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)

func taggedWorkspaceRoot(typst string) string { return filepath.Dir(typst) }

func configureTaggedCommand(cmd *exec.Cmd, dir string) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	cmd.Env = append(cmd.Env, "USERPROFILE="+dir, "LOCALAPPDATA="+dir, "APPDATA="+dir, "TEMP="+dir, "TMP="+dir)
}

func privateTaggedCache(dir string) (string, error) {
	dir = filepath.Clean(dir)
	volume := filepath.VolumeName(dir)
	if !filepath.IsAbs(dir) || len(volume) != 2 || !filepath.IsLocal(dir[3:]) {
		return "", fmt.Errorf("cache directory must be an absolute path on a local drive")
	}
	parts := strings.Split(dir[3:], "\\")
	for _, part := range parts {
		if strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return "", fmt.Errorf("cache directory components must not end in a dot or space")
		}
	}
	path := volume + "\\"
	root, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	if windows.GetDriveType(root) == windows.DRIVE_REMOTE {
		return "", fmt.Errorf("cache directory must be on a local drive")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return "", err
	}
	attrs := &windows.SecurityAttributes{SecurityDescriptor: descriptor}
	attrs.Length = uint32(unsafe.Sizeof(*attrs))
	if err := checkTaggedWindowsACL(path, user.User.Sid, true, false); err != nil {
		return "", err
	}
	for i, part := range parts {
		path = filepath.Join(path, part)
		final := i == len(parts)-1
		err := checkTaggedWindowsACL(path, user.User.Sid, true, final)
		if errors.Is(err, os.ErrNotExist) {
			name, nameErr := taggedWindowsPath(path)
			if nameErr != nil {
				return "", nameErr
			}
			if err := windows.CreateDirectory(name, attrs); err != nil && !errors.Is(err, os.ErrExist) {
				return "", err
			}
			err = checkTaggedWindowsACL(path, user.User.Sid, true, final)
		}
		if err != nil {
			return "", err
		}
	}
	return dir, nil
}

func privateTaggedExecutable(path string) bool {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && checkTaggedWindowsACL(path, user.User.Sid, false, true) == nil
}

func taggedWindowsPath(path string) (*uint16, error) {
	return windows.UTF16PtrFromString("\\\\?\\" + path)
}

func checkTaggedWindowsACL(path string, user *windows.SID, directory, private bool) error {
	name, err := taggedWindowsPath(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return &os.PathError{Op: "open cache path", Path: path, Err: err}
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	invalidPath := func() error { return fmt.Errorf("cache path %q must have a private ACL and no reparse point", path) }
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return invalidPath()
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	trusted := func(sid *windows.SID) bool {
		return sid.Equals(user) || sid.IsWellKnown(windows.WinLocalSystemSid) ||
			sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || (!private && sid.String() == trustedInstallerSID)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !trusted(owner) {
		return invalidPath()
	}
	acl, _, err := descriptor.DACL()
	if err != nil || acl == nil {
		return invalidPath()
	}
	// A shared ancestor may allow new subdirectories without allowing replacement of an existing child.
	unsafeAccess := uint32(windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL |
		windows.GENERIC_WRITE | windows.FILE_WRITE_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | fileDeleteChild)
	if private {
		unsafeAccess = ^uint32(0)
		if directory {
			control, _, err := descriptor.Control()
			if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
				return invalidPath()
			}
		}
	}
	inherits := false
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			// Owner Rights only applies to the already-validated owner of this ancestor.
			if !private && sid.IsWellKnown(windows.WinCreatorOwnerRightsSid) {
				continue
			}
			if trusted(sid) {
				const inheritBoth = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
				if ace.Header.AceFlags&inheritBoth == inheritBoth && ace.Header.AceFlags&windows.NO_PROPAGATE_INHERIT_ACE == 0 {
					inherits = true
				}
				continue
			}
			if uint32(ace.Mask)&unsafeAccess == 0 || (!private && ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0) {
				continue
			}
		}
		return invalidPath()
	}
	if private && directory && !inherits {
		return invalidPath()
	}
	return nil
}
