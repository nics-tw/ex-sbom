// SPDX-License-Identifier: MIT

package first

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

type archiveWindowsBasicInfo struct {
	creationTime, accessTime, writeTime, changeTime int64
	attributes                                      uint32
	_                                               uint32
}

func archiveWindowsHandle(path string, access uint32) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(name, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0, &os.PathError{Op: "inspect archive file", Path: path, Err: err}
	}
	return handle, nil
}

func archiveIndexIdentity(path string) (string, error) {
	return archiveWindowsIdentity(path, false)
}

func archiveIndexSealedIdentity(path string) (string, error) {
	return archiveWindowsIdentity(path, true)
}

func archiveWindowsIdentity(path string, sealed bool) (string, error) {
	access := uint32(windows.FILE_READ_ATTRIBUTES)
	if sealed {
		access |= windows.READ_CONTROL
	}
	handle, err := archiveWindowsHandle(path, access)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	info, err := archiveWindowsInfo(handle, path)
	if err != nil {
		return "", err
	}
	if sealed {
		if err := checkArchiveWindowsDACL(handle, path); err != nil {
			return "", err
		}
	}
	var basic archiveWindowsBasicInfo
	if err := windows.GetFileInformationByHandleEx(handle, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic))); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%d:%d:%d:%d:%d:%d:%d", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow,
		info.FileSizeHigh, info.FileSizeLow, basic.writeTime, basic.changeTime, basic.attributes), nil
}

func archiveWindowsInfo(handle windows.Handle, path string) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return info, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 && info.NumberOfLinks != 1) {
		return info, fmt.Errorf("archive path must not be a reparse point or hard link: %s", path)
	}
	return info, nil
}

func checkSealedArchiveDirectory(path string) error {
	handle, err := archiveWindowsHandle(path, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	info, err := archiveWindowsInfo(handle, path)
	if err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("archive snapshot directory must be a real directory: %s", path)
	}
	return checkArchiveWindowsDACL(handle, path)
}

func checkArchiveWindowsDACL(handle windows.Handle, path string) error {
	security, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	control, _, err := security.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("archive snapshot path must have protected permissions: %s", path)
	}
	acl, _, err := security.DACL()
	if err != nil || acl == nil {
		return fmt.Errorf("archive snapshot path must have an ACL: %s", path)
	}
	const readAndExecute = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE | windows.GENERIC_READ | windows.GENERIC_EXECUTE
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask&^readAndExecute != 0 {
			return fmt.Errorf("archive snapshot path must have a read-only DACL: %s", path)
		}
	}
	return nil
}

func archiveWindowsSecurity(rights string, staging bool) (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	sid := user.User.Sid.String()
	if staging {
		return windows.SecurityDescriptorFromString("D:P(A;OICI;" + rights + ";;;" + sid + ")")
	}
	return windows.SecurityDescriptorFromString("D:P(A;;" + rights + ";;;SY)(A;;" + rights + ";;;BA)(A;;" + rights + ";;;" + sid + ")")
}

func makeArchiveStaging(parent string) (string, error) {
	// Files and temporary DuckDB directories initially inherit builder access.
	security, err := archiveWindowsSecurity("FRFWFXSDWD", true)
	if err != nil {
		return "", err
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: security}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	for {
		var suffix [16]byte
		rand.Read(suffix[:])
		path := filepath.Join(parent, ".lev-index-"+hex.EncodeToString(suffix[:]))
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return "", err
		}
		err = windows.CreateDirectory(name, &attributes)
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			continue
		}
		if err != nil {
			return "", &os.PathError{Op: "create archive staging directory", Path: path, Err: err}
		}
		return path, nil
	}
}

func setArchiveWindowsDACL(handle windows.Handle, path, rights string, staging bool) error {
	security, err := archiveWindowsSecurity(rights, staging)
	if err != nil {
		return err
	}
	acl, _, err := security.DACL()
	if err != nil {
		return err
	}
	const flags = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, flags, nil, nil, acl, nil); err != nil {
		return &os.PathError{Op: "set archive permissions", Path: path, Err: err}
	}
	return nil
}

func setArchiveWindowsPathDACL(path, rights string, directory, staging bool) error {
	handle, err := archiveWindowsHandle(path, windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	info, err := archiveWindowsInfo(handle, path)
	if err != nil {
		return err
	}
	if directory != (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) {
		return fmt.Errorf("unexpected archive path type: %s", path)
	}
	return setArchiveWindowsDACL(handle, path, rights, staging)
}

func sealArchiveDirectory(path string) error {
	return setArchiveWindowsPathDACL(path, "FRFX", true, false)
}

func unsealArchiveDirectory(path string) error {
	return setArchiveWindowsPathDACL(path, "FA", true, true)
}

func sealArchiveFile(path string) error {
	return setArchiveWindowsPathDACL(path, "FR", false, false)
}

func unsealArchiveFile(path string) error {
	return setArchiveWindowsPathDACL(path, "FA", false, false)
}

func removeArchiveStaging(path string) error {
	if err := unsealArchiveDirectory(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			err = errors.Join(err, unsealArchiveFile(filepath.Join(path, entry.Name())))
		}
	}
	return errors.Join(err, os.RemoveAll(path))
}

func sealAndPublishArchiveDirectory(ctx context.Context, staging, output string) error {
	// Keep the rename right on this handle while removing it from the DACL.
	handle, err := archiveWindowsHandle(staging, windows.DELETE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES|windows.WRITE_DAC)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	info, err := archiveWindowsInfo(handle, staging)
	if err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("archive snapshot directory must be a real directory: %s", staging)
	}
	if err := setArchiveWindowsDACL(handle, staging, "FRFX", false); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	name, err := windows.UTF16FromString(output)
	if err != nil {
		return err
	}
	// FILE_RENAME_INFO uses zero flags for an atomic rename without replacement.
	var rename struct {
		flags          uint32
		rootDirectory  windows.Handle
		fileNameLength uint32
		fileName       [windows.MAX_LONG_PATH]uint16
	}
	if len(name) > len(rename.fileName) {
		return &os.LinkError{Op: "publish archive", Old: staging, New: output, Err: windows.ERROR_FILENAME_EXCED_RANGE}
	}
	copy(rename.fileName[:], name)
	rename.fileNameLength = uint32((len(name) - 1) * 2)
	size := uint32(unsafe.Offsetof(rename.fileName)) + uint32(len(name))*2
	if err := windows.SetFileInformationByHandle(handle, windows.FileRenameInfo, (*byte)(unsafe.Pointer(&rename)), size); err != nil {
		// Some Windows filesystems report access denied for a name collision.
		if _, existingErr := os.Lstat(output); existingErr == nil {
			err = os.ErrExist
		}
		return &os.LinkError{Op: "publish archive", Old: staging, New: output, Err: err}
	}
	return nil
}
