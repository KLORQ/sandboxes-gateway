//go:build windows

package gateway

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func checkGatewayPlatform() error { return ErrWindowsTransportUnavailable }

func configureGatewayProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
}

func openManagedFile(path string, flags int) (*os.File, error) {
	sid, err := currentGatewaySID()
	if err != nil {
		return nil, err
	}
	sddl := "O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;FA;;;SY)"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("create gateway file security descriptor: %w", err)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ, &sa, windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("open gateway file: %w", err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("inspect gateway file: %w", err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.NumberOfLinks != 1 {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("gateway file must be a private regular file with one link")
	}
	actualSD, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("inspect gateway file permissions: %w", err)
	}
	owner, _, err := actualSD.Owner()
	if err != nil || owner.String() != sid || !gatewayDACLIsPrivate(actualSD, sid) {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("gateway file must have a current-user-only security descriptor")
	}
	file := os.NewFile(uintptr(handle), path)
	if flags&os.O_APPEND != 0 {
		if _, err := file.Seek(0, io.SeekEnd); err != nil {
			_ = file.Close()
			return nil, err
		}
	}
	return file, nil
}

func currentGatewaySID() (string, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("read current user SID: %w", err)
	}
	return user.User.Sid.String(), nil
}

func gatewayDACLIsPrivate(descriptor *windows.SECURITY_DESCRIPTOR, sid string) bool {
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	dacl, defaulted, err := descriptor.DACL()
	if err != nil || defaulted || dacl == nil || dacl.AceCount != 2 {
		return false
	}
	seenUser, seenSystem := false, false
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		aceSID, ok := gatewayACEPrincipal(dacl, i)
		if !ok {
			return false
		}
		switch aceSID {
		case sid:
			seenUser = true
		case "S-1-5-18":
			seenSystem = true
		default:
			return false
		}
	}
	return seenUser && seenSystem
}

func gatewayACEPrincipal(dacl *windows.ACL, index uint32) (string, bool) {
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, index, &ace); err != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
		ace.Header.AceFlags != 0 || ace.Mask != 0x001f01ff {
		return "", false
	}
	// #nosec G103 -- SidStart is the SID's first DWORD in the Win32 ACCESS_ALLOWED_ACE layout.
	return (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String(), true
}
