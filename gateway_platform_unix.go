//go:build !windows

package gateway

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func checkGatewayPlatform() error { return nil }

func configureGatewayProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

func openManagedFile(path string, flags int) (*os.File, error) {
	file, err := os.OpenFile(path, flags|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- managed run dir; no-follow and descriptor checks reject links
	if err != nil {
		return nil, fmt.Errorf("open gateway file: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect gateway file: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ok || stat.Nlink != 1 {
		_ = file.Close()
		return nil, errors.New("gateway file must be private, regular, and have one link")
	}
	return file, nil
}
