//go:build !windows

package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rheic/sandboxes-gateway/policy"
)

func checkGatewayPlatform() error { return nil }

func gatewayEndpoints(runDir, name string) (string, string, string, error) {
	networkEndpoint := filepath.Join(runDir, name+".sock")
	apiEndpoint := filepath.Join(runDir, name+".api.sock")
	if err := shortSocket(networkEndpoint); err != nil {
		return "", "", "", err
	}
	if err := shortSocket(apiEndpoint); err != nil {
		return "", "", "", err
	}
	return networkEndpoint, apiEndpoint, "", nil
}

func ensureGatewayEndpointAvailable(endpoint string) error {
	return ensureSocketPathAvailable(endpoint)
}

func createGatewayAPIToken(string) (string, error) { return "", nil }

func removeManagedGatewaySecret(string) error { return nil }

func startManagedGateway(supervisor, gvproxy, configPath, networkEndpoint, apiEndpoint, _ string, logFile *os.File) (*exec.Cmd, io.Closer, error) {
	if supervisor == "" {
		return nil, nil, errors.New("gateway supervisor is required")
	}
	leaseRead, leaseWrite, err := os.Pipe()
	if err != nil {
		return nil, nil, fmt.Errorf("create gateway owner lease: %w", err)
	}
	cmd := exec.Command(supervisor, // #nosec G204 -- supervisor and gvproxy are operator-configured local binaries
		SupervisorArgument, gvproxy,
		"-config", configPath,
		"-require-egress-policy",
		"-require-owner-lease",
		"-listen-vfkit", "unixgram://"+networkEndpoint,
		"-services", "unix://"+apiEndpoint,
	)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.ExtraFiles = []*os.File{leaseRead}
	configureGatewayProcess(cmd)
	if err := cmd.Start(); err != nil {
		_ = leaseRead.Close()
		_ = leaseWrite.Close()
		return nil, nil, fmt.Errorf("start gateway supervisor: %w", err)
	}
	_ = leaseRead.Close()
	return cmd, leaseWrite, nil
}

func gatewayEndpointReady(_ context.Context, endpoint, _, _ string, _ <-chan struct{}) bool {
	info, err := os.Lstat(endpoint)
	return err == nil && info.Mode()&os.ModeSocket != 0
}

func qemuNetworkEndpoint(string) string { return "" }

func gatewayNetworkAnnotations(socket, mac string) []string {
	return []string{
		fmt.Sprintf("io.containerd.nerdbox.network.0=socket=%s,mode=unixgram,mac=%s,addr=%s/24", socket, mac, deviceIP),
		fmt.Sprintf("io.containerd.nerdbox.ctr.network.0=vmmac=%s,addr=%s/24,gw=%s", mac, guestIP, gatewayIP),
	}
}

func staleGatewayEndpoints(runDir, name string) []string {
	return []string{filepath.Join(runDir, name+".sock"), filepath.Join(runDir, name+".api.sock")}
}

func verifyGatewayEndpointStopped(endpoint string) error {
	if _, err := os.Lstat(endpoint); err == nil {
		return errors.New("gateway exited but its socket path remains; ownership is unverified")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect gateway socket: %w", err)
	}
	return nil
}

func reloadGateway(ctx context.Context, proc process, next policy.Policy, offset int64) error {
	if err := proc.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("signal gateway reload: %w", err)
	}
	return waitForReloadAck(ctx, proc, offset, next.Revision)
}

func validateGatewayAPIAuth(endpoint, token string) error {
	if strings.HasPrefix(endpoint, "tcp://") && token == "" {
		return errors.New("gateway TCP API requires bearer authentication")
	}
	return nil
}

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
