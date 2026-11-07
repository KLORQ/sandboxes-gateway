//go:build !windows

package gateway

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func gatewayTestDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "kqgw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestRecoverStaleEndpointRemovesDeadSocket(t *testing.T) {
	if testing.Short() {
		t.Skip("requires unix sockets")
	}
	dir := gatewayTestDir(t)
	m, err := New(Config{GVProxy: "/bin/true", RunDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "stale.sock")
	// Bind and close at the syscall level so the socket file remains, as
	// after a gateway crash (Go listeners unlink their socket on Close).
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(fd)
	if err := m.recoverStaleEndpoint(path); err != nil {
		t.Fatalf("recover stale endpoint: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale socket still present: %v", err)
	}
}

func TestRecoverStaleEndpointRejectsLiveListener(t *testing.T) {
	if testing.Short() {
		t.Skip("requires unix sockets")
	}
	dir := gatewayTestDir(t)
	m, err := New(Config{GVProxy: "/bin/true", RunDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "live.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if err := m.recoverStaleEndpoint(path); err == nil {
		t.Fatal("live endpoint was removed")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("live socket was removed: %v", err)
	}
}

func TestRecoverStaleEndpointLeavesForeignPaths(t *testing.T) {
	dir := t.TempDir()
	m, err := New(Config{GVProxy: "/bin/true", RunDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.recoverStaleEndpoint(regular); err == nil {
		t.Fatal("regular file was removed")
	}
	outside := filepath.Join(t.TempDir(), "other.sock")
	if err := m.recoverStaleEndpoint(outside); err == nil {
		t.Fatal("path outside run dir was removed")
	}
	if _, err := os.Lstat(regular); err != nil {
		t.Fatalf("regular file was removed: %v", err)
	}
}

func TestRecoverStaleEndpointRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	m, err := New(Config{GVProxy: "/bin/true", RunDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target.sock")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.sock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := m.recoverStaleEndpoint(link); err == nil {
		t.Fatal("symlink endpoint was removed")
	}
	if _, err := os.Lstat(target); err != nil {
		t.Fatalf("symlink target was removed: %v", err)
	}
}

func TestEnsureEndpointAvailableFailsClosedOnLiveSocket(t *testing.T) {
	if testing.Short() {
		t.Skip("requires unix sockets")
	}
	dir := gatewayTestDir(t)
	m, err := New(Config{GVProxy: "/bin/true", RunDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "live.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if err := m.ensureEndpointAvailable(path); err == nil {
		t.Fatal("live endpoint was accepted")
	}
}
