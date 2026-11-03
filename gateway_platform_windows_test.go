//go:build windows

package gateway

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/quoiner/sandboxes-gateway/policy"
)

func TestWindowsGatewayStartFailsClosedBeforeCreatingResources(t *testing.T) {
	runDir := filepath.Join(t.TempDir(), "must-not-be-created")
	manager, err := New(Config{GVProxy: "gvproxy.exe", RunDir: runDir})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Start(context.Background(), policy.Policy{SandboxID: "owned-test"})
	if !errors.Is(err, ErrWindowsTransportUnavailable) {
		t.Fatalf("expected explicit unsupported transport error, got %v", err)
	}
	if _, statErr := os.Lstat(runDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("gateway created host resources before refusing transport: %v", statErr)
	}
}

func TestWindowsManagedFileRejectsHardLinks(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "managed.log")
	file, err := openManagedFile(original, os.O_CREATE|os.O_APPEND|os.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(dir, "linked.log")
	if err := os.Link(original, linked); err != nil {
		t.Fatal(err)
	}
	if file, err := openManagedFile(linked, os.O_CREATE|os.O_WRONLY); err == nil {
		_ = file.Close()
		t.Fatal("managed file with multiple hard links was accepted")
	}
}

func TestWindowsManagedFileCreatesPrivateRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.yaml")
	file, err := openManagedFile(path, os.O_CREATE|os.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if file, err := openManagedFile(path, os.O_CREATE|os.O_WRONLY); err != nil {
		t.Fatalf("reopen own private file: %v", err)
	} else {
		_ = file.Close()
	}
}

func TestWindowsManagedFileRejectsJunction(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(dir, "junction")
	if output, err := exec.Command("cmd.exe", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Fatalf("create owned junction: %v: %s", err, output)
	}
	defer func() { _ = os.Remove(junction) }()
	if file, err := openManagedFile(junction, os.O_CREATE|os.O_WRONLY); err == nil {
		_ = file.Close()
		t.Fatal("managed file open followed a directory junction")
	}
}
