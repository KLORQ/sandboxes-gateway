package gateway

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/KLORQ/sandboxes-gateway/policy"
)

// TestLiveGatewayLifecycle requires an explicitly supplied patched gvproxy.
// It starts no VM and creates only an isolated, uniquely named gateway.
func TestLiveGatewayLifecycle(t *testing.T) {
	binary := os.Getenv("KLORQ_TEST_GVPROXY")
	if binary == "" {
		t.Skip("set KLORQ_TEST_GVPROXY to a patched gvproxy for the local integration test")
	}
	supervisor := os.Getenv("KLORQ_TEST_SUPERVISOR")
	if supervisor == "" {
		t.Skip("set KLORQ_TEST_SUPERVISOR to a daemon binary")
	}
	dir, err := os.MkdirTemp("/tmp", "ksbx-gw-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("cleanup isolated gateway directory: %v", err)
		}
	})
	manager, err := New(Config{GVProxy: binary, Supervisor: supervisor, RunDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	startCtx, cancelStart := context.WithCancel(ctx)
	network, err := manager.Start(startCtx, policy.Policy{SandboxID: "fixture", AuditPath: filepath.Join(dir, "audit.jsonl")})
	if err != nil {
		cancelStart()
		t.Fatal(err)
	}
	cancelStart()
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			if err := manager.Stop(context.Background(), "fixture"); err != nil {
				t.Errorf("stop test gateway: %v", err)
			}
		}
	})
	info, err := os.Lstat(network.SocketPath)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("gateway socket unavailable: %v", err)
	}
	manager.mu.Lock()
	proc := manager.procs["fixture"]
	manager.mu.Unlock()
	select {
	case <-proc.done:
		t.Fatal("gateway exited when the start request context was canceled")
	case <-time.After(250 * time.Millisecond):
	}
	if _, err := manager.Start(ctx, policy.Policy{SandboxID: "fixture"}); err == nil {
		t.Fatal("duplicate gateway start succeeded")
	}
	select {
	case <-proc.done:
		t.Fatal("duplicate start disturbed the existing gateway")
	default:
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hostPort := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	if err := manager.SetPorts(ctx, "fixture", []policy.Port{{Host: uint16(hostPort), Guest: 3000, Proto: "tcp"}}); err != nil {
		t.Fatalf("expose forward: %v", err)
	}
	forwards, err := listForwards(ctx, manager.procs["fixture"].apiSocket)
	if err != nil || len(forwards) != 1 || forwards[0].Local != fmt.Sprintf("127.0.0.1:%d", hostPort) {
		t.Fatalf("forwards=%+v err=%v", forwards, err)
	}
	if err := manager.SetPorts(ctx, "fixture", nil); err != nil || len(func() []forwardAPI { f, _ := listForwards(ctx, manager.procs["fixture"].apiSocket); return f }()) != 0 {
		t.Fatalf("remove forward: %v", err)
	}
	if err := manager.Reload(ctx, policy.Policy{SandboxID: "fixture", Revision: 2, AuditPath: filepath.Join(dir, "audit.jsonl")}); err != nil {
		t.Fatalf("verified reload failed: %v", err)
	}
	if err := manager.Reload(ctx, policy.Policy{SandboxID: "fixture", Revision: 2, AuditPath: filepath.Join(dir, "audit.jsonl")}); err == nil {
		t.Fatal("non-advancing reload succeeded")
	}
	if err := manager.Stop(ctx, "fixture"); err != nil {
		t.Fatalf("stop test gateway: %v", err)
	}
	stopped = true
	select {
	case <-proc.done:
	default:
		t.Fatal("gateway stop returned before process exit")
	}
	if _, err := os.Lstat(network.SocketPath); !os.IsNotExist(err) {
		t.Fatalf("gateway socket remains: %v", err)
	}
}

func TestLiveGatewayOwnerHelper(t *testing.T) {
	if os.Getenv("KLORQ_TEST_OWNER_HELPER") != "1" {
		return
	}
	dir := os.Getenv("KLORQ_TEST_OWNER_DIR")
	manager, err := New(Config{GVProxy: os.Getenv("KLORQ_TEST_GVPROXY"), Supervisor: os.Getenv("KLORQ_TEST_SUPERVISOR"), RunDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Start(context.Background(), policy.Policy{SandboxID: "owned", AuditPath: filepath.Join(dir, "audit")}); err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(os.Stdout, "OWNER_READY %d\n", manager.procs["owned"].cmd.Process.Pid)
	for {
		time.Sleep(time.Hour)
	}
}

func TestLiveGatewayStopsAfterOwnerKill(t *testing.T) {
	if os.Getenv("KLORQ_TEST_GVPROXY") == "" || os.Getenv("KLORQ_TEST_SUPERVISOR") == "" {
		t.Skip("requires patched gvproxy and daemon supervisor")
	}
	dir, err := os.MkdirTemp("/tmp", "ksbx-owner-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cmd := exec.Command(os.Args[0], "-test.run=^TestLiveGatewayOwnerHelper$")
	cmd.Env = append(os.Environ(), "KLORQ_TEST_OWNER_HELPER=1", "KLORQ_TEST_OWNER_DIR="+dir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	scanner := bufio.NewScanner(stdout)
	ready := false
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "OWNER_READY ") {
			ready = true
			break
		}
	}
	if !ready {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("gateway owner did not become ready")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	socket := filepath.Join(dir, "owned.sock")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(socket); os.IsNotExist(err) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("gateway socket remained after owner was killed")
}

func TestLiveGatewayStopsAfterSupervisorKill(t *testing.T) {
	if os.Getenv("KLORQ_TEST_GVPROXY") == "" || os.Getenv("KLORQ_TEST_SUPERVISOR") == "" {
		t.Skip("requires patched gvproxy and daemon supervisor")
	}
	dir, err := os.MkdirTemp("/tmp", "ksbx-supervisor-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cmd := exec.Command(os.Args[0], "-test.run=^TestLiveGatewayOwnerHelper$")
	cmd.Env = append(os.Environ(), "KLORQ_TEST_OWNER_HELPER=1", "KLORQ_TEST_OWNER_DIR="+dir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	scanner := bufio.NewScanner(stdout)
	var supervisorPID int
	for scanner.Scan() {
		if value, ok := strings.CutPrefix(scanner.Text(), "OWNER_READY "); ok {
			supervisorPID, err = strconv.Atoi(value)
			break
		}
	}
	if err != nil || supervisorPID <= 0 {
		t.Fatalf("gateway owner did not report supervisor: %d %v", supervisorPID, err)
	}
	supervisor, err := os.FindProcess(supervisorPID)
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Kill(); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "owned.sock")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(socket); os.IsNotExist(err) {
			if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
				t.Fatalf("owner exited while testing supervisor loss: %v", err)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("gateway socket remained after supervisor was killed")
}

func TestLiveGatewayRejectsBinaryWithoutOwnerLease(t *testing.T) {
	binary, supervisor := os.Getenv("KLORQ_TEST_OLD_GVPROXY"), os.Getenv("KLORQ_TEST_SUPERVISOR")
	if binary == "" || supervisor == "" {
		t.Skip("requires old gvproxy and daemon supervisor")
	}
	dir, err := os.MkdirTemp("/tmp", "ksbx-old-gateway-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	manager, err := New(Config{GVProxy: binary, Supervisor: supervisor, RunDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := manager.Start(ctx, policy.Policy{SandboxID: "owned"}); err == nil {
		t.Fatal("gateway without an owner lease was accepted")
	}
}
