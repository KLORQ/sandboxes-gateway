package gateway

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestSupervisorHelper(t *testing.T) {
	if os.Getenv("KLORQ_SUPERVISOR_HELPER") != "1" {
		return
	}
	_ = RunSupervisor([]string{"/bin/sleep", "60"})
	os.Exit(0)
}

func TestSupervisorExitsWhenOwnerLeaseCloses(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSupervisorHelper$")
	cmd.Env = append(os.Environ(), "KLORQ_SUPERVISOR_HELPER=1")
	cmd.ExtraFiles = []*os.File{read}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = read.Close()
	t.Cleanup(func() {
		_ = write.Close()
		_ = cmd.Process.Kill()
	})
	_ = write.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor did not exit after owner lease closed")
	}
}
