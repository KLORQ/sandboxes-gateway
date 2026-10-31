package gateway

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

// SupervisorArgument selects the private gateway supervisor entry point.
const SupervisorArgument = "--internal-gateway-supervisor"

// RunSupervisor runs a gateway while descriptor 3 remains open in its owner.
func RunSupervisor(args []string) error {
	if len(args) == 0 {
		return errors.New("gateway supervisor requires a command")
	}
	lease := os.NewFile(3, "gateway-owner-lease")
	if lease == nil {
		return errors.New("gateway owner lease is unavailable")
	}
	defer func() { _ = lease.Close() }()
	childLease, ownerLease, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create gateway supervisor lease: %w", err)
	}
	defer func() { _ = childLease.Close() }()
	defer func() { _ = ownerLease.Close() }()
	child := exec.Command(args[0], args[1:]...) // #nosec G204 -- arguments are supplied by the local daemon
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	child.ExtraFiles = []*os.File{childLease}
	if err := child.Start(); err != nil {
		return fmt.Errorf("start gateway child: %w", err)
	}
	_ = childLease.Close()
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	ownerGone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, lease)
		close(ownerGone)
	}()
	exited := make(chan error, 1)
	go func() { exited <- child.Wait() }()
	for {
		select {
		case <-ownerGone:
			_ = child.Process.Signal(syscall.SIGTERM)
			select {
			case err := <-exited:
				return err
			case <-time.After(time.Second):
				_ = child.Process.Kill()
				return <-exited
			}
		case sig := <-signals:
			_ = child.Process.Signal(sig)
		case err := <-exited:
			return err
		}
	}
}
