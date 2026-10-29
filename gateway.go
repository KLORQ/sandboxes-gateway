// Package gateway manages one gvproxy process per sandbox.
package gateway

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/KLORQ/sandboxes-gateway/policy"
)

const (
	guestIP   = "192.168.127.3"
	deviceIP  = "192.168.127.2"
	gatewayIP = "192.168.127.1"
)

// Config controls the gateway process manager.
type Config struct {
	GVProxy     string
	RunDir      string
	DNSUpstream string
}

// Network describes the host-side network attachment.
type Network struct {
	SocketPath  string
	MAC         string
	DeviceIP    string
	GatewayIP   string
	AuditPath   string
	Annotations []string
}

type process struct {
	pid    int
	socket string
	config string
	log    string
}

// Manager owns gateway processes by sandbox name.
type Manager struct {
	cfg   Config
	mu    sync.Mutex
	procs map[string]process
}

// New creates a gateway manager.
func New(cfg Config) (*Manager, error) {
	if cfg.GVProxy == "" {
		return nil, fmt.Errorf("gvproxy path is required")
	}
	if cfg.RunDir == "" {
		return nil, fmt.Errorf("run dir is required")
	}
	return &Manager{cfg: cfg, procs: make(map[string]process)}, nil
}

// Start launches a default-deny gateway for one sandbox.
func (m *Manager) Start(ctx context.Context, p policy.Policy) (Network, error) {
	if p.SandboxID == "" {
		return Network{}, fmt.Errorf("sandbox id is required")
	}
	if p.Revision <= 0 {
		p.Revision = 1
	}
	name := p.SandboxID
	if err := os.MkdirAll(m.cfg.RunDir, 0o700); err != nil {
		return Network{}, err
	}
	socket := filepath.Join(m.cfg.RunDir, name+".sock")
	if err := shortSocket(socket); err != nil {
		return Network{}, err
	}
	cfgPath := filepath.Join(m.cfg.RunDir, name+".yaml")
	logPath := filepath.Join(m.cfg.RunDir, name+".gateway.log")
	if err := writeConfig(cfgPath, p, m.cfg.DNSUpstream); err != nil {
		return Network{}, err
	}
	_ = os.Remove(socket)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- log path is derived from the managed run dir
	if err != nil {
		return Network{}, err
	}
	cmd := exec.CommandContext(ctx, m.cfg.GVProxy, // #nosec G204 -- gvproxy is an operator-configured local binary
		"-config", cfgPath,
		"-require-egress-policy",
		"-listen-vfkit", "unixgram://"+socket,
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return Network{}, fmt.Errorf("start gateway: %w", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Release()
	_ = logFile.Close()

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socket); err == nil {
			m.mu.Lock()
			m.procs[name] = process{pid: pid, socket: socket, config: cfgPath, log: logPath}
			m.mu.Unlock()
			mac := MAC(name)
			return Network{
				SocketPath: socket,
				MAC:        mac,
				DeviceIP:   deviceIP,
				GatewayIP:  gatewayIP,
				AuditPath:  p.AuditPath,
				Annotations: []string{
					fmt.Sprintf("io.containerd.nerdbox.network.0=socket=%s,mode=unixgram,mac=%s,addr=%s/24", socket, mac, deviceIP),
					fmt.Sprintf("io.containerd.nerdbox.ctr.network.0=vmmac=%s,addr=%s/24,gw=%s", mac, guestIP, gatewayIP),
				},
			}, nil
		}
		if !alive(pid) {
			break
		}
		select {
		case <-ctx.Done():
			return Network{}, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	_ = kill(pid, syscall.SIGKILL)
	return Network{}, fmt.Errorf("gateway did not create %s; see %s", socket, logPath)
}

// Stop terminates the sandbox gateway.
func (m *Manager) Stop(ctx context.Context, name string) error {
	m.mu.Lock()
	p, ok := m.procs[name]
	delete(m.procs, name)
	m.mu.Unlock()
	if !ok {
		return nil
	}
	if alive(p.pid) {
		_ = kill(p.pid, syscall.SIGTERM)
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if !alive(p.pid) {
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
		if alive(p.pid) {
			_ = kill(p.pid, syscall.SIGKILL)
		}
	}
	_ = os.Remove(p.socket)
	return nil
}

// Reload writes a new policy and asks the gateway to reload it.
func (m *Manager) Reload(ctx context.Context, p policy.Policy) error {
	m.mu.Lock()
	proc, ok := m.procs[p.SandboxID]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("gateway for %s is not running", p.SandboxID)
	}
	if err := writeConfig(proc.config, p, m.cfg.DNSUpstream); err != nil {
		return err
	}
	if err := kill(proc.pid, syscall.SIGHUP); err != nil {
		return fmt.Errorf("reload gateway: %w", err)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// Close stops all managed gateways.
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	names := make([]string, 0, len(m.procs))
	for name := range m.procs {
		names = append(names, name)
	}
	m.mu.Unlock()
	for _, name := range names {
		if err := m.Stop(ctx, name); err != nil {
			return err
		}
	}
	return nil
}

// MAC returns a deterministic local MAC for a sandbox.
func MAC(name string) string {
	sum := sha256.Sum256([]byte(name))
	return fmt.Sprintf("fa:43:25:%02x:%02x:%02x", sum[0], sum[1], sum[2])
}

func writeConfig(path string, p policy.Policy, dnsUpstream string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if p.AuditPath != "" {
		if err := os.MkdirAll(filepath.Dir(p.AuditPath), 0o700); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(renderConfig(p, dnsUpstream)), 0o600)
}

func renderConfig(p policy.Policy, dnsUpstream string) string {
	var b strings.Builder
	b.WriteString("stack:\n")
	b.WriteString("  subnet: 192.168.127.0/24\n")
	b.WriteString("  gatewayIP: 192.168.127.1\n")
	b.WriteString("  deviceIP: 192.168.127.2\n")
	b.WriteString("  hostIP: 192.168.127.254\n")
	b.WriteString("  mtu: 1500\n")
	if dnsUpstream != "" {
		fmt.Fprintf(&b, "  dnsUpstream: %s\n", strconv.Quote(dnsUpstream))
	}
	b.WriteString("  nat:\n    192.168.127.254: 127.0.0.1\n")
	b.WriteString("  gatewayVirtualIPs:\n    - 192.168.127.254\n")
	if len(p.Ports) > 0 {
		b.WriteString("  forwards:\n")
		for _, port := range p.Ports {
			if port.Proto != "" && port.Proto != "tcp" {
				continue
			}
			fmt.Fprintf(&b, "    %s: %s\n",
				strconv.Quote(fmt.Sprintf("127.0.0.1:%d", port.Host)),
				strconv.Quote(fmt.Sprintf("%s:%d", guestIP, port.Guest)))
		}
	}
	b.WriteString("  egressPolicy:\n")
	fmt.Fprintf(&b, "    revision: %s\n", strconv.Quote(strconv.Itoa(p.Revision)))
	fmt.Fprintf(&b, "    sandboxID: %s\n", strconv.Quote(p.SandboxID))
	fmt.Fprintf(&b, "    auditLog: %s\n", strconv.Quote(p.AuditPath))
	writeRules(&b, "allow", p.Allow)
	writeRules(&b, "deny", p.Deny)
	return b.String()
}

func writeRules(b *strings.Builder, name string, rules []policy.Rule) {
	if len(rules) == 0 {
		return
	}
	fmt.Fprintf(b, "    %s:\n", name)
	for _, r := range rules {
		proto := r.Protocol
		if proto == "" {
			proto = "tcp"
		}
		fmt.Fprintf(b, "      - protocol: %s\n", strconv.Quote(proto))
		if r.CIDR != "" {
			fmt.Fprintf(b, "        cidr: %s\n", strconv.Quote(r.CIDR))
		}
		if r.Port != 0 {
			fmt.Fprintf(b, "        port: %d\n", r.Port)
		}
	}
}

func shortSocket(path string) error {
	if len(path) > 100 {
		return fmt.Errorf("unix socket path is too long (%d bytes): %s", len(path), path)
	}
	return nil
}

func alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

func kill(pid int, sig syscall.Signal) error {
	if pid <= 0 {
		return nil
	}
	return syscall.Kill(pid, sig)
}
