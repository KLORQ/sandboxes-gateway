// Package gateway manages one gvproxy process per sandbox.
package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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
	protocolTCP = "tcp"
	protocolUDP = "udp"
	guestIP     = "192.168.127.3"
	deviceIP    = "192.168.127.2"
	gatewayIP   = "192.168.127.1"
)

// Config controls the gateway process manager.
type Config struct {
	GVProxy     string
	Supervisor  string
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
	cmd       *exec.Cmd
	done      chan struct{}
	socket    string
	cfgPath   string
	logPath   string
	apiSocket string
	revision  int
	lease     *os.File
}

// Manager owns gateway processes by sandbox name.
type Manager struct {
	cfg      Config
	mu       sync.Mutex
	procs    map[string]process
	starting map[string]chan struct{}
	closed   bool
}

// New creates a gateway manager.
func New(cfg Config) (*Manager, error) {
	if cfg.GVProxy == "" {
		return nil, fmt.Errorf("gvproxy path is required")
	}
	if cfg.RunDir == "" {
		return nil, fmt.Errorf("run dir is required")
	}
	return &Manager{cfg: cfg, procs: make(map[string]process), starting: make(map[string]chan struct{})}, nil
}

// Start launches a default-deny gateway for one sandbox.
func (m *Manager) Start(ctx context.Context, p policy.Policy) (Network, error) {
	if !validSandboxID(p.SandboxID) {
		return Network{}, fmt.Errorf("invalid sandbox id")
	}
	if p.Revision <= 0 {
		p.Revision = 1
	}
	name := p.SandboxID
	if err := m.reserveStart(name); err != nil {
		return Network{}, err
	}
	defer func() {
		m.mu.Lock()
		finished := m.starting[name]
		delete(m.starting, name)
		close(finished)
		m.mu.Unlock()
	}()
	if err := ctx.Err(); err != nil {
		return Network{}, err
	}
	if err := os.MkdirAll(m.cfg.RunDir, 0o700); err != nil {
		return Network{}, err
	}
	socket := filepath.Join(m.cfg.RunDir, name+".sock")
	if err := shortSocket(socket); err != nil {
		return Network{}, err
	}
	if err := ensureSocketPathAvailable(socket); err != nil {
		return Network{}, err
	}
	cfgPath := filepath.Join(m.cfg.RunDir, name+".yaml")
	logPath := filepath.Join(m.cfg.RunDir, name+".gateway.log")
	apiSocket := filepath.Join(m.cfg.RunDir, name+".api.sock")
	if err := shortSocket(apiSocket); err != nil {
		return Network{}, err
	}
	if err := ensureSocketPathAvailable(apiSocket); err != nil {
		return Network{}, err
	}
	return m.launch(ctx, p, socket, cfgPath, logPath, apiSocket)
}

func (m *Manager) reserveStart(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, active := m.procs[name]
	_, starting := m.starting[name]
	if m.closed {
		return errors.New("gateway manager is closed")
	}
	if active || starting {
		return errors.New("gateway is already running or starting")
	}
	m.starting[name] = make(chan struct{})
	return nil
}

func ensureSocketPathAvailable(socket string) error {
	if _, err := os.Lstat(socket); err == nil {
		return errors.New("gateway socket path already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect gateway socket: %w", err)
	}
	return nil
}

func (m *Manager) launch(ctx context.Context, p policy.Policy, socket, cfgPath, logPath, apiSocket string) (Network, error) {
	name := p.SandboxID
	if m.cfg.Supervisor == "" {
		return Network{}, errors.New("gateway supervisor is required")
	}
	if err := writeConfig(cfgPath, p, m.cfg.DNSUpstream); err != nil {
		return Network{}, err
	}
	logFile, err := openManagedFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY)
	if err != nil {
		return Network{}, err
	}
	leaseRead, leaseWrite, err := os.Pipe()
	if err != nil {
		_ = logFile.Close()
		return Network{}, fmt.Errorf("create gateway owner lease: %w", err)
	}
	cmd := exec.Command(m.cfg.Supervisor, // #nosec G204 -- supervisor and gvproxy are operator-configured local binaries
		SupervisorArgument, m.cfg.GVProxy,
		"-config", cfgPath,
		"-require-egress-policy",
		"-require-owner-lease",
		"-listen-vfkit", "unixgram://"+socket,
		"-services", "unix://"+apiSocket,
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.ExtraFiles = []*os.File{leaseRead}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = leaseRead.Close()
		_ = leaseWrite.Close()
		_ = logFile.Close()
		return Network{}, fmt.Errorf("start gateway: %w", err)
	}
	_ = leaseRead.Close()
	_ = logFile.Close()
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		_ = leaseWrite.Close()
		close(done)
	}()
	proc := process{cmd: cmd, done: done, socket: socket, cfgPath: cfgPath, logPath: logPath, apiSocket: apiSocket, revision: p.Revision, lease: leaseWrite}

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			return Network{}, errors.New("gateway exited before becoming ready")
		default:
		}
		if info, err := os.Lstat(socket); err == nil && info.Mode()&os.ModeSocket != 0 {
			m.mu.Lock()
			if m.closed {
				m.mu.Unlock()
				return Network{}, m.abortStart(name, proc, errors.New("gateway manager closed during startup"))
			}
			m.procs[name] = proc
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
		select {
		case <-ctx.Done():
			return Network{}, m.abortStart(name, proc, ctx.Err())
		case <-done:
			return Network{}, fmt.Errorf("gateway exited before becoming ready")
		case <-time.After(100 * time.Millisecond):
		}
	}
	return Network{}, m.abortStart(name, proc, errors.New("gateway did not create socket"))
}

func (m *Manager) abortStart(name string, proc process, cause error) error {
	_ = proc.lease.Close()
	var cleanupErr error
	select {
	case <-proc.done:
	case <-time.After(2 * time.Second):
		cleanupErr = errors.New("gateway supervisor did not stop after lease closed")
	}
	if cleanupErr != nil {
		m.mu.Lock()
		m.procs[name] = proc
		m.mu.Unlock()
	}
	return errors.Join(cause, cleanupErr)
}

// validSandboxID confines generated file names to the configured run directory.
func validSandboxID(id string) bool {
	if id == "" || len(id) > 63 || id == "." || id == ".." {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') &&
			(c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

// Stop terminates the sandbox gateway.
func (m *Manager) Stop(ctx context.Context, name string) error {
	m.mu.Lock()
	p, ok := m.procs[name]
	_, starting := m.starting[name]
	m.mu.Unlock()
	if starting {
		return errors.New("gateway is starting")
	}
	if !ok {
		return nil
	}
	_ = p.lease.Close()
	select {
	case <-p.done:
	default:
		select {
		case <-p.done:
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
			return errors.New("gateway supervisor did not stop after lease closed")
		}
	}
	m.mu.Lock()
	if current, ok := m.procs[name]; ok && current.cmd == p.cmd {
		delete(m.procs, name)
	}
	m.mu.Unlock()
	if _, err := os.Lstat(p.socket); err == nil {
		return errors.New("gateway exited but its socket path remains; ownership is unverified")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect gateway socket: %w", err)
	}
	return nil
}

// ErrReloadUnverified reports that the current gvproxy has no revision ACK.
var ErrReloadUnverified = errors.New("gateway policy reload has no verified acknowledgement")

// Reload rewrites the gateway config, sends SIGHUP, and verifies the patched
// gvproxy's appended revision acknowledgement. Without an acknowledgement the
// gateway is stopped and the error fails closed.
func (m *Manager) Reload(ctx context.Context, p policy.Policy) error {
	if !validSandboxID(p.SandboxID) {
		return fmt.Errorf("invalid sandbox id")
	}
	m.mu.Lock()
	proc, ok := m.procs[p.SandboxID]
	starting := m.starting[p.SandboxID]
	m.mu.Unlock()
	if starting != nil {
		select {
		case <-starting:
		case <-ctx.Done():
			return ctx.Err()
		}
		m.mu.Lock()
		proc, ok = m.procs[p.SandboxID]
		m.mu.Unlock()
	}
	if !ok {
		return fmt.Errorf("gateway for %s is not running", p.SandboxID)
	}
	if p.Revision <= 0 {
		return fmt.Errorf("policy revision must be positive")
	}
	if err := validatePolicy(p); err != nil {
		return err
	}
	if p.Revision <= proc.revision {
		return fmt.Errorf("policy revision %d must advance past %d", p.Revision, proc.revision)
	}
	if err := writeConfig(proc.cfgPath, p, m.cfg.DNSUpstream); err != nil {
		return err
	}
	offset, err := fileSize(proc.logPath)
	if err != nil {
		return err
	}
	if err := proc.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("signal gateway reload: %w", err)
	}
	ackCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := waitForReloadAck(ackCtx, proc, offset, p.Revision); err != nil {
		stopCtx, stopCancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		stopErr := m.Stop(stopCtx, p.SandboxID)
		stopCancel()
		return errors.Join(ErrReloadUnverified, err, stopErr)
	}
	m.mu.Lock()
	if current, ok := m.procs[p.SandboxID]; ok && current.cmd == proc.cmd {
		current.revision = p.Revision
		m.procs[p.SandboxID] = current
	}
	m.mu.Unlock()
	return nil
}

func fileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("inspect gateway log: %w", err)
	}
	return info.Size(), nil
}

func waitForReloadAck(ctx context.Context, proc process, offset int64, revision int) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	want := fmt.Sprintf("egress policy reloaded revision=%d", revision)
	for {
		if data, err := readFrom(proc.logPath, offset); err == nil && strings.Contains(string(data), want) {
			return nil
		}
		select {
		case <-proc.done:
			return errors.New("gateway exited before acknowledging policy reload")
		case <-ctx.Done():
			return errors.New("gateway did not acknowledge policy reload")
		case <-ticker.C:
		}
	}
}

func readFrom(path string, offset int64) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- managed gateway log in the configured run directory
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(file, 64*1024))
}

// Close stops all managed gateways.
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	m.closed = true
	names := make([]string, 0, len(m.procs))
	for name := range m.procs {
		names = append(names, name)
	}
	starting := len(m.starting) != 0
	m.mu.Unlock()
	for _, name := range names {
		if err := m.Stop(ctx, name); err != nil {
			return err
		}
	}
	if starting {
		return errors.New("gateway startup still in progress")
	}
	return nil
}

// MAC returns a deterministic local MAC for a sandbox.
func MAC(name string) string {
	sum := sha256.Sum256([]byte(name))
	return fmt.Sprintf("fa:43:25:%02x:%02x:%02x", sum[0], sum[1], sum[2])
}

func writeConfig(path string, p policy.Policy, dnsUpstream string) error {
	if err := validatePolicy(p); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if p.AuditPath != "" {
		if err := os.MkdirAll(filepath.Dir(p.AuditPath), 0o700); err != nil {
			return err
		}
	}
	file, err := openManagedFile(path, os.O_CREATE|os.O_WRONLY)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	if err := file.Truncate(0); err != nil {
		return fmt.Errorf("truncate gateway config: %w", err)
	}
	if _, err := file.WriteString(renderConfig(p, dnsUpstream)); err != nil {
		return fmt.Errorf("write gateway config: %w", err)
	}
	return nil
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

// validatePolicy rejects rule forms the configured gvproxy policy engine
// cannot enforce. Domain matching is currently unsupported by that engine.
func validatePolicy(p policy.Policy) error {
	for _, group := range []struct {
		name  string
		rules []policy.Rule
	}{{name: "allow", rules: p.Allow}, {name: "deny", rules: p.Deny}} {
		for i, rule := range group.rules {
			if rule.Domain != "" {
				return fmt.Errorf("%s rule %d: domain policies are unsupported by the configured gateway", group.name, i)
			}
			if rule.CIDR == "" {
				return fmt.Errorf("%s rule %d: cidr is required", group.name, i)
			}
			if _, _, err := net.ParseCIDR(rule.CIDR); err != nil {
				return fmt.Errorf("%s rule %d: invalid cidr %q: %w", group.name, i, rule.CIDR, err)
			}
			protocol := strings.ToLower(strings.TrimSpace(rule.Protocol))
			if protocol != protocolTCP && protocol != protocolUDP {
				return fmt.Errorf("%s rule %d: protocol must be tcp or udp", group.name, i)
			}
		}
	}
	return nil
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
			local := fmt.Sprintf("127.0.0.1:%d", port.Host)
			if port.Proto == "udp" {
				local = "udp:" + local
			} else if port.Proto != "" && port.Proto != protocolTCP {
				continue
			}
			fmt.Fprintf(&b, "    %s: %s\n",
				strconv.Quote(local),
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

type forwardAPI struct {
	Local    string `json:"local"`
	Remote   string `json:"remote"`
	Protocol string `json:"protocol"`
}

// SetPorts reconciles gvproxy's TCP forwarders with the requested host->guest
// mappings through its private services API.
func (m *Manager) SetPorts(ctx context.Context, name string, ports []policy.Port) error {
	m.mu.Lock()
	proc, ok := m.procs[name]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("gateway for %s is not running", name)
	}
	if err := waitServicesAPI(ctx, proc); err != nil {
		return err
	}
	current, err := listForwards(ctx, proc.apiSocket)
	if err != nil {
		return err
	}
	return applyForwardDiff(ctx, proc.apiSocket, current, desiredForwards(ports))
}

func waitServicesAPI(ctx context.Context, proc process) error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(proc.apiSocket); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("gateway services API did not become ready")
		}
		select {
		case <-proc.done:
			return errors.New("gateway exited before its services API became ready")
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func desiredForwards(ports []policy.Port) map[string]forwardAPI {
	desired := make(map[string]forwardAPI, len(ports))
	for _, port := range ports {
		protocol := port.Proto
		if protocol == "" {
			protocol = protocolTCP
		}
		if protocol != protocolTCP && protocol != protocolUDP {
			continue
		}
		local := fmt.Sprintf("127.0.0.1:%d", port.Host)
		key := protocol + "|" + local
		desired[key] = forwardAPI{Local: local, Remote: fmt.Sprintf("%s:%d", guestIP, port.Guest), Protocol: protocol}
	}
	return desired
}

func applyForwardDiff(ctx context.Context, socket string, current []forwardAPI, desired map[string]forwardAPI) error {
	currentSet := make(map[string]struct{}, len(current))
	for _, forward := range current {
		protocol := forward.Protocol
		if protocol == "" {
			protocol = protocolTCP
		}
		if protocol != protocolTCP && protocol != protocolUDP {
			continue
		}
		key := protocol + "|" + forward.Local
		currentSet[key] = struct{}{}
		if _, keep := desired[key]; keep {
			continue
		}
		if err := postForward(ctx, socket, "/services/forwarder/unexpose", forwardAPI{Local: forward.Local, Protocol: protocol}); err != nil {
			return err
		}
	}
	for key, forward := range desired {
		if _, exists := currentSet[key]; exists {
			continue
		}
		if err := postForward(ctx, socket, "/services/forwarder/expose", forward); err != nil {
			return err
		}
	}
	return nil
}

func listForwards(ctx context.Context, socket string) ([]forwardAPI, error) {
	client := unixHTTPClient(socket)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://gvproxy/services/forwarder/all", http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list gateway forwards: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("list gateway forwards: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var forwards []forwardAPI
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&forwards); err != nil {
		return nil, fmt.Errorf("decode gateway forwards: %w", err)
	}
	return forwards, nil
}

func postForward(ctx context.Context, socket, endpoint string, payload forwardAPI) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://gvproxy"+endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := unixHTTPClient(socket).Do(req)
	if err != nil {
		return fmt.Errorf("gateway forward API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("gateway forward API: status %d: %s", resp.StatusCode, strings.TrimSpace(string(message)))
	}
	return nil
}

func unixHTTPClient(socket string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
		Timeout: 5 * time.Second,
	}
}
