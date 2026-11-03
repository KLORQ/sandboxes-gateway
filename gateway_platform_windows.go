//go:build windows

package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
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
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/rheic/sandboxes-gateway/policy"
)

func checkGatewayPlatform() error { return ErrWindowsTransportUnavailable }

func configureGatewayProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
}

func gatewayEndpoints(runDir, name string) (string, string, string, error) {
	networkPort, err := freeGatewayPort()
	if err != nil {
		return "", "", "", err
	}
	var apiPort int
	for attempt := 0; attempt < 8; attempt++ {
		apiPort, err = freeGatewayPort()
		if err != nil {
			return "", "", "", err
		}
		if apiPort != networkPort {
			break
		}
	}
	if apiPort == networkPort {
		return "", "", "", errors.New("could not allocate distinct gateway loopback ports")
	}
	return "tcp://127.0.0.1:" + strconv.Itoa(networkPort),
		"tcp://127.0.0.1:" + strconv.Itoa(apiPort), filepath.Join(runDir, name+".api-token"), nil
}

func freeGatewayPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("reserve gateway loopback port: %w", err)
	}
	defer func() { _ = listener.Close() }()
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address.Port < 1 || address.Port > 65535 {
		return 0, errors.New("gateway loopback listener returned an invalid port")
	}
	return address.Port, nil
}

func ensureGatewayEndpointAvailable(endpoint string) error {
	if !strings.HasPrefix(endpoint, "tcp://127.0.0.1:") {
		return errors.New("Windows gateway endpoints must use IPv4 loopback TCP")
	}
	address := strings.TrimPrefix(endpoint, "tcp://")
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("Windows gateway endpoint is already occupied: %w", err)
	}
	return listener.Close()
}

func createGatewayAPIToken(path string) (string, error) {
	if path == "" {
		return "", errors.New("Windows gateway API token path is required")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate gateway API token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	file, err := openManagedFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if err != nil {
		return "", fmt.Errorf("create private gateway API token: %w", err)
	}
	if _, err := file.WriteString(token + "\n"); err != nil {
		_ = file.Close()
		_ = removeManagedGatewaySecret(path)
		return "", fmt.Errorf("write gateway API token: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = removeManagedGatewaySecret(path)
		return "", fmt.Errorf("sync gateway API token: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = removeManagedGatewaySecret(path)
		return "", fmt.Errorf("close gateway API token: %w", err)
	}
	return token, nil
}

func removeManagedGatewaySecret(path string) error {
	if path == "" {
		return nil
	}
	file, err := openManagedFile(path, os.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("verify private gateway token before removal: %w", err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove gateway token: %w", err)
	}
	return nil
}

type windowsGatewayJob struct {
	handle windows.Handle
	once   sync.Once
	err    error
}

func (j *windowsGatewayJob) Close() error {
	j.once.Do(func() { j.err = windows.CloseHandle(j.handle) })
	return j.err
}

func startManagedGateway(_ string, gvproxy, configPath, networkEndpoint, apiEndpoint, tokenPath string, logFile *os.File) (*exec.Cmd, io.Closer, error) {
	if gvproxy == "" || tokenPath == "" {
		return nil, nil, errors.New("Windows gateway requires gvproxy and a private API token")
	}
	job, err := newGatewayKillOnCloseJob()
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.Command(gvproxy, // #nosec G204 -- operator-configured pinned local gateway binary, argv is constructed here without a shell
		"-config", configPath,
		"-require-egress-policy",
		"-listen-qemu", networkEndpoint,
		"-services", apiEndpoint,
		"-api-token-file", tokenPath,
	)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	configureGatewayProcess(cmd)
	if err := cmd.Start(); err != nil {
		_ = job.Close()
		return nil, nil, fmt.Errorf("start Windows gateway: %w", err)
	}
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err == nil {
		err = windows.AssignProcessToJobObject(job.handle, process)
		_ = windows.CloseHandle(process)
	}
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = job.Close()
		return nil, nil, fmt.Errorf("assign gateway to kill-on-close job: %w", err)
	}
	return cmd, job, nil
}

func newGatewayKillOnCloseJob() (*windowsGatewayJob, error) {
	handle, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create Windows gateway job: %w", err)
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(handle, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("set gateway job kill-on-close policy: %w", err)
	}
	return &windowsGatewayJob{handle: handle}, nil
}

func gatewayEndpointReady(ctx context.Context, _, apiEndpoint, token string, _ <-chan struct{}) bool {
	readyCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	_, err := listForwardsAuth(readyCtx, apiEndpoint, token)
	return err == nil
}

func qemuNetworkEndpoint(endpoint string) string { return strings.TrimPrefix(endpoint, "tcp://") }

func gatewayNetworkAnnotations(string, string) []string { return nil }

func staleGatewayEndpoints(string, string) []string { return nil }

func verifyGatewayEndpointStopped(string) error { return nil }

func reloadGateway(ctx context.Context, proc process, next policy.Policy, _ int64) error {
	if err := validateGatewayAPIAuth(proc.apiSocket, proc.apiToken); err != nil {
		return err
	}
	allow, deny := make([]gatewayEgressRule, 0, len(next.Allow)), make([]gatewayEgressRule, 0, len(next.Deny))
	for _, rule := range next.Allow {
		allow = append(allow, gatewayRule(rule))
	}
	for _, rule := range next.Deny {
		deny = append(deny, gatewayRule(rule))
	}
	payload, err := json.Marshal(gatewayEgressPolicy{
		Revision: strconv.Itoa(next.Revision), SandboxID: next.SandboxID,
		Allow: allow, Deny: deny, AuditLog: next.AuditPath,
	})
	if err != nil {
		return fmt.Errorf("encode gateway egress policy: %w", err)
	}
	client, err := gatewayHTTPClient(proc.apiSocket)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://gvproxy/services/egress-policy/reload", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+proc.apiToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("reload Windows gateway policy: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("reload Windows gateway policy returned HTTP %d", resp.StatusCode)
	}
	var ack struct {
		Revision string `json:"revision"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ack); err != nil || ack.Revision != strconv.Itoa(next.Revision) {
		return ErrReloadUnverified
	}
	return nil
}

type gatewayEgressRule struct {
	ID       string `json:"id,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	CIDR     string `json:"cidr,omitempty"`
	Port     uint16 `json:"port,omitempty"`
	Domain   string `json:"domain,omitempty"`
}

type gatewayEgressPolicy struct {
	Revision  string              `json:"revision"`
	SandboxID string              `json:"sandboxID"`
	AllowAny  bool                `json:"allowAny,omitempty"`
	Allow     []gatewayEgressRule `json:"allow,omitempty"`
	Deny      []gatewayEgressRule `json:"deny,omitempty"`
	AuditLog  string              `json:"auditLog,omitempty"`
}

func gatewayRule(rule policy.Rule) gatewayEgressRule {
	protocol := rule.Protocol
	if protocol == "" {
		protocol = "tcp"
	}
	return gatewayEgressRule{ID: rule.ID, Protocol: protocol, CIDR: rule.CIDR, Port: rule.Port, Domain: rule.Domain}
}

func validateGatewayAPIAuth(endpoint, token string) error {
	if strings.HasPrefix(endpoint, "tcp://") && token == "" {
		return errors.New("Windows gateway TCP API requires bearer authentication")
	}
	return nil
}

func gatewayTCPReady(endpoint string) bool {
	conn, err := net.Dial("tcp", strings.TrimPrefix(endpoint, "tcp://"))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
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
	creationMode := uint32(windows.OPEN_EXISTING)
	if flags&os.O_CREATE != 0 {
		creationMode = windows.OPEN_ALWAYS
		if flags&os.O_EXCL != 0 {
			creationMode = windows.CREATE_NEW
		}
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ, &sa, creationMode,
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
