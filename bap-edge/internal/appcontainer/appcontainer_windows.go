//go:build windows

// Package appcontainer runs a process inside a Windows AppContainer: a kernel-enforced boundary that
// needs NO administrator rights and NO Docker/WSL. An AppContainer process
//   - can read/write only paths whose ACL names its AppContainer SID (we grant the workspace and nothing
//     else, so the user's profile, ~/.ssh, ~/.aws, .env elsewhere are simply unreachable), and
//   - has no network at all unless granted capabilities (we grant none); the only way out is a pipe or
//     socket we deliberately open to it (the BAP egress proxy).
package appcontainer

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var (
	modUserenv  = syscall.NewLazyDLL("userenv.dll")
	modAdvapi   = syscall.NewLazyDLL("advapi32.dll")
	modKernel   = syscall.NewLazyDLL("kernel32.dll")
	pCreateProf = modUserenv.NewProc("CreateAppContainerProfile")
	pDeriveSid  = modUserenv.NewProc("DeriveAppContainerSidFromAppContainerName")
	pSidToStr   = modAdvapi.NewProc("ConvertSidToStringSidW")
	pFreeSid    = modAdvapi.NewProc("FreeSid")
	pLocalFree  = modKernel.NewProc("LocalFree")
	pInitAttr   = modKernel.NewProc("InitializeProcThreadAttributeList")
	pUpdAttr    = modKernel.NewProc("UpdateProcThreadAttribute")
	pDelAttr    = modKernel.NewProc("DeleteProcThreadAttributeList")
	pCreateProc = modKernel.NewProc("CreateProcessW")
)

const (
	procThreadAttributeSecurityCapabilities = 0x00020009
	extendedStartupInfoPresent              = 0x00080000
	createUnicodeEnvironment                = 0x00000400
	errAlreadyExistsHR                      = 0x800700B7
)

type securityCapabilities struct {
	AppContainerSid uintptr
	Capabilities    uintptr
	CapabilityCount uint32
	Reserved        uint32
}

type startupInfoEx struct {
	syscall.StartupInfo
	AttributeList uintptr
}

// Options describes one contained run.
type Options struct {
	Name     string // AppContainer profile name (per workspace)
	Argv     []string
	Dir      string
	Env      []string
	Writable []string // directories granted read/write (workspace)
	Readable []string // files/directories granted read+execute (the tool binaries it must run)
	Stdin    *os.File
	Stdout   *os.File
	Stderr   *os.File
}

func hrFailed(r uintptr) bool { return int32(r) < 0 }

// SID returns the string SID of the named AppContainer, creating the profile on first use.
func SID(name string) (string, error) {
	n, _ := syscall.UTF16PtrFromString(name)
	d, _ := syscall.UTF16PtrFromString("BAP agent sandbox")
	var psid uintptr
	r, _, _ := pCreateProf.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(d)), uintptr(unsafe.Pointer(d)), 0, 0, uintptr(unsafe.Pointer(&psid)))
	if hrFailed(r) {
		if uint32(r) != errAlreadyExistsHR {
			return "", fmt.Errorf("CreateAppContainerProfile: 0x%08x", uint32(r))
		}
		r, _, _ = pDeriveSid.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(&psid)))
		if hrFailed(r) {
			return "", fmt.Errorf("DeriveAppContainerSidFromAppContainerName: 0x%08x", uint32(r))
		}
	}
	defer pFreeSid.Call(psid)
	var sp *uint16
	if ok, _, e := pSidToStr.Call(psid, uintptr(unsafe.Pointer(&sp))); ok == 0 {
		return "", fmt.Errorf("ConvertSidToStringSid: %v", e)
	}
	defer pLocalFree.Call(uintptr(unsafe.Pointer(sp)))
	return syscall.UTF16ToString((*[256]uint16)(unsafe.Pointer(sp))[:]), nil
}

// Grant gives the AppContainer access to path. mode: "M" (modify) or "RX" (read+execute). Directories get
// inheritable ACEs. Uses icacls, which a standard user may run on files they own.
func Grant(sid, path, mode string) error {
	perm := mode
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		perm = "(OI)(CI)" + mode
	} else if err != nil {
		return err
	} else {
		perm = mode
	}
	out, err := exec.Command("icacls", path, "/grant", "*"+sid+":"+perm, "/Q").CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls grant %s: %v: %s", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func envBlock(env []string) *uint16 {
	// Never inherit the launcher's environment (it may hold tokens): always an explicit block. Windows
	// rejects entries with an empty value, so drop them, and a process needs SystemRoot to start.
	// Measured on Windows 11: CreateProcess into an AppContainer fails with ERROR_ENVVAR_NOT_FOUND unless the
	// block carries the standard profile/system variables. They are locations and names, not secrets, and
	// the contained process cannot read those locations anyway.
	have := map[string]bool{}
	var clean []string
	for _, e := range env {
		if i := strings.IndexByte(e, '='); i > 0 && i < len(e)-1 {
			clean = append(clean, e)
			have[strings.ToUpper(e[:i])] = true
		}
	}
	defaults := map[string]string{"SystemRoot": `C:\Windows`, "windir": `C:\Windows`, "SystemDrive": "C:", "ComSpec": `C:\Windows\System32\cmd.exe`,
		"PATHEXT": ".COM;.EXE;.BAT;.CMD", "LOCALAPPDATA": "", "APPDATA": "", "USERPROFILE": "", "HOMEDRIVE": "", "HOMEPATH": "", "USERNAME": "", "COMPUTERNAME": ""}
	for k, def := range defaults {
		if have[strings.ToUpper(k)] {
			continue
		}
		v := os.Getenv(k)
		if v == "" {
			v = def
		}
		if v != "" {
			clean = append(clean, k+"="+v)
		}
	}
	env = clean
	var b []uint16
	sort.Slice(env, func(i, j int) bool { return strings.ToUpper(env[i]) < strings.ToUpper(env[j]) }) // Windows wants a sorted block
	for _, e := range env {
		b = append(b, utf16.Encode([]rune(e))...)
		b = append(b, 0)
	}
	b = append(b, 0, 0)
	return &b[0]
}

func quoteArg(a string) string {
	if a != "" && !strings.ContainsAny(a, " \t\"") {
		return a
	}
	return `"` + strings.ReplaceAll(strings.ReplaceAll(a, `\`, `\\`), `"`, `\"`) + `"`
}

// Run grants the AppContainer access to Writable/Readable, starts argv inside it with no capabilities
// (no network), waits, and returns the exit code.
func Run(o Options) (int, error) {
	if len(o.Argv) == 0 {
		return 2, fmt.Errorf("appcontainer: no command")
	}
	sid, err := SID(o.Name)
	if err != nil {
		return 2, err
	}
	for _, w := range o.Writable {
		if err := Grant(sid, w, "M"); err != nil {
			return 2, err
		}
	}
	for _, r := range o.Readable {
		if err := Grant(sid, r, "RX"); err != nil {
			return 2, err
		}
	}

	// SID string -> binary SID for SECURITY_CAPABILITIES.
	var psid uintptr
	n, _ := syscall.UTF16PtrFromString(o.Name)
	if r, _, _ := pDeriveSid.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(&psid))); hrFailed(r) {
		return 2, fmt.Errorf("derive sid: 0x%08x", uint32(r))
	}
	defer pFreeSid.Call(psid)
	sc := securityCapabilities{AppContainerSid: psid}

	var size uintptr
	pInitAttr.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)))
	buf := make([]byte, size)
	list := uintptr(unsafe.Pointer(&buf[0]))
	if r, _, e := pInitAttr.Call(list, 1, 0, uintptr(unsafe.Pointer(&size))); r == 0 {
		return 2, fmt.Errorf("InitializeProcThreadAttributeList: %v", e)
	}
	defer pDelAttr.Call(list)
	if r, _, e := pUpdAttr.Call(list, 0, procThreadAttributeSecurityCapabilities, uintptr(unsafe.Pointer(&sc)), unsafe.Sizeof(sc), 0, 0); r == 0 {
		return 2, fmt.Errorf("UpdateProcThreadAttribute: %v", e)
	}

	si := startupInfoEx{AttributeList: list}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = syscall.STARTF_USESTDHANDLES
	stdin, stdout, stderr := o.Stdin, o.Stdout, o.Stderr
	if stdin == nil {
		stdin = os.Stdin
	}
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	for _, f := range []*os.File{stdin, stdout, stderr} {
		_ = syscall.SetHandleInformation(syscall.Handle(f.Fd()), syscall.HANDLE_FLAG_INHERIT, syscall.HANDLE_FLAG_INHERIT)
	}
	si.StdInput, si.StdOutput, si.StdErr = syscall.Handle(stdin.Fd()), syscall.Handle(stdout.Fd()), syscall.Handle(stderr.Fd())

	parts := make([]string, len(o.Argv))
	for i, a := range o.Argv {
		parts[i] = quoteArg(a)
	}
	cmdline, _ := syscall.UTF16PtrFromString(strings.Join(parts, " "))
	var dir *uint16
	if o.Dir != "" {
		dir, _ = syscall.UTF16PtrFromString(o.Dir)
	}
	var pi syscall.ProcessInformation
	r, _, e := pCreateProc.Call(0, uintptr(unsafe.Pointer(cmdline)), 0, 0, 1,
		extendedStartupInfoPresent|createUnicodeEnvironment,
		uintptr(unsafe.Pointer(envBlock(o.Env))), uintptr(unsafe.Pointer(dir)),
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		return 2, fmt.Errorf("CreateProcess in AppContainer: %v", e)
	}
	defer syscall.CloseHandle(pi.Thread)
	defer syscall.CloseHandle(pi.Process)
	if ev, err := syscall.WaitForSingleObject(pi.Process, syscall.INFINITE); err != nil || ev != 0 {
		return 2, fmt.Errorf("wait: %v", err)
	}
	var code uint32
	if err := syscall.GetExitCodeProcess(pi.Process, &code); err != nil {
		return 2, err
	}
	return int(code), nil
}
