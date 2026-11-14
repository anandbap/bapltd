//go:build windows

package sandbox

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var (
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")

	procOpenProcessToken       = modadvapi32.NewProc("OpenProcessToken")
	procCreateRestrictedToken  = modadvapi32.NewProc("CreateRestrictedToken")
	procDuplicateTokenEx       = modadvapi32.NewProc("DuplicateTokenEx")
	procSetTokenInformation    = modadvapi32.NewProc("SetTokenInformation")
	procConvertStringSidToSidW = modadvapi32.NewProc("ConvertStringSidToSidW")

	procCreateJobObjectW         = modkernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = modkernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = modkernel32.NewProc("AssignProcessToJobObject")
	procOpenProcess              = modkernel32.NewProc("OpenProcess")
	procLocalFree                = modkernel32.NewProc("LocalFree")
)

const (
	TOKEN_ASSIGN_PRIMARY = 0x0001
	TOKEN_DUPLICATE      = 0x0002
	TOKEN_QUERY          = 0x0008
	TOKEN_ALL_ACCESS     = 0xF01FF

	DISABLE_MAX_PRIVILEGE = 0x1

	SecurityImpersonation = 2
	TokenPrimary          = 1

	TokenIntegrityLevel = 25
	SE_GROUP_INTEGRITY  = 0x00000020

	JobObjectExtendedLimitInformation           = 9
	JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE          = 0x2000
	JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x0400

	PROCESS_SET_QUOTA = 0x0100
	PROCESS_TERMINATE = 0x0001
)

type sidAndAttributes struct {
	sid        uintptr
	attributes uint32
}

type tokenMandatoryLabel struct {
	label sidAndAttributes
}

var (
	restrictedTokenOnce sync.Once
	restrictedTokenOk   bool
)

func GetActiveProfile() string {
	return "windows-restricted-token"
}

// createRestrictedProcessToken creates a restricted primary token where all
// administrative, debug, and high-privilege rights are stripped via DISABLE_MAX_PRIVILEGE.
func createRestrictedProcessToken() (syscall.Token, error) {
	currentProc, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, err
	}

	var hToken syscall.Token
	r1, _, err := procOpenProcessToken.Call(
		uintptr(currentProc),
		uintptr(TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_QUERY),
		uintptr(unsafe.Pointer(&hToken)),
	)
	if r1 == 0 {
		return 0, fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(hToken))

	var hRestricted syscall.Token
	r1, _, err = procCreateRestrictedToken.Call(
		uintptr(hToken),
		uintptr(DISABLE_MAX_PRIVILEGE),
		0, 0,
		0, 0,
		0, 0,
		uintptr(unsafe.Pointer(&hRestricted)),
	)
	if r1 == 0 {
		return 0, fmt.Errorf("CreateRestrictedToken failed: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(hRestricted))

	var hPrimary syscall.Token
	r1, _, err = procDuplicateTokenEx.Call(
		uintptr(hRestricted),
		uintptr(TOKEN_ALL_ACCESS),
		0,
		uintptr(SecurityImpersonation),
		uintptr(TokenPrimary),
		uintptr(unsafe.Pointer(&hPrimary)),
	)
	if r1 == 0 {
		return 0, fmt.Errorf("DuplicateTokenEx failed: %v", err)
	}

	// Ensure the restricted token runs at Medium Mandatory Level (S-1-16-8192)
	// so standard user-mode developer toolchains (Python, Node, git) and user files
	// remain executable/readable without stripping the non-admin restriction.
	sidStr, errSid := syscall.UTF16PtrFromString("S-1-16-8192")
	if errSid == nil {
		var pSid uintptr
		rSid, _, _ := procConvertStringSidToSidW.Call(
			uintptr(unsafe.Pointer(sidStr)),
			uintptr(unsafe.Pointer(&pSid)),
		)
		if rSid != 0 {
			defer procLocalFree.Call(pSid)
			tml := tokenMandatoryLabel{
				label: sidAndAttributes{
					sid:        pSid,
					attributes: SE_GROUP_INTEGRITY,
				},
			}
			_, _, _ = procSetTokenInformation.Call(
				uintptr(hPrimary),
				uintptr(TokenIntegrityLevel),
				uintptr(unsafe.Pointer(&tml)),
				uintptr(unsafe.Sizeof(tml)),
			)
		}
	}

	return hPrimary, nil
}

// CreateRestrictedJob creates a Windows Job Object configured to terminate
// all child processes if the job object handle is closed.
func CreateRestrictedJob() (syscall.Handle, error) {
	r1, _, err := procCreateJobObjectW.Call(0, 0)
	if r1 == 0 {
		return 0, err
	}
	hJob := syscall.Handle(r1)

	var info struct {
		BasicLimitInformation struct {
			PerProcessUserTimeLimit int64
			PerJobUserTimeLimit     int64
			LimitFlags              uint32
			MinimumWorkingSetSize   uintptr
			MaximumWorkingSetSize   uintptr
			ActiveProcessLimit      uint32
			Affinity                uintptr
			PriorityClass           uint32
			SchedulingClass         uint32
		}
		IoInfo struct {
			ReadOperationCount  uint64
			WriteOperationCount uint64
			OtherOperationCount uint64
			ReadTransferCount   uint64
			WriteTransferCount  uint64
			OtherTransferCount  uint64
		}
		ProcessMemoryLimit    uintptr
		JobMemoryLimit        uintptr
		PeakProcessMemoryUsed uintptr
		PeakJobMemoryUsed     uintptr
	}

	info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION

	r1, _, err = procSetInformationJobObject.Call(
		uintptr(hJob),
		uintptr(JobObjectExtendedLimitInformation),
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Sizeof(info)),
	)
	if r1 == 0 {
		syscall.CloseHandle(hJob)
		return 0, err
	}
	return hJob, nil
}

// AssignProcessToJob binds a running process PID to the Job Object.
func AssignProcessToJob(hJob syscall.Handle, pid int) error {
	r1, _, err := procOpenProcess.Call(
		uintptr(PROCESS_SET_QUOTA|PROCESS_TERMINATE),
		0,
		uintptr(pid),
	)
	if r1 == 0 {
		return err
	}
	hProc := syscall.Handle(r1)
	defer syscall.CloseHandle(hProc)

	r1, _, err = procAssignProcessToJobObject.Call(uintptr(hJob), uintptr(hProc))
	if r1 == 0 {
		return err
	}
	return nil
}

// ConfigureSandbox configures sandbox attributes for Windows.
// It isolates process groups, hides console windows, applies the restricted token,
// and preserves raw command line formatting.
func ConfigureSandbox(cmd *exec.Cmd) func() {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags = syscall.CREATE_NEW_PROCESS_GROUP
	cmd.SysProcAttr.HideWindow = true

	// Apply Windows Restricted Token (strips all admin and debug privileges)
	token, err := createRestrictedProcessToken()
	if err == nil {
		cmd.SysProcAttr.Token = token
		restrictedTokenOk = true
	}

	// If cmd is invoking cmd.exe /c, pass the raw command string via CmdLine
	// to prevent Go's makeCmdLine from double-escaping quotes or breaking cmd.exe's parsing.
	if len(cmd.Args) >= 3 && strings.EqualFold(filepath.Base(cmd.Path), "cmd.exe") && cmd.Args[1] == "/c" {
		cmd.SysProcAttr.CmdLine = fmt.Sprintf(`cmd.exe /c %s`, cmd.Args[2])
	}

	return func() {
		if token != 0 {
			syscall.CloseHandle(syscall.Handle(token))
		}
	}
}

// PostStartProcess assigns the started process to a Windows Job Object.
func PostStartProcess(cmd *exec.Cmd) func() {
	if cmd.Process == nil || cmd.Process.Pid <= 0 {
		return func() {}
	}
	hJob, err := CreateRestrictedJob()
	if err != nil {
		return func() {}
	}
	_ = AssignProcessToJob(hJob, cmd.Process.Pid)
	var once sync.Once
	return func() {
		once.Do(func() { syscall.CloseHandle(hJob) })
	}
}
