//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// Win32 DLL + Proc declarations (tray icon subset only)
var (
	user32DLL   = syscall.NewLazyDLL("user32.dll")
	shell32DLL  = syscall.NewLazyDLL("shell32.dll")
	kernel32DLL = syscall.NewLazyDLL("kernel32.dll")
)

var (
	procSetForegroundWindow = user32DLL.NewProc("SetForegroundWindow")
	procPostMessageW        = user32DLL.NewProc("PostMessageW")

	// Tray icon
	procShell_NotifyIconW = shell32DLL.NewProc("Shell_NotifyIconW")

	// Window class / message loop
	procRegisterClassExW = user32DLL.NewProc("RegisterClassExW")
	procCreateWindowExW  = user32DLL.NewProc("CreateWindowExW")
	procDefWindowProcW   = user32DLL.NewProc("DefWindowProcW")
	procGetMessageW      = user32DLL.NewProc("GetMessageW")
	procTranslateMessage = user32DLL.NewProc("TranslateMessage")
	procDispatchMessageW = user32DLL.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32DLL.NewProc("PostQuitMessage")
	procLoadIconW        = user32DLL.NewProc("LoadIconW")
	procLoadCursorW      = user32DLL.NewProc("LoadCursorW")
	procDestroyWindow    = user32DLL.NewProc("DestroyWindow")

	// Context menu
	procCreatePopupMenu = user32DLL.NewProc("CreatePopupMenu")
	procAppendMenuW     = user32DLL.NewProc("AppendMenuW")
	procTrackPopupMenu  = user32DLL.NewProc("TrackPopupMenu")
	procDestroyMenu     = user32DLL.NewProc("DestroyMenu")
	procGetCursorPos    = user32DLL.NewProc("GetCursorPos")

	// Module / console
	procGetModuleHandleW = kernel32DLL.NewProc("GetModuleHandleW")
	procGetConsoleWindow = kernel32DLL.NewProc("GetConsoleWindow")
	procShowWindow       = user32DLL.NewProc("ShowWindow")
)

// Win32 constants
const (
	wmApp       = 0x8000
	wmCommand   = 0x0111
	wmDestroy   = 0x0002
	wmRButtonUp = 0x0205

	wmTrayIcon  = wmApp + 1
	wmUpdateTip = wmApp + 2

	wsExToolWindow = 0x00000080

	nimAdd    = 0
	nimModify = 1
	nimDelete = 2

	nifMessage = 0x01
	nifIcon    = 0x02
	nifTip     = 0x04

	idiApplication = 32512
	idcArrow       = 32512

	mfString    = 0x0000
	mfSeparator = 0x0800
	mfGrayed    = 0x0001

	tpmBottomAlign = 0x0020
	tpmLeftAlign   = 0x0000

	swHide = 0
)

// Win32 structs
type point struct {
	X, Y int32
}

type msg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

type wndClassExW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm      uintptr
}

type notifyIconDataW struct {
	CbSize           uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         [16]byte
	HBalloonIcon     uintptr
}

func utf16Ptr(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func appendMenu(menu uintptr, flags, id uint32, text string) {
	procAppendMenuW.Call(menu, uintptr(flags), uintptr(id),
		uintptr(unsafe.Pointer(utf16Ptr(text))))
}

func hideConsole() {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		procShowWindow.Call(hwnd, swHide)
	}
}
