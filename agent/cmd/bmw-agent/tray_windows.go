//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	trayAppName = "BMW Agent"
	idmQuit     = 2001
)

var (
	gHwnd     uintptr
	gNID      notifyIconDataW
	gModCount int
	gPollSec  int
)

// initPlatform redirects log output to a file (no console in tray mode).
func initPlatform() {
	logPath := resolveRelPath("bmw-agent.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	log.SetOutput(logFile)
	log.SetFlags(log.Ldate | log.Ltime)
}

func resolveRelPath(name string) string {
	exe, err := os.Executable()
	if err != nil {
		return name
	}
	return filepath.Join(filepath.Dir(exe), name)
}

// waitForShutdown hides the console, shows a tray icon, and blocks until quit.
func waitForShutdown(moduleCount, pollInterval int) {
	gModCount = moduleCount
	gPollSec = pollInterval

	hideConsole()
	runtime.LockOSThread()

	hInstance, _, _ := procGetModuleHandleW.Call(0)

	className := utf16Ptr("BMWAgentClass")
	hIcon, _, _ := procLoadIconW.Call(hInstance, uintptr(1))
	if hIcon == 0 {
		hIcon, _, _ = procLoadIconW.Call(0, uintptr(idiApplication))
	}
	hCursor, _, _ := procLoadCursorW.Call(0, uintptr(idcArrow))

	wc := wndClassExW{
		Style:         0,
		LpfnWndProc:   syscall.NewCallback(wndProc),
		HInstance:     hInstance,
		HIcon:         hIcon,
		HCursor:       hCursor,
		HbrBackground: 0,
		LpszClassName: className,
		HIconSm:      hIcon,
	}
	wc.CbSize = uint32(unsafe.Sizeof(wc))

	atom, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		log.Fatalf("RegisterClassExW failed: %v", err)
	}

	hwnd, _, err := procCreateWindowExW.Call(
		uintptr(wsExToolWindow),
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(utf16Ptr(trayAppName))),
		0, 0, 0, 0, 0, 0, 0, hInstance, 0,
	)
	if hwnd == 0 {
		log.Fatalf("CreateWindowExW failed: %v", err)
	}
	gHwnd = hwnd

	addTrayIcon(hwnd, hIcon)
	log.Println("INFO: tray icon created")

	// Message loop (blocks until WM_QUIT)
	var m msg
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if ret == 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}

	removeTrayIcon()
	procDestroyWindow.Call(hwnd)
}

func addTrayIcon(hwnd, hIcon uintptr) {
	gNID = notifyIconDataW{}
	gNID.CbSize = uint32(unsafe.Sizeof(gNID))
	gNID.HWnd = hwnd
	gNID.UID = 1
	gNID.UFlags = nifMessage | nifIcon | nifTip
	gNID.UCallbackMessage = wmTrayIcon
	gNID.HIcon = hIcon
	setTip(&gNID, buildTooltip())
	procShell_NotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&gNID)))
}

func removeTrayIcon() {
	procShell_NotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&gNID)))
}

func buildTooltip() string {
	tip := fmt.Sprintf("%s | %d modules | poll %ds", trayAppName, gModCount, gPollSec)
	if len(tip) > 127 {
		tip = tip[:127]
	}
	return tip
}

func setTip(nid *notifyIconDataW, tip string) {
	tipUTF16, _ := syscall.UTF16FromString(tip)
	for i := range nid.SzTip {
		nid.SzTip[i] = 0
	}
	copy(nid.SzTip[:], tipUTF16)
}

func showContextMenu(hwnd uintptr) {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}

	info := fmt.Sprintf("Modules: %d | Poll: %ds", gModCount, gPollSec)
	appendMenu(menu, mfString|mfGrayed, 0, info)
	appendMenu(menu, mfSeparator, 0, "")
	appendMenu(menu, mfString, idmQuit, "Quit")

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(hwnd)

	procTrackPopupMenu.Call(menu,
		uintptr(tpmBottomAlign|tpmLeftAlign),
		uintptr(pt.X), uintptr(pt.Y),
		0, hwnd, 0,
	)
	procDestroyMenu.Call(menu)
}

func wndProc(hwnd, m, wParam, lParam uintptr) uintptr {
	switch uint32(m) {
	case wmTrayIcon:
		if uint32(lParam) == wmRButtonUp {
			showContextMenu(hwnd)
		}
		return 0
	case wmCommand:
		if uint32(wParam&0xFFFF) == idmQuit {
			procPostQuitMessage.Call(0)
		}
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	ret, _, _ := procDefWindowProcW.Call(hwnd, m, wParam, lParam)
	return ret
}
