//go:build windows

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"

	"retransmission-vpn/internal/client"
	"retransmission-vpn/internal/config"
	"retransmission-vpn/internal/netutil"
)

type AppWindow struct {
	*walk.MainWindow
	serverEdit *walk.LineEdit
	keyEdit    *walk.LineEdit
	connectBtn *walk.PushButton
	statusLbl  *walk.Label
	trayIcon   *walk.NotifyIcon

	vpnClient *client.VPNClient
	connected bool
	mu        sync.Mutex
}

func main() {
	// Prevent duplicate instances
	mutex, err := windows.CreateMutex(nil, false, windows.StringToUTF16Ptr("VPNClientMutex"))
	if err != nil || windows.GetLastError() == windows.ERROR_ALREADY_EXISTS {
		return
	}
	defer windows.CloseHandle(mutex)

	mw := &AppWindow{}

	if err := (MainWindow{
		AssignTo: &mw.MainWindow,
		Title:    "VPN Client",
		MinSize:  Size{Width: 280, Height: 180},
		Size:     Size{Width: 280, Height: 180},
		Layout:   VBox{},
		Children: []Widget{
			Label{Text: "서버 IP:"},
			LineEdit{AssignTo: &mw.serverEdit},
			Label{Text: "인증 키:"},
			LineEdit{AssignTo: &mw.keyEdit, PasswordMode: true},
			PushButton{
				AssignTo:  &mw.connectBtn,
				Text:      "연결",
				OnClicked: func() { mw.onConnect() },
			},
			Label{AssignTo: &mw.statusLbl, Text: "연결 안됨"},
		},
	}).Create(); err != nil {
		return
	}

	// Center window on screen
	screenW := int(win.GetSystemMetrics(win.SM_CXSCREEN))
	screenH := int(win.GetSystemMetrics(win.SM_CYSCREEN))
	winBounds := mw.Bounds()
	mw.SetBounds(walk.Rectangle{
		X:      (screenW - winBounds.Width) / 2,
		Y:      (screenH - winBounds.Height) / 2,
		Width:  winBounds.Width,
		Height: winBounds.Height,
	})

	if savedIP := loadServerIP(); savedIP != "" {
		mw.serverEdit.SetText(savedIP)
	}

	mw.setupTray()
	defer mw.trayIcon.Dispose()

	mw.Run()
}

func (mw *AppWindow) setupTray() {
	var err error
	mw.trayIcon, err = walk.NewNotifyIcon(mw.MainWindow)
	if err != nil {
		return
	}

	// Minimize to tray on close
	mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		if mw.trayIcon != nil {
			*canceled = true
			mw.SetVisible(false)
		}
	})

	// Use default system icon
	icon, _ := walk.NewIconFromSysDLL("shell32", 14)
	if icon != nil {
		mw.trayIcon.SetIcon(icon)
		mw.SetIcon(icon)
	}

	mw.trayIcon.SetToolTip("VPN Client")
	mw.trayIcon.SetVisible(true)

	mw.trayIcon.MouseUp().Attach(func(x, y int, btn walk.MouseButton) {
		if btn == walk.LeftButton {
			mw.Show()
			mw.Activate()
		}
	})

	exitAction := walk.NewAction()
	exitAction.SetText("종료")
	exitAction.Triggered().Attach(func() {
		mw.mu.Lock()
		if mw.vpnClient != nil {
			mw.vpnClient.Stop()
		}
		mw.mu.Unlock()
		walk.App().Exit(0)
	})
	mw.trayIcon.ContextMenu().Actions().Add(exitAction)
}

func (mw *AppWindow) onConnect() {
	mw.mu.Lock()
	defer mw.mu.Unlock()

	if mw.connected {
		if mw.vpnClient != nil {
			mw.vpnClient.Stop()
			mw.vpnClient = nil
		}
		mw.connected = false
		mw.connectBtn.SetText("연결")
		mw.statusLbl.SetText("연결 안됨")
		return
	}

	addr := mw.serverEdit.Text()
	serverIP, serverPort := parseAddr(addr)
	if serverIP == nil {
		mw.statusLbl.SetText("잘못된 서버 IP")
		return
	}

	key := strings.TrimSpace(mw.keyEdit.Text())
	if key == "" {
		mw.statusLbl.SetText("PSK 필요")
		return
	}

	if !netutil.IsAdmin() {
		mw.statusLbl.SetText("관리자 권한 필요")
		return
	}

	mw.vpnClient = client.New(serverIP, serverPort, []byte(key),
		client.WithStatusCallback(func(status string) {
			mw.Synchronize(func() {
				mw.statusLbl.SetText(status)
			})
		}),
	)

	mw.statusLbl.SetText("연결 중...")
	mw.connectBtn.SetEnabled(false)

	go func() {
		err := mw.vpnClient.Start()

		mw.Synchronize(func() {
			mw.mu.Lock()
			defer mw.mu.Unlock()

			if err != nil {
				mw.statusLbl.SetText(fmt.Sprintf("실패: %v", err))
				mw.connectBtn.SetText("연결")
				mw.connectBtn.SetEnabled(true)
				mw.vpnClient = nil
				return
			}

			mw.connected = true
			mw.statusLbl.SetText("연결됨")
			mw.connectBtn.SetText("연결 해제")
			mw.connectBtn.SetEnabled(true)
			saveServerIP(mw.serverEdit.Text())
		})
	}()
}

func parseAddr(addr string) (net.IP, uint16) {
	if strings.Contains(addr, ":") {
		parts := strings.Split(addr, ":")
		ip := net.ParseIP(parts[0])
		port, err := strconv.Atoi(parts[1])
		if err != nil || port <= 0 || port > 65535 {
			return ip, config.DefaultPort
		}
		return ip, uint16(port)
	}
	return net.ParseIP(addr), config.DefaultPort
}

func getConfigPath() string {
	exe, _ := os.Executable()
	return filepath.Join(filepath.Dir(exe), "config.txt")
}

func loadServerIP() string {
	data, err := os.ReadFile(getConfigPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func saveServerIP(ip string) {
	os.WriteFile(getConfigPath(), []byte(ip), 0644)
}
