package gui

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
	"win-encrypt/internal/crypto"

	"github.com/lxn/win"
)

var (
	user32  = syscall.NewLazyDLL("user32.dll")
	shell32 = syscall.NewLazyDLL("shell32.dll")

	setWindowText       = user32.NewProc("SetWindowTextW")
	getWindowTextLength = user32.NewProc("GetWindowTextLengthW")
	getWindowText       = user32.NewProc("GetWindowTextW")

	passwordEdit   win.HWND
	filePathEdit   win.HWND
	selectedFiles  []string
	operationMutex sync.Mutex
	isProcessing   bool
)

const (
	ID_PASSWORDEDIT = 1
	ID_FILEPATHEDIT = 2
	ID_SELECTFILES  = 3
	ID_SELECTFOLDER = 4
	ID_ENCRYPT      = 5
	ID_DECRYPT      = 6
	ID_RECOVERY     = 7
	ID_ABOUT        = 8

	MAX_PATH             = 260
	BIF_RETURNONLYFSDIRS = 0x00000001
	BIF_NEWDIALOGSTYLE   = 0x00000040

	WM_UPDATE_PROGRESS = win.WM_USER + 1
)

func sendProgress(hwnd win.HWND, current, total int, message string) {
	win.SendMessage(hwnd, WM_UPDATE_PROGRESS, uintptr(current), uintptr(total))
	setWindowTextStr(filePathEdit, message)
}

func RunApp() error {
	className, _ := syscall.UTF16PtrFromString("FileEncryptorClass")
	windowName, _ := syscall.UTF16PtrFromString("File Encryptor")

	wc := win.WNDCLASSEX{
		CbSize:        uint32(unsafe.Sizeof(win.WNDCLASSEX{})),
		Style:         win.CS_HREDRAW | win.CS_VREDRAW,
		LpfnWndProc:   syscall.NewCallback(wndProc),
		HInstance:     win.GetModuleHandle(nil),
		HbrBackground: win.COLOR_BTNFACE + 1,
		LpszClassName: className,
	}

	if atom := win.RegisterClassEx(&wc); atom == 0 {
		return syscall.GetLastError()
	}

	hwnd := win.CreateWindowEx(
		0,
		className,
		windowName,
		win.WS_OVERLAPPEDWINDOW,
		win.CW_USEDEFAULT,
		win.CW_USEDEFAULT,
		500,
		400,
		0,
		0,
		win.GetModuleHandle(nil),
		nil)

	if hwnd == 0 {
		return syscall.GetLastError()
	}

	win.ShowWindow(hwnd, win.SW_SHOW)
	win.UpdateWindow(hwnd)

	var msg win.MSG
	for win.GetMessage(&msg, 0, 0, 0) > 0 {
		win.TranslateMessage(&msg)
		win.DispatchMessage(&msg)
	}

	return nil
}

func createControls(hwnd win.HWND) {
	passwordLabel, _ := syscall.UTF16PtrFromString("Hasło:")
	win.CreateWindowEx(
		0,
		syscall.StringToUTF16Ptr("STATIC"),
		passwordLabel,
		win.WS_CHILD|win.WS_VISIBLE,
		10, 10, 70, 20,
		hwnd,
		0,
		win.GetModuleHandle(nil),
		nil)

	passwordEdit = win.CreateWindowEx(
		win.WS_EX_CLIENTEDGE,
		syscall.StringToUTF16Ptr("EDIT"),
		nil,
		win.WS_CHILD|win.WS_VISIBLE|win.ES_PASSWORD|win.ES_AUTOHSCROLL,
		90, 10, 380, 20,
		hwnd,
		win.HMENU(ID_PASSWORDEDIT),
		win.GetModuleHandle(nil),
		nil)

	filePathEdit = win.CreateWindowEx(
		win.WS_EX_CLIENTEDGE,
		syscall.StringToUTF16Ptr("EDIT"),
		nil,
		win.WS_CHILD|win.WS_VISIBLE|win.ES_MULTILINE|win.ES_AUTOVSCROLL|win.WS_VSCROLL|win.ES_READONLY,
		10, 40, 460, 150,
		hwnd,
		win.HMENU(ID_FILEPATHEDIT),
		win.GetModuleHandle(nil),
		nil)

	createButton(hwnd, "Wybierz pliki", 10, 200, 100, 30, ID_SELECTFILES)
	createButton(hwnd, "Wybierz folder", 120, 200, 100, 30, ID_SELECTFOLDER)
	createButton(hwnd, "Szyfruj", 10, 240, 100, 30, ID_ENCRYPT)
	createButton(hwnd, "Deszyfruj", 120, 240, 100, 30, ID_DECRYPT)
	createButton(hwnd, "Recovery", 230, 240, 100, 30, ID_RECOVERY)
	createButton(hwnd, "O programie", 10, 280, 100, 30, ID_ABOUT)
}

func wndProc(hwnd win.HWND, msg uint32, wparam, lparam uintptr) uintptr {
	switch msg {
	case win.WM_CREATE:
		createControls(hwnd)
		return 0

	case win.WM_COMMAND:
		id := win.LOWORD(uint32(wparam))
		switch id {
		case ID_SELECTFILES:
			if !isProcessing {
				go func() {
					operationMutex.Lock()
					defer operationMutex.Unlock()
					isProcessing = true
					selectFiles(hwnd)
					isProcessing = false
				}()
			}
		case ID_SELECTFOLDER:
			if !isProcessing {
				go func() {
					operationMutex.Lock()
					defer operationMutex.Unlock()
					isProcessing = true
					selectFolder(hwnd)
					isProcessing = false
				}()
			}
		case ID_ENCRYPT:
			if !isProcessing {
				go func() {
					operationMutex.Lock()
					defer operationMutex.Unlock()
					isProcessing = true
					encrypt(hwnd)
					isProcessing = false
				}()
			}
		case ID_DECRYPT:
			if !isProcessing {
				go func() {
					operationMutex.Lock()
					defer operationMutex.Unlock()
					isProcessing = true
					decrypt(hwnd)
					isProcessing = false
				}()
			}
		case ID_RECOVERY:
			if !isProcessing {
				go func() {
					operationMutex.Lock()
					defer operationMutex.Unlock()
					isProcessing = true
					handleRecovery(hwnd)
					isProcessing = false
				}()
			}
		case ID_ABOUT:
			showAbout(hwnd)
		}
		return 0

	case WM_UPDATE_PROGRESS:
		current := int(wparam)
		total := int(lparam)
		if current > 0 && total > 0 {
			text := fmt.Sprintf("Postęp: %d/%d", current, total)
			setWindowTextStr(filePathEdit, text)
		}
		return 0

	case win.WM_DESTROY:
		win.PostQuitMessage(0)
		return 0
	}

	return win.DefWindowProc(hwnd, msg, wparam, lparam)
}

func selectFiles(hwnd win.HWND) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	filename := make([]uint16, 32768)
	ofn := win.OPENFILENAME{
		LStructSize: uint32(unsafe.Sizeof(win.OPENFILENAME{})),
		HwndOwner:   hwnd,
		LpstrFile:   &filename[0],
		NMaxFile:    uint32(len(filename)),
		Flags:       win.OFN_FILEMUSTEXIST | win.OFN_HIDEREADONLY | win.OFN_ALLOWMULTISELECT | win.OFN_EXPLORER,
	}

	if win.GetOpenFileName(&ofn) {
		selectedFiles = nil
		runtime.GC()

		path := syscall.UTF16ToString(filename)
		if path != "" {
			selectedFiles = append(selectedFiles, path)
			setWindowTextStr(filePathEdit, path)
		}
	}
}

func selectFolder(hwnd win.HWND) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var bi win.BROWSEINFO
	bi.HwndOwner = hwnd
	bi.UlFlags = uint32(BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE)

	title, _ := syscall.UTF16PtrFromString("Wybierz folder")
	bi.LpszTitle = title

	lpItem, _, _ := shell32.NewProc("SHBrowseForFolderW").Call(uintptr(unsafe.Pointer(&bi)))
	if lpItem == 0 {
		return
	}

	pathBuf := make([]uint16, MAX_PATH)
	ret, _, _ := shell32.NewProc("SHGetPathFromIDListW").Call(lpItem, uintptr(unsafe.Pointer(&pathBuf[0])))
	if ret == 0 {
		return
	}

	folderPath := syscall.UTF16ToString(pathBuf)
	if folderPath == "" {
		return
	}

	files, err := filepath.Glob(filepath.Join(folderPath, "*"))
	if err != nil {
		messageBox(hwnd, "Błąd odczytu folderu: "+err.Error(), "Błąd", win.MB_ICONERROR)
		return
	}

	selectedFiles = nil
	runtime.GC()

	var validFiles []string
	for _, file := range files {
		fileInfo, err := os.Stat(file)
		if err == nil && !fileInfo.IsDir() {
			validFiles = append(validFiles, file)
		}
	}

	if len(validFiles) == 0 {
		messageBox(hwnd, "Brak plików do przetworzenia w wybranym folderze", "Informacja", win.MB_ICONINFORMATION)
		return
	}

	selectedFiles = validFiles
	text := fmt.Sprintf("%s (Wybrano folder z %d plikami)", folderPath, len(validFiles))
	setWindowTextStr(filePathEdit, text)
}

func encrypt(hwnd win.HWND) {
	if len(selectedFiles) == 0 {
		messageBox(hwnd, "Proszę najpierw wybrać pliki", "Błąd", win.MB_ICONERROR)
		return
	}

	password := getWindowTextStr(passwordEdit)
	if password == "" {
		messageBox(hwnd, "Proszę wprowadzić hasło", "Błąd", win.MB_ICONERROR)
		return
	}

	key := []byte(password)
	successCount := 0
	errorCount := 0

	for i, file := range selectedFiles {
		message := fmt.Sprintf("Szyfrowanie pliku %d z %d", i+1, len(selectedFiles))
		sendProgress(hwnd, i+1, len(selectedFiles), message)

		if !strings.HasSuffix(file, ".enc") && !strings.HasSuffix(file, ".keyinfo") {
			_, err := crypto.EncryptFile(file, key)
			if err != nil {
				log.Printf("Błąd szyfrowania pliku %s: %v", file, err)
				errorCount++
			} else {
				successCount++
			}
		}

		runtime.GC()
	}

	message := fmt.Sprintf("Zakończono szyfrowanie:\nPomyślnie: %d\nBłędy: %d", successCount, errorCount)
	messageBox(hwnd, message, "Podsumowanie", win.MB_ICONINFORMATION)
}

func decrypt(hwnd win.HWND) {
	if len(selectedFiles) == 0 {
		messageBox(hwnd, "Proszę najpierw wybrać zaszyfrowane pliki", "Błąd", win.MB_ICONERROR)
		return
	}

	password := getWindowTextStr(passwordEdit)
	if password == "" {
		messageBox(hwnd, "Proszę wprowadzić hasło", "Błąd", win.MB_ICONERROR)
		return
	}

	key := []byte(password)
	successCount := 0
	errorCount := 0

	for i, file := range selectedFiles {
		message := fmt.Sprintf("Deszyfrowanie pliku %d z %d", i+1, len(selectedFiles))
		sendProgress(hwnd, i+1, len(selectedFiles), message)

		if strings.HasSuffix(file, ".enc") {
			baseFile := strings.TrimSuffix(file, ".enc")
			err := crypto.DecryptFile(baseFile, key)
			if err != nil {
				log.Printf("Błąd deszyfrowania pliku %s: %v", file, err)
				errorCount++
			} else {
				successCount++
			}
		}

		runtime.GC()
	}

	message := fmt.Sprintf("Zakończono deszyfrowanie:\nPomyślnie: %d\nBłędy: %d", successCount, errorCount)
	messageBox(hwnd, message, "Podsumowanie", win.MB_ICONINFORMATION)
}

func handleRecovery(hwnd win.HWND) {
	if len(selectedFiles) == 0 {
		messageBox(hwnd, "Proszę wybrać pliki do odzyskania", "Błąd", win.MB_ICONERROR)
		return
	}

	password := getWindowTextStr(passwordEdit)
	if password == "" {
		messageBox(hwnd, "Proszę wprowadzić hasło", "Błąd", win.MB_ICONERROR)
		return
	}

	key := []byte(password)
	successCount := 0
	errorCount := 0

	for i, file := range selectedFiles {
		message := fmt.Sprintf("Odzyskiwanie pliku %d z %d", i+1, len(selectedFiles))
		sendProgress(hwnd, i+1, len(selectedFiles), message)

		if strings.HasSuffix(file, ".enc") {
			baseFile := strings.TrimSuffix(file, ".enc")
			err := crypto.RecoverKeyInfo(baseFile, key)
			if err != nil {
				log.Printf("Błąd odzyskiwania keyinfo dla pliku %s: %v", file, err)
				errorCount++
			} else {
				successCount++
			}
		}

		runtime.GC()
	}

	message := fmt.Sprintf("Zakończono odzyskiwanie:\nPomyślnie: %d\nBłędy: %d", successCount, errorCount)
	messageBox(hwnd, message, "Podsumowanie", win.MB_ICONINFORMATION)
}

func createButton(hwnd win.HWND, text string, x, y, width, height int32, id int) win.HWND {
	buttonText, _ := syscall.UTF16PtrFromString(text)
	return win.CreateWindowEx(
		0,
		syscall.StringToUTF16Ptr("BUTTON"),
		buttonText,
		win.WS_CHILD|win.WS_VISIBLE|win.BS_PUSHBUTTON,
		x, y, width, height,
		hwnd,
		win.HMENU(id),
		win.GetModuleHandle(nil),
		nil)
}

func setWindowTextStr(hwnd win.HWND, text string) {
	ptr, _ := syscall.UTF16PtrFromString(text)
	setWindowText.Call(uintptr(hwnd), uintptr(unsafe.Pointer(ptr)))
}

func getWindowTextStr(hwnd win.HWND) string {
	length, _, _ := getWindowTextLength.Call(uintptr(hwnd))
	buf := make([]uint16, length+1)
	getWindowText.Call(
		uintptr(hwnd),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(length+1))
	return syscall.UTF16ToString(buf)
}

func messageBox(hwnd win.HWND, text, caption string, flags uint32) {
	textPtr, _ := syscall.UTF16PtrFromString(text)
	captionPtr, _ := syscall.UTF16PtrFromString(caption)
	win.MessageBox(hwnd, textPtr, captionPtr, flags)
}

func showAbout(hwnd win.HWND) {
	message := "Program File Encryptor\n\nWersja: 1.1\n\nAutor: R3PER\nGitHub: https://github.com/R3PER\n\nProgram do bezpiecznego szyfrowania i deszyfrowania plików"
	messageBox(hwnd, message, "O programie", win.MB_ICONINFORMATION)
}
