package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32     = syscall.NewLazyDLL("kernel32.dll")
	monitorMutex sync.Mutex
	isMonitoring bool
)

const (
	saltSize         = 32
	maxRetries       = 5
	retryDelay       = 100 * time.Millisecond
	maxFileSize      = 1024 * 1024 * 1024 // 1GB limit
	recoveryAttempts = 3
	recoveryDelay    = 2 * time.Second
)

type FileInfo struct {
	Path         string
	Salt         []byte
	IV           []byte
	Checksum     []byte
	MetaChecksum []byte
	Size         int64
	TimeStamp    int64  // Dodane dla recovery
	Version      int    // Dodane dla recovery
	RecoveryData []byte // Dodane dla recovery
}

type KeyInfo struct {
	FilePath    string
	FileHash    []byte
	TimeStamp   int64
	FolderFiles []string
	MetaHash    []byte
	RecoveryKey []byte // Dodane dla recovery
	Version     int    // Dodane dla recovery
}

func startMonitoring() {
	monitorMutex.Lock()
	if isMonitoring {
		monitorMutex.Unlock()
		return
	}
	isMonitoring = true
	monitorMutex.Unlock()

	go func() {
		for {
			if detectDebugger() {
				forceExit()
			}
			time.Sleep(time.Second)
		}
	}()
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	startMonitoring()
}

// Nowa funkcja do weryfikacji rozmiaru pliku
func validateFileSize(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Size() > maxFileSize {
		return fmt.Errorf("plik jest zbyt duży (maksymalny rozmiar: 1GB)")
	}
	return nil
}

// Funkcje pomocnicze do szyfrowania
func adjustKeySize(key []byte) []byte {
	switch {
	case len(key) < 16:
		newKey := make([]byte, 16)
		copy(newKey, key)
		for i := len(key); i < 16; i++ {
			newKey[i] = key[i%len(key)]
		}
		return newKey
	case len(key) < 24:
		return key[:16]
	case len(key) < 32:
		return key[:24]
	default:
		return key[:32]
	}
}

func generateRecoveryKey(key []byte, salt []byte) []byte {
	h := sha256.New()
	h.Write(key)
	h.Write(salt)
	return h.Sum(nil)
}

func encryptData(data []byte, key []byte) ([]byte, error) {
	key = adjustKeySize(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(data))
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext, data)

	result := make([]byte, 0, len(iv)+len(ciphertext))
	result = append(result, iv...)
	result = append(result, ciphertext...)

	return result, nil
}

func decryptData(data []byte, key []byte) ([]byte, error) {
	if len(data) < aes.BlockSize {
		return nil, errors.New("zaszyfrowane dane są za krótkie")
	}

	key = adjustKeySize(key)
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// Nowa funkcja do tworzenia kopii zapasowej keyinfo
func createKeyInfoBackup(keyInfo *KeyInfo, path string) error {
	backupPath := path + ".keyinfo.bak"
	data, err := json.Marshal(keyInfo)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(backupPath, data, 0600)
}

// Nowa funkcja do odzyskiwania keyinfo
func RecoverKeyInfo(path string, key []byte) error {
	// Sprawdzenie liczby prób
	for i := 0; i < recoveryAttempts; i++ {
		err := tryRecoverKeyInfo(path, key)
		if err == nil {
			return nil
		}
		time.Sleep(recoveryDelay)
	}
	return errors.New("przekroczono limit prób odzyskiwania")
}

func detectDebugger() bool {
	isDebuggerPresent := kernel32.NewProc("IsDebuggerPresent")
	ret, _, _ := isDebuggerPresent.Call()
	if ret != 0 {
		return true
	}

	var pbDebugger int32
	checkRemoteDebugger := kernel32.NewProc("CheckRemoteDebuggerPresent")
	handle, _ := syscall.GetCurrentProcess()
	ret, _, _ = checkRemoteDebugger.Call(uintptr(handle), uintptr(unsafe.Pointer(&pbDebugger)))
	return ret != 0 && pbDebugger != 0
}

func tryRecoverKeyInfo(path string, key []byte) error {
	encPath := path + ".enc"
	data, err := ioutil.ReadFile(encPath)
	if err != nil {
		return fmt.Errorf("nie można odczytać zaszyfrowanego pliku: %v", err)
	}

	if len(data) < 8 {
		return errors.New("uszkodzony plik")
	}

	metaSize := binary.LittleEndian.Uint64(data[:8])
	if len(data) < int(8+metaSize) {
		return errors.New("uszkodzony plik - nieprawidłowy rozmiar metadanych")
	}

	metadata := data[8 : 8+metaSize]
	var fileInfo FileInfo
	if err := json.Unmarshal(metadata, &fileInfo); err != nil {
		return fmt.Errorf("błąd deserializacji metadanych: %v", err)
	}

	recoveryKey := generateRecoveryKey(key, fileInfo.Salt)

	keyInfo := KeyInfo{
		FilePath:    path,
		TimeStamp:   time.Now().Unix(),
		MetaHash:    fileInfo.MetaChecksum,
		RecoveryKey: recoveryKey,
		Version:     1,
	}

	keyInfoData, err := json.Marshal(keyInfo)
	if err != nil {
		return fmt.Errorf("błąd serializacji keyInfo: %v", err)
	}

	keyInfoEncrypted, err := encryptData(keyInfoData, key)
	if err != nil {
		return fmt.Errorf("błąd szyfrowania keyInfo: %v", err)
	}

	keyInfoPath := path + ".keyinfo"
	if err := ioutil.WriteFile(keyInfoPath, keyInfoEncrypted, 0600); err != nil {
		return fmt.Errorf("nie można zapisać keyInfo: %v", err)
	}

	return createKeyInfoBackup(&keyInfo, path)
}

func EncryptFile(path string, key []byte) (*FileInfo, error) {
	// Sprawdzenie rozmiaru pliku
	if err := validateFileSize(path); err != nil {
		return nil, err
	}

	key = adjustKeySize(key)
	dir := filepath.Dir(path)
	var folderFiles []string

	if dir != "." && dir != "/" && dir != "\\" {
		files, err := ioutil.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("nie można przeskanować folderu: %v", err)
		}

		for _, f := range files {
			if !f.IsDir() {
				fullPath := filepath.Join(dir, f.Name())
				if !strings.HasSuffix(fullPath, ".enc") && !strings.HasSuffix(fullPath, ".keyinfo") {
					folderFiles = append(folderFiles, fullPath)
				}
			}
		}
	}

	plaintext, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("nie można odczytać pliku: %v", err)
	}
	defer runtime.GC() // Wymuszenie garbage collection po zakończeniu szyfrowania

	fileHash := sha256.Sum256(plaintext)

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("błąd generowania salt: %v", err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("błąd generowania IV: %v", err)
	}

	// Generowanie recovery data
	recoveryKey := generateRecoveryKey(key, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("błąd inicjalizacji szyfru: %v", err)
	}

	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)

	checksum := sha256.Sum256(plaintext)

	fileInfo := &FileInfo{
		Path:         path,
		Salt:         salt,
		IV:           iv,
		Checksum:     checksum[:],
		Size:         int64(len(plaintext)),
		TimeStamp:    time.Now().Unix(),
		Version:      1,
		RecoveryData: recoveryKey,
	}
	fileInfo.MetaChecksum = fileInfo.calculateMetaChecksum()

	keyInfo := KeyInfo{
		FilePath:    path,
		FileHash:    fileHash[:],
		TimeStamp:   time.Now().Unix(),
		FolderFiles: folderFiles,
		MetaHash:    fileInfo.MetaChecksum,
		RecoveryKey: recoveryKey,
		Version:     1,
	}

	keyInfoData, err := json.Marshal(keyInfo)
	if err != nil {
		return nil, fmt.Errorf("błąd serializacji keyInfo: %v", err)
	}

	keyInfoEncrypted, err := encryptData(keyInfoData, key)
	if err != nil {
		return nil, fmt.Errorf("błąd szyfrowania keyInfo: %v", err)
	}

	keyInfoPath := path + ".keyinfo"
	if err := ioutil.WriteFile(keyInfoPath, keyInfoEncrypted, 0600); err != nil {
		return nil, fmt.Errorf("nie można zapisać keyInfo: %v", err)
	}

	// Tworzenie kopii zapasowej keyinfo
	if err := createKeyInfoBackup(&keyInfo, path); err != nil {
		os.Remove(keyInfoPath)
		return nil, fmt.Errorf("błąd tworzenia kopii zapasowej: %v", err)
	}

	finalData := make([]byte, 0)
	metadata, err := json.Marshal(fileInfo)
	if err != nil {
		os.Remove(keyInfoPath)
		return nil, fmt.Errorf("błąd serializacji metadanych: %v", err)
	}

	metaSize := make([]byte, 8)
	binary.LittleEndian.PutUint64(metaSize, uint64(len(metadata)))

	finalData = append(finalData, metaSize...)
	finalData = append(finalData, metadata...)
	finalData = append(finalData, ciphertext...)

	encPath := path + ".enc"
	if err := ioutil.WriteFile(encPath, finalData, 0600); err != nil {
		os.Remove(keyInfoPath)
		return nil, fmt.Errorf("nie można zapisać zaszyfrowanego pliku: %v", err)
	}

	if err := secureDelete(path); err != nil {
		os.Remove(keyInfoPath)
		os.Remove(encPath)
		return nil, fmt.Errorf("nie można usunąć oryginalnego pliku: %v", err)
	}

	return fileInfo, nil
}

func DecryptFile(path string, key []byte) error {
	key = adjustKeySize(key)
	keyInfoPath := path + ".keyinfo"

	// Próba odzyskania keyinfo jeśli nie istnieje
	if _, err := os.Stat(keyInfoPath); os.IsNotExist(err) {
		if err := RecoverKeyInfo(path, key); err != nil {
			return fmt.Errorf("nie można odzyskać keyinfo: %v", err)
		}
	}

	keyInfoEncrypted, err := ioutil.ReadFile(keyInfoPath)
	if err != nil {
		return fmt.Errorf("nie znaleziono pliku weryfikacyjnego .keyinfo: %v", err)
	}

	keyInfoData, err := decryptData(keyInfoEncrypted, key)
	if err != nil {
		return fmt.Errorf("błąd deszyfrowania keyInfo: %v", err)
	}

	var keyInfo KeyInfo
	if err := json.Unmarshal(keyInfoData, &keyInfo); err != nil {
		return fmt.Errorf("błąd deserializacji keyInfo: %v", err)
	}

	encPath := path + ".enc"
	data, err := ioutil.ReadFile(encPath)
	if err != nil {
		return fmt.Errorf("nie można odczytać zaszyfrowanego pliku: %v", err)
	}
	defer runtime.GC()

	if len(data) < 8 {
		return fmt.Errorf("uszkodzony plik")
	}

	metaSize := binary.LittleEndian.Uint64(data[:8])
	if len(data) < int(8+metaSize) {
		return fmt.Errorf("uszkodzony plik - nieprawidłowy rozmiar metadanych")
	}

	metadata := data[8 : 8+metaSize]
	ciphertext := data[8+metaSize:]

	var fileInfo FileInfo
	if err := json.Unmarshal(metadata, &fileInfo); err != nil {
		return fmt.Errorf("błąd deserializacji metadanych: %v", err)
	}

	if !fileInfo.verifyIntegrity() {
		return fmt.Errorf("naruszona integralność metadanych")
	}

	if !bytes.Equal(fileInfo.MetaChecksum, keyInfo.MetaHash) {
		return fmt.Errorf("niezgodność sum kontrolnych metadanych")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("błąd inicjalizacji szyfru: %v", err)
	}

	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCFBDecrypter(block, fileInfo.IV)
	stream.XORKeyStream(plaintext, ciphertext)

	checksum := sha256.Sum256(plaintext)
	if subtle.ConstantTimeCompare(checksum[:], fileInfo.Checksum) != 1 {
		return fmt.Errorf("nieprawidłowa suma kontrolna - plik mógł zostać uszkodzony lub hasło jest nieprawidłowe")
	}

	if int64(len(plaintext)) != fileInfo.Size {
		return fmt.Errorf("nieprawidłowy rozmiar odszyfrowanych danych")
	}

	if err := ioutil.WriteFile(path, plaintext, 0600); err != nil {
		return fmt.Errorf("nie można zapisać odszyfrowanego pliku: %v", err)
	}

	if err := secureDelete(encPath); err != nil {
		return fmt.Errorf("nie można usunąć zaszyfrowanego pliku: %v", err)
	}

	// Usuwanie plików pomocniczych
	os.Remove(keyInfoPath)
	os.Remove(path + ".keyinfo.bak")

	return nil
}

func secureDelete(path string) error {
	for i := 0; i < maxRetries; i++ {
		if err := trySecureDelete(path); err == nil {
			return nil
		}
		time.Sleep(retryDelay)
		runtime.GC()
	}
	return fmt.Errorf("nie można usunąć pliku po %d próbach", maxRetries)
}

func trySecureDelete(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_SYNC, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	size := info.Size()
	randomData := make([]byte, 4096)

	for pass := 0; pass < 3; pass++ {
		if _, err := file.Seek(0, 0); err != nil {
			break
		}

		for written := int64(0); written < size; {
			n := size - written
			if n > int64(len(randomData)) {
				n = int64(len(randomData))
			}
			rand.Read(randomData)
			if _, err := file.Write(randomData[:n]); err != nil {
				break
			}
			written += n
		}
		file.Sync()
	}

	file.Close()
	return os.Remove(path)
}

func (fi *FileInfo) calculateMetaChecksum() []byte {
	h := sha256.New()
	h.Write([]byte(fi.Path))
	h.Write(fi.Salt)
	h.Write(fi.IV)
	h.Write(fi.Checksum)
	h.Write([]byte(strconv.FormatInt(fi.Size, 10)))
	h.Write([]byte(strconv.FormatInt(fi.TimeStamp, 10)))
	h.Write([]byte(strconv.Itoa(fi.Version)))
	return h.Sum(nil)
}

func (fi *FileInfo) verifyIntegrity() bool {
	if fi == nil {
		return false
	}
	expectedChecksum := fi.calculateMetaChecksum()
	return subtle.ConstantTimeCompare(fi.MetaChecksum, expectedChecksum) == 1
}

func secureZeroMemory(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func forceExit() {
	runtime.GC()
	secureZeroMemory(make([]byte, 1024*1024))
	os.Exit(1)
}
