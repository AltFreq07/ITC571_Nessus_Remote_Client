package main

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/QMUL/ntlmgen"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/crypto/ssh/terminal"
)

//go:embed netbird/linux/amd/x64/netbird
var netbirdLinux embed.FS

//go:embed netbird/windows/amd/x64/netbird.exe
var netbirdWindows embed.FS

//go:embed netbird/macosx/amd/x64/netbird
var netbirdMacOS embed.FS

const baseAPI = "http://api.smbdefence.com/"

type ScanRequest struct {
	Email           string  `json:"email"`
	Username        *string `json:"username,omitempty"`
	Password        *string `json:"password,omitempty"`
	OperatingSystem string  `json:"operating_system"`
}

type ScanStatusResponse struct {
	Hosts []struct {
		Critical            int    `json:"critical"`
		High                int    `json:"high"`
		Medium              int    `json:"medium"`
		Low                 int    `json:"low"`
		Info                int    `json:"info"`
		ScanProgressCurrent int    `json:"scanprogresscurrent"`
		Progress            string `json:"progress"`
	} `json:"hosts"`
	Info struct {
		Status string `json:"status"`
	} `json:"info"`
}

type ScanResponse struct {
	ScanID int `json:"scan_id"`
}

type ExportRequest struct {
	ScanID int    `json:"scan_id"`
	Email  string `json:"email"`
}

type debugWriter struct{}

func (dw debugWriter) Write(p []byte) (n int, err error) {
	debugPrint(string(p))
	return len(p), nil
}

func capitalizeFirstLetter(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(string(s[0])) + s[1:]
}

func getScanStatus(scanID int) (int, int, int, int, int, int, string, string, error) {
	resp, err := http.Get(fmt.Sprintf("%sscan_status/%d", baseAPI, scanID))
	if err != nil {
		return 0, 0, 0, 0, 0, 0, "", "", fmt.Errorf("error sending GET request: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, 0, 0, 0, 0, "", "", fmt.Errorf("error reading response body: %v", err)
	}

	var scanStatus ScanStatusResponse
	err = json.Unmarshal(body, &scanStatus)
	if err != nil {
		return 0, 0, 0, 0, 0, 0, "", "", fmt.Errorf("error unmarshaling JSON response: %v", err)
	}
	if len(scanStatus.Hosts) > 0 {
		host := scanStatus.Hosts[0]
		return host.Critical, host.High, host.Medium, host.Low, host.Info, host.ScanProgressCurrent, host.Progress, scanStatus.Info.Status, nil
	} else {
		return 0, 0, 0, 0, 0, 0, "", "", fmt.Errorf("error unmarshaling JSON response: %v", err)
	}
}

func startScan(email, username, password string) int {
	var reqBody ScanRequest

	reqBody.Email = email
	if username != "" {
		reqBody.Username = &username
	}
	if password != "" {
		reqBody.Password = &password
	}
	reqBody.OperatingSystem = capitalizeFirstLetter(runtime.GOOS)

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		os.Exit(1)
	}

	resp, err := http.Post(baseAPI+"create_scan", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error sending POST request:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("Error: received non-200 status code:", resp.StatusCode)
		os.Exit(1)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		os.Exit(1)
	}

	var scanResponse ScanResponse
	err = json.Unmarshal(bodyBytes, &scanResponse)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		os.Exit(1)
	}

	return scanResponse.ScanID
}

func installCommands(tempBinaryPath string) {
	debugPrint("Running Install commands")
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		installCmd := fmt.Sprintf("%s service install; %s service start; %s up --setup-key 31847937-F42C-421D-88E5-248096337E2C", tempBinaryPath, tempBinaryPath, tempBinaryPath)
		cmd = exec.Command("bash", "-c", installCmd)
	case "windows":
		cmd = exec.Command("powershell", "-Command",
			"Start-Process", tempBinaryPath, "'service install'", "-NoNewWindow", "-Wait;",
			"Start-Process", tempBinaryPath, "'service start'", "-NoNewWindow", "-Wait;",
			"Start-Process", tempBinaryPath, "'up --setup-key 31847937-F42C-421D-88E5-248096337E2C'", "-NoNewWindow", "-Wait")
	case "darwin":
		installCmd := fmt.Sprintf("%s service install; %s service start; %s up --setup-key 31847937-F42C-421D-88E5-248096337E2C", tempBinaryPath, tempBinaryPath, tempBinaryPath)
		cmd = exec.Command("bash", "-c", installCmd)
	}

	cmd.Stdout = debugWriter{}
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		fmt.Println("Error executing install command:", err)
		os.Exit(1)
	}
}

func uninstallCommands() {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux", "darwin":
		cmd = exec.Command(tempBinaryPath, "down;", tempBinaryPath, "service stop;", tempBinaryPath, "service uninstall;")
	case "windows":
		cmd = exec.Command("powershell", "-Command",
			"Start-Process", tempBinaryPath, "'down'", "-NoNewWindow", "-Wait;",
			"Start-Process", tempBinaryPath, "'service stop'", "-NoNewWindow", "-Wait;",
			"Start-Process", tempBinaryPath, "'service uninstall'", "-NoNewWindow", "-Wait")
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		fmt.Println("Error executing uninstall command:", err)
		os.Exit(1)
	}
}

func privilegesCheck() {
	if runtime.GOOS == "windows" {
		if !isAdminWindows() {
			fmt.Println("Requesting administrator privileges...")
			cmd := exec.Command("powershell", "-Command", "Start-Process", os.Args[0], "-Verb", "runas")
			err := cmd.Run()
			if err != nil {
				fmt.Println("Error requesting administrator privileges:", err)
			}
			os.Exit(1)
		}
	} else {
		if !isRoot() {
			if runtime.GOOS == "darwin" {
				fmt.Println("Requesting administrator privileges...")
				executablePath, err := os.Executable()
				if err != nil {
					fmt.Println("Error getting executable path:", err)
					os.Exit(1)
				}

				script := fmt.Sprintf(`tell application "Terminal" to do script "sudo %s"`, executablePath)
				cmd := exec.Command("osascript", "-e", script)
				err = cmd.Run()
				if err != nil {
					fmt.Println("Error requesting administrator privileges:", err)
				}
				os.Exit(1)
			} else {
				fmt.Println("Please run as root or with sudo.")
			}
			os.Exit(1)
		}
	}
}

func isRoot() bool {
	return os.Geteuid() == 0
}

func installNetbird() string {
	tempDir, err := ioutil.TempDir("", "netbird")
	if err != nil {
		fmt.Println("Error creating temp directory:", err)
		os.Exit(1)
	}

	var binaryFS embed.FS
	var binaryName string
	switch runtime.GOOS {
	case "linux":
		binaryFS = netbirdLinux
		binaryName = "netbird/linux/amd/x64/netbird"
	case "windows":
		binaryFS = netbirdWindows
		binaryName = "netbird/windows/amd/x64/netbird.exe"
	case "darwin":
		binaryFS = netbirdMacOS
		binaryName = "netbird/macosx/amd/x64/netbird"
	default:
		fmt.Println("Unsupported operating system:", runtime.GOOS)
		os.Exit(1)
	}

	binaryFile, err := binaryFS.Open(binaryName)
	if err != nil {
		fmt.Println("Error opening binary:", err)
		os.Exit(1)
	}

	data, err := ioutil.ReadAll(binaryFile)
	if err != nil {
		fmt.Println("Error reading binary:", err)
		os.Exit(1)
	}

	debugPrint("Binary size: %d bytes\n", len(data))

	tempBinaryPath := filepath.Join(tempDir, filepath.Base(binaryName))

	debugPrint("Writing binary to", tempBinaryPath)
	err = ioutil.WriteFile(tempBinaryPath, data, 0755)
	if err != nil {
		fmt.Println("Error writing binary to temp directory:", err)
		os.Exit(1)
	}
	fileInfo, _ := os.Stat(tempBinaryPath)
	debugPrint("Written binary size: %d bytes\n", fileInfo.Size())

	return tempBinaryPath
}

func removeTempFile(tempFilePath string) {
	err := os.Remove(tempFilePath)
	if err != nil {
		fmt.Printf("Error removing temporary file %s: %v\n", tempFilePath, err)
	}
}

func removeTempDir(tempDirPath string) {
	err := os.RemoveAll(tempDirPath)
	if err != nil {
		fmt.Printf("Error removing temporary directory %s: %v\n", tempDirPath, err)
	}
}

func askForCredentialedScan() bool {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Do you want to run a credentialed/full scan? Y/n: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading input:", err)
			continue
		}

		input = strings.ToLower(strings.TrimSpace(input))
		if input == "y" || input == "yes" || input == "" {
			return true
		} else if input == "n" || input == "no" {
			return false
		} else {
			fmt.Println("Invalid input. Please enter Y (yes) or N (no).")
		}
	}
}

func getEmailAddress() string {
	reader := bufio.NewReader(os.Stdin)
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	for {
		fmt.Print("Please enter your email address to receive the scan results: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading input:", err)
			continue
		}

		input = strings.TrimSpace(input)
		if emailRegex.MatchString(input) {
			return input
		} else {
			fmt.Println("Invalid email address. Please enter a valid email address.")
		}
	}
}

func checkAPIStatus() bool {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	response, err := client.Get(baseAPI + "status")
	if err != nil {
		debugPrint("Error fetching API status:", err)
		return false
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		debugPrint("Unexpected response status:", response.Status)
		return false
	}

	var apiResponse map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&apiResponse)
	if err != nil {
		debugPrint("Error decoding API response:", err)
		return false
	}

	status, ok := apiResponse["status"].(string)
	return ok && status == "online"
}

func ntlmPasswordToHash(password string) string {
	ntlmHash := ntlmgen.Ntlmgen(password)
	return ntlmHash
}

func promptCredentials() (string, string) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter your username with administrative privileges: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Print("Enter the password for the account: ")
	passwordBytes, _ := terminal.ReadPassword(int(os.Stdin.Fd()))
	password := string(passwordBytes)
	fmt.Println()

	if runtime.GOOS == "windows" {
		ntlmHash := ntlmPasswordToHash(password)
		password = ntlmHash
	}

	return username, password
}

func statusLoop(scanID int) {
	fmt.Printf("Scan started successfully with Scan ID: %d\n", scanID)
	fmt.Println("Scanning...")
	bar := progressbar.NewOptions(100,
		progressbar.OptionSetWidth(40),
		progressbar.OptionSetDescription("Scanning"),
		progressbar.OptionFullWidth(),
		progressbar.OptionSetPredictTime(false),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowDescriptionAtLineEnd(),
	)
	time.Sleep(20 * time.Second)
	count := 0
	for {
		critical, high, medium, low, info, scanProgressCurrent, percentage, status, err := getScanStatus(scanID)
		if err != nil {
			debugPrint("Error getting scan status: %v\nTrying again in 20s", err)
			count++
			if count > 20 {
				fmt.Println("Error getting scan status: %v\nExiting", err)
				os.Exit(1)
			}
			time.Sleep(20 * time.Second)
			continue
		}
		count = 0

		// Update the progress bar
		_ = bar.Set(scanProgressCurrent)
		bar.Describe(fmt.Sprintf("[reset]%s [red][Critical: %d][yellow][High: %d][light_yellow][Medium: %d][green][Low: %d][blue][Info: %d]", percentage, critical, high, medium, low, info))

		// Print the counts for each severity level and the total count
		// _ = critical + high + medium + low + info

		fmt.Printf("\r%s", bar.String())

		// Break the loop if the status is no longer "running"
		if status != "running" {
			break
		}

		// Sleep for a while before checking the status again
		time.Sleep(20 * time.Second)
	}
}

// Declare tempDir as a global variable
var tempDir string = ""
var filename string = "settings.json"
var tempBinaryPath string = ""
var settings CurrentSettings = CurrentSettings{}

type CurrentSettings struct {
	WmiStatus                     string `json:"wmi_status"`
	RemoteRegistryStatus          string `json:"remote_registry_status"`
	RemoteRegistryStartupType     string `json:"remote_registry_startup_type"`
	FileSharingStatus             string `json:"file_sharing_status"`
	LocalAccountTokenFilterPolicy string `json:"local_account_token_filter_policy"`
}

func uninstallTunnel() {
	fmt.Println("Uninstalling Tunnel")
	debugPrint(tempDir)
	uninstallCommands()
	removeTempFile(tempBinaryPath)
	removeTempDir(tempDir)
}

func restore() {
	// Load settings from the JSON file
	debugPrint("Loading settings from JSON file...")
	loadedSettings := loadSettingsFromFile(filename)

	// Restore the original settings
	debugPrint("Restoring original settings from JSON file...")
	restoreOriginalSettings(loadedSettings)
}

func isSSHRunning() bool {

	address := "localhost:22"
	timeout := time.Second

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		fmt.Printf("SSH is not running on %s\n", address)
		return false
	}

	conn.Close()
	fmt.Printf("SSH is running on %s\n", address)
	return true
}

func installTunnel() {
	fmt.Println("Installing Tunnel...")
	tempBinaryPath = installNetbird()
	tempDir = filepath.Dir(tempBinaryPath)

	installCommands(tempBinaryPath)
}

func exportReport(scanID int, email string) {
	var reqBody ExportRequest

	reqBody.ScanID = scanID
	reqBody.Email = email

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		os.Exit(1)
	}

	resp, err := http.Post(baseAPI+"export_report", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error sending POST request:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("Error: received non-200 status code:", resp.StatusCode)
		os.Exit(1)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		os.Exit(1)
	}

	var jsonResponse map[string]interface{}
	err = json.Unmarshal(bodyBytes, &jsonResponse)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		os.Exit(1)
	}

	fmt.Printf("JSON Response: %+v\n", jsonResponse)
}

func debugPrint(format string, a ...interface{}) {
	if debug {
		fmt.Printf(format, a...)
	}
}

func deleteScan(scanID int) error {
	fmt.Println("Deleting scan...")
	_, _, _, _, _, _, _, status, err := getScanStatus(scanID)
	if err != nil {
		return fmt.Errorf("Error getting scan status: %v", err)
	}

	if status == "running" {
		stopScanURL := fmt.Sprintf("%sstop_scan/%d", baseAPI, scanID)
		resp, err := http.Post(stopScanURL, "application/json", nil)
		if err != nil {
			return fmt.Errorf("Error sending POST request to stop the scan: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("Error: received non-200 status code while stopping the scan: %d", resp.StatusCode)
		}

		time.Sleep(5 * time.Second)
	}

	deleteScanURL := fmt.Sprintf("%sdelete_scan/%d", baseAPI, scanID)
	req, err := http.NewRequest("DELETE", deleteScanURL, nil)
	if err != nil {
		return fmt.Errorf("Error creating DELETE request to delete the scan: %v", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Error sending DELETE request to delete the scan: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Error: received non-200 status code while deleting the scan: %d", resp.StatusCode)
	}

	return nil
}

var debug bool
var credentialedScan bool
var scanID int

func main() {
	// Define the flag
	flag.BoolVar(&debug, "debug", false, "Enable debug prints")

	// Parse the command-line flags
	flag.Parse()
	privilegesCheck()

	installTunnel()
	// Set up a signal handler to capture Ctrl+C (SIGINT)
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChan
		fmt.Println("\nReceived an interrupt, restoring settings and exiting...")
		if runtime.GOOS == "windows" && credentialedScan {
			restore()
		}
		if scanID > 0 {
			deleteScan(scanID)
		}
		uninstallTunnel()
		os.Exit(1)
	}()
	fmt.Println("Attempting to connect to API")
	time.Sleep(5 * time.Second)
	maxRetries := 4
	retries := 0
	for {
		apiOnline := checkAPIStatus()
		if apiOnline {
			debugPrint("API is online.")
			break
		} else if retries < maxRetries {
			debugPrint("API is offline. Retrying...")
			retries++
			time.Sleep(5 * time.Second)
		} else {
			fmt.Println("API is offline.")
			uninstallTunnel()
			os.Exit(1)
		}
	}

	email := getEmailAddress()
	fmt.Printf("Scan results will be sent to: %s\n", email)
	credentialedScan = askForCredentialedScan()
	username, password := "", ""
	if credentialedScan {
		username, password = promptCredentials()
		debugPrint(username, password)
	}
	if runtime.GOOS == "windows" && credentialedScan {
		debugPrint("Storing current settings...")
		settings = storeCurrentSettings()
		saveSettingsToFile(settings, filename)
	}

	if credentialedScan {
		fmt.Println("Running a credentialed/full scan...")
		// Do stuff for a credentialed scan
		if runtime.GOOS == "windows" {
			// Enable settings for Nessus scan
			setupWindowsNessus(settings)
			scanID = startScan(email, username, password)
			statusLoop(scanID)
			fmt.Println("\nScan completed.")
			// Restore original settings
			restore()
		} else {
			if !isSSHRunning() {
				os.Exit(1)
			}
			scanID = startScan(email, username, password)
			statusLoop(scanID)
			fmt.Println("\nScan completed.")
		}
	} else {
		fmt.Println("Running a non-credentialed scan...")
		// Do stuff for a non-credentialed scan
		scanID = startScan(email, "", "")
		statusLoop(scanID)
		fmt.Println("\nScan completed.")
	}
	fmt.Println("Exporting full report...")
	time.Sleep(20 * time.Second)
	exportReport(scanID, email)
	deleteScan(scanID)
	uninstallTunnel()
}
