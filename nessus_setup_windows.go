//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"strings"
)

func storeCurrentSettings() CurrentSettings {
	return CurrentSettings{
		WmiStatus:                     getServiceStatus("Winmgmt"),
		RemoteRegistryStatus:          getServiceStatus("RemoteRegistry"),
		RemoteRegistryStartupType:     getRemoteRegistryStartupType(),
		FileSharingStatus:             getFileSharingStatus(),
		LocalAccountTokenFilterPolicy: getLocalAccountTokenFilterPolicy(),
	}
}

func saveSettingsToFile(settings CurrentSettings, filename string) {
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal settings: %s", err)
	}

	err = ioutil.WriteFile(filename, data, 0644)
	if err != nil {
		log.Fatalf("Failed to write settings to file: %s", err)
	}
}

func loadSettingsFromFile(filename string) CurrentSettings {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("Failed to read settings from file: %s", err)
	}

	var settings CurrentSettings
	err = json.Unmarshal(data, &settings)
	if err != nil {
		log.Fatalf("Failed to unmarshal settings: %s", err)
	}

	return settings
}

func setupWindowsNessus(settings CurrentSettings) {
	fmt.Println("Enabling services and settings for Nessus scan...")

	commands := []string{
		"net start Winmgmt",
		"sc config RemoteRegistry start= auto",
		"net start RemoteRegistry",
		"netsh advfirewall firewall set rule group=\"File and Printer Sharing\" new enable=yes",
		"netsh advfirewall firewall set rule group=\"Windows Management Instrumentation (WMI)\" new enable=yes",
		"reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f",
	}

	executeCommands(commands)
}

func restoreOriginalSettings(settings CurrentSettings) {
	fmt.Println("Restoring original settings...")

	commands := []string{
		fmt.Sprintf("net %s Winmgmt", settings.WmiStatus),
		"sc config RemoteRegistry start=" + settings.RemoteRegistryStartupType,
		fmt.Sprintf("net %s RemoteRegistry", settings.RemoteRegistryStatus),
		"netsh advfirewall firewall set rule group=\"File and Printer Sharing\" new enable=" + settings.FileSharingStatus,
		"reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d " + settings.LocalAccountTokenFilterPolicy + " /f",
	}

	executeCommands(commands)
}

func getLocalAccountTokenFilterPolicy() string {
	cmd := exec.Command("reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\system", "/v", "LocalAccountTokenFilterPolicy")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Failed to query LocalAccountTokenFilterPolicy: %v\n", err)
		return ""
	}
	if strings.Contains(string(output), "0x1") {
		return "1"
	}
	return "0"
}
func revertSettings(wmiStatus, remoteRegistryStatus, remoteRegistryStartupType, fileSharingStatus, localAccountTokenFilterPolicy string) {
	fmt.Println("Restoring original settings...")

	commands := []string{
		fmt.Sprintf("net %s Winmgmt", wmiStatus),
		"sc config RemoteRegistry start=" + remoteRegistryStartupType,
		fmt.Sprintf("net %s RemoteRegistry", remoteRegistryStatus),
		"netsh advfirewall firewall set rule group=\"File and Printer Sharing\" new enable=" + fileSharingStatus,
		"reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d " + localAccountTokenFilterPolicy + " /f",
	}

	executeCommands(commands)
}

func executeCommands(commands []string) {
	for _, cmd := range commands {
		debugPrint("Executing command: %s\n", cmd) // Change this line
		parts := strings.Fields(cmd)
		head := parts[0]
		parts = parts[1:len(parts)]

		output, err := exec.Command(head, parts...).CombinedOutput()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				debugPrint("Command exited with non-zero status: %s\nOutput: %s", exitErr, strings.TrimSpace(string(output)))
			} else {
				log.Fatalf("Failed to run command: %s", err)
			}
		} else {
			debugPrint("Command output: %s\n", strings.TrimSpace(string(output))) // Change this line
		}
	}
}

func getServiceStatus(serviceName string) string {
	cmd := "sc query " + serviceName
	output, err := exec.Command("cmd", "/C", cmd).Output()
	if err != nil {
		log.Fatalf("Failed to query service status: %s", err)
	}

	if strings.Contains(string(output), "STATE              : 4  RUNNING") {
		return "stop"
	}
	return "start"
}

func getFileSharingStatus() string {
	cmd := "powershell -Command \"Get-NetFirewallRule -Group 'File and Printer Sharing'| Select -ExpandProperty Enabled\""
	output, err := exec.Command("cmd", "/C", cmd).Output()
	if err != nil {
		log.Fatalf("Failed to query File and Printer Sharing status: %s", err)
	}

	if strings.Contains(string(output), "True") {
		return "no"
	}
	return "yes"
}

func getRemoteRegistryStartupType() string {
	cmd := "sc qc RemoteRegistry"
	output, err := exec.Command("cmd", "/C", cmd).Output()
	if err != nil {
		log.Fatalf("Failed to query RemoteRegistry startup type: %s", err)
	}

	if strings.Contains(string(output), "START_TYPE         : 3   DEMAND_START") {
		return "demand"
	}
	return "auto"
}
