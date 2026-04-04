package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ghRelease represents a GitHub release from the API.
type ghRelease struct {
	TagName string    `json:"tag_name"`
	Name    string    `json:"name"`
	Assets  []ghAsset `json:"assets"`
}

// ghAsset represents a downloadable asset in a GitHub release.
type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

const ghReleaseURL = "https://api.github.com/repos/Evr1kys/HydraFlow/releases/latest"

// cmdUpdate checks for a new version and updates the binary.
func cmdUpdate() {
	fmt.Printf("HydraFlow %s -- checking for updates...\n\n", version)

	// Fetch latest release from GitHub.
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(ghReleaseURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to check for updates: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "error: GitHub API returned %d\n", resp.StatusCode)
		os.Exit(1)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading response: %v\n", err)
		os.Exit(1)
	}

	var release ghRelease
	if err := json.Unmarshal(body, &release); err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing release info: %v\n", err)
		os.Exit(1)
	}

	latestVersion := strings.TrimPrefix(release.TagName, "v")
	currentVersion := strings.TrimPrefix(version, "v")

	fmt.Printf("  Current version: %s\n", currentVersion)
	fmt.Printf("  Latest version:  %s\n", latestVersion)
	fmt.Println()

	if currentVersion == latestVersion {
		fmt.Println("Already up to date.")
		return
	}

	// Find the right asset for this OS/arch.
	assetName := fmt.Sprintf("hydraflow-%s-%s", runtime.GOOS, runtime.GOARCH)
	var downloadURL string
	var assetSize int64

	for _, asset := range release.Assets {
		if strings.Contains(asset.Name, assetName) {
			downloadURL = asset.BrowserDownloadURL
			assetSize = asset.Size
			break
		}
	}

	if downloadURL == "" {
		// Try a generic name pattern.
		for _, asset := range release.Assets {
			if strings.Contains(asset.Name, runtime.GOOS) && strings.Contains(asset.Name, runtime.GOARCH) {
				downloadURL = asset.BrowserDownloadURL
				assetSize = asset.Size
				break
			}
		}
	}

	if downloadURL == "" {
		fmt.Fprintf(os.Stderr, "error: no binary found for %s/%s in release %s\n",
			runtime.GOOS, runtime.GOARCH, release.TagName)
		fmt.Fprintf(os.Stderr, "Available assets:\n")
		for _, asset := range release.Assets {
			fmt.Fprintf(os.Stderr, "  - %s\n", asset.Name)
		}
		os.Exit(1)
	}

	fmt.Printf("Downloading %s (%.1f MB)...\n", release.TagName, float64(assetSize)/(1024*1024))

	// Download the new binary.
	dlResp, err := client.Get(downloadURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: download failed: %v\n", err)
		os.Exit(1)
	}
	defer dlResp.Body.Close()

	if dlResp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "error: download returned %d\n", dlResp.StatusCode)
		os.Exit(1)
	}

	newBinary, err := io.ReadAll(dlResp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading download: %v\n", err)
		os.Exit(1)
	}

	// Get path of current binary.
	execPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot determine executable path: %v\n", err)
		os.Exit(1)
	}

	// Write to temp file, then rename (atomic replacement).
	tmpPath := execPath + ".new"
	if err := os.WriteFile(tmpPath, newBinary, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing new binary: %v\n", err)
		os.Exit(1)
	}

	if err := os.Rename(tmpPath, execPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: replacing binary: %v\n", err)
		os.Remove(tmpPath)
		os.Exit(1)
	}

	fmt.Printf("Updated to %s successfully.\n\n", release.TagName)

	// Restart services if running.
	restartServices()
}

// restartServices checks for running HydraFlow systemd services and restarts them.
func restartServices() {
	services := []string{"hydraflow", "hydraflow-xray", "hydraflow-sub"}
	restarted := false

	for _, svc := range services {
		// Check if service exists and is active.
		cmd := exec.Command("systemctl", "is-active", "--quiet", svc)
		if err := cmd.Run(); err != nil {
			continue // Service not active or systemctl not available.
		}

		fmt.Printf("Restarting %s...\n", svc)
		restart := exec.Command("systemctl", "restart", svc)
		if err := restart.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: failed to restart %s: %v\n", svc, err)
		} else {
			fmt.Printf("  %s restarted.\n", svc)
			restarted = true
		}
	}

	if !restarted {
		fmt.Println("No running services found to restart.")
	}
}
