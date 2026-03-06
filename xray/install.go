package xray

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

const (
	// xrayGitHubAPI is the endpoint for latest release info.
	xrayGitHubAPI = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"

	// xrayDownloadBase is the base URL for downloading xray releases.
	xrayDownloadBase = "https://github.com/XTLS/Xray-core/releases/download"
)

// InstallConfig configures the xray-core installation.
type InstallConfig struct {
	// InstallPath is where to install the xray binary.
	// Default: /usr/local/bin/xray
	InstallPath string

	// AssetPath is where to install geo data files.
	// Default: /usr/local/share/xray
	AssetPath string

	// Version specifies a particular version to install (e.g., "v1.8.24").
	// If empty, the latest release is used.
	Version string

	// SkipGeoData skips downloading geoip.dat and geosite.dat.
	SkipGeoData bool
}

// DefaultInstallConfig returns default installation paths.
func DefaultInstallConfig() InstallConfig {
	return InstallConfig{
		InstallPath: "/usr/local/bin/xray",
		AssetPath:   "/usr/local/share/xray",
	}
}

// EnsureXray checks whether xray-core is installed and working.
// If not found, it downloads and installs the latest release.
// Returns the path to the xray binary.
func EnsureXray(ctx context.Context, cfg InstallConfig, logger *slog.Logger) (string, error) {
	if logger == nil {
		logger = slog.Default()
	}

	installPath := cfg.InstallPath
	if installPath == "" {
		installPath = DefaultInstallConfig().InstallPath
	}

	// Check if xray already exists and works.
	if isXrayWorking(installPath) {
		logger.Info("xray-core already installed", "path", installPath)
		return installPath, nil
	}

	// Also check PATH.
	if pathXray, err := exec.LookPath("xray"); err == nil {
		if isXrayWorking(pathXray) {
			logger.Info("xray-core found in PATH", "path", pathXray)
			return pathXray, nil
		}
	}

	logger.Info("xray-core not found, installing...")

	if err := installXray(ctx, cfg, logger); err != nil {
		return "", fmt.Errorf("install xray: %w", err)
	}

	return installPath, nil
}

// isXrayWorking checks if the xray binary exists and runs.
func isXrayWorking(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return false
	}

	// Try running it.
	cmd := exec.Command(path, "version")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run() == nil
}

// installXray downloads and installs xray-core.
func installXray(ctx context.Context, cfg InstallConfig, logger *slog.Logger) error {
	installPath := cfg.InstallPath
	if installPath == "" {
		installPath = DefaultInstallConfig().InstallPath
	}
	assetPath := cfg.AssetPath
	if assetPath == "" {
		assetPath = DefaultInstallConfig().AssetPath
	}

	version := cfg.Version
	if version == "" {
		var err error
		version, err = getLatestVersion(ctx, logger)
		if err != nil {
			return fmt.Errorf("get latest version: %w", err)
		}
	}

	logger.Info("installing xray-core", "version", version)

	// Determine platform.
	osName, archName, err := detectPlatform()
	if err != nil {
		return err
	}

	// Download the release archive.
	archiveURL := buildDownloadURL(version, osName, archName)
	logger.Info("downloading xray-core", "url", archiveURL)

	archivePath := filepath.Join(os.TempDir(), fmt.Sprintf("xray-%s-%s-%s.zip", version, osName, archName))
	if err := downloadFile(ctx, archiveURL, archivePath); err != nil {
		return fmt.Errorf("download xray: %w", err)
	}
	defer os.Remove(archivePath)

	// Download checksum.
	checksumURL := archiveURL + ".dgst"
	checksumPath := archivePath + ".dgst"
	checksumErr := downloadFile(ctx, checksumURL, checksumPath)
	if checksumErr != nil {
		logger.Warn("checksum download failed, skipping verification", "error", checksumErr)
	} else {
		defer os.Remove(checksumPath)
		if err := verifyChecksum(archivePath, checksumPath, logger); err != nil {
			return fmt.Errorf("checksum verification failed: %w", err)
		}
		logger.Info("checksum verified")
	}

	// Extract archive.
	extractDir := filepath.Join(os.TempDir(), "xray-extract")
	os.RemoveAll(extractDir)
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return fmt.Errorf("create extract dir: %w", err)
	}
	defer os.RemoveAll(extractDir)

	if err := extractZip(archivePath, extractDir); err != nil {
		return fmt.Errorf("extract archive: %w", err)
	}

	// Install binary.
	if err := os.MkdirAll(filepath.Dir(installPath), 0755); err != nil {
		return fmt.Errorf("create install dir: %w", err)
	}

	srcBinary := filepath.Join(extractDir, "xray")
	if runtime.GOOS == "windows" {
		srcBinary += ".exe"
	}
	if err := copyFile(srcBinary, installPath, 0755); err != nil {
		return fmt.Errorf("install binary: %w", err)
	}
	logger.Info("xray binary installed", "path", installPath)

	// Install geo data files.
	if !cfg.SkipGeoData {
		if err := os.MkdirAll(assetPath, 0755); err != nil {
			return fmt.Errorf("create asset dir: %w", err)
		}

		for _, geoFile := range []string{"geoip.dat", "geosite.dat"} {
			src := filepath.Join(extractDir, geoFile)
			dst := filepath.Join(assetPath, geoFile)
			if err := copyFile(src, dst, 0644); err != nil {
				logger.Warn("geo data file not found in archive, downloading separately",
					"file", geoFile, "error", err)
				if dlErr := downloadGeoFile(ctx, geoFile, dst, logger); dlErr != nil {
					logger.Warn("failed to download geo file", "file", geoFile, "error", dlErr)
				}
			}
		}
		logger.Info("geo data installed", "path", assetPath)
	}

	return nil
}

// getLatestVersion queries GitHub for the latest xray-core release tag.
func getLatestVersion(ctx context.Context, logger *slog.Logger) (string, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Use the redirect-based approach to avoid parsing JSON.
	reqURL := "https://github.com/XTLS/Xray-core/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, reqURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("check latest release: %w", err)
	}
	resp.Body.Close()

	location := resp.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("no redirect for latest release")
	}

	// Extract version from URL like .../releases/tag/v1.8.24
	for i := len(location) - 1; i >= 0; i-- {
		if location[i] == '/' {
			return location[i+1:], nil
		}
	}

	return "", fmt.Errorf("could not parse version from %s", location)
}

// detectPlatform returns the OS and architecture names used in xray release filenames.
func detectPlatform() (string, string, error) {
	var osName string
	switch runtime.GOOS {
	case "linux":
		osName = "linux"
	case "darwin":
		osName = "macos"
	case "windows":
		osName = "windows"
	case "freebsd":
		osName = "freebsd"
	default:
		return "", "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	var archName string
	switch runtime.GOARCH {
	case "amd64":
		archName = "64"
	case "386":
		archName = "32"
	case "arm64":
		archName = "arm64-v8a"
	case "arm":
		archName = "arm32-v7a"
	case "s390x":
		archName = "s390x"
	case "mips64":
		archName = "mips64"
	case "mips64le":
		archName = "mips64le"
	case "riscv64":
		archName = "riscv64"
	default:
		return "", "", fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}

	return osName, archName, nil
}

// buildDownloadURL constructs the download URL for a specific release.
func buildDownloadURL(version, osName, archName string) string {
	filename := fmt.Sprintf("Xray-%s-%s.zip", osName, archName)
	return fmt.Sprintf("%s/%s/%s", xrayDownloadBase, version, filename)
}

// downloadFile downloads a URL to a local file path.
func downloadFile(ctx context.Context, url, destPath string) error {
	client := &http.Client{Timeout: 5 * time.Minute}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "HydraFlow/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}

	f, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

// verifyChecksum verifies the SHA-256 checksum of a file against the dgst file.
func verifyChecksum(filePath, checksumPath string, _ *slog.Logger) error {
	// Compute file hash.
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hash file: %w", err)
	}
	actualHash := hex.EncodeToString(h.Sum(nil))

	// Read checksum file. Format varies, but typically contains lines like:
	// SHA2-256(filename)= <hash>
	// or just the hash.
	checksumData, err := os.ReadFile(checksumPath)
	if err != nil {
		return fmt.Errorf("read checksum: %w", err)
	}

	checksumStr := string(checksumData)

	// Look for the SHA256 hash anywhere in the checksum data.
	// The dgst file contains multiple hash types; find SHA256.
	found := false
	start := 0
	for i := 0; i <= len(checksumStr)-64; i++ {
		candidate := checksumStr[i : i+64]
		if isHexString(candidate) {
			// Check line context for SHA256 indicator.
			lineStart := i
			for lineStart > 0 && checksumStr[lineStart-1] != '\n' {
				lineStart--
			}
			linePrefix := checksumStr[lineStart:i]
			// Accept if line mentions SHA256/SHA2-256 or if it is the only hash.
			if containsSubstring(linePrefix, "SHA256") || containsSubstring(linePrefix, "SHA2-256") || containsSubstring(linePrefix, "sha256") {
				if candidate == actualHash {
					found = true
					break
				}
				return fmt.Errorf("SHA256 mismatch: expected %s, got %s", candidate, actualHash)
			}
			start = i + 64
			_ = start
		}
	}

	if !found {
		return fmt.Errorf("could not find SHA256 hash in checksum file; verification cannot proceed")
	}

	return nil
}

// extractZip extracts a ZIP archive to a directory.
// Uses the unzip command to avoid importing archive/zip
// and to handle all zip variants.
func extractZip(archivePath, destDir string) error {
	// Try unzip command first.
	if _, err := exec.LookPath("unzip"); err == nil {
		cmd := exec.Command("unzip", "-o", archivePath, "-d", destDir)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		return cmd.Run()
	}

	// Fallback: use Go's archive/zip via a helper approach.
	// We shell out to Python as a universal fallback.
	// Paths are passed as sys.argv arguments to avoid injection.
	if _, err := exec.LookPath("python3"); err == nil {
		script := `import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])`
		cmd := exec.Command("python3", "-c", script, archivePath, destDir)
		return cmd.Run()
	}

	// Last resort: try jar command (available on some systems).
	if _, err := exec.LookPath("jar"); err == nil {
		cmd := exec.Command("jar", "xf", archivePath)
		cmd.Dir = destDir
		return cmd.Run()
	}

	return fmt.Errorf("no zip extraction tool found (install unzip)")
}

// downloadGeoFile downloads a geo data file from the Loyalsoldier repo.
func downloadGeoFile(ctx context.Context, filename, destPath string, logger *slog.Logger) error {
	urls := map[string]string{
		"geoip.dat":   "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
		"geosite.dat": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
	}

	url, ok := urls[filename]
	if !ok {
		return fmt.Errorf("unknown geo file: %s", filename)
	}

	logger.Info("downloading geo data", "file", filename)
	return downloadFile(ctx, url, destPath)
}

// copyFile copies a file from src to dst with the given permissions.
func copyFile(src, dst string, perm os.FileMode) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// isHexString checks if a string is a valid hex string.
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

// containsSubstring checks if s contains substr (case-sensitive).
func containsSubstring(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
