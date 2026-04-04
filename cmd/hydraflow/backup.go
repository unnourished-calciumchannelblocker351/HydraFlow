package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	backupDir     = "/etc/hydraflow"
	defaultBackup = "/etc/hydraflow/backup.tar.gz"
)

// cmdBackup creates a compressed archive of all HydraFlow configs.
func cmdBackup() {
	// Determine output path.
	outputPath := defaultBackup
	if p := getFlagValue("--output"); p != "" {
		outputPath = p
	}
	// Also support positional argument: hydraflow backup /path/to/file.tar.gz
	if len(os.Args) >= 3 && !isFlag(os.Args[2]) {
		outputPath = os.Args[2]
	}

	// Verify config directory exists.
	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "error: config directory %s does not exist\n", backupDir)
		fmt.Fprintf(os.Stderr, "Is HydraFlow installed?\n")
		os.Exit(1)
	}

	// Collect files to back up.
	var files []string
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading %s: %v\n", backupDir, err)
		os.Exit(1)
	}

	for _, e := range entries {
		name := e.Name()
		// Skip the backup file itself and temp files.
		if name == "backup.tar.gz" || name[0] == '.' {
			continue
		}
		files = append(files, name)
	}

	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "error: no config files found in %s\n", backupDir)
		os.Exit(1)
	}

	fmt.Printf("Creating backup of %d files from %s...\n\n", len(files), backupDir)
	for _, f := range files {
		fmt.Printf("  + %s\n", f)
	}

	// Create tar.gz archive.
	// Use tar with -C to change directory so paths inside the archive are relative.
	args := []string{"-czf", outputPath, "-C", backupDir}
	args = append(args, files...)

	cmd := exec.Command("tar", args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nerror: tar failed: %v\n", err)
		os.Exit(1)
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nerror: stat backup file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nBackup created: %s (%.1f KB)\n", outputPath, float64(info.Size())/1024)
	fmt.Printf("Timestamp: %s\n", time.Now().Format(time.RFC3339))
}

// cmdRestore restores configs from a backup archive.
func cmdRestore() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: hydraflow restore <backup-file.tar.gz>\n\n")
		fmt.Fprintf(os.Stderr, "Restores HydraFlow configuration from a backup archive.\n")
		fmt.Fprintf(os.Stderr, "The backup is extracted to %s.\n", backupDir)
		os.Exit(1)
	}

	archivePath := os.Args[2]

	// Verify archive exists.
	if _, err := os.Stat(archivePath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "error: file not found: %s\n", archivePath)
		os.Exit(1)
	}

	// Make archive path absolute for tar.
	absPath, err := filepath.Abs(archivePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: resolving path: %v\n", err)
		os.Exit(1)
	}

	// Ensure config directory exists.
	if err := os.MkdirAll(backupDir, 0750); err != nil {
		fmt.Fprintf(os.Stderr, "error: creating %s: %v\n", backupDir, err)
		os.Exit(1)
	}

	// List archive contents first.
	fmt.Printf("Restoring from %s...\n\n", absPath)

	listCmd := exec.Command("tar", "-tzf", absPath)
	listOutput, err := listCmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read archive: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Files to restore:\n")
	fmt.Printf("%s\n", string(listOutput))

	// Extract to config directory.
	extractCmd := exec.Command("tar", "-xzf", absPath, "-C", backupDir)
	extractCmd.Stderr = os.Stderr
	if err := extractCmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: extraction failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Restore complete. Files extracted to %s.\n\n", backupDir)
	fmt.Printf("To apply changes, restart services:\n")
	fmt.Printf("  systemctl restart hydraflow-xray\n")
	fmt.Printf("  systemctl restart hydraflow-sub\n")
}

// isFlag returns true if the string looks like a CLI flag.
func isFlag(s string) bool {
	return len(s) > 0 && s[0] == '-'
}
