package main

import (
	"fmt"
	"os"

	"github.com/Evr1kys/HydraFlow/config"
	"github.com/Evr1kys/HydraFlow/xray"
)

// cmdUser handles all user management subcommands.
func cmdUser() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: hydraflow user <add|list|del|sub> [args]\n")
		os.Exit(1)
	}

	cfgPath := getConfigPath()
	cfg, err := loadCLIConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	if cfg.Mode != config.ModeStandalone {
		fmt.Fprintf(os.Stderr, "user management is only available in standalone mode (current: %s)\n", cfg.Mode)
		os.Exit(1)
	}

	switch os.Args[2] {
	case "add":
		cmdUserAdd(cfg)
	case "list":
		cmdUserList(cfg)
	case "del", "delete", "rm", "remove":
		cmdUserDel(cfg)
	case "sub":
		cmdUserSub(cfg)
	default:
		fmt.Fprintf(os.Stderr, "unknown user command: %s\n", os.Args[2])
		fmt.Fprintf(os.Stderr, "usage: hydraflow user <add|list|del|sub> [args]\n")
		os.Exit(1)
	}
}

func cmdUserAdd(cfg *config.Config) {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "usage: hydraflow user add <email>\n")
		os.Exit(1)
	}

	email := os.Args[3]

	user, err := addUser(cfg.Standalone.UsersFile, email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("User added:\n")
	fmt.Printf("  Email: %s\n", user.Email)
	fmt.Printf("  UUID:  %s\n", user.UUID)
	fmt.Printf("\n")
	fmt.Printf("  Subscription URL: http://<server>:%s/sub/%s/%s\n",
		portFromListen(cfg.Listen), cfg.AdminToken, user.Email)
	fmt.Printf("\n")
	fmt.Printf("  Restart HydraFlow to apply: systemctl restart hydraflow\n")
}

func cmdUserList(cfg *config.Config) {
	users, err := loadUsers(cfg.Standalone.UsersFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No users found. Add one with: hydraflow user add <email>")
			return
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if len(users) == 0 {
		fmt.Println("No users found. Add one with: hydraflow user add <email>")
		return
	}

	// Try to get live traffic stats from xray.
	statsClient := xray.NewStatsClient("127.0.0.1:10085", nil)
	allTraffic, _ := statsClient.GetAllUserTraffic(false)

	fmt.Printf("%-30s %-8s %-12s %-12s %s\n", "EMAIL", "STATUS", "UPLOAD", "DOWNLOAD", "UUID")
	fmt.Printf("%-30s %-8s %-12s %-12s %s\n", "-----", "------", "------", "--------", "----")

	for _, u := range users {
		status := "active"
		if !u.Enabled {
			status = "disabled"
		}

		upStr := formatBytes(u.TrafficUp)
		downStr := formatBytes(u.TrafficDown)

		// Merge live stats if available.
		if allTraffic != nil {
			if t, ok := allTraffic[u.Email]; ok {
				upStr = formatBytes(t.Uplink + u.TrafficUp)
				downStr = formatBytes(t.Downlink + u.TrafficDown)
			}
		}

		fmt.Printf("%-30s %-8s %-12s %-12s %s\n", u.Email, status, upStr, downStr, u.UUID)
	}

	fmt.Printf("\nTotal: %d users\n", len(users))
}

func cmdUserDel(cfg *config.Config) {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "usage: hydraflow user del <email>\n")
		os.Exit(1)
	}

	email := os.Args[3]

	if err := deleteUser(cfg.Standalone.UsersFile, email); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("User %s removed.\n", email)
	fmt.Printf("Restart HydraFlow to apply: systemctl restart hydraflow\n")
}

func cmdUserSub(cfg *config.Config) {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "usage: hydraflow user sub <email>\n")
		os.Exit(1)
	}

	email := os.Args[3]

	// Verify user exists.
	users, err := loadUsers(cfg.Standalone.UsersFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	found := false
	for _, u := range users {
		if u.Email == email {
			found = true
			break
		}
	}

	if !found {
		fmt.Fprintf(os.Stderr, "user %q not found\n", email)
		os.Exit(1)
	}

	port := portFromListen(cfg.Listen)

	fmt.Printf("Subscription URLs for %s:\n\n", email)
	fmt.Printf("  Universal:  http://<server>:%s/sub/%s/%s\n", port, cfg.AdminToken, email)
	fmt.Printf("  V2Ray:      http://<server>:%s/sub/%s/%s?format=v2ray\n", port, cfg.AdminToken, email)
	fmt.Printf("  Clash:      http://<server>:%s/sub/%s/%s?format=clash\n", port, cfg.AdminToken, email)
	fmt.Printf("  sing-box:   http://<server>:%s/sub/%s/%s?format=singbox\n", port, cfg.AdminToken, email)
	fmt.Printf("\n")
	fmt.Printf("  The format is auto-detected from User-Agent if not specified.\n")
}

// formatBytes formats a byte count as a human-readable string.
func formatBytes(b int64) string {
	if b == 0 {
		return "0 B"
	}
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	suffix := []string{"KB", "MB", "GB", "TB"}
	if exp >= len(suffix) {
		exp = len(suffix) - 1
	}
	return fmt.Sprintf("%.1f %s", float64(b)/float64(div), suffix[exp])
}
