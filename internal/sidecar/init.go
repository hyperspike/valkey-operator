package sidecar

import (
	"fmt"
	"os"
	"strconv"
)

// Set permissions on valkey data volume
func SetVolumePermissions() {
	dir := os.Getenv("DATA_DIR")
	if dir == "" {
		dir = "/data"
	}
	user := os.Getenv("VALKEY_USER")
	if user == "" {
		user = "1001"
	}
	group := os.Getenv("VALKEY_GROUP")
	if group == "" {
		group = user
	}
	uid, err := strconv.Atoi(user)
	if err != nil {
		fmt.Println("Failed to convert user to int: ", err)
		os.Exit(1)
	}
	gid, err := strconv.Atoi(group)
	if err != nil {
		fmt.Println("Failed to convert group to int: ", err)
		os.Exit(1)
	}
	if err := os.Chown(dir, uid, gid); err != nil {
		fmt.Println("Failed to chown data dir: ", err)
		os.Exit(1)
	}
}
