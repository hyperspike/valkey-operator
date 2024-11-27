package main

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "sidecar",
	Short: "The Valkey Sidecar",
	Long:  "A tool to manage Valkey clusters withing Kubernetes",
}

func main() {
	rootCmd.Execute()
}
