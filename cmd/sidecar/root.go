package main

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "sidecar",
	Short: "The Valkey Sidecar",
	Long:  "A tool to manage Valkey clusters within Kubernetes",
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}
