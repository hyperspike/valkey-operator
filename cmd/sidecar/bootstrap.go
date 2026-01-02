package main

import (
	"github.com/spf13/cobra"

	"oxlayer/valkey-operator/internal/sidecar"
)

var bootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Long:  "Bootstrap",
	Short: "Bootstrap",
	Run: func(cmd *cobra.Command, args []string) {
		sidecar.SetVolumePermissions()
	},
}

func init() {
	rootCmd.AddCommand(bootstrapCmd)
}
