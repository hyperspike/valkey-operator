package main

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	/*
		BuildVersion, BuildDate, BuildCommitSha are filled in by the build script
	*/
	Version   = "<<< filled in by build >>>"
	BuildDate = "<<< filled in by build >>>"
	Commit    = "<<< filled in by build >>>"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print package versions",
	Long:  `Print package versions`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Version:    ", Version)
		fmt.Println("Build Date: ", BuildDate)
		fmt.Println("Commit:     ", Commit)
		fmt.Println("Go Version: ", runtime.Version())
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
