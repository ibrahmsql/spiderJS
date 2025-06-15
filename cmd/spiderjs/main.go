package main

import (
	"fmt"
	"os"

	"github.com/ibrahmsql/spiderjs/cmd/spiderjs/commands"
	"github.com/ibrahmsql/spiderjs/internal/utils/logger"
	"github.com/ibrahmsql/spiderjs/pkg/version"
)

// PrintBanner prints the SpiderJS banner to the console
func PrintBanner() {
	banner := `
   _____       _     __          __  _____
  / ___/____  (_)___/ /__  _____/ /_/ ___/
  \__ \/ __ \/ / __  / _ \/ ___/ __/\__ \ 
 ___/ / /_/ / / /_/ /  __/ /  / /_ ___/ / 
/____/ .___/_/\__,_/\___/_/   \__//____/  
    /_/                                   
                                   v%s
`
	fmt.Printf(banner, version.GetVersion())
	fmt.Println("JavaScript Application Security Scanner")
	fmt.Println("https://github.com/ibrahmsql/spiderjs")
	fmt.Println()
}

func main() {
	// Initialize logger
	log := logger.NewLogger()

	// Print banner
	PrintBanner()

	// Create root command
	rootCmd := commands.NewRootCommand(log)

	// Execute
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}
