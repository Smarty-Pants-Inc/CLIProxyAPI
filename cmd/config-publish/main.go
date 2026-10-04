// config-publish replaces a config file using its previously read content hash.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	path := flag.String("config", "config.yaml", "config file to replace")
	input := flag.String("input", "", "edited YAML file")
	expected := flag.String("expected-version", "", "SHA-256 hash of the original config bytes")
	flag.Parse()
	if *input == "" || *expected == "" {
		return fmt.Errorf("--input and --expected-version are required")
	}
	data, err := os.ReadFile(*input)
	if err != nil {
		return fmt.Errorf("read edited config: %w", err)
	}
	data, err = config.PrepareConfigPublication(data)
	if err != nil {
		return fmt.Errorf("validate edited config: %w", err)
	}
	version, err := config.AtomicWriteConfigCAS(*path, data, *expected)
	if err != nil {
		return fmt.Errorf("publish config: %w", err)
	}
	fmt.Println(version)
	return nil
}
