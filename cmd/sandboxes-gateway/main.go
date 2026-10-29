package main

import (
	"fmt"
	"os"

	"github.com/KLORQ/sandboxes-gateway/internal/version"
)

func main() {
	_, _ = fmt.Fprintf(os.Stdout, "sandboxes-gateway %s\n", version.Version)
}
