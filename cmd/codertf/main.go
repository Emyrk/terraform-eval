package main

import (
	"errors"
	"log"
	"os"

	"github.com/hashicorp/hcl/v2"

	"github.com/coder/terraform-eval/cli"
)

func main() {
	log.SetOutput(os.Stderr)
	cmd := cli.Root()

	err := cmd.Invoke().WithOS().Run()
	if err != nil {
		var diags hcl.Diagnostics
		if errors.As(err, &diags) {

		}
		log.Fatal(err.Error())
		os.Exit(1)
	}
}
