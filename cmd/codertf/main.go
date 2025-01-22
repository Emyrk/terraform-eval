package main

import (
	"log"

	"github.com/coder/terraform-eval/cli"
)

func main() {
	cmd := cli.Root()
	err := cmd.Invoke().WithOS().Run()
	if err != nil {
		log.Fatal(err.Error())
	}
}
