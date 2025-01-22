package main

import (
	"fmt"
	"log"

	"github.com/coder/terraform-eval/cli"
)

func main() {
	cmd := cli.Root()
	err := cmd.Invoke().WithOS().Run()
	if err != nil {
		fmt.Println(err)
		log.Fatal(err.Error())
	}
}
