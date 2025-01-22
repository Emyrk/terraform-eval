package cli

import (
	"fmt"
	"os"

	"github.com/coder/serpent"
	"github.com/coder/terraform-eval/engine"
	"github.com/coder/terraform-eval/engine/coderism"
)

func Root() *serpent.Command {
	var (
		dir string
	)
	cmd := &serpent.Command{
		Use:   "codertf",
		Short: "codertf is a command line tool for previewing terraform template outputs.",
		Options: serpent.OptionSet{
			{
				Name:          "dir",
				Description:   "Directory with terraform files.",
				Flag:          "dir",
				FlagShorthand: "d",
				Default:       ".",
			},
		},
		Handler: func(i *serpent.Invocation) error {
			dfs := os.DirFS(dir)
			modules, _, err := engine.ParseTerraform(dfs)
			if err != nil {
				return fmt.Errorf("parse tf: %w", err)
			}

			// TODO: Implement the parameter cli resolver in this package
			output, err := coderism.Extract(modules, coderism.Input{})
			if err != nil {
				return fmt.Errorf("extract: %w", err)
			}

			var _ = output

			return nil
		},
	}
	return cmd
}
