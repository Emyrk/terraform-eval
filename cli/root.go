package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"

	"github.com/coder/serpent"
	"github.com/coder/terraform-eval/cli/clidisplay"
	"github.com/coder/terraform-eval/engine"
	"github.com/coder/terraform-eval/engine/coderism"
	"github.com/coder/terraform-eval/engine/coderism/proto"
)

type RootCmd struct {
	Parser *parser.Parser
}

func (r *RootCmd) Root() *serpent.Command {
	var (
		dir  string
		vars []string
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
				Value:         serpent.StringOf(&dir),
			},
			{
				Name:          "vars",
				Description:   "Variables.",
				Flag:          "vars",
				FlagShorthand: "v",
				Default:       ".",
				Value:         serpent.StringArrayOf(&vars),
			},
		},
		Handler: func(i *serpent.Invocation) error {
			dfs := os.DirFS(dir)

			psr, modules, _, err := engine.ParseTerraform(i.Context(), dfs)
			if err != nil {
				return fmt.Errorf("parse tf: %w", err)
			}
			r.Parser = psr

			var rvars []*proto.RichParameterValue
			for _, val := range vars {
				parts := strings.Split(val, "=")
				if len(parts) != 2 {
					continue
				}
				rvars = append(rvars, &proto.RichParameterValue{
					Name:  parts[0],
					Value: parts[1],
				})
			}

			// TODO: Implement the parameter cli resolver in this package
			output, diags := coderism.Extract(modules, coderism.Input{
				ParameterValues: rvars,
			})

			if len(diags) > 0 {
				_, _ = fmt.Fprintf(os.Stderr, "Parsing Diagnostics:\n")
				clidisplay.WriteDiagnostics(os.Stderr, psr, diags)
			}

			diags = clidisplay.WorkspaceTags(os.Stdout, output.WorkspaceTags)
			if len(diags) > 0 {
				_, _ = fmt.Fprintf(os.Stderr, "Workspace Tags Diagnostics:\n")
				clidisplay.WriteDiagnostics(os.Stderr, psr, diags)
			}

			clidisplay.Parameters(os.Stdout, output.Parameters)

			return nil
		},
	}
	return cmd
}
