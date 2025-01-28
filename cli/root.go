package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/coder/serpent"
	"github.com/coder/terraform-eval/cli/clidisplay"
	"github.com/coder/terraform-eval/engine"
	"github.com/coder/terraform-eval/engine/coderism"
	"github.com/coder/terraform-eval/engine/coderism/proto"
	"github.com/coder/terraform-eval/lintengine"
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

			input := coderism.Input{
				ParameterValues: rvars,
			}

			psr, modules, _, err := engine.ParseTerraform(i.Context(), input, dfs)
			if err != nil {
				return fmt.Errorf("parse tf: %w", err)
			}
			r.Parser = psr

			// TODO: Implement the parameter cli resolver in this package
			output, diags := coderism.Extract(modules, input)

			if len(i.Args) > 0 {
				eval, _, ptDiags := lintengine.ParseTerraform(i.Context(), input, dfs)
				if ptDiags.HasErrors() {
					return fmt.Errorf("parse lint: %w", ptDiags)
				}

				var _ = eval
				//for _, arg := range i.Args {
				//	fmt.Printf("Evaluating: %s\n", arg)
				//	v, vdiags := eval.EvaluateExpr(hclExpr(arg), cty.String)
				//	if vdiags.HasErrors() {
				//		fmt.Println(vdiags.Error())
				//		continue
				//	}
				//	fmt.Printf("Evaluated: %s\n", v.AsString())
				//}
				//for _, param := range output.Parameters {

				//}
			}

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

func hclExpr(expr string) hcl.Expression {
	file, diags := hclsyntax.ParseConfig([]byte(fmt.Sprintf(`expr = %s`, expr)), "test.tf", hcl.InitialPos)
	if diags.HasErrors() {
		panic(diags)
	}
	attributes, diags := file.Body.JustAttributes()
	if diags.HasErrors() {
		panic(diags)
	}
	return attributes["expr"].Expr
}
