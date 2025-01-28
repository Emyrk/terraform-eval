package engine

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"

	"github.com/coder/terraform-eval/engine/coderism"
)

func ParseTerraform(ctx context.Context, input coderism.Input, dir fs.FS) (*parser.Parser, terraform.Modules, cty.Value, error) {
	varFiles, err := tfVarFiles("", dir)
	if err != nil {
		return nil, nil, cty.NilVal, fmt.Errorf("find tfvars files: %w", err)
	}

	diags := make(hcl.Diagnostics, 0)
	hook := coderism.ParameterContextsEvalHook(input, diags)
	// moduleSource is "" for a local module
	p := parser.New(dir, "",
		parser.OptionWithDownloads(false),
		parser.OptionWithTFVarsPaths(varFiles...),
		parser.OptionWithEvalHook(hook),
	)

	err = p.ParseFS(ctx, ".")
	if err != nil {
		return p, nil, cty.NilVal, fmt.Errorf("parse terraform: %w", err)
	}

	modules, outputs, err := p.EvaluateAll(ctx)
	if err != nil {
		return p, nil, cty.NilVal, err
	}
	var _, _ = modules, outputs

	return p, modules, outputs, nil
}

func tfVarFiles(path string, dir fs.FS) ([]string, error) {
	dp := "."
	entries, err := fs.ReadDir(dir, dp)
	if err != nil {
		return nil, fmt.Errorf("read dir %q: %w", dp, err)
	}

	files := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			subD, err := fs.Sub(dir, entry.Name())
			if err != nil {
				return nil, fmt.Errorf("sub dir %q: %w", entry.Name(), err)
			}
			newFiles, err := tfVarFiles(filepath.Join(path, entry.Name()), subD)
			if err != nil {
				return nil, err
			}
			files = append(files, newFiles...)
		}

		if filepath.Ext(entry.Name()) == ".tfvars" {
			files = append(files, filepath.Join(path, entry.Name()))
		}
	}
	return files, nil
}
