package engine

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/zclconf/go-cty/cty"
)

func ParseTerraform(ctx context.Context, dir fs.FS) (*parser.Parser, terraform.Modules, cty.Value, error) {
	// moduleSource is "" for a local module
	p := parser.New(dir, "",
		parser.OptionWithDownloads(false),
	)

	err := p.ParseFS(ctx, ".")
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
