package engine

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/zclconf/go-cty/cty"
)

func ParseTerraform(dir fs.FS) (terraform.Modules, cty.Value, error) {
	// moduleSource is "" for a local module
	p := parser.New(dir, "",
		parser.OptionWithDownloads(false),
	)

	ctx := context.Background()
	err := p.ParseFS(ctx, ".")
	if err != nil {
		return nil, cty.NilVal, fmt.Errorf("parse terraform: %w", err)
	}

	modules, outputs, err := p.EvaluateAll(ctx)
	if err != nil {
		return nil, cty.NilVal, err
	}
	var _, _ = modules, outputs

	return modules, outputs, nil
}
