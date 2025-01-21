package engine

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/trivy-iac/pkg/scanners/terraform/executor"
	"github.com/aquasecurity/trivy-iac/pkg/scanners/terraform/parser"
	"github.com/zclconf/go-cty/cty"
)

var _ = parser.New
var _ = executor.OptionExcludeRules

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
