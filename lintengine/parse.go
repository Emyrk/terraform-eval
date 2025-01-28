package lintengine

import (
	"context"
	"fmt"
	"io"
	"io/fs"

	"github.com/hashicorp/go-version"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/spf13/afero"
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint/terraform"
	"github.com/zclconf/go-cty/cty"

	"github.com/coder/terraform-eval/engine/coderism"
)

func ParseTerraform(ctx context.Context, input coderism.Input, dir fs.FS) (*terraform.Evaluator, *hcl.BodyContent, hcl.Diagnostics) {
	adfs := afero.NewReadOnlyFs(afero.FromIOFS{FS: dir})

	// terraform parsing
	tp := terraform.NewParser(adfs)
	mod, diags := tp.LoadConfigDir(".", ".")
	if diags.HasErrors() {
		return nil, nil, diags
	}

	config, diags := terraform.BuildConfig(mod, terraform.ModuleWalkerFunc(
		func(req *terraform.ModuleRequest) (*terraform.Module, *version.Version, hcl.Diagnostics) {

			return nil, nil, nil
		}),
	)

	extInputs := make(map[string]*terraform.InputValue)
	for _, v := range input.ParameterValues {
		extInputs[v.Name] = &terraform.InputValue{
			Value: cty.StringVal(v.Value),
		}
	}

	variableValues, diags := terraform.VariableValues(config, extInputs)
	if diags.HasErrors() {
		return nil, nil, diags
	}

	evaluator := &terraform.Evaluator{
		Meta:           &terraform.ContextMeta{},
		ModulePath:     config.Path.UnkeyedInstanceShim(),
		Config:         config,
		VariableValues: variableValues,
	}

	// hcl parsed
	hp, diags := ParseHCL(adfs)
	if diags.HasErrors() {
		return nil, nil, diags
	}
	var _ = hp

	bodies := make([]hcl.Body, 0)
	ehp := hclparse.NewParser()
	for k, v := range hp.Files() {
		expanded, fdiags := evaluator.ExpandBlock(v.Body, &hclext.BodySchema{})
		diags = diags.Extend(fdiags)

		ehp.AddFile(k, &hcl.File{
			Body:  expanded,
			Bytes: v.Bytes,
			Nav:   v.Nav,
		})

		bodies = append(bodies, expanded)
	}

	body := hcl.MergeBodies(bodies)
	cc, cdiags := body.Content(Schema)
	diags = diags.Extend(cdiags)

	return evaluator, cc, diags
}

func ParseHCL(adfs afero.Fs) (*hclparse.Parser, hcl.Diagnostics) {
	diags := make(hcl.Diagnostics, 0)
	hp := hclparse.NewParser()
	_ = afero.Walk(adfs, ".", func(path string, info fs.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		f, err := adfs.Open(path)
		if err != nil {
			return fmt.Errorf("open %q: %w", path, err)
		}
		defer f.Close()

		data, err := io.ReadAll(f)
		if err != nil {
			return fmt.Errorf("read %q: %w", path, err)
		}

		_, fdiags := hp.ParseHCL(data, info.Name())
		diags = diags.Extend(fdiags)

		// Stop on first hcl error
		if fdiags.HasErrors() {
			return fmt.Errorf("parse %q: %w", path, fdiags)
		}

		return nil
	})
	if diags.HasErrors() {
		return nil, diags
	}
	return hp, nil
}
