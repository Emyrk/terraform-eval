package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
	tfjson "github.com/hashicorp/terraform-json"
	"github.com/spf13/afero"
)

var _ = tfjson.ActionRead

func ParseTFShow(dir fs.FS, filename string) error {
	jsonData, err := dir.Open(filename)
	if err != nil {
		return fmt.Errorf("open 'show' json: %w", err)
	}
	defer jsonData.Close()

	input, err := io.ReadAll(jsonData)
	if err != nil {
		return fmt.Errorf("read 'show' json: %w", err)
	}

	var state tfjson.State
	err = json.Unmarshal(input, &state)
	if err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}

	return nil
}

func ParseTFState(ctx context.Context, input json.RawMessage) error {
	mem := afero.NewMemMapFs()
	err := afero.WriteFile(mem, "main.tf", input, 0644)
	if err != nil {
		return fmt.Errorf("mem fs: %w", err)
	}

	p := parser.New(afero.NewIOFS(mem), "")
	err = p.ParseFS(ctx, ".")
	if err != nil {
		return fmt.Errorf("parse terraform: %w", err)
	}
	modules, _, err := p.EvaluateAll(ctx)
	if err != nil {
		return fmt.Errorf("evaluate all: %w", err)
	}
	_ = modules
	return nil
}
