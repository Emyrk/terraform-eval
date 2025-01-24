package coderism

import (
	"errors"
	"fmt"

	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/coder/terraform-eval/engine/coderism/proto"
)

type Parameter struct {
	Data *proto.RichParameter
	// TODO: Can this be better?
	Value cty.Value

	block *terraform.Block
}

func (p Parameter) ValueAsString() (string, error) {
	return CtyValueString(p.Value)
}

func RichParameters(modules terraform.Modules) ([]Parameter, error) {
	params := make([]Parameter, 0)
	for _, module := range modules {
		blocks := module.GetDatasByType("coder_parameter")
		for _, block := range blocks {
			p := newAttributeParser(block)

			// Find the value of the parameter from the context.
			paramPath := append([]string{"data"}, block.Labels()...)
			valueRef := scopeTraversalExpr(append(paramPath, "value")...)
			paramValue, diag := valueRef.Value(block.Context().Inner())
			if diag != nil && diag.HasErrors() {
				return nil, errors.Join(diag.Errs()...)
			}

			var paramOptions []*proto.RichParameterOption
			optionBlocks := block.GetBlocks("option")
			for _, optionBlock := range optionBlocks {
				option, err := paramOption(optionBlock)
				if err != nil {
					// Add the error and continue
					p.errors = append(p.errors, fmt.Errorf("param option: %w", err))
					continue
				}
				paramOptions = append(paramOptions, option)
			}

			param := Parameter{
				Value: paramValue,
				Data: &proto.RichParameter{
					Name:                p.attr("name").required().string(),
					Description:         p.attr("description").string(),
					Type:                "",
					Mutable:             p.attr("mutable").bool(),
					DefaultValue:        "",
					Icon:                p.attr("icon").string(),
					Options:             paramOptions,
					ValidationRegex:     "",
					ValidationError:     "",
					ValidationMin:       nil,
					ValidationMax:       nil,
					ValidationMonotonic: "",
					Required:            false,
					DisplayName:         "",
					Order:               0,
					Ephemeral:           false,
				},
				block: block,
			}
			if err := p.error(); err != nil {
				return nil, err
			}

			params = append(params, param)
		}
	}
	return params, nil
}

func paramOption(block *terraform.Block) (*proto.RichParameterOption, error) {
	p := newAttributeParser(block)
	return &proto.RichParameterOption{
		Name:        p.attr("name").required().string(),
		Description: p.attr("description").string(),
		// Does it need to be a string?
		Value: p.attr("value").required().string(),
		Icon:  p.attr("icon").string(),
	}, p.error()
}

func scopeTraversalExpr(parts ...string) hclsyntax.ScopeTraversalExpr {
	if len(parts) == 0 {
		return hclsyntax.ScopeTraversalExpr{}
	}

	v := hclsyntax.ScopeTraversalExpr{
		Traversal: []hcl.Traverser{
			hcl.TraverseRoot{
				Name: parts[0],
			},
		},
	}
	for _, part := range parts[1:] {
		v.Traversal = append(v.Traversal, hcl.TraverseAttr{
			Name: part,
		})
	}
	return v
}
