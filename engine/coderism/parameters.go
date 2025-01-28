package coderism

import (
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/coder/terraform-eval/engine/coderism/proto"
)

type Parameter struct {
	Data  *proto.RichParameter
	Value ParameterValue
	Block *terraform.Block
}

type ParameterValue struct {
	// Value is the value of the parameter.
	// If it is unknown, check the 'diags' for more information
	// on why it might be unknown.
	Value cty.Value
	diags hcl.Diagnostics
}

func (p Parameter) ValueAsString() (string, error) {
	return CtyValueString(p.Value.Value)
}

func RichParameters(modules terraform.Modules) ([]Parameter, hcl.Diagnostics) {
	rpDiags := make(hcl.Diagnostics, 0)

	params := make([]Parameter, 0)
	for _, module := range modules {
		blocks := module.GetDatasByType("coder_parameter")
		for _, block := range blocks {
			p := newAttributeParser(block)

			var paramOptions []*proto.RichParameterOption
			optionBlocks := block.GetBlocks("option")
			for _, optionBlock := range optionBlocks {
				option, diags := paramOption(optionBlock)
				if diags.HasErrors() {
					// Add the error and continue
					rpDiags = rpDiags.Extend(diags)
					continue
				}
				paramOptions = append(paramOptions, option)
			}

			// Find the value of the parameter from the context.
			paramValue, paramValueDiags := richParameterValue(block)

			param := Parameter{
				Value: ParameterValue{
					Value: paramValue,
					diags: paramValueDiags,
				},
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
				Block: block,
			}
			rpDiags = rpDiags.Extend(p.diags)
			if p.diags.HasErrors() {
				continue
			}

			params = append(params, param)
		}
	}
	return params, rpDiags
}

func richParameterValue(block *terraform.Block) (cty.Value, hcl.Diagnostics) {
	// Find the value of the parameter from the context.
	paramPath := append([]string{"data"}, block.Labels()...)
	valueRef := scopeTraversalExpr(append(paramPath, "value")...)
	paramValue, diags := valueRef.Value(block.Context().Inner())
	if diags != nil && diags.HasErrors() {
		for _, diag := range diags {
			b := block.HCLBlock().Body.MissingItemRange()
			diag.Subject = &b
		}
		return cty.UnknownVal(cty.NilType), diags
	}

	return paramValue, hcl.Diagnostics{}
}

func paramOption(block *terraform.Block) (*proto.RichParameterOption, hcl.Diagnostics) {
	p := newAttributeParser(block)
	opt := &proto.RichParameterOption{
		Name:        p.attr("name").required().string(),
		Description: p.attr("description").string(),
		// Does it need to be a string?
		Value: p.attr("value").required().string(),
		Icon:  p.attr("icon").string(),
	}
	if p.diags.HasErrors() {
		return nil, p.diags
	}
	return opt, nil
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
