package coderism

import (
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/typeexpr"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"

	"github.com/coder/terraform-eval/engine/coderism/proto"
)

type Input struct {
	ParameterValues []*proto.RichParameterValue
}

func (i Input) RichParameterValue(key string) (*proto.RichParameterValue, bool) {
	for _, p := range i.ParameterValues {
		if p.Name == key {
			return p, true
		}
	}
	return nil, false
}

type Output struct {
	WorkspaceTags TagBlocks
	Parameters    []Parameter
}

func Extract(modules terraform.Modules, input Input) (Output, hcl.Diagnostics) {
	pcDiags := ParameterContexts(modules, input)
	tags, tagDiags := WorkspaceTags(modules)
	params, rpDiags := RichParameters(modules)

	return Output{
		WorkspaceTags: tags,
		Parameters:    params,
	}, tagDiags.Extend(rpDiags).Extend(pcDiags)
}

// ParameterContexts handles applying coder parameters to the evaluation context.
// We do this instead of modifying the original modules to match the behavior
// of how 'default' value 'vars' are handled.
//
// Parameter values first come from the inputs, and then the 'defaults'.
// TODO: This should be done in the evaluateStep in a loop, but that would
// require forking. This might need to be done in a loop??
func ParameterContexts(modules terraform.Modules, input Input) hcl.Diagnostics {
	var diags hcl.Diagnostics
	for _, module := range modules {
		parameterBlocks := module.GetDatasByType("coder_parameter")
		for _, block := range parameterBlocks {
			valAttr := block.GetAttribute("value")
			if !valAttr.IsNil() {
				// value already exists
				continue
			}

			name := block.NameLabel()
			var defDiags hcl.Diagnostics
			var value cty.Value
			pv, ok := input.RichParameterValue(name)
			if ok {
				// TODO: Handle non-string types
				value = cty.StringVal(pv.Value)
			} else {
				// get the default value
				value, defDiags = evaluateCoderParameterDefault(block)
				diags = diags.Extend(defDiags)
			}

			// Set the default value as the 'value' attribute
			path := []string{"data"}
			path = append(path, block.Labels()...)
			path = append(path, "value")
			// The current context is in the `coder_parameter` block.
			// Use the parent context to "export" the value
			block.Context().Parent().Set(value, path...)
		}
	}
	return diags
}

func evaluateCoderParameterDefault(b *terraform.Block) (cty.Value, hcl.Diagnostics) {
	//if b.Label() == "" {
	//	return cty.NilVal,  errors.New("empty label - cannot resolve")
	//}

	attributes := b.Attributes()
	if attributes == nil {
		r := b.HCLBlock().Body.MissingItemRange()
		return cty.NilVal, hcl.Diagnostics{
			{
				Severity: hcl.DiagWarning,
				Summary:  "'coder_parameter' block has no attributes",
				Detail:   "No default value will be set for this paramete",
				Subject:  &r,
			},
		}
	}

	var valType cty.Type
	var defaults *typeexpr.Defaults
	// TODO: Disabling this because "string" keeps failing. Unsure why
	typeAttr, exists := attributes["type"]
	if exists && false {
		ty, def, err := typeAttr.DecodeVarType()
		if err != nil {
			return cty.NilVal, hcl.Diagnostics{
				{
					Severity:    hcl.DiagWarning,
					Summary:     "Decoding parameter type",
					Detail:      err.Error(),
					Subject:     &typeAttr.HCLAttribute().Range,
					Context:     &b.HCLBlock().DefRange,
					Expression:  typeAttr.HCLAttribute().Expr,
					EvalContext: b.Context().Inner(),
				},
			}
		}
		valType = ty
		defaults = def
	}

	var val cty.Value

	if def, exists := attributes["default"]; exists {
		val = def.NullableValue()
	} else {
		return cty.NilVal, nil
	}

	if valType != cty.NilType {
		if defaults != nil {
			val = defaults.Apply(val)
		}

		typedVal, err := convert.Convert(val, valType)
		if err != nil {
			return cty.NilVal, hcl.Diagnostics{
				{
					Severity:    hcl.DiagWarning,
					Summary:     "Converting default parameter value type",
					Detail:      err.Error(),
					Subject:     &typeAttr.HCLAttribute().Range,
					Context:     &b.HCLBlock().DefRange,
					Expression:  typeAttr.HCLAttribute().Expr,
					EvalContext: b.Context().Inner(),
				},
			}
		}
		return typedVal, nil
	}

	return val, nil

}
