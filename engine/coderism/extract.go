package coderism

import (
	"errors"
	"fmt"

	"github.com/aquasecurity/trivy/pkg/iac/terraform"
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

func Extract(modules terraform.Modules, input Input) (Output, error) {
	err := ParameterContexts(modules, input)
	if err != nil {
		return Output{}, fmt.Errorf("parameter ctx: %w", err)
	}

	tags, err := WorkspaceTags(modules)
	if err != nil {
		return Output{}, err
	}

	params, err := RichParameters(modules)
	if err != nil {
		return Output{}, err
	}

	return Output{
		WorkspaceTags: tags,
		Parameters:    params,
	}, nil
}

// ParameterContexts handles applying coder parameters to the evaluation context.
// We do this instead of modifying the original modules to match the behavior
// of how 'default' value 'vars' are handled.
//
// Parameter values first come from the inputs, and then the 'defaults'.
// TODO: This should be done in the evaluateStep in a loop, but that would
// require forking. This might need to be done in a loop??
func ParameterContexts(modules terraform.Modules, input Input) error {
	for _, module := range modules {
		parameterBlocks := module.GetDatasByType("coder_parameter")
		for _, block := range parameterBlocks {
			valAttr := block.GetAttribute("value")
			if !valAttr.IsNil() {
				// value already exists
				continue
			}

			name := block.NameLabel()
			var err error
			var value cty.Value
			pv, ok := input.RichParameterValue(name)
			if ok {
				// TODO: Handle non-string types
				value = cty.StringVal(pv.Value)
			} else {
				// get the default value
				value, err = evaluateCoderParameterDefault(block)
				if err != nil {
					continue
				}
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
	return nil
}

func evaluateCoderParameterDefault(b *terraform.Block) (cty.Value, error) {
	if b.Label() == "" {
		return cty.NilVal, errors.New("empty label - cannot resolve")
	}

	attributes := b.Attributes()
	if attributes == nil {
		return cty.NilVal, errors.New("cannot resolve variable with no attributes")
	}

	var valType cty.Type
	var defaults *typeexpr.Defaults
	// TODO: Disabling this because "string" keeps failing. Unsure why
	if typeAttr, exists := attributes["type"]; exists && false {
		ty, def, err := typeAttr.DecodeVarType()
		if err != nil {
			return cty.NilVal, err
		}
		valType = ty
		defaults = def
	}

	var val cty.Value

	if def, exists := attributes["default"]; exists {
		val = def.NullableValue()
	} else {
		return cty.NilVal, errors.New("no value found")
	}

	if valType != cty.NilType {
		if defaults != nil {
			val = defaults.Apply(val)
		}

		typedVal, err := convert.Convert(val, valType)
		if err != nil {
			return cty.NilVal, err
		}
		return typedVal, nil
	}

	return val, nil

}
