package coderism

import (
	"errors"
	"fmt"

	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/hashicorp/hcl/v2/ext/typeexpr"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

type Output struct {
	WorkspaceTags Tags
}

func Extract(modules terraform.Modules) (Output, error) {
	err := ParameterContexts(modules)
	if err != nil {
		return Output{}, fmt.Errorf("parameter ctx: %w", err)
	}

	tags, err := WorkspaceTags(modules)
	if err != nil {
		return Output{}, err
	}

	return Output{WorkspaceTags: tags}, nil
}

// ParameterContexts applies the "default" value to parameters if no "value"
// attribute is set.
// TODO: This should happen in the `evaluateStep` block of the evaluator
func ParameterContexts(modules terraform.Modules) error {
	for _, module := range modules {
		parameterBlocks := module.GetDatasByType("coder_parameter")
		for _, block := range parameterBlocks {
			valAttr := block.GetAttribute("value")
			if !valAttr.IsNil() {
				// value already exists
				continue
			}

			// get the default value
			v, err := evaluateCoderParameterDefault(block)
			if err != nil {
				return fmt.Errorf("evaluate coder_parameter %q: %w", block.Label(), err)
			}

			// Set the default value as the 'value' attribute
			path := []string{"data"}
			path = append(path, block.Labels()...)
			path = append(path, "value")
			// The current context is in the `coder_parameter` block.
			// Use the parent context to "export" the value
			block.Context().Parent().Set(v, path...)
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

	// TODO: Potentially source from user inputs
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
