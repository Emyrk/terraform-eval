package coderism

import (
	"fmt"

	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/zclconf/go-cty/cty"
)

type Tags map[string]Tag

// ValidTags returns the valid set of 'key=value' tags that are valid.
// Valid tags require that the value is statically known.
func (t Tags) ValidTags() map[string]string {
	known := make(map[string]string)
	for k, tag := range t {
		if !tag.raw.IsWhollyKnown() {
			continue
		}

		str, err := CtyValueString(tag.raw)
		if err != nil {
			// TODO: Raise this error somewhere
			continue
		}
		known[k] = str
	}
	return known
}

// Unknowns returns the list of tags that cannot be resolved due to an unknown
// value. Unknown values are usually caused by a reference to a value that is
// populated at `terraform <plan/apply>`
func (t Tags) Unknowns() []string {
	var unknowns []string
	for k, tag := range t {
		if !tag.raw.IsWhollyKnown() {
			unknowns = append(unknowns, k)
		}
	}
	return unknowns
}

type Tag struct {
	raw cty.Value
}

func WorkspaceTags(modules terraform.Modules) (Tags, error) {
	wtags := make(map[string]Tag)
	for _, module := range modules {
		blocks := module.GetDatasByType("coder_workspace_tags")
		for _, block := range blocks {
			//cc := block.Context()
			//var _ = cc
			// TODO: Set the var in the hcl context, not the terraform context
			//ctx := block.Context().Inner()
			//ctx.Variables = map[string]cty.Value{
			//	"data": cty.ObjectVal(map[string]cty.Value{
			//		"coder_parameter": cty.ObjectVal(map[string]cty.Value{
			//			"az": cty.ObjectVal(map[string]cty.Value{
			//				"value": cty.StringVal("a"),
			//			}),
			//		}),
			//	}),
			//}

			//block.OverrideContext(ctx)
			//block.Context().
			//block.OverrideContext(tfcontext.NewContext(&hcl.EvalContext{}, ctx))

			//block.OverrideContext(tfcontext.NewContext(&hcl.EvalContext{
			//	Variables: map[string]cty.Value{
			//		"data": cty.ObjectVal(map[string]cty.Value{
			//			"coder_parameter": cty.ObjectVal(map[string]cty.Value{
			//				"az": cty.ObjectVal(map[string]cty.Value{
			//					"value": cty.StringVal("a"),
			//				}),
			//			}),
			//		}),
			//	},
			//	Functions: nil,
			//}, block.Context()))
			tags := block.GetAttribute("tags")
			if tags.IsEmpty() {
				// TODO: Throw a warning up about a custom_workspace_tags block that is missing
				// 	the tags attribute.
				continue
			}

			err := tags.Each(func(key cty.Value, val cty.Value) {
				// TODO: If '!val.IsWhollyKnown', dig into the HCL expression and
				// extract what external data is being referenced. This adds guidance.
				wtags[key.AsString()] = Tag{raw: val}
			})
			if err != nil {
				return nil, fmt.Errorf("parse tags: %w", err)
			}
		}
	}
	return wtags, nil
}
