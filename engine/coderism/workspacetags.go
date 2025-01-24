package coderism

import (
	"fmt"

	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

func WorkspaceTags(modules terraform.Modules) (TagBlocks, hcl.Diagnostics) {
	diags := make(hcl.Diagnostics, 0)
	var tagBlocks []TagBlock
	for _, module := range modules {
		blocks := module.GetDatasByType("coder_workspace_tags")
		for _, block := range blocks {
			block := block
			wtags := make(map[string]Tag)
			tags := block.GetAttribute("tags")
			if tags.IsNil() {
				r := block.HCLBlock().Body.MissingItemRange()
				diags = diags.Append(&hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  "Missing required argument",
					Detail:   `"tags" attribute is required by coder_workspace_tags blocks`,
					Subject:  &r,
				})
				continue
			}

			tagObj, ok := tags.HCLAttribute().Expr.(*hclsyntax.ObjectConsExpr)
			if !ok {
				diags = diags.Append(&hcl.Diagnostic{
					Severity:    hcl.DiagError,
					Summary:     "Incorrect type for \"tags\" attribute",
					Detail:      fmt.Sprintf(`"tags" attribute must be an object, but got %T`, tags.HCLAttribute().Expr),
					Subject:     &tags.HCLAttribute().NameRange,
					Context:     &tags.HCLAttribute().Range,
					Expression:  tags.HCLAttribute().Expr,
					EvalContext: block.Context().Inner(),
				})
				continue
			}

			ctx := block.Context().Inner()
			for _, item := range tagObj.Items {
				key, kdiags := item.KeyExpr.Value(ctx)
				val, vdiags := item.ValueExpr.Value(ctx)

				if kdiags.HasErrors() || vdiags.HasErrors() {
					diags = diags.Extend(kdiags)
					diags = diags.Extend(vdiags)
					continue
				}

				// TODO: If '!val.IsWhollyKnown', dig into the HCL expression and
				// extract what external data is being referenced. This adds guidance.
				// We have tags.AllReferences, but that only works for the entire block.
				wtags[key.AsString()] = Tag{
					raw:       val,
					keyExpr:   item.KeyExpr,
					valueExpr: item.ValueExpr,
				}
			}

			tagBlocks = append(tagBlocks, TagBlock{
				Tags:  wtags,
				block: block,
			})
		}
	}

	return tagBlocks, diags
}

type TagBlocks []TagBlock

func (t TagBlocks) ValidTags() (map[string]string, error) {
	tags := make(map[string]string)
	for _, block := range t {
		valid, err := block.ValidTags()
		if err != nil {
			return nil, fmt.Errorf("block %q: %w", block.block.Label(), err)
		}
		for k, v := range valid {
			// TODO: What about tags overriding each other?
			tags[k] = v
		}
	}
	return tags, nil
}

func (t TagBlocks) Unknowns() []string {
	unknowns := make([]string, 0)
	for _, block := range t {
		unknown := block.Unknowns()
		// TODO: What about duplicates?
		unknowns = append(unknowns, unknown...)
	}
	return unknowns
}

type TagBlock struct {
	Tags  map[string]Tag
	block *terraform.Block
}

func (t TagBlock) AllReferences() []*terraform.Reference {
	return t.block.GetAttribute("tags").AllReferences()
}

// ValidTags returns the valid set of 'key=value' tags that are valid.
// Valid tags require that the value is statically known.
func (t TagBlock) ValidTags() (map[string]string, hcl.Diagnostics) {
	diags := make(hcl.Diagnostics, 0)
	known := make(map[string]string)
	for k, tag := range t.Tags {
		if !tag.raw.IsWhollyKnown() {
			continue
		}

		str, err := CtyValueString(tag.raw)
		if err != nil {
			r := tag.valueExpr.Range()
			diags = diags.Append(&hcl.Diagnostic{
				Severity:    hcl.DiagError,
				Summary:     "Tag value is not known",
				Detail:      fmt.Sprintf("Tag %q must be resolvable", k),
				Subject:     &r,
				EvalContext: t.block.Context().Inner(),
			})
			continue
		}
		known[k] = str
	}

	if diags.HasErrors() {
		return nil, diags
	}
	return known, nil
}

// Unknowns returns the list of tags that cannot be resolved due to an unknown
// value. Unknown values are usually caused by a reference to a value that is
// populated at `terraform <plan/apply>`
func (t TagBlock) Unknowns() []string {
	var unknowns []string
	for k, tag := range t.Tags {
		if !tag.raw.IsWhollyKnown() {
			unknowns = append(unknowns, k)
		}
	}
	return unknowns
}

type Tag struct {
	raw       cty.Value
	keyExpr   hclsyntax.Expression
	valueExpr hclsyntax.Expression
}
