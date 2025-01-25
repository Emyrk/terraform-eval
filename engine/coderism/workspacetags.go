package coderism

import (
	"fmt"

	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/coder/terraform-eval/engine/hclext"
)

func WorkspaceTags(modules terraform.Modules) (TagBlocks, hcl.Diagnostics) {
	var diags hcl.Diagnostics
	var tagBlocks []TagBlock

	for _, module := range modules {
		blocks := module.GetDatasByType("coder_workspace_tags")
		for _, block := range blocks {
			evCtx := block.Context().Inner()

			tagsAttr := block.GetAttribute("tags")
			if tagsAttr.IsNil() {
				r := block.HCLBlock().Body.MissingItemRange()
				diags = diags.Append(&hcl.Diagnostic{
					Severity:    hcl.DiagError,
					Summary:     "Missing required argument",
					Detail:      `"tags" attribute is required by coder_workspace_tags blocks`,
					Subject:     &r,
					EvalContext: evCtx,
				})
				continue
			}

			tagObj, ok := tagsAttr.HCLAttribute().Expr.(*hclsyntax.ObjectConsExpr)
			if !ok {
				diags = diags.Append(&hcl.Diagnostic{
					Severity:    hcl.DiagError,
					Summary:     "Incorrect type for \"tags\" attribute",
					Detail:      fmt.Sprintf(`"tags" attribute must be an 'ObjectConsExpr', but got %T`, tagsAttr.HCLAttribute().Expr),
					Subject:     &tagsAttr.HCLAttribute().NameRange,
					Context:     &tagsAttr.HCLAttribute().Range,
					Expression:  tagsAttr.HCLAttribute().Expr,
					EvalContext: block.Context().Inner(),
				})
				continue
			}

			var tags []Tag
			for _, item := range tagObj.Items {
				key, kdiags := item.KeyExpr.Value(evCtx)
				val, vdiags := item.ValueExpr.Value(evCtx)

				diags = diags.Extend(kdiags)
				diags = diags.Extend(vdiags)

				if kdiags.HasErrors() {
					key = cty.UnknownVal(cty.String)
				}

				if vdiags.HasErrors() {
					val = cty.UnknownVal(cty.NilType)
				}

				tags = append(tags, Tag{
					key:       key,
					val:       val,
					keyExpr:   item.KeyExpr,
					valueExpr: item.ValueExpr,
				})
			}
			tagBlocks = append(tagBlocks, TagBlock{
				Tags:  tags,
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
	Tags  []Tag
	block *terraform.Block
}

func (t TagBlock) AllReferences() []*terraform.Reference {
	return t.block.GetAttribute("tags").AllReferences()
}

// ValidTags returns the valid set of 'key=value' tags that are valid.
// Valid tags require that the value is statically known.
func (t TagBlock) ValidTags() (map[string]string, hcl.Diagnostics) {
	var diags hcl.Diagnostics
	known := make(map[string]string)
	for _, tag := range t.Tags {
		if !tag.val.IsWhollyKnown() || !tag.val.IsWhollyKnown() {
			continue
		}

		k, v, eDiags := tag.EvalToString(t)
		diags = diags.Extend(eDiags)
		if diags.HasErrors() {
			continue
		}

		known[k] = v
	}

	return known, diags
}

// Unknowns returns the list of tags that cannot be resolved due to an unknown
// value. Unknown values are usually caused by a reference to a value that is
// populated at `terraform <plan/apply>`
func (t TagBlock) Unknowns() []string {
	var unknowns []string
	for _, tag := range t.Tags {
		if !tag.key.IsWhollyKnown() {
			// TODO: improve this
			unknowns = append(unknowns, "???")
			continue
		}

		if !tag.val.IsWhollyKnown() {
			keyStr, err := CtyValueString(tag.key)
			if err != nil {
				unknowns = append(unknowns, "?ERR?")
				continue
			}
			unknowns = append(unknowns, keyStr)
		}
	}
	return unknowns
}

type Tag struct {
	key     cty.Value
	keyExpr hclsyntax.Expression

	val       cty.Value
	valueExpr hclsyntax.Expression
}

func (tag Tag) IsKnown() bool {
	return tag.key.IsWhollyKnown() && tag.val.IsWhollyKnown()
}

func (tag Tag) References() []string {
	keyVars := hclext.ReferenceNames(tag.keyExpr)
	valVars := hclext.ReferenceNames(tag.valueExpr)
	return append(keyVars, valVars...)
}

// TODO: I dislike this
func (tag Tag) SafeKeyString() (str string) {
	defer func() {
		if r := recover(); r != nil {
		}
	}()
	str, _ = CtyValueString(tag.key)
	return str
}

func (tag Tag) EvalToString(tb TagBlock) (string, string, hcl.Diagnostics) {
	var diags hcl.Diagnostics
	keyStr, err := CtyValueString(tag.key)
	if err != nil {
		r := tag.keyExpr.Range()
		diags = diags.Append(&hcl.Diagnostic{
			Severity:    hcl.DiagError,
			Summary:     "Tag key is not known",
			Detail:      "Tag must be resolvable",
			Subject:     &r,
			Expression:  tag.keyExpr,
			EvalContext: tb.block.Context().Inner(),
		})
	}

	valStr, err := CtyValueString(tag.val)
	if err != nil {
		r := tag.valueExpr.Range()
		diags = diags.Append(&hcl.Diagnostic{
			Severity:    hcl.DiagError,
			Summary:     "Tag value is not known",
			Detail:      "Tag must be resolvable",
			Subject:     &r,
			Expression:  tag.valueExpr,
			EvalContext: tb.block.Context().Inner(),
		})
	}
	return keyStr, valStr, diags
}
