package coderism

import (
	"errors"
	"fmt"

	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/zclconf/go-cty/cty"
)

func WorkspaceTags(modules terraform.Modules) (TagBlocks, error) {
	var tagBlocks []TagBlock
	for _, module := range modules {
		blocks := module.GetDatasByType("coder_workspace_tags")
		for _, block := range blocks {
			block := block
			wtags := make(map[string]Tag)
			tags := block.GetAttribute("tags")
			if tags.IsNil() {
				return nil, fmt.Errorf(`"tags" attribute is required by coder_workspace_tags.%s`, block.NameLabel())
			}

			err := tags.Each(func(key cty.Value, val cty.Value) {
				// TODO: If '!val.IsWhollyKnown', dig into the HCL expression and
				// extract what external data is being referenced. This adds guidance.
				// We have tags.AllReferences, but that only works for the entire block.
				wtags[key.AsString()] = Tag{raw: val}
			})
			if err != nil {
				return nil, fmt.Errorf("parse tags: %w", err)
			}
			tagBlocks = append(tagBlocks, TagBlock{
				Tags:  wtags,
				block: block,
			})
		}
	}

	return tagBlocks, nil
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

// ValidTags returns the valid set of 'key=value' tags that are valid.
// Valid tags require that the value is statically known.
func (t TagBlock) ValidTags() (map[string]string, error) {
	var errs []error
	known := make(map[string]string)
	for k, tag := range t.Tags {
		if !tag.raw.IsWhollyKnown() {
			continue
		}

		str, err := CtyValueString(tag.raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("convert tag %q: %w", k, err))
			continue
		}
		known[k] = str
	}
	return known, errors.Join(errs...)
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
	raw cty.Value
}
