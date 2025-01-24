package coderism

import (
	"fmt"

	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

type attributeParser struct {
	block *terraform.Block
	diags hcl.Diagnostics
}

func newAttributeParser(block *terraform.Block) *attributeParser {
	return &attributeParser{
		block: block,
		diags: make(hcl.Diagnostics, 0),
	}
}

func (a *attributeParser) attr(key string) *expectedAttribute {
	return &expectedAttribute{
		p:   a,
		key: key,
	}
}

type expectedAttribute struct {
	diag *hcl.Diagnostic
	key  string

	p *attributeParser
}

func (a *expectedAttribute) error(diag hcl.Diagnostic) *expectedAttribute {
	if a.diag != nil {
		return a // already have an error, don't overwrite
	}

	a.p.diags = a.p.diags.Append(&diag)
	a.diag = &diag
	return a
}

func (a *expectedAttribute) required() *expectedAttribute {
	if a.p.block.GetAttribute(a.key).IsNil() {
		r := a.p.block.HCLBlock().Body.MissingItemRange()
		a.error(hcl.Diagnostic{
			Severity:    hcl.DiagError,
			Summary:     "Missing required argument",
			Detail:      fmt.Sprintf("The argument %q is required, but no definition is found.", a.key),
			Subject:     &r,
			Expression:  nil,
			EvalContext: a.p.block.Context().Inner(),
		})
	}
	return a
}

func (a *expectedAttribute) string() string {
	attr := a.p.block.GetAttribute(a.key)
	if attr.IsNil() {
		return ""
	}
	if attr.Type() != cty.String {
		a.expectedTypeError(attr, "string")
		return ""
	}
	return attr.Value().AsString()
}

func (a *expectedAttribute) bool() bool {
	attr := a.p.block.GetAttribute(a.key)
	if attr.IsNil() {
		return false
	}
	if attr.Type() != cty.Bool {
		a.expectedTypeError(attr, "bool")
		return false
	}
	return attr.Value().True()
}

func (a *expectedAttribute) expectedTypeError(attr *terraform.Attribute, expectedType string) {
	a.error(hcl.Diagnostic{
		Severity:   hcl.DiagError,
		Summary:    "Invalid attribute type",
		Detail:     fmt.Sprintf("The attribute %q must be of type %q, found type %q", attr.Name(), expectedType, attr.Type().FriendlyNameForConstraint()),
		Subject:    &attr.HCLAttribute().Range,
		Context:    &a.p.block.HCLBlock().DefRange,
		Expression: attr.HCLAttribute().Expr,

		EvalContext: a.p.block.Context().Inner(),
	})
}
