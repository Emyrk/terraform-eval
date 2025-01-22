package coderism

import (
	"errors"
	"fmt"

	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/zclconf/go-cty/cty"
)

type attributeParser struct {
	block  *terraform.Block
	errors []error
}

func newAttributeParser(block *terraform.Block) *attributeParser {
	return &attributeParser{
		block:  block,
		errors: make([]error, 0),
	}
}

func (a *attributeParser) attr(key string) *expectedAttribute {
	return &expectedAttribute{
		p:   a,
		key: key,
	}
}

func (a *attributeParser) error() error {
	if len(a.errors) == 0 {
		return nil
	}
	return errors.Join(a.errors...)
}

type expectedAttribute struct {
	err error
	key string

	p *attributeParser
}

func (a *expectedAttribute) error(err error) *expectedAttribute {
	if a.err != nil {
		return a // already have an error, don't overwrite
	}
	a.p.errors = append(a.p.errors, err)
	a.err = err
	return a
}

func (a *expectedAttribute) required() *expectedAttribute {
	if a.p.block.GetAttribute(a.key).IsNil() {
		a.error(fmt.Errorf(`%q attribute is required and missing for %s`, a.key, a.p.block.Label()))
	}
	return a
}

func (a *expectedAttribute) string() string {
	attr := a.p.block.GetAttribute(a.key)
	if attr.IsNil() {
		return ""
	}
	if attr.Type() != cty.String {
		a.error(a.expectedTypeError(a.key, "bool"))
	}
	return attr.Value().AsString()
}

func (a *expectedAttribute) bool() bool {
	attr := a.p.block.GetAttribute(a.key)
	if attr.IsNil() {
		return false
	}
	if attr.Type() != cty.Bool {
		a.error(a.expectedTypeError(a.key, "bool"))
	}
	return attr.Value().True()
}

func (a *expectedAttribute) expectedTypeError(key string, expectedType string) error {
	return fmt.Errorf(`%q attribute must be of type %s for %s`, key, expectedType, a.p.block.Label())
}
