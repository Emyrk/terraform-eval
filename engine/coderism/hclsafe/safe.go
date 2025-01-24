package hclsafe

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

func Value(ctx *hcl.EvalContext, expression hcl.Expression) (ctyVal cty.Value) {
	if expression == nil {
		return cty.NilVal
	}
	defer func() {
		if err := recover(); err != nil {
			ctyVal = cty.NilVal
		}
	}()
	ctyVal, _ = expression.Value(a.ctx.Inner())
	if !ctyVal.IsKnown() || ctyVal.IsNull() {
		return cty.NilVal
	}

	return ctyVal
}
