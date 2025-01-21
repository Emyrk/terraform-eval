package coderism

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"
)

// CtyValueString converts a cty.Value to a string.
// It supports only primitive types - bool, number, and string.
// As a special case, it also supports map[string]interface{} with key "value".
func CtyValueString(val cty.Value) (string, error) {
	switch val.Type() {
	case cty.Bool:
		if val.True() {
			return "true", nil
		} else {
			return "false", nil
		}
	case cty.Number:
		return val.AsBigFloat().String(), nil
	case cty.String:
		return val.AsString(), nil
	// We may also have a map[string]interface{} with key "value".
	case cty.Map(cty.String):
		valval, ok := val.AsValueMap()["value"]
		if !ok {
			return "", fmt.Errorf("map does not have key 'value'")
		}
		return CtyValueString(valval)
	default:
		return "", fmt.Errorf("only primitive types are supported - bool, number, and string")
	}
}
