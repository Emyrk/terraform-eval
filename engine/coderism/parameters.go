package coderism

// ParameterValues returns the values for all coder parameters.
// TODO: Handle different user choices
func ParameterValues() {
	//hcl.EvalContext{}
	//wtags := make(map[string]Tag)
	//for _, module := range modules {
	//	blocks := module.GetDatasByType("coder_workspace_tags")
	//	for _, block := range blocks {
	//		tags := block.GetAttribute("tags")
	//		if tags.IsEmpty() {
	//			// TODO: Throw a warning up about a custom_workspace_tags block that is missing
	//			// 	the tags attribute.
	//			continue
	//		}
	//
	//		err := tags.Each(func(key cty.Value, val cty.Value) {
	//			// TODO: If '!val.IsWhollyKnown', dig into the HCL expression and
	//			// extract what external data is being referenced. This adds guidance.
	//			wtags[key.AsString()] = Tag{raw: val}
	//		})
	//		if err != nil {
	//			return nil, fmt.Errorf("parse tags: %w", err)
	//		}
	//	}
	//}
	//return wtags, nil
}
