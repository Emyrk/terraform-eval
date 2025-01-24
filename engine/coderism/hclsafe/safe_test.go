package hclsafe_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/hcl/v2"
)

func TestHCL(t *testing.T) {
	a := hcl.Diagnostics{}
	var b hcl.Diagnostics
	fmt.Println(a.Extend(b))
}
