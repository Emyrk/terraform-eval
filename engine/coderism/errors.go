package coderism

import (
	"fmt"

	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func notes() {
	var block *terraform.Block
	fmt.Println(block.Label())         // coder_parameter.region
	fmt.Println(block.NameLabel())     // region
	fmt.Println(block.FullName())      // data.coder_parameter.region
	fmt.Println(block.FullLocalName()) // data.coder_parameter.region
	fmt.Println(block.TypeLabel())     // coder_parameter
}
