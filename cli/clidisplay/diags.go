package clidisplay

import (
	"io"
	"log"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
	"github.com/hashicorp/hcl/v2"
)

func WriteDiagnostics(out io.Writer, p *parser.Parser, diags hcl.Diagnostics) {
	files := p.Files()

	wr := hcl.NewDiagnosticTextWriter(out, files, 80, true)
	werr := wr.WriteDiagnostics(diags)
	if werr != nil {
		log.Printf("diagnostic writer: %s", werr.Error())
	}
}
