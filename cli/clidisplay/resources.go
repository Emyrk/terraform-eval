package clidisplay

import (
	"fmt"
	"io"
	"strings"

	"github.com/hashicorp/hcl/v2"

	"github.com/coder/terraform-eval/engine/coderism"
	"github.com/coder/terraform-eval/engine/coderism/proto"

	"github.com/jedib0t/go-pretty/v6/table"
)

func WorkspaceTags(writer io.Writer, tags coderism.TagBlocks) hcl.Diagnostics {
	var diags hcl.Diagnostics

	tableWriter := table.NewWriter()
	tableWriter.SetTitle("Provisioner Tags")
	tableWriter.SetStyle(table.StyleLight)
	tableWriter.Style().Options.SeparateColumns = false
	row := table.Row{"Key", "Value", "Refs"}
	tableWriter.AppendHeader(row)
	for _, tb := range tags {
		valid, tagDiags := tb.ValidTags()
		diags = diags.Extend(tagDiags)
		if diags.HasErrors() {
			continue
		}
		for k, v := range valid {
			tableWriter.AppendRow(table.Row{k, v, ""})
		}

		for _, unknown := range tb.Unknowns() {
			refs := tb.AllReferences()
			refsStr := make([]string, 0, len(refs))
			for _, ref := range refs {
				refsStr = append(refsStr, ref.String())
			}
			tableWriter.AppendRow(table.Row{unknown, "???", strings.Join(refsStr, "\n")})
		}
	}
	_, _ = fmt.Fprintln(writer, tableWriter.Render())
	return diags
}

func Parameters(writer io.Writer, params []coderism.Parameter) {
	tableWriter := table.NewWriter()
	//tableWriter.SetTitle("Parameters")
	tableWriter.SetStyle(table.StyleLight)
	tableWriter.Style().Options.SeparateColumns = false
	row := table.Row{"Parameter"}
	tableWriter.AppendHeader(row)
	for _, p := range params {
		v, _ := p.ValueAsString()
		if p.Value.Value.IsNull() {
			v = "null"
		}
		if !p.Value.Value.IsKnown() {
			v = "unknown"
		}

		tableWriter.AppendRow(table.Row{
			fmt.Sprintf("%s\n%s", p.Data.Name, formatOptions(v, p.Data.Options)),
		})
		tableWriter.AppendSeparator()
	}
	_, _ = fmt.Fprintln(writer, tableWriter.Render())
}

func formatOptions(selected string, options []*proto.RichParameterOption) string {
	var str strings.Builder
	sep := ""
	found := false
	for _, opt := range options {
		str.WriteString(sep)
		prefix := "[ ]"
		if opt.Value == selected {
			prefix = "[X]"
			found = true
		}
		str.WriteString(fmt.Sprintf("%s %s (%s)", prefix, opt.Name, opt.Value))
		if opt.Description != "" {
			str.WriteString(fmt.Sprintf(": %s", maxLength(opt.Description, 20)))
		}
		sep = "\n"
	}
	if !found {
		str.WriteString(sep)
		str.WriteString(fmt.Sprintf("= %s", selected))
	}
	return str.String()
}

func maxLength(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
