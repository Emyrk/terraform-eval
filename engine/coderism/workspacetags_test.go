package coderism_test

import (
	"context"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"

	"github.com/coder/terraform-eval/engine"
	"github.com/coder/terraform-eval/engine/coderism"
)

func Test_WorkspaceTags(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name           string
		files          map[string]string
		expectTags     map[string]string
		expectUnknowns []string
		expectError    string
	}{
		{
			name:        "empty",
			files:       map[string]string{},
			expectTags:  map[string]string{},
			expectError: "",
		},
		{
			name: "single text file",
			files: map[string]string{
				"file.txt": `
					hello world`,
			},
			expectTags:  map[string]string{},
			expectError: "",
		},
		{
			name: "main.tf with no workspace_tags",
			files: map[string]string{
				"main.tf": `
					provider "foo" {}
					resource "foo_bar" "baz" {}
					variable "region" {
						type    = string
						default = "us"
					}
					data "coder_parameter" "unrelated" {
						name    = "unrelated"
						type    = "list(string)"
						default = jsonencode(["a", "b"])
					}
					data "coder_parameter" "az" {
						name = "az"
						type = "string"
						default = "a"
					}`,
			},
			expectTags:  map[string]string{},
			expectError: "",
		},
		{
			name: "main.tf with empty workspace tags",
			files: map[string]string{
				"main.tf": `
					provider "foo" {}
					resource "foo_bar" "baz" {}
					variable "region" {
						type    = string
						default = "us"
					}
					data "coder_parameter" "unrelated" {
						name    = "unrelated"
						type    = "list(string)"
						default = jsonencode(["a", "b"])
					}
					data "coder_parameter" "az" {
						name = "az"
						type = "string"
						default = "a"
					}
					data "coder_workspace_tags" "tags" {}`,
			},
			expectTags:  map[string]string{},
			expectError: `"tags" attribute is required by coder_workspace_tags`,
		},
		{
			name: "main.tf with valid workspace tags",
			files: map[string]string{
				"main.tf": `
					provider "foo" {}
					resource "foo_bar" "baz" {}
					variable "region" {
						type    = string
						default = "us"
					}
					variable "unrelated" {
						type = bool
					}
					data "coder_parameter" "unrelated" {
						name    = "unrelated"
						type    = "list(string)"
						default = jsonencode(["a", "b"])
					}
					data "coder_parameter" "az" {
						name = "az"
						type = "string"
						default = "a"
					}
					data "coder_workspace_tags" "tags" {
						tags = {
							"platform" = "kubernetes",
							"cluster"  = "${"devel"}${"opers"}"
							"region"   = var.region
							"az"       = data.coder_parameter.az.value
						}
					}`,
			},
			expectTags:  map[string]string{"platform": "kubernetes", "cluster": "developers", "region": "us", "az": "a"},
			expectError: "",
		},
		{
			name: "main.tf with parameter that has default value from dynamic value",
			files: map[string]string{
				"main.tf": `
					provider "foo" {}
					resource "foo_bar" "baz" {}
					variable "region" {
						type    = string
						default = "us"
					}
					variable "az" {
						type    = string
						default = "${""}${"a"}"
					}
					data "coder_parameter" "unrelated" {
						name    = "unrelated"
						type    = "list(string)"
						default = jsonencode(["a", "b"])
					}
					data "coder_parameter" "az" {
						name = "az"
						type = "string"
						default = var.az
					}
					data "coder_workspace_tags" "tags" {
						tags = {
							"platform" = "kubernetes",
							"cluster"  = "${"devel"}${"opers"}"
							"region"   = var.region
							"az"       = data.coder_parameter.az.value
						}
					}`,
			},
			expectTags:  map[string]string{"platform": "kubernetes", "cluster": "developers", "region": "us", "az": "a"},
			expectError: "",
		},
		{
			// TODO: Why should this fail?
			name: "main.tf with parameter that has default value from another parameter",
			files: map[string]string{
				"main.tf": `
					provider "foo" {}
					resource "foo_bar" "baz" {}
					variable "region" {
						type    = string
						default = "us"
					}
					data "coder_parameter" "unrelated" {
						name    = "unrelated"
						type    = "list(string)"
						default = jsonencode(["a", "b"])
					}
					data "coder_parameter" "az" {
						type    = string
						default = "${""}${"a"}"
					}
					data "coder_parameter" "az2" {
					  name = "az"
						type = "string"
						default = data.coder_parameter.az.value
					}
					data "coder_workspace_tags" "tags" {
						tags = {
							"platform" = "kubernetes",
							"cluster"  = "${"devel"}${"opers"}"
							"region"   = var.region
							"az"       = data.coder_parameter.az2.value
						}
					}`,
			},
			expectError: "Unknown variable; There is no variable named \"data\".",
		},
		{
			name: "main.tf with multiple valid workspace tags",
			files: map[string]string{
				"main.tf": `
					provider "foo" {}
					resource "foo_bar" "baz" {}
					variable "region" {
						type    = string
						default = "us"
					}
					variable "region2" {
						type    = string
						default = "eu"
					}
					data "coder_parameter" "unrelated" {
						name    = "unrelated"
						type    = "list(string)"
						default = jsonencode(["a", "b"])
					}
					data "coder_parameter" "az" {
					  name = "az"
						type = "string"
						default = "a"
					}
					data "coder_parameter" "az2" {
					  name = "az2"
						type = "string"
						default = "b"
					}
					data "coder_workspace_tags" "tags" {
						tags = {
							"platform" = "kubernetes",
							"cluster"  = "${"devel"}${"opers"}"
							"region"   = var.region
							"az"       = data.coder_parameter.az.value
						}
					}
					data "coder_workspace_tags" "more_tags" {
						tags = {
							"foo" = "bar"
						}
					}`,
			},
			expectTags:  map[string]string{"platform": "kubernetes", "cluster": "developers", "region": "us", "az": "a", "foo": "bar"},
			expectError: "",
		},
		{
			name: "main.tf with missing parameter default value for workspace tags",
			files: map[string]string{
				"main.tf": `
					provider "foo" {}
					resource "foo_bar" "baz" {}
					variable "region" {
						type    = string
						default = "us"
					}
					data "coder_parameter" "unrelated" {
						name    = "unrelated"
						type    = "list(string)"
						default = jsonencode(["a", "b"])
					}
					data "coder_parameter" "az" {
						name = "az"
						type = "string"
					}
					data "coder_workspace_tags" "tags" {
						tags = {
							"platform" = "kubernetes",
							"cluster"  = "${"devel"}${"opers"}"
							"region"   = var.region
							"az"       = data.coder_parameter.az.value
						}
					}`,
			},
			expectError: "parameter ctx: evaluate coder_parameter \"coder_parameter.az\": no value found",
			//expectError: `provisioner tag "az" evaluated to an empty value, please set a default value`,
		},
		{
			name: "main.tf with missing parameter default value outside workspace tags",
			files: map[string]string{
				"main.tf": `
					provider "foo" {}
					resource "foo_bar" "baz" {}
					variable "region" {
						type    = string
						default = "us"
					}
					data "coder_parameter" "unrelated" {
						name    = "unrelated"
						type    = "list(string)"
						default = jsonencode(["a", "b"])
					}
					data "coder_parameter" "az" {
						name = "az"
						type = "string"
						default = "a"
					}
					data "coder_parameter" "notaz" {
						name = "notaz"
						type = "string"
					}
					data "coder_workspace_tags" "tags" {
						tags = {
							"platform" = "kubernetes",
							"cluster"  = "${"devel"}${"opers"}"
							"region"   = var.region
							"az"       = data.coder_parameter.az.value
						}
					}`,
			},
			expectTags:  map[string]string{"platform": "kubernetes", "cluster": "developers", "region": "us", "az": "a"},
			expectError: ``,
		},
		{
			name: "main.tf with missing variable default value outside workspace tags",
			files: map[string]string{
				"main.tf": `
					provider "foo" {}
					resource "foo_bar" "baz" {}
					variable "region" {
						type    = string
						default = "us"
					}
					variable "notregion" {
						type = string
					}
					data "coder_parameter" "unrelated" {
						name    = "unrelated"
						type    = "list(string)"
						default = jsonencode(["a", "b"])
					}
					data "coder_parameter" "az" {
						name = "az"
						type = "string"
						default = "a"
					}
					data "coder_workspace_tags" "tags" {
						tags = {
							"platform"  = "kubernetes",
							"cluster"   = "${"devel"}${"opers"}"
							"region"    = var.region
							"az"        = data.coder_parameter.az.value
						}
					}`,
			},
			expectTags:  map[string]string{"platform": "kubernetes", "cluster": "developers", "region": "us", "az": "a"},
			expectError: ``,
		},
		{
			name: "main.tf with disallowed data source for workspace tags",
			files: map[string]string{
				"main.tf": `
					provider "foo" {}
					resource "foo_bar" "baz" {
						name = "foobar"
					}
					variable "region" {
						type    = string
						default = "us"
					}
					data "coder_parameter" "unrelated" {
						name    = "unrelated"
						type    = "list(string)"
						default = jsonencode(["a", "b"])
					}
					data "coder_parameter" "az" {
						name = "az"
						type = "string"
						default = "a"
					}
					data "local_file" "hostname" {
						filename = "/etc/hostname"
					}
					data "coder_workspace_tags" "tags" {
						tags = {
							"platform"  = "kubernetes",
							"cluster"   = "${"devel"}${"opers"}"
							"region"    = var.region
							"az"        = data.coder_parameter.az.value
							"hostname"  = data.local_file.hostname.content
						}
					}`,
			},
			expectTags:  nil,
			expectError: `invalid workspace tag value "data.local_file.hostname.content": only the "coder_parameter" data source is supported here`,
		},
		{
			name: "main.tf with disallowed resource for workspace tags",
			files: map[string]string{
				"main.tf": `
					provider "foo" {}
					resource "foo_bar" "baz" {
						name = "foobar"
					}
					variable "region" {
						type    = string
						default = "us"
					}
					data "coder_parameter" "unrelated" {
						name    = "unrelated"
						type    = "list(string)"
						default = jsonencode(["a", "b"])
					}
					data "coder_parameter" "az" {
						name = "az"
						type = "string"
						default = "a"
					}
					data "coder_workspace_tags" "tags" {
						tags = {
							"platform"  = "kubernetes",
							"cluster"   = "${"devel"}${"opers"}"
							"region"    = var.region
							"az"        = data.coder_parameter.az.value
							"foobarbaz" = foo_bar.baz.name
						}
					}`,
			},
			expectTags: nil,
			// TODO: this error isn't great, but it has the desired effect.
			expectError: `There is no variable named "foo_bar"`,
		},
		{
			name: "main.tf with functions in workspace tags",
			files: map[string]string{
				"main.tf": `
					provider "foo" {}
					resource "foo_bar" "baz" {
						name = "foobar"
					}
					variable "region" {
						type    = string
						default = "region.us"
					}
					data "coder_parameter" "unrelated" {
						name    = "unrelated"
						type    = "list(string)"
						default = jsonencode(["a", "b"])
					}
					data "coder_parameter" "az" {
						name = "az"
						type = "string"
						default = "az.a"
					}
					data "coder_workspace_tags" "tags" {
						tags = {
							"platform"  = "kubernetes",
							"cluster"   = "${"devel"}${"opers"}"
							"region"    = try(split(".", var.region)[1], "placeholder")
							"az"        = try(split(".", data.coder_parameter.az.value)[1], "placeholder")
						}
					}`,
			},
			expectTags:  nil,
			expectError: `Function calls not allowed; Functions may not be called here.`,
		},
		{
			name: "supported types",
			files: map[string]string{
				"main.tf": `
					variable "stringvar" {
						type    = string
						default = "a"
					}
					variable "numvar" {
						type    = number
						default = 1
					}
					variable "boolvar" {
						type    = bool
						default = true
					}
					variable "listvar" {
						type    = list(string)
						default = ["a"]
					}
					variable "mapvar" {
						type    = map(string)
						default = {"a": "b"}
					}
					data "coder_parameter" "stringparam" {
						name    = "stringparam"
						type    = "string"
						default = "a"
					}
					data "coder_parameter" "numparam" {
						name    = "numparam"
						type    = "number"
						default = 1
					}
					data "coder_parameter" "boolparam" {
						name    = "boolparam"
						type    = "bool"
						default = true
					}
					data "coder_parameter" "listparam" {
						name    = "listparam"
						type    = "list(string)"
						default = "[\"a\", \"b\"]"
					}
					data "coder_workspace_tags" "tags" {
						tags = {
							"stringvar"   = var.stringvar
							"numvar"      = var.numvar
							"boolvar"     = var.boolvar
							"listvar"     = var.listvar
							"mapvar"      = var.mapvar
							"stringparam" = data.coder_parameter.stringparam.value
							"numparam"    = data.coder_parameter.numparam.value
							"boolparam"   = data.coder_parameter.boolparam.value
							"listparam"   = data.coder_parameter.listparam.value
						}
					}`,
			},
			expectTags: map[string]string{
				"stringvar":   "a",
				"numvar":      "1",
				"boolvar":     "true",
				"listvar":     `["a"]`,
				"mapvar":      `{"a":"b"}`,
				"stringparam": "a",
				"numparam":    "1",
				"boolparam":   "true",
				"listparam":   `["a", "b"]`,
			},
			expectError: ``,
		},
		{
			name: "overlapping var name",
			files: map[string]string{
				`main.tf`: `
				variable "a" {
					type = string
					default = "1"
				}
				variable "unused" {
					type = map(string)
					default = {"a" : "b"}
				}
				variable "ab" {
					description = "This is a variable of type string"
					type        = string
					default     = "ab"
				}
				data "coder_workspace_tags" "tags" {
					tags = {
						"foo": "bar",
						"a": var.a,
					}
				}`,
			},
			expectTags: map[string]string{"foo": "bar", "a": "1"},
		},
		{
			name: "dynamic parameter options",
			files: map[string]string{
				`main.tf`: `
				variable "regions" {
				  type    = set(string)
				  default = ["us", "au", "eu"]
				}
				
				data "coder_parameter" "region" {
				  name        = "Region"
				  description = "Which region would you like to deploy to?"
				  type        = "string"
				  default     = sort(tolist(var.regions))[0]
				
				
				  # option = var.region_options
				  dynamic "option" {
					for_each = var.regions
					content {
					  name  = option.value
					  value = option.value
					}
				  }
				}
				
				
				data "coder_workspace_tags" "custom_workspace_tags" {
				  tags = {
					"zone" = data.coder_parameter.region.value
				  }
				}
`,
			},
			expectTags: map[string]string{"zone": "au"},
		},
		{
			name: "external data source",
			files: map[string]string{
				`main.tf`: `
				data "coder_workspace_tags" "custom_workspace_tags" {
				  tags = {
					"zone" = docker_image.ubuntu.repo_digest
					"static" = "static"
				  }
				}
				
				
				# Pulls the image
				resource "docker_image" "ubuntu" {
				  name = "ubuntu:latest"
				}
`,
			},
			expectUnknowns: []string{"zone"},
			expectTags:     map[string]string{},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			memfs := afero.NewMemMapFs()
			for filename, content := range tc.files {
				err := afero.WriteFile(memfs, filename, []byte(content), 0644)
				require.NoError(t, err)
			}

			_, modules, _, err := engine.ParseTerraform(context.Background(), afero.NewIOFS(memfs))
			require.NoError(t, err)

			output, err := coderism.Extract(modules, coderism.Input{})
			if tc.expectError != "" {
				require.ErrorContains(t, err, tc.expectError)
				return
			}
			require.NoError(t, err)

			valid, err := output.WorkspaceTags.ValidTags()
			require.NoError(t, err)
			unknowns := output.WorkspaceTags.Unknowns()

			require.ElementsMatchf(t, tc.expectUnknowns, unknowns, "unknown tags")
			require.Equal(t, tc.expectTags, valid)
		})
	}
}
