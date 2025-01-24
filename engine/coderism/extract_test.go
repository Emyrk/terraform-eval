package coderism_test

import (
	"context"
	"embed"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"

	"github.com/coder/terraform-eval/engine"
	"github.com/coder/terraform-eval/engine/coderism"
	"github.com/coder/terraform-eval/engine/coderism/proto"
)

//go:embed testdata
var testdata embed.FS

func Test_Extract(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		dir      string
		showJSON string
		input    coderism.Input

		expTags     map[string]string
		expUnknowns []string
		params      map[string]func(t *testing.T, parameter coderism.Parameter)
	}{
		{
			name: "simple static values",
			dir:  "static",
			expTags: map[string]string{
				"zone": "developers",
			},
			expUnknowns: []string{},
			params: map[string]func(t *testing.T, parameter coderism.Parameter){
				"Region": ap[cty.Value]().value(cty.StringVal("us")).f(),
			},
		},
		{
			name: "tags from param values",
			dir:  "paramtags",
			expTags: map[string]string{
				"zone": "eu",
			},
			input: coderism.Input{
				ParameterValues: []*proto.RichParameterValue{
					{
						Name:  "region",
						Value: "eu",
					},
				},
			},
			expUnknowns: []string{},
			params: map[string]func(t *testing.T, parameter coderism.Parameter){
				"Region": ap[cty.Value]().value(cty.StringVal("eu")).f(),
			},
		},
		{
			name: "dynamic block",
			dir:  "dynamicblock",
			expTags: map[string]string{
				"zone": "eu",
			},
			input: coderism.Input{
				ParameterValues: []*proto.RichParameterValue{
					{
						Name:  "region",
						Value: "eu",
					},
				},
			},
			expUnknowns: []string{},
			params: map[string]func(t *testing.T, parameter coderism.Parameter){
				"Region": ap[cty.Value]().
					value(cty.StringVal("eu")).
					options("us", "eu", "au").
					f(),
			},
		},
		{
			name:    "external docker resource",
			dir:     "dockerdata",
			expTags: map[string]string{"qux": "quux"},
			expUnknowns: []string{
				"foo", "bar",
			},
			input:  coderism.Input{},
			params: map[string]func(t *testing.T, parameter coderism.Parameter){},
		},
		{
			name:     "external docker resource",
			dir:      "dockerdata",
			showJSON: "show.json",
			expTags: map[string]string{
				"qux": "quux",
				"foo": "ubuntu@sha256:80dd3c3b9c6cecb9f1667e9290b3bc61b78c2678c02cbdae5f0fea92cc6734ab",
				"bar": "centos@sha256:a27fd8080b517143cbbbab9dfb7c8571c40d67d534bbdee55bd6c473f432b177",
			},
			expUnknowns: []string{},
			input:       coderism.Input{},
			params:      map[string]func(t *testing.T, parameter coderism.Parameter){},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.expUnknowns == nil {
				tc.expUnknowns = []string{}
			}
			if tc.expTags == nil {
				tc.expTags = map[string]string{}
			}

			dirFs, err := fs.Sub(testdata, filepath.Join("testdata", tc.dir))
			require.NoError(t, err)

			modules, _, err := engine.ParseTerraform(context.Background(), dirFs)
			require.NoError(t, err)

			if tc.showJSON != "" {
				err = engine.ParseTFShow(dirFs, tc.showJSON)
				require.NoError(t, err)
			}

			output, err := coderism.Extract(modules, tc.input)
			require.NoError(t, err)

			// Assert tags
			validTags, err := output.WorkspaceTags.ValidTags()
			require.NoError(t, err)

			assert.Equal(t, tc.expTags, validTags)
			assert.ElementsMatch(t, tc.expUnknowns, output.WorkspaceTags.Unknowns())

			// Assert params
			require.Len(t, output.Parameters, len(tc.params), "wrong number of parameters expected")
			for _, param := range output.Parameters {
				check, ok := tc.params[param.Data.Name]
				require.True(t, ok, "unknown parameter %s", param.Data.Name)
				check(t, param)
			}
		})
	}
}

type assertParam[T any] func(t *testing.T, parameter coderism.Parameter)

func ap[T any]() *assertParam[T] {
	x := assertParam[T](func(t *testing.T, parameter coderism.Parameter) {})
	return &x
}

func (a *assertParam[T]) f() func(t *testing.T, parameter coderism.Parameter) {
	return *a
}

func (a *assertParam[T]) options(opts ...string) *assertParam[T] {
	cpy := *a
	x := assertParam[T](func(t *testing.T, parameter coderism.Parameter) {
		allOpts := make([]string, 0)
		for _, opt := range parameter.Data.Options {
			allOpts = append(allOpts, opt.Value)
		}
		assert.ElementsMatch(t, opts, allOpts)
		cpy(t, parameter)
	})
	return &x
}

func (a *assertParam[T]) value(v T) *assertParam[T] {
	cpy := *a
	x := assertParam[T](func(t *testing.T, parameter coderism.Parameter) {
		assert.Equal(t, v, parameter.Value)
		cpy(t, parameter)
	})
	return &x
}
