package coderism_test

import (
	"embed"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"

	"github.com/coder/terraform-eval/engine"
	"github.com/coder/terraform-eval/engine/coderism"
)

//go:embed testdata
var testdata embed.FS

func Test_Extract(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		dir  string

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

			modules, _, err := engine.ParseTerraform(dirFs)
			require.NoError(t, err)

			output, err := coderism.Extract(modules, coderism.Input{})
			require.NoError(t, err)

			// Assert tags
			validTags, err := output.WorkspaceTags.ValidTags()
			require.NoError(t, err)

			assert.Equal(t, tc.expTags, validTags)
			assert.Equal(t, tc.expUnknowns, output.WorkspaceTags.Unknowns())

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

func (a *assertParam[T]) value(v T) *assertParam[T] {
	cpy := *a
	x := assertParam[T](func(t *testing.T, parameter coderism.Parameter) {
		assert.Equal(t, v, parameter.Value)
		cpy(t, parameter)
	})
	return &x
}
