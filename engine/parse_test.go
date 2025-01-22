package engine_test

import (
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coder/terraform-eval/engine"
	"github.com/coder/terraform-eval/engine/coderism"
)

//go:embed testdata
var testdata embed.FS

func TestParseTF(t *testing.T) {
	root := "testdata"
	entries, err := testdata.ReadDir(root)
	require.NoError(t, err)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		dir, err := fs.Sub(testdata, filepath.Join(root, entry.Name()))
		require.NoError(t, err)

		t.Run(entry.Name(), func(t *testing.T) {
			modules, _, err := engine.ParseTerraform(dir)
			require.NoError(t, err)

			output, err := coderism.Extract(modules)
			require.NoError(t, err)
			fmt.Println(output)
		})
	}
}
