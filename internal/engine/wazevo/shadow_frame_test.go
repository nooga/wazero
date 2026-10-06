package wazevo_test

import (
	"context"
	_ "embed"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/internal/engine/wazevo"
	"github.com/tetratelabs/wazero/internal/platform"
	"github.com/tetratelabs/wazero/internal/testing/require"
)

//go:embed testdata/shadow_frame.wasm
var shadowFrameWasm []byte

// TestShadowFrameBalance checks that every frame releases the shadow slots it
// reserved. A raise is what can get this wrong: it skips the epilogue of every
// frame it unwinds, so those frames never release anything and the depth has
// to be restored from the try_table checkpoint instead. Left unbalanced the
// shadow stack grows for as long as a call keeps catching, and a handler
// addresses its slots from the wrong base.
func TestShadowFrameBalance(t *testing.T) {
	if !platform.CompilerSupported() {
		t.Skip()
	}
	ctx := context.Background()
	cfg := wazero.NewRuntimeConfigCompiler().
		WithCoreFeatures(api.CoreFeaturesV2 | experimental.CoreFeaturesExceptionHandling)
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	mod, err := r.InstantiateWithConfig(ctx, shadowFrameWasm,
		wazero.NewModuleConfig().WithStartFunctions())
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		want int32
	}{
		{"unwind_once", 1},
		{"unwind_many", 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := mod.ExportedFunction(tc.name)
			res, err := f.Call(ctx)
			require.NoError(t, err)
			require.Equal(t, tc.want, api.DecodeI32(res[0]))
			require.Equal(t, uintptr(0), wazevo.ShadowRefsTopOf(f),
				"frames left shadow slots reserved after the call returned")
		})
	}
}
