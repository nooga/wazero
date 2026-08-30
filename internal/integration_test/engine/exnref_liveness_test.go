package adhoc

// Regression test for wazero/wazero#2522: an exnref is a raw *wasm.Exception
// handed to the guest as an integer, so Go's collector cannot see it. Engines
// that root only the most recent exception let an earlier one, still held by
// the guest, be freed and its memory reused.

import (
	"context"
	_ "embed"
	"runtime"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/internal/platform"
	"github.com/tetratelabs/wazero/internal/testing/require"
	"github.com/tetratelabs/wazero/internal/wasm"
)

//go:embed testdata/exnref_liveness.wasm
var exnrefLivenessWasm []byte

// exnFillerCount is large enough that the fillers reuse the span the collected
// exception came from.
const exnFillerCount = 1 << 16

// exnPoison is the param value a filler carries: reading it back instead of
// the wasm-visible value means the guest's exnref pointed at reused memory.
const exnPoison = 0xdead

// churn collects, then allocates well-formed exceptions over the freed memory.
// They are well-formed so a dangling exnref reads back as a *different*
// exception — a clean tag mismatch or a poisoned param — rather than crashing
// on a garbage tag pointer.
func churn() {
	for i := 0; i < 10; i++ {
		runtime.GC()
		runtime.Gosched()
	}

	tag := &wasm.TagInstance{Type: &wasm.FunctionType{Params: []wasm.ValueType{wasm.ValueTypeI32}}}
	fillers := make([]*wasm.Exception, exnFillerCount)
	for i := range fillers {
		fillers[i] = &wasm.Exception{Tag: tag, Params: []uint64{exnPoison}}
	}
	runtime.KeepAlive(fillers)
}

func TestExnrefLivenessInterpreter(t *testing.T) {
	cfg := wazero.NewRuntimeConfigInterpreter().
		WithCoreFeatures(api.CoreFeaturesV2 | experimental.CoreFeaturesExceptionHandling)
	runExnrefLivenessTests(t, cfg)
}

func TestExnrefLivenessCompiler(t *testing.T) {
	if !platform.CompilerSupported() {
		t.Skip()
	}
	cfg := wazero.NewRuntimeConfigCompiler().
		WithCoreFeatures(api.CoreFeaturesV2 | experimental.CoreFeaturesExceptionHandling)
	runExnrefLivenessTests(t, cfg)
}

func runExnrefLivenessTests(t *testing.T, cfg wazero.RuntimeConfig) {
	for _, tc := range []struct {
		name string
		want int32
	}{
		{"exnref_local", 13},
		{"exnref_global", 14},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			r := wazero.NewRuntimeWithConfig(ctx, cfg)
			defer r.Close(ctx)

			_, err := r.NewHostModuleBuilder("env").
				NewFunctionBuilder().WithFunc(churn).Export("churn").
				Instantiate(ctx)
			require.NoError(t, err)

			mod, err := r.InstantiateWithConfig(ctx, exnrefLivenessWasm,
				wazero.NewModuleConfig().WithStartFunctions())
			require.NoError(t, err)

			res, err := mod.ExportedFunction(tc.name).Call(ctx)
			require.NoError(t, err)
			require.Equal(t, tc.want, api.DecodeI32(res[0]))
		})
	}
}
