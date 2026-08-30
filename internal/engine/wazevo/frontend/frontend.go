// Package frontend implements the translation of WebAssembly to SSA IR using the ssa package.
package frontend

import (
	"bytes"
	"math"
	"sync"

	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/wazevoapi"
	"github.com/tetratelabs/wazero/internal/wasm"
)

// Compiler is in charge of lowering Wasm to SSA IR, and does the optimization
// on top of it in architecture-independent way.
type Compiler struct {
	// Per-module data that is used across all functions.

	m      *wasm.Module
	offset *wazevoapi.ModuleContextOffsetData
	// ssaBuilder is a ssa.Builder used by this frontend.
	ssaBuilder             ssa.Builder
	signatures             map[*wasm.FunctionType]*ssa.Signature
	listenerSignatures     map[*wasm.FunctionType][2]*ssa.Signature
	memoryGrowSig          ssa.Signature
	memoryWait32Sig        ssa.Signature
	memoryWait64Sig        ssa.Signature
	memoryNotifySig        ssa.Signature
	checkModuleExitCodeSig ssa.Signature
	tableGrowSig           ssa.Signature
	refFuncSig             ssa.Signature
	memmoveSig             ssa.Signature
	memclrSig              ssa.Signature
	ensureTermination      bool

	// Followings are reset by per function.

	// wasmLocalToVariable maps the index (considered as wasm.Index of locals)
	// to the corresponding ssa.Variable.
	wasmLocalToVariable                   [] /* local index to */ ssa.Variable
	wasmLocalFunctionIndex                wasm.Index
	wasmFunctionTypeIndex                 wasm.Index
	wasmFunctionTyp                       *wasm.FunctionType
	wasmFunctionLocalTypes                []wasm.ValueType
	wasmFunctionBody                      []byte
	wasmFunctionBodyOffsetInCodeSection   uint64
	memoryBaseVariable, memoryLenVariable ssa.Variable
	needMemory                            bool
	memoryShared                          bool
	// memoryMinSizeInBytes is the static minimum size of the memory in bytes
	// (zero if there is no memory). Since memories never shrink, any access
	// whose end is a constant within this bound can never be out of bounds.
	memoryMinSizeInBytes uint64
	globalVariables      []ssa.Variable
	globalVariablesTypes []ssa.Type
	// globalShadowed is index-correlated with globalVariables and marks the
	// globals whose value carries a reference the collector must see.
	globalShadowed                []bool
	mutableGlobalVariablesIndexes []wasm.Index // index to ^.
	needListener                  bool
	needSourceOffsetInfo          bool
	// br is reused during lowering.
	br            *bytes.Reader
	loweringState loweringState

	knownSafeBounds    [] /* ssa.ValueID to */ knownSafeBound
	knownSafeBoundsSet []ssa.ValueID

	knownSafeBoundsAtTheEndOfBlocks   [] /* ssa.BlockID to */ knownSafeBoundsAtTheEndOfBlock
	varLengthKnownSafeBoundWithIDPool wazevoapi.VarLengthPool[knownSafeBoundWithID]

	execCtxPtrValue, moduleCtxPtrValue ssa.Value

	// throwAllocSig is the signature for the throw-alloc trampoline:
	// (execCtx, tagIndex) → (exnref). Allocates the Exception and returns
	// its pointer so compiled code can pass it to the throw trampoline.
	throwAllocSig ssa.Signature
	// throwSig is the signature for the throw/throw_ref trampoline:
	// (execCtx, exnref) → (). Searches for a matching handler and restores.
	throwSig ssa.Signature
	// shadowStoreSig is the signature for the shadow-store trampoline:
	// (execCtx, slot, ptr) -> (). Roots ptr in this frame's shadow slot.
	shadowStoreSig ssa.Signature
	// globalRefStoreSig is the signature for the global-ref-store trampoline:
	// (execCtx, globalIndex, ptr) -> ().
	globalRefStoreSig ssa.Signature
	// tableRefSyncSig is the signature for the table-ref-sync trampoline:
	// (execCtx, tableIndex) -> ().
	tableRefSyncSig ssa.Signature
	// shadowSlots counts the shadow slots this function reserves. Assigned
	// as sites are lowered; the total reaches the backend through
	// ssa.Builder.SetShadowFrameSize.
	shadowSlots int
	// exnrefLocalSlot maps a wasm local index to its shadow slot, for the
	// exnref-typed locals only. -1 means the local holds no reference.
	exnrefLocalSlot []int
	// needsShadowFrame gates every shadow-frame instruction, so that a
	// function which can hold no reference compiles exactly as before.
	needsShadowFrame bool
	// tryTableEnterSig is the signature for the try_table enter trampoline.
	tryTableEnterSig ssa.Signature
	// tryTableLeaveSig is the signature for the try_table leave trampoline.
	tryTableLeaveSig ssa.Signature
	// tryTableMetadata accumulates try_table metadata during compilation.
	tryTableMetadata tryTableMetadata
	// tryTableDepth tracks try_table nesting. When > 0, local.set/local.tee
	// emit extra stores to the locals save area so handler blocks can read
	// throw-time values.
	tryTableDepth int

	// Following are reused for the known safe bounds analysis.

	pointers []int
	bounds   [][]knownSafeBoundWithID
}

type (
	// knownSafeBound represents a known safe bound for a value.
	knownSafeBound struct {
		// bound is a constant upper bound for the value.
		bound uint64
		// absoluteAddr is the absolute address of the value.
		absoluteAddr ssa.Value
	}
	// knownSafeBoundWithID is a knownSafeBound with the ID of the value.
	knownSafeBoundWithID struct {
		knownSafeBound
		id ssa.ValueID
	}
	knownSafeBoundsAtTheEndOfBlock = wazevoapi.VarLength[knownSafeBoundWithID]
)

var knownSafeBoundsAtTheEndOfBlockNil = wazevoapi.NewNilVarLength[knownSafeBoundWithID]()

// NewFrontendCompiler returns a frontend Compiler.
func NewFrontendCompiler(m *wasm.Module, ssaBuilder ssa.Builder, offset *wazevoapi.ModuleContextOffsetData, ensureTermination bool, listenerOn bool, sourceInfo bool) *Compiler {
	c := &Compiler{
		m:                                 m,
		ssaBuilder:                        ssaBuilder,
		br:                                bytes.NewReader(nil),
		offset:                            offset,
		ensureTermination:                 ensureTermination,
		needSourceOffsetInfo:              sourceInfo,
		tryTableMetadata:                  &localTryTableMetadata{},
		varLengthKnownSafeBoundWithIDPool: wazevoapi.NewVarLengthPool[knownSafeBoundWithID](),
	}
	c.declareSignatures(listenerOn)
	return c
}

// tryTableMetadata accumulates try_table metadata during compilation.
type tryTableMetadata interface {
	Append(info wazevoapi.TryTableInfo) int
	Table() []wazevoapi.TryTableInfo
}

// localTryTableMetadata is the single-threaded implementation.
type localTryTableMetadata struct {
	table []wazevoapi.TryTableInfo
}

func (t *localTryTableMetadata) Append(info wazevoapi.TryTableInfo) int {
	id := len(t.table)
	t.table = append(t.table, info)
	return id
}

func (t *localTryTableMetadata) Table() []wazevoapi.TryTableInfo {
	return t.table
}

// SharedTryTableMetadata is the thread-safe implementation for parallel compilation.
type SharedTryTableMetadata struct {
	mu        sync.Mutex
	table     []wazevoapi.TryTableInfo
	finalized bool
}

// NewSharedTryTableMetadata creates a new SharedTryTableMetadata.
func NewSharedTryTableMetadata() *SharedTryTableMetadata {
	return &SharedTryTableMetadata{}
}

func (s *SharedTryTableMetadata) Append(info wazevoapi.TryTableInfo) int {
	if s.finalized {
		panic("already finalized")
	}
	s.mu.Lock()
	id := len(s.table)
	s.table = append(s.table, info)
	s.mu.Unlock()
	return id
}

func (s *SharedTryTableMetadata) Table() []wazevoapi.TryTableInfo {
	s.finalized = true
	return s.table
}

// WithTryTableMetadata replaces the try_table metadata table implementation.
func (c *Compiler) WithTryTableMetadata(t tryTableMetadata) *Compiler {
	c.tryTableMetadata = t
	return c
}

// TryTableMetadata returns the accumulated try_table metadata.
func (c *Compiler) TryTableMetadata() []wazevoapi.TryTableInfo {
	return c.tryTableMetadata.Table()
}

func (c *Compiler) declareSignatures(listenerOn bool) {
	m := c.m
	c.signatures = make(map[*wasm.FunctionType]*ssa.Signature, len(m.TypeSection)+2)
	if listenerOn {
		c.listenerSignatures = make(map[*wasm.FunctionType][2]*ssa.Signature, len(m.TypeSection))
	}
	for i := range m.TypeSection {
		wasmSig := &m.TypeSection[i]
		sig := SignatureForWasmFunctionType(wasmSig)
		sig.ID = ssa.SignatureID(i)
		c.signatures[wasmSig] = &sig
		c.ssaBuilder.DeclareSignature(&sig)

		if listenerOn {
			beforeSig, afterSig := SignatureForListener(wasmSig)
			beforeSig.ID = ssa.SignatureID(i) + ssa.SignatureID(len(m.TypeSection))
			afterSig.ID = ssa.SignatureID(i) + ssa.SignatureID(len(m.TypeSection))*2
			c.listenerSignatures[wasmSig] = [2]*ssa.Signature{beforeSig, afterSig}
			c.ssaBuilder.DeclareSignature(beforeSig)
			c.ssaBuilder.DeclareSignature(afterSig)
		}
	}

	begin := ssa.SignatureID(len(m.TypeSection))
	if listenerOn {
		begin *= 3
	}
	c.memoryGrowSig = ssa.Signature{
		ID: begin,
		// Takes execution context and the page size to grow.
		Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32},
		// Returns the previous page size.
		Results: []ssa.Type{ssa.TypeI32},
	}
	c.ssaBuilder.DeclareSignature(&c.memoryGrowSig)

	c.checkModuleExitCodeSig = ssa.Signature{
		ID: c.memoryGrowSig.ID + 1,
		// Only takes execution context.
		Params: []ssa.Type{ssa.TypeI64},
	}
	c.ssaBuilder.DeclareSignature(&c.checkModuleExitCodeSig)

	c.tableGrowSig = ssa.Signature{
		ID:     c.checkModuleExitCodeSig.ID + 1,
		Params: []ssa.Type{ssa.TypeI64 /* exec context */, ssa.TypeI32 /* table index */, ssa.TypeI32 /* num */, ssa.TypeI64 /* ref */},
		// Returns the previous size.
		Results: []ssa.Type{ssa.TypeI32},
	}
	c.ssaBuilder.DeclareSignature(&c.tableGrowSig)

	c.refFuncSig = ssa.Signature{
		ID:     c.tableGrowSig.ID + 1,
		Params: []ssa.Type{ssa.TypeI64 /* exec context */, ssa.TypeI32 /* func index */},
		// Returns the function reference.
		Results: []ssa.Type{ssa.TypeI64},
	}
	c.ssaBuilder.DeclareSignature(&c.refFuncSig)

	c.memmoveSig = ssa.Signature{
		ID: c.refFuncSig.ID + 1,
		// dst, src, and the byte count.
		Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64, ssa.TypeI64},
	}

	c.ssaBuilder.DeclareSignature(&c.memmoveSig)

	c.memoryWait32Sig = ssa.Signature{
		ID: c.memmoveSig.ID + 1,
		// exec context, timeout, expected, addr
		Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64, ssa.TypeI32, ssa.TypeI64},
		// Returns the status.
		Results: []ssa.Type{ssa.TypeI32},
	}
	c.ssaBuilder.DeclareSignature(&c.memoryWait32Sig)

	c.memoryWait64Sig = ssa.Signature{
		ID: c.memoryWait32Sig.ID + 1,
		// exec context, timeout, expected, addr
		Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64, ssa.TypeI64, ssa.TypeI64},
		// Returns the status.
		Results: []ssa.Type{ssa.TypeI32},
	}
	c.ssaBuilder.DeclareSignature(&c.memoryWait64Sig)

	c.memoryNotifySig = ssa.Signature{
		ID: c.memoryWait64Sig.ID + 1,
		// exec context, count, addr
		Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32, ssa.TypeI64},
		// Returns the number notified.
		Results: []ssa.Type{ssa.TypeI32},
	}
	c.ssaBuilder.DeclareSignature(&c.memoryNotifySig)

	c.throwAllocSig = ssa.Signature{
		ID:      c.memoryNotifySig.ID + 1,
		Params:  []ssa.Type{ssa.TypeI64 /* exec context */, ssa.TypeI64 /* tag index */},
		Results: []ssa.Type{ssa.TypeI64 /* exnref */},
	}
	c.ssaBuilder.DeclareSignature(&c.throwAllocSig)

	c.throwSig = ssa.Signature{
		ID:      c.throwAllocSig.ID + 1,
		Params:  []ssa.Type{ssa.TypeI64 /* exec context */, ssa.TypeI64 /* exnref */},
		Results: []ssa.Type{},
	}
	c.ssaBuilder.DeclareSignature(&c.throwSig)

	c.tryTableEnterSig = ssa.Signature{
		ID:      c.throwSig.ID + 1,
		Params:  []ssa.Type{ssa.TypeI64 /* exec context */, ssa.TypeI64 /* encoded exit code */},
		Results: []ssa.Type{},
	}
	c.ssaBuilder.DeclareSignature(&c.tryTableEnterSig)

	c.tryTableLeaveSig = ssa.Signature{
		ID:      c.tryTableEnterSig.ID + 1,
		Params:  []ssa.Type{ssa.TypeI64 /* exec context */},
		Results: []ssa.Type{},
	}
	c.ssaBuilder.DeclareSignature(&c.tryTableLeaveSig)

	c.memclrSig = ssa.Signature{
		ID: c.tryTableLeaveSig.ID + 1,
		// ptr and the byte count.
		Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64},
	}
	c.ssaBuilder.DeclareSignature(&c.memclrSig)
	c.shadowStoreSig = ssa.Signature{
		ID:      c.memclrSig.ID + 1,
		Params:  []ssa.Type{ssa.TypeI64 /* exec context */, ssa.TypeI64 /* slot */, ssa.TypeI64 /* ptr */},
		Results: []ssa.Type{},
	}
	c.ssaBuilder.DeclareSignature(&c.shadowStoreSig)

	c.globalRefStoreSig = ssa.Signature{
		ID:      c.shadowStoreSig.ID + 1,
		Params:  []ssa.Type{ssa.TypeI64 /* exec context */, ssa.TypeI64 /* global index */, ssa.TypeI64 /* ptr */},
		Results: []ssa.Type{},
	}
	c.ssaBuilder.DeclareSignature(&c.globalRefStoreSig)

	c.tableRefSyncSig = ssa.Signature{
		ID:      c.globalRefStoreSig.ID + 1,
		Params:  []ssa.Type{ssa.TypeI64 /* exec context */, ssa.TypeI64 /* table index */},
		Results: []ssa.Type{},
	}
	c.ssaBuilder.DeclareSignature(&c.tableRefSyncSig)
}

// SignatureForWasmFunctionType returns the ssa.Signature for the given wasm.FunctionType.
func SignatureForWasmFunctionType(typ *wasm.FunctionType) ssa.Signature {
	sig := ssa.Signature{
		// +2 to pass moduleContextPtr and executionContextPtr. See the inline comment LowerToSSA.
		Params:  make([]ssa.Type, len(typ.Params)+2),
		Results: make([]ssa.Type, len(typ.Results)),
	}
	sig.Params[0] = executionContextPtrTyp
	sig.Params[1] = moduleContextPtrTyp
	for j, typ := range typ.Params {
		sig.Params[j+2] = WasmTypeToSSAType(typ)
	}
	for j, typ := range typ.Results {
		sig.Results[j] = WasmTypeToSSAType(typ)
	}
	return sig
}

// Init initializes the state of frontendCompiler and make it ready for a next function.
func (c *Compiler) Init(idx, typIndex wasm.Index, typ *wasm.FunctionType, localTypes []wasm.ValueType, body []byte, needListener bool, bodyOffsetInCodeSection uint64) {
	c.ssaBuilder.Init(c.signatures[typ])
	c.loweringState.reset()

	c.wasmFunctionTypeIndex = typIndex
	c.wasmLocalFunctionIndex = idx
	c.wasmFunctionTyp = typ
	c.wasmFunctionLocalTypes = localTypes
	c.wasmFunctionBody = body
	c.wasmFunctionBodyOffsetInCodeSection = bodyOffsetInCodeSection
	c.needListener = needListener
	c.tryTableDepth = 0
	c.clearSafeBounds()
	c.varLengthKnownSafeBoundWithIDPool.Reset()
	c.knownSafeBoundsAtTheEndOfBlocks = c.knownSafeBoundsAtTheEndOfBlocks[:0]
}

// Note: this assumes 64-bit platform (I believe we won't have 32-bit backend ;)).
const executionContextPtrTyp, moduleContextPtrTyp = ssa.TypeI64, ssa.TypeI64

// LowerToSSA lowers the current function to SSA IR which will be held by ssaBuilder.
//
// After calling this, the caller will be able to access the SSA info in *Compiler.ssaBuilder.
//
// Note that this only does the naive lowering, and do not do any optimization, instead the caller is expected to do so.
func (c *Compiler) LowerToSSA() {
	builder := c.ssaBuilder

	// Set up the entry block.
	entryBlock := builder.AllocateBasicBlock()
	builder.SetCurrentBlock(entryBlock)

	// Functions always take two parameters in addition to Wasm-level parameters:
	//
	//  1. executionContextPtr: pointer to the *executionContext in wazevo package.
	//    This will be used to exit the execution in the face of trap, plus used for host function calls.
	//
	// 	2. moduleContextPtr: pointer to the *moduleContextOpaque in wazevo package.
	//	  This will be used to access memory, etc. Also, this will be used during host function calls.
	//
	// Note: it's clear that sometimes a function won't need them. For example,
	//  if the function doesn't trap and doesn't make function call, then
	// 	we might be able to eliminate the parameter. However, if that function
	//	can be called via call_indirect, then we cannot eliminate because the
	//  signature won't match with the expected one.
	// TODO: maybe there's some way to do this optimization without glitches, but so far I have no clue about the feasibility.
	//
	// Note: In Wasmtime or many other runtimes, moduleContextPtr is called "vmContext". Also note that `moduleContextPtr`
	//  is wazero-specific since other runtimes can naturally use the OS-level signal to do this job thanks to the fact that
	//  they can use native stack vs wazero cannot use Go-routine stack and have to use Go-runtime allocated []byte as a stack.
	c.execCtxPtrValue = entryBlock.AddParam(builder, executionContextPtrTyp)
	c.moduleCtxPtrValue = entryBlock.AddParam(builder, moduleContextPtrTyp)
	builder.AnnotateValue(c.execCtxPtrValue, "exec_ctx")
	builder.AnnotateValue(c.moduleCtxPtrValue, "module_ctx")

	for i, typ := range c.wasmFunctionTyp.Params {
		st := WasmTypeToSSAType(typ)
		variable := builder.DeclareVariable(st)
		value := entryBlock.AddParam(builder, st)
		builder.DefineVariable(variable, value, entryBlock)
		c.setWasmLocalVariable(wasm.Index(i), variable)
	}
	c.declareWasmLocals()
	c.declareNecessaryVariables()
	c.declareShadowSlots()

	if c.needsShadowFrame {
		// Reserve this frame's shadow slots. The count is not an operand: it
		// is only final once the body is lowered, so the backend reads it
		// from the builder.
		builder.InsertInstruction(builder.AllocateInstruction().AsShadowFrameEnter(c.execCtxPtrValue))
		// Only now do the slots belong to this frame, so params root after it.
		c.rootParams()
	}

	c.lowerBody(entryBlock)

	if c.needsShadowFrame {
		// The gate over-approximates, so a frame may turn out to hold no
		// slots. Keep at least one, so that the frame instructions the body
		// already carries always adjust by a non-zero amount.
		builder.SetShadowFrameSize(max(c.shadowSlots, 1))
	}
}

// declareShadowSlots assigns a shadow slot to every exnref-typed param and
// local. These are the locations that can hold a reference across a point
// where another one is produced, which is the two-live-exceptions shape of
// wazero/wazero#2522.
func (c *Compiler) declareShadowSlots() {
	c.shadowSlots = 0
	params, locals := c.wasmFunctionTyp.Params, c.wasmFunctionLocalTypes
	c.exnrefLocalSlot = c.exnrefLocalSlot[:0]
	c.needsShadowFrame = false
	for i := 0; i < len(params)+len(locals); i++ {
		var t wasm.ValueType
		if i < len(params) {
			t = params[i]
		} else {
			t = locals[i-len(params)]
		}
		slot := -1
		if wasm.IsShadowedRef(t) {
			slot = c.allocShadowSlot()
		}
		c.exnrefLocalSlot = append(c.exnrefLocalSlot, slot)
	}

	// The body can also take a reference from a try_table's catch_ref, a
	// global, a table or a call result, none of which the signature reveals.
	// Searching for the opcode byte over-approximates — a v128 shuffle mask
	// or any other immediate can look like one — but it never misses a real
	// instruction, and a false positive only costs a frame adjust. Each
	// search is guarded by whether the module declares such a source at all,
	// so a module that has none compiles exactly as before.
	c.needsShadowFrame = c.shadowSlots > 0 || c.bodyMayTakeRef()
}

// rootParams roots exnref-typed parameters in their own frame. The caller
// normally holds them rooted for the duration of the call, but a tail call
// frees the caller's frame, so the callee cannot rely on that.
func (c *Compiler) rootParams() {
	for i, t := range c.wasmFunctionTyp.Params {
		if !wasm.IsShadowedRef(t) {
			continue
		}
		c.emitShadowStore(c.exnrefLocalSlot[i], c.ssaBuilder.MustFindValue(c.localVariable(wasm.Index(i))))
	}
}

// bodyMayTakeRef reports whether this function body might take a reference
// from somewhere its signature does not show. Over-approximates: see the
// caller.
func (c *Compiler) bodyMayTakeRef() bool {
	body := c.wasmFunctionBody
	has := func(op wasm.Opcode) bool { return bytes.IndexByte(body, op) >= 0 }

	if c.m.ImportTagCount > 0 || len(c.m.TagSection) > 0 {
		if has(wasm.OpcodeTryTable) {
			return true
		}
	}
	for _, shadowed := range c.globalShadowed {
		if shadowed && has(wasm.OpcodeGlobalGet) {
			return true
		}
	}
	if c.moduleHasShadowedTable() && has(wasm.OpcodeTableGet) {
		return true
	}
	if c.moduleReturnsRef() &&
		(has(wasm.OpcodeCall) || has(wasm.OpcodeCallIndirect) || has(wasm.OpcodeCallRef)) {
		return true
	}
	return false
}

// moduleHasShadowedTable reports whether any table in the module holds
// reference-typed elements.
func (c *Compiler) moduleHasShadowedTable() bool {
	for i := range c.m.ImportSection {
		if imp := &c.m.ImportSection[i]; imp.Type == wasm.ExternTypeTable &&
			wasm.IsShadowedRef(imp.DescTable.Type) {
			return true
		}
	}
	for i := range c.m.TableSection {
		if wasm.IsShadowedRef(c.m.TableSection[i].Type) {
			return true
		}
	}
	return false
}

// moduleReturnsRef reports whether any declared type returns a reference, so
// that a call in this body could hand one back.
func (c *Compiler) moduleReturnsRef() bool {
	for i := range c.m.TypeSection {
		for _, t := range c.m.TypeSection[i].Results {
			if wasm.IsShadowedRef(t) {
				return true
			}
		}
	}
	return false
}

// rootGlobal records in the module's side table that global index now holds v.
// Compiled code writes the global itself as raw bytes into the module context,
// where Go cannot see it, so without this the object dies as soon as the frame
// that produced it releases its slots.
func (c *Compiler) rootGlobal(index wasm.Index, v ssa.Value) {
	if !c.globalShadowed[index] {
		return
	}
	builder := c.ssaBuilder
	ptr := builder.AllocateInstruction().
		AsLoad(c.execCtxPtrValue,
			wazevoapi.ExecutionContextOffsetGlobalRefStoreTrampolineAddress.U32(),
			ssa.TypeI64,
		).Insert(builder).Return()
	idx := builder.AllocateInstruction().AsIconst64(uint64(index)).Insert(builder).Return()
	args := c.allocateVarLengthValues(3, c.execCtxPtrValue, idx, v)
	builder.AllocateInstruction().
		AsCallIndirect(ptr, &c.globalRefStoreSig, args).
		Insert(builder)
}

// syncTableRefs has Go rebuild the table's side table after a write compiled
// code just made. Table elements live in memory Go does not scan, so this is
// what keeps a reference stored there alive. Emitted only for
// reference-typed tables, which leaves every ordinary table untouched.
func (c *Compiler) syncTableRefs(index wasm.Index) {
	if !c.tableShadowed(index) {
		return
	}
	builder := c.ssaBuilder
	c.storeCallerModuleContext()
	ptr := builder.AllocateInstruction().
		AsLoad(c.execCtxPtrValue,
			wazevoapi.ExecutionContextOffsetTableRefSyncTrampolineAddress.U32(),
			ssa.TypeI64,
		).Insert(builder).Return()
	idx := builder.AllocateInstruction().AsIconst64(uint64(index)).Insert(builder).Return()
	args := c.allocateVarLengthValues(2, c.execCtxPtrValue, idx)
	builder.AllocateInstruction().
		AsCallIndirect(ptr, &c.tableRefSyncSig, args).
		Insert(builder)
	c.reloadAfterCall()
}

// rootIfShadowed roots v in a fresh slot when t is a reference type, and
// reports whether it did. Used where a value enters the frame from outside:
// a global, a table, or a call result.
func (c *Compiler) rootIfShadowed(t wasm.ValueType, v ssa.Value) {
	if wasm.IsShadowedRef(t) {
		c.emitShadowStore(c.allocShadowSlot(), v)
	}
}

// rootResults roots the reference-typed results a call just returned. The
// callee's frame is gone by now, so its slots no longer hold them.
func (c *Compiler) rootResults(typ *wasm.FunctionType, first ssa.Value, rest []ssa.Value) {
	for i, t := range typ.Results {
		if !wasm.IsShadowedRef(t) {
			continue
		}
		if i == 0 {
			c.rootIfShadowed(t, first)
			continue
		}
		c.rootIfShadowed(t, rest[i-1])
	}
}

// wasmFuncType returns the declared type of function fnIndex, which may be
// imported or defined in this module.
func (c *Compiler) wasmFuncType(fnIndex uint32) *wasm.FunctionType {
	var typIndex wasm.Index
	if fnIndex < c.m.ImportFunctionCount {
		var fi int
		for i := range c.m.ImportSection {
			imp := &c.m.ImportSection[i]
			if imp.Type != wasm.ExternTypeFunc {
				continue
			}
			if fi == int(fnIndex) {
				typIndex = imp.DescFunc
				break
			}
			fi++
		}
	} else {
		typIndex = c.m.FunctionSection[fnIndex-c.m.ImportFunctionCount]
	}
	return &c.m.TypeSection[typIndex]
}

// tableShadowed reports whether table index holds reference-typed elements.
func (c *Compiler) tableShadowed(index wasm.Index) bool {
	var i wasm.Index
	for j := range c.m.ImportSection {
		if imp := &c.m.ImportSection[j]; imp.Type == wasm.ExternTypeTable {
			if i == index {
				return wasm.IsShadowedRef(imp.DescTable.Type)
			}
			i++
		}
	}
	if idx := int(index - i); idx < len(c.m.TableSection) {
		return wasm.IsShadowedRef(c.m.TableSection[idx].Type)
	}
	return false
}

// allocShadowSlot reserves the next shadow slot in this frame.
func (c *Compiler) allocShadowSlot() int {
	s := c.shadowSlots
	c.shadowSlots++
	return s
}

// emitShadowStore roots v in this frame's shadow slot, so Go's collector keeps
// the object alive while compiled code holds it as an opaque integer.
func (c *Compiler) emitShadowStore(slot int, v ssa.Value) {
	builder := c.ssaBuilder
	ptr := builder.AllocateInstruction().
		AsLoad(c.execCtxPtrValue,
			wazevoapi.ExecutionContextOffsetShadowStoreTrampolineAddress.U32(),
			ssa.TypeI64,
		).Insert(builder).Return()
	slotVal := builder.AllocateInstruction().AsIconst64(uint64(slot)).Insert(builder).Return()
	args := c.allocateVarLengthValues(3, c.execCtxPtrValue, slotVal, v)
	builder.AllocateInstruction().
		AsCallIndirect(ptr, &c.shadowStoreSig, args).
		Insert(builder)
}

// rootExnRef loads the caught exnref and roots it in a shadow slot of its own.
// catch_ref and catch_all_ref are where an exception enters the frame: the
// dispatch loop drops its own reference as soon as the next one is thrown, so
// without this the guest would be left holding a freed pointer. See
// wazero/wazero#2522.
func (c *Compiler) rootExnRef() ssa.Value {
	v := c.loadExnRef()
	c.emitShadowStore(c.allocShadowSlot(), v)
	return v
}

// rootLocal roots v in the shadow slot of local index, when that local is
// exnref-typed. A no-op for every other local, so ordinary code is unchanged.
func (c *Compiler) rootLocal(index uint32, v ssa.Value) {
	if int(index) >= len(c.exnrefLocalSlot) {
		return
	}
	if slot := c.exnrefLocalSlot[index]; slot >= 0 {
		c.emitShadowStore(slot, v)
	}
}

// emitShadowFrameLeave releases this frame's shadow slots. Emitted before every
// return and tail call, since a tail call frees the frame too.
func (c *Compiler) emitShadowFrameLeave() {
	if !c.needsShadowFrame {
		return
	}
	builder := c.ssaBuilder
	builder.InsertInstruction(builder.AllocateInstruction().AsShadowFrameLeave(c.execCtxPtrValue))
}

// localVariable returns the SSA variable for the given Wasm local index.
func (c *Compiler) localVariable(index wasm.Index) ssa.Variable {
	return c.wasmLocalToVariable[index]
}

func (c *Compiler) setWasmLocalVariable(index wasm.Index, variable ssa.Variable) {
	idx := int(index)
	if idx >= len(c.wasmLocalToVariable) {
		c.wasmLocalToVariable = append(c.wasmLocalToVariable, make([]ssa.Variable, idx+1-len(c.wasmLocalToVariable))...)
	}
	c.wasmLocalToVariable[idx] = variable
}

// declareWasmLocals declares the SSA variables for the Wasm locals.
func (c *Compiler) declareWasmLocals() {
	localCount := wasm.Index(len(c.wasmFunctionTyp.Params))
	for i, typ := range c.wasmFunctionLocalTypes {
		st := WasmTypeToSSAType(typ)
		variable := c.ssaBuilder.DeclareVariable(st)
		c.setWasmLocalVariable(wasm.Index(i)+localCount, variable)
		c.ssaBuilder.InsertZeroValue(st)
	}
}

func (c *Compiler) declareNecessaryVariables() {
	if c.needMemory = c.m.MemorySection != nil; c.needMemory {
		c.memoryShared = c.m.MemorySection.IsShared
		c.memoryMinSizeInBytes = uint64(c.m.MemorySection.Min) * uint64(wasm.MemoryPageSize)
	} else if c.needMemory = c.m.ImportMemoryCount > 0; c.needMemory {
		for _, imp := range c.m.ImportSection {
			if imp.Type == wasm.ExternTypeMemory {
				c.memoryShared = imp.DescMem.IsShared
				// The import's minimum is a type constraint on the provided
				// memory, so it is a valid static lower bound as well.
				c.memoryMinSizeInBytes = uint64(imp.DescMem.Min) * uint64(wasm.MemoryPageSize)
				break
			}
		}
	}

	if c.needMemory {
		c.memoryBaseVariable = c.ssaBuilder.DeclareVariable(ssa.TypeI64)
		c.memoryLenVariable = c.ssaBuilder.DeclareVariable(ssa.TypeI64)
	}

	c.globalVariables = c.globalVariables[:0]
	c.mutableGlobalVariablesIndexes = c.mutableGlobalVariablesIndexes[:0]
	c.globalVariablesTypes = c.globalVariablesTypes[:0]
	c.globalShadowed = c.globalShadowed[:0]
	for _, imp := range c.m.ImportSection {
		if imp.Type == wasm.ExternTypeGlobal {
			desc := imp.DescGlobal
			c.declareWasmGlobal(desc.ValType, desc.Mutable)
		}
	}
	for _, g := range c.m.GlobalSection {
		desc := g.Type
		c.declareWasmGlobal(desc.ValType, desc.Mutable)
	}

	// TODO: add tables.
}

func (c *Compiler) declareWasmGlobal(typ wasm.ValueType, mutable bool) {
	st := WasmTypeToSSAType(typ)
	v := c.ssaBuilder.DeclareVariable(st)
	index := wasm.Index(len(c.globalVariables))
	c.globalVariables = append(c.globalVariables, v)
	c.globalVariablesTypes = append(c.globalVariablesTypes, st)
	c.globalShadowed = append(c.globalShadowed, wasm.IsShadowedRef(typ))
	if mutable {
		c.mutableGlobalVariablesIndexes = append(c.mutableGlobalVariablesIndexes, index)
	}
}

// WasmTypeToSSAType converts wasm.ValueType to ssa.Type.
func WasmTypeToSSAType(vt wasm.ValueType) ssa.Type {
	switch vt {
	case wasm.ValueTypeI32:
		return ssa.TypeI32
	case wasm.ValueTypeI64,
		// externref, funcref, and exnref are represented as I64 since we only support 64-bit platforms.
		wasm.ValueTypeExternref, wasm.ValueTypeFuncref,
		wasm.ValueTypeExnref:
		return ssa.TypeI64
	case wasm.ValueTypeF32:
		return ssa.TypeF32
	case wasm.ValueTypeF64:
		return ssa.TypeF64
	case wasm.ValueTypeV128:
		return ssa.TypeV128
	default:
		// Concrete ref types (ref $t) have variable bit patterns.
		if vt.IsRef() {
			return ssa.TypeI64
		}
		panic("TODO: " + wasm.ValueTypeName(vt))
	}
}

// addBlockParamsFromWasmTypes adds the block parameters to the given block.
func (c *Compiler) addBlockParamsFromWasmTypes(tps []wasm.ValueType, blk ssa.BasicBlock) {
	for _, typ := range tps {
		st := WasmTypeToSSAType(typ)
		blk.AddParam(c.ssaBuilder, st)
	}
}

// formatBuilder outputs the constructed SSA function as a string with a source information.
func (c *Compiler) formatBuilder() string {
	return c.ssaBuilder.Format()
}

// SignatureForListener returns the signatures for the listener functions.
func SignatureForListener(wasmSig *wasm.FunctionType) (*ssa.Signature, *ssa.Signature) {
	beforeSig := &ssa.Signature{}
	beforeSig.Params = make([]ssa.Type, len(wasmSig.Params)+2)
	beforeSig.Params[0] = ssa.TypeI64 // Execution context.
	beforeSig.Params[1] = ssa.TypeI32 // Function index.
	for i, p := range wasmSig.Params {
		beforeSig.Params[i+2] = WasmTypeToSSAType(p)
	}
	afterSig := &ssa.Signature{}
	afterSig.Params = make([]ssa.Type, len(wasmSig.Results)+2)
	afterSig.Params[0] = ssa.TypeI64 // Execution context.
	afterSig.Params[1] = ssa.TypeI32 // Function index.
	for i, p := range wasmSig.Results {
		afterSig.Params[i+2] = WasmTypeToSSAType(p)
	}
	return beforeSig, afterSig
}

// isBoundSafe returns true if the given value is known to be safe to access up to the given bound.
func (c *Compiler) getKnownSafeBound(v ssa.ValueID) *knownSafeBound {
	if int(v) >= len(c.knownSafeBounds) {
		return nil
	}
	return &c.knownSafeBounds[v]
}

// recordKnownSafeBound records the given safe bound for the given value.
func (c *Compiler) recordKnownSafeBound(v ssa.ValueID, safeBound uint64, absoluteAddr ssa.Value) {
	if int(v) >= len(c.knownSafeBounds) {
		c.knownSafeBounds = append(c.knownSafeBounds, make([]knownSafeBound, v+1)...)
	}

	if exiting := c.knownSafeBounds[v]; exiting.bound == 0 {
		c.knownSafeBounds[v] = knownSafeBound{
			bound:        safeBound,
			absoluteAddr: absoluteAddr,
		}
		c.knownSafeBoundsSet = append(c.knownSafeBoundsSet, v)
	} else if safeBound > exiting.bound {
		c.knownSafeBounds[v].bound = safeBound
	}
}

// clearSafeBounds clears the known safe bounds.
func (c *Compiler) clearSafeBounds() {
	for _, v := range c.knownSafeBoundsSet {
		ptr := &c.knownSafeBounds[v]
		ptr.bound = 0
		ptr.absoluteAddr = ssa.ValueInvalid
	}
	c.knownSafeBoundsSet = c.knownSafeBoundsSet[:0]
}

// resetAbsoluteAddressInSafeBounds resets the absolute addresses recorded in the known safe bounds.
func (c *Compiler) resetAbsoluteAddressInSafeBounds() {
	for _, v := range c.knownSafeBoundsSet {
		ptr := &c.knownSafeBounds[v]
		ptr.absoluteAddr = ssa.ValueInvalid
	}
}

func (k *knownSafeBound) valid() bool {
	return k != nil && k.bound > 0
}

func (c *Compiler) allocateVarLengthValues(_cap int, vs ...ssa.Value) ssa.Values {
	builder := c.ssaBuilder
	pool := builder.VarLengthPool()
	args := pool.Allocate(_cap)
	args = args.Append(pool, vs...)
	return args
}

func (c *Compiler) finalizeKnownSafeBoundsAtTheEndOfBlock(bID ssa.BasicBlockID) {
	_bID := int(bID)
	if l := len(c.knownSafeBoundsAtTheEndOfBlocks); _bID >= l {
		c.knownSafeBoundsAtTheEndOfBlocks = append(c.knownSafeBoundsAtTheEndOfBlocks,
			make([]knownSafeBoundsAtTheEndOfBlock, _bID+1-len(c.knownSafeBoundsAtTheEndOfBlocks))...)
		for i := l; i < len(c.knownSafeBoundsAtTheEndOfBlocks); i++ {
			c.knownSafeBoundsAtTheEndOfBlocks[i] = knownSafeBoundsAtTheEndOfBlockNil
		}
	}
	p := &c.varLengthKnownSafeBoundWithIDPool
	size := len(c.knownSafeBoundsSet)
	allocated := c.varLengthKnownSafeBoundWithIDPool.Allocate(size)
	// Sort the known safe bounds by the value ID so that we can use the intersection algorithm in initializeCurrentBlockKnownBounds.
	sortSSAValueIDs(c.knownSafeBoundsSet)
	for _, vID := range c.knownSafeBoundsSet {
		kb := c.knownSafeBounds[vID]
		allocated = allocated.Append(p, knownSafeBoundWithID{
			knownSafeBound: kb,
			id:             vID,
		})
	}
	c.knownSafeBoundsAtTheEndOfBlocks[bID] = allocated
	c.clearSafeBounds()
}

func (c *Compiler) initializeCurrentBlockKnownBounds() {
	currentBlk := c.ssaBuilder.CurrentBlock()
	switch preds := currentBlk.Preds(); preds {
	case 0:
	case 1:
		pred := currentBlk.Pred(0).ID()
		for _, kb := range c.getKnownSafeBoundsAtTheEndOfBlocks(pred).View() {
			// Unless the block is sealed, we cannot assume the absolute address is valid:
			// later we might add another predecessor that has no visibility of that value.
			addr := ssa.ValueInvalid
			if currentBlk.Sealed() {
				addr = kb.absoluteAddr
			}
			c.recordKnownSafeBound(kb.id, kb.bound, addr)
		}
	default:
		c.pointers = c.pointers[:0]
		c.bounds = c.bounds[:0]
		for i := 0; i < preds; i++ {
			c.bounds = append(c.bounds, c.getKnownSafeBoundsAtTheEndOfBlocks(currentBlk.Pred(i).ID()).View())
			c.pointers = append(c.pointers, 0)
		}

		// If there are multiple predecessors, we need to find the intersection of the known safe bounds.

	outer:
		for {
			smallestID := ssa.ValueID(math.MaxUint32)
			for i, ptr := range c.pointers {
				if ptr >= len(c.bounds[i]) {
					break outer
				}
				cb := &c.bounds[i][ptr]
				if id := cb.id; id < smallestID {
					smallestID = cb.id
				}
			}

			// Check if current elements are the same across all lists.
			same := true
			minBound := uint64(math.MaxUint64)
			for i := 0; i < preds; i++ {
				cb := &c.bounds[i][c.pointers[i]]
				if cb.id != smallestID {
					same = false
				} else {
					if cb.bound < minBound {
						minBound = cb.bound
					}
					c.pointers[i]++
				}
			}

			if same { // All elements are the same.
				// Absolute address cannot be used in the intersection since the value might be only defined in one of the predecessors.
				c.recordKnownSafeBound(smallestID, minBound, ssa.ValueInvalid)
			}
		}
	}
}

func (c *Compiler) getKnownSafeBoundsAtTheEndOfBlocks(id ssa.BasicBlockID) knownSafeBoundsAtTheEndOfBlock {
	if int(id) >= len(c.knownSafeBoundsAtTheEndOfBlocks) {
		return knownSafeBoundsAtTheEndOfBlockNil
	}
	return c.knownSafeBoundsAtTheEndOfBlocks[id]
}
