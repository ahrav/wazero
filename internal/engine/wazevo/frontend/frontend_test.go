package frontend

import (
	"fmt"
	"reflect"
	"testing"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/testcases"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/wazevoapi"
	"github.com/tetratelabs/wazero/internal/testing/require"
	"github.com/tetratelabs/wazero/internal/wasm"
)

func TestMemoryInstanceBufferOffsets(t *testing.T) {
	var mem wasm.MemoryInstance
	var sliceHeader reflect.SliceHeader
	bufferOffset := unsafe.Offsetof(mem.Buffer)
	lengthOffset := bufferOffset + unsafe.Offsetof(sliceHeader.Len)
	require.Equal(t, uintptr(memoryInstanceBufOffset), bufferOffset)
	require.Equal(t, uintptr(memoryInstanceBufSizeOffset), lengthOffset)
	require.Equal(t, uintptr(0), lengthOffset%8)
}

func TestCompiler_LowerToSSA(t *testing.T) {
	// Most of the logic should look similar to Cranelift's Wasm frontend, so when you want to see
	// what output should look like, you can run:
	// `~/wasmtime/target/debug/clif-util wasm --target aarch64-apple-darwin testcase.wat -p -t`
	for _, tc := range []struct {
		name              string
		ensureTermination bool
		needListener      bool
		boundsElision     bool
		// m is the *wasm.Module to be compiled in this test.
		m *wasm.Module
		// targetIndex is the index of a local function to be compiled in this test.
		targetIndex wasm.Index
		// exp is the *unoptimized* expected SSA IR for the function m.FunctionSection[targetIndex].
		exp string
		// expAfterPasses is not empty when we want to check the result after SSA passes.
		expAfterPasses string
		features       api.CoreFeatures
	}{
		{
			name: "empty", m: testcases.Empty.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64)
	Jump blk_ret
`,
		},
		{
			name: "unreachable", m: testcases.Unreachable.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64)
	Exit exec_ctx, unreachable
`,
		},
		{
			name: testcases.OnlyReturn.Name, m: testcases.OnlyReturn.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64)
	Return
`,
		},
		{
			name: "params", m: testcases.Params.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:f32, v4:f64)
	Return
`,
		},
		{
			name: "add/sub params return", m: testcases.AddSubParamsReturn.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32)
	v4:i32 = Iadd v2, v3
	v5:i32 = Isub v4, v2
	Jump blk_ret, v5
`,
		},
		{
			name: "add/sub params return / listener", m: testcases.AddSubParamsReturn.Module,
			needListener: true,
			exp: `
signatures:
	sig1: i64i32i32i32_v
	sig2: i64i32i32_v

blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32)
	Store module_ctx, exec_ctx, 0x8
	v4:i64 = Load module_ctx, 0x8
	v5:i64 = Load v4, 0x0
	v6:i32 = Iconst_32 0x0
	CallIndirect v5:sig1, exec_ctx, v6, v2, v3
	v7:i32 = Iadd v2, v3
	v8:i32 = Isub v7, v2
	Store module_ctx, exec_ctx, 0x8
	v9:i64 = Load module_ctx, 0x10
	v10:i64 = Load v9, 0x0
	v11:i32 = Iconst_32 0x0
	CallIndirect v10:sig2, exec_ctx, v11, v8
	Jump blk_ret, v8
`,
		},
		{
			name: "locals", m: testcases.Locals.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64)
	v2:i32 = Iconst_32 0x0
	v3:i64 = Iconst_64 0x0
	v4:f32 = F32const 0.000000
	v5:f64 = F64const 0.000000
	Jump blk_ret
`,
			expAfterPasses: `
blk0: (exec_ctx:i64, module_ctx:i64)
	Jump blk_ret
`,
		},
		{
			name: "selects", m: testcases.Selects.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32, v4:i64, v5:i64, v6:f32, v7:f32, v8:f64, v9:f64)
	v10:i32 = Icmp eq, v4, v5
	v11:i32 = Select v10, v2, v3
	v12:i64 = Select v3, v4, v5
	v13:i32 = Fcmp gt, v8, v9
	v14:f32 = Select v13, v6, v7
	v15:i32 = Fcmp neq, v6, v7
	v16:f64 = Select v15, v8, v9
	Jump blk_ret, v11, v12, v14, v16
`,
		},
		{
			name: "local param tee return", m: testcases.LocalParamTeeReturn.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32)
	v3:i32 = Iconst_32 0x0
	Jump blk_ret, v2, v2
`,
			expAfterPasses: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32)
	Jump blk_ret, v2, v2
`,
		},
		{
			name: "locals + params", m: testcases.LocalsParams.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i64, v3:f32, v4:f64)
	v5:i32 = Iconst_32 0x0
	v6:i64 = Iconst_64 0x0
	v7:f32 = F32const 0.000000
	v8:f64 = F64const 0.000000
	v9:i64 = Iadd v2, v2
	v10:i64 = Isub v9, v2
	v11:f32 = Fadd v3, v3
	v12:f32 = Fsub v11, v3
	v13:f32 = Fmul v12, v3
	v14:f32 = Fdiv v13, v3
	v15:f32 = Fmax v14, v3
	v16:f32 = Fmin v15, v3
	v17:f64 = Fadd v4, v4
	v18:f64 = Fsub v17, v4
	v19:f64 = Fmul v18, v4
	v20:f64 = Fdiv v19, v4
	v21:f64 = Fmax v20, v4
	v22:f64 = Fmin v21, v4
	Jump blk_ret, v10, v16, v22
`,
			expAfterPasses: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i64, v3:f32, v4:f64)
	v9:i64 = Iadd v2, v2
	v10:i64 = Isub v9, v2
	v11:f32 = Fadd v3, v3
	v12:f32 = Fsub v11, v3
	v13:f32 = Fmul v12, v3
	v14:f32 = Fdiv v13, v3
	v15:f32 = Fmax v14, v3
	v16:f32 = Fmin v15, v3
	v17:f64 = Fadd v4, v4
	v18:f64 = Fsub v17, v4
	v19:f64 = Fmul v18, v4
	v20:f64 = Fdiv v19, v4
	v21:f64 = Fmax v20, v4
	v22:f64 = Fmin v21, v4
	Jump blk_ret, v10, v16, v22
`,
		},
		{
			name: "locals + params + return", m: testcases.LocalParamReturn.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32)
	v3:i32 = Iconst_32 0x0
	Jump blk_ret, v2, v3
`,
		},
		{
			name: "swap param and return", m: testcases.SwapParamAndReturn.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32)
	Jump blk_ret, v3, v2
`,
		},
		{
			name: "swap params and return", m: testcases.SwapParamsAndReturn.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32)
	Jump blk1

blk1: () <-- (blk0)
	Jump blk_ret, v3, v2
`,
		},
		{
			name: "block - br", m: testcases.BlockBr.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64)
	v2:i32 = Iconst_32 0x0
	v3:i64 = Iconst_64 0x0
	v4:f32 = F32const 0.000000
	v5:f64 = F64const 0.000000
	Jump blk1

blk1: () <-- (blk0)
	Jump blk_ret
`,
		},
		{
			name: "block - br_if", m: testcases.BlockBrIf.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64)
	v2:i32 = Iconst_32 0x0
	Brnz v2, blk1
	Jump blk2

blk1: () <-- (blk0)
	Jump blk_ret

blk2: () <-- (blk0)
	Exit exec_ctx, unreachable
`,
		},
		{
			name: "loop - br", m: testcases.LoopBr.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64)
	Jump blk1

blk1: () <-- (blk0,blk1)
	Jump blk1

blk2: ()
`,
			expAfterPasses: `
blk0: (exec_ctx:i64, module_ctx:i64)
	Jump fallthrough

blk1: () <-- (blk0,blk1)
	Jump blk1
`,
		},
		{
			name: "loop - br / ensure termination", m: testcases.LoopBr.Module,
			ensureTermination: true,
			exp: `
signatures:
	sig2: i64_v

blk0: (exec_ctx:i64, module_ctx:i64)
	Jump blk1

blk1: () <-- (blk0,blk1)
	v2:i64 = Load exec_ctx, 0x58
	CallIndirect v2:sig2, exec_ctx
	Jump blk1

blk2: ()
`,
			expAfterPasses: `
signatures:
	sig2: i64_v

blk0: (exec_ctx:i64, module_ctx:i64)
	Jump fallthrough

blk1: () <-- (blk0,blk1)
	v2:i64 = Load exec_ctx, 0x58
	CallIndirect v2:sig2, exec_ctx
	Jump blk1
`,
		},
		{
			name: "loop - br_if", m: testcases.LoopBrIf.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64)
	Jump blk1

blk1: () <-- (blk0,blk1)
	v2:i32 = Iconst_32 0x1
	Brnz v2, blk1
	Jump blk3

blk2: ()

blk3: () <-- (blk1)
	Return
`,
			expAfterPasses: `
blk0: (exec_ctx:i64, module_ctx:i64)
	Jump fallthrough

blk1: () <-- (blk0,blk4)
	v2:i32 = Iconst_32 0x1
	Brz v2, blk3
	Jump fallthrough

blk4: () <-- (blk1)
	Jump blk1

blk3: () <-- (blk1)
	Return
`,
		},
		{
			name: "block - block - br", m: testcases.BlockBlockBr.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64)
	v2:i32 = Iconst_32 0x0
	v3:i64 = Iconst_64 0x0
	v4:f32 = F32const 0.000000
	v5:f64 = F64const 0.000000
	Jump blk1

blk1: () <-- (blk0)
	Jump blk_ret

blk2: ()
`,
			expAfterPasses: `
blk0: (exec_ctx:i64, module_ctx:i64)
	Jump fallthrough

blk1: () <-- (blk0)
	Jump blk_ret
`,
		},
		{
			name: "if without else", m: testcases.IfWithoutElse.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64)
	v2:i32 = Iconst_32 0x0
	Brz v2, blk2
	Jump blk1

blk1: () <-- (blk0)
	Jump blk3

blk2: () <-- (blk0)
	Jump blk3

blk3: () <-- (blk1,blk2)
	Jump blk_ret
`,
		},
		{
			name: "if-else", m: testcases.IfElse.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64)
	v2:i32 = Iconst_32 0x0
	Brz v2, blk2
	Jump blk1

blk1: () <-- (blk0)
	Jump blk3

blk2: () <-- (blk0)
	Jump blk_ret

blk3: () <-- (blk1)
	Jump blk_ret
`,
		},
		{
			name: "single predecessor local refs", m: testcases.SinglePredecessorLocalRefs.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64)
	v2:i32 = Iconst_32 0x0
	Brz v2, blk2
	Jump blk1

blk1: () <-- (blk0)
	Return v2

blk2: () <-- (blk0)
	Jump blk3

blk3: () <-- (blk2)
	Jump blk_ret, v2
`,
			expAfterPasses: `
blk0: (exec_ctx:i64, module_ctx:i64)
	v2:i32 = Iconst_32 0x0
	Brz v2, blk2
	Jump fallthrough

blk1: () <-- (blk0)
	Return v2

blk2: () <-- (blk0)
	Jump fallthrough

blk3: () <-- (blk2)
	Jump blk_ret, v2
`,
		},
		{
			name: "multi predecessors local ref",
			m:    testcases.MultiPredecessorLocalRef.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32)
	v4:i32 = Iconst_32 0x0
	Brz v2, blk2
	Jump blk1

blk1: () <-- (blk0)
	Jump blk3, v2

blk2: () <-- (blk0)
	Jump blk3, v3

blk3: (v5:i32) <-- (blk1,blk2)
	Jump blk_ret, v5
`,
			expAfterPasses: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32)
	Brz v2, blk2
	Jump fallthrough

blk1: () <-- (blk0)
	Jump blk3, v2

blk2: () <-- (blk0)
	Jump fallthrough, v3

blk3: (v5:i32) <-- (blk1,blk2)
	Jump blk_ret, v5
`,
		},
		{
			name: "reference value from unsealed block",
			m:    testcases.ReferenceValueFromUnsealedBlock.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32)
	v3:i32 = Iconst_32 0x0
	Jump blk1, v2

blk1: (v4:i32) <-- (blk0)
	Return v4

blk2: ()
`,
			expAfterPasses: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32)
	Jump fallthrough

blk1: () <-- (blk0)
	Return v2
`,
		},
		{
			name: "reference value from unsealed block - #2",
			m:    testcases.ReferenceValueFromUnsealedBlock2.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32)
	Jump blk1, v2

blk1: (v3:i32) <-- (blk0,blk1)
	Brnz v3, blk1, v3
	Jump blk4

blk2: () <-- (blk3)
	v4:i32 = Iconst_32 0x0
	Jump blk_ret, v4

blk3: () <-- (blk4)
	Jump blk2

blk4: () <-- (blk1)
	Jump blk3
`,
			expAfterPasses: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32)
	Jump fallthrough

blk1: () <-- (blk0,blk5)
	Brz v2, blk4
	Jump fallthrough

blk5: () <-- (blk1)
	Jump blk1

blk4: () <-- (blk1)
	Jump fallthrough

blk3: () <-- (blk4)
	Jump fallthrough

blk2: () <-- (blk3)
	v4:i32 = Iconst_32 0x0
	Jump blk_ret, v4
`,
		},
		{
			name: "reference value from unsealed block - #3",
			m:    testcases.ReferenceValueFromUnsealedBlock3.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32)
	Jump blk1, v2

blk1: (v3:i32) <-- (blk0,blk3)
	Brnz v3, blk_ret
	Jump blk4

blk2: ()

blk3: () <-- (blk4)
	v4:i32 = Iconst_32 0x1
	Jump blk1, v4

blk4: () <-- (blk1)
	Jump blk3
`,
			expAfterPasses: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32)
	Jump fallthrough, v2

blk1: (v3:i32) <-- (blk0,blk3)
	Brnz v3, blk5
	Jump blk4

blk5: () <-- (blk1)
	Jump blk_ret

blk4: () <-- (blk1)
	Jump fallthrough

blk3: () <-- (blk4)
	v4:i32 = Iconst_32 0x1
	Jump blk1, v4
`,
		},
		{
			name: "call",
			m:    testcases.Call.Module,
			exp: `
signatures:
	sig1: i64i64_i32
	sig2: i64i64i32i32_i32
	sig3: i64i64i32_i32i32

blk0: (exec_ctx:i64, module_ctx:i64)
	v2:i32 = Call f1:sig1, exec_ctx, module_ctx
	v3:i32 = Iconst_32 0x5
	v4:i32 = Call f2:sig2, exec_ctx, module_ctx, v2, v3
	v5:i32, v6:i32 = Call f3:sig3, exec_ctx, module_ctx, v4
	Jump blk_ret, v5, v6
`,
		},
		{
			name: "call_many_params",
			m:    testcases.CallManyParams.Module,
			exp: `
signatures:
	sig1: i64i64i32i64f32f64i32i64f32f64i32i64f32f64i32i64f32f64i32i64f32f64i32i64f32f64i32i64f32f64i32i64f32f64i32i64f32f64i32i64f32f64_v

blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i64, v4:f32, v5:f64)
	Call f1:sig1, exec_ctx, module_ctx, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5
	Jump blk_ret
`,
		},
		{
			name: "call_many_returns",
			m:    testcases.CallManyReturns.Module,
			exp: `
signatures:
	sig0: i64i64i32i64f32f64_i32i64f32f64i32i64f32f64i32i64f32f64i32i64f32f64i32i64f32f64i32i64f32f64i32i64f32f64i32i64f32f64i32i64f32f64i32i64f32f64

blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i64, v4:f32, v5:f64)
	v6:i32, v7:i64, v8:f32, v9:f64, v10:i32, v11:i64, v12:f32, v13:f64, v14:i32, v15:i64, v16:f32, v17:f64, v18:i32, v19:i64, v20:f32, v21:f64, v22:i32, v23:i64, v24:f32, v25:f64, v26:i32, v27:i64, v28:f32, v29:f64, v30:i32, v31:i64, v32:f32, v33:f64, v34:i32, v35:i64, v36:f32, v37:f64, v38:i32, v39:i64, v40:f32, v41:f64, v42:i32, v43:i64, v44:f32, v45:f64 = Call f1:sig0, exec_ctx, module_ctx, v2, v3, v4, v5
	Jump blk_ret, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45
`,
		},
		{
			name: "integer comparisons", m: testcases.IntegerComparisons.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32, v4:i64, v5:i64)
	v6:i32 = Icmp eq, v2, v3
	v7:i32 = Icmp eq, v4, v5
	v8:i32 = Icmp neq, v2, v3
	v9:i32 = Icmp neq, v4, v5
	v10:i32 = Icmp lt_s, v2, v3
	v11:i32 = Icmp lt_s, v4, v5
	v12:i32 = Icmp lt_u, v2, v3
	v13:i32 = Icmp lt_u, v4, v5
	v14:i32 = Icmp gt_s, v2, v3
	v15:i32 = Icmp gt_s, v4, v5
	v16:i32 = Icmp gt_u, v2, v3
	v17:i32 = Icmp gt_u, v4, v5
	v18:i32 = Icmp le_s, v2, v3
	v19:i32 = Icmp le_s, v4, v5
	v20:i32 = Icmp le_u, v2, v3
	v21:i32 = Icmp le_u, v4, v5
	v22:i32 = Icmp ge_s, v2, v3
	v23:i32 = Icmp ge_s, v4, v5
	v24:i32 = Icmp ge_u, v2, v3
	v25:i32 = Icmp ge_u, v4, v5
	Jump blk_ret, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25
`,
			expAfterPasses: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32, v4:i64, v5:i64)
	v6:i32 = Icmp eq, v2, v3
	v7:i32 = Icmp eq, v4, v5
	v8:i32 = Icmp neq, v2, v3
	v9:i32 = Icmp neq, v4, v5
	v10:i32 = Icmp lt_s, v2, v3
	v11:i32 = Icmp lt_s, v4, v5
	v12:i32 = Icmp lt_u, v2, v3
	v13:i32 = Icmp lt_u, v4, v5
	v14:i32 = Icmp gt_s, v2, v3
	v15:i32 = Icmp gt_s, v4, v5
	v16:i32 = Icmp gt_u, v2, v3
	v17:i32 = Icmp gt_u, v4, v5
	v18:i32 = Icmp le_s, v2, v3
	v19:i32 = Icmp le_s, v4, v5
	v20:i32 = Icmp le_u, v2, v3
	v21:i32 = Icmp le_u, v4, v5
	v22:i32 = Icmp ge_s, v2, v3
	v23:i32 = Icmp ge_s, v4, v5
	v24:i32 = Icmp ge_u, v2, v3
	v25:i32 = Icmp ge_u, v4, v5
	Jump blk_ret, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25
`,
		},
		{
			name: "integer bitwise", m: testcases.IntegerBitwise.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32, v4:i64, v5:i64)
	v6:i32 = Band v2, v3
	v7:i32 = Bor v2, v3
	v8:i32 = Bxor v2, v3
	v9:i32 = Rotr v2, v3
	v10:i64 = Band v4, v5
	v11:i64 = Bor v4, v5
	v12:i64 = Bxor v4, v5
	v13:i64 = Iconst_64 0x8
	v14:i64 = Ishl v5, v13
	v15:i64 = Bxor v4, v14
	v16:i64 = Rotl v4, v5
	v17:i64 = Rotr v4, v5
	Jump blk_ret, v6, v7, v8, v9, v10, v11, v12, v15, v16, v17
`,
		},
		{
			name: "integer shift", m: testcases.IntegerShift.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32, v4:i64, v5:i64)
	v6:i32 = Ishl v2, v3
	v7:i32 = Iconst_32 0x1f
	v8:i32 = Ishl v2, v7
	v9:i64 = Ishl v4, v5
	v10:i64 = Iconst_64 0x20
	v11:i64 = Ishl v4, v10
	v12:i32 = Ushr v2, v3
	v13:i32 = Iconst_32 0x1f
	v14:i32 = Ushr v2, v13
	v15:i64 = Ushr v4, v5
	v16:i64 = Iconst_64 0x20
	v17:i64 = Ushr v4, v16
	v18:i32 = Sshr v2, v3
	v19:i32 = Iconst_32 0x1f
	v20:i32 = Sshr v2, v19
	v21:i64 = Sshr v4, v5
	v22:i64 = Iconst_64 0x20
	v23:i64 = Sshr v4, v22
	Jump blk_ret, v6, v8, v9, v11, v12, v14, v15, v17, v18, v20, v21, v23
`,
		},
		{
			name: "integer extension", m: testcases.IntegerExtensions.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i64)
	v4:i64 = SExtend v2, 32->64
	v5:i64 = UExtend v2, 32->64
	v6:i64 = SExtend v3, 8->64
	v7:i64 = SExtend v3, 16->64
	v8:i64 = SExtend v3, 32->64
	v9:i32 = SExtend v2, 8->32
	v10:i32 = SExtend v2, 16->32
	Jump blk_ret, v4, v5, v6, v7, v8, v9, v10
`,
		},
		{
			name: "integer bit counts", m: testcases.IntegerBitCounts.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i64)
	v4:i32 = Clz v2
	v5:i32 = Ctz v2
	v6:i32 = Popcnt v2
	v7:i64 = Clz v3
	v8:i64 = Ctz v3
	v9:i64 = Popcnt v3
	Jump blk_ret, v4, v5, v6, v7, v8, v9
`,
		},
		{
			name: "float comparisons", m: testcases.FloatComparisons.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:f32, v3:f32, v4:f64, v5:f64)
	v6:i32 = Fcmp eq, v2, v3
	v7:i32 = Fcmp neq, v2, v3
	v8:i32 = Fcmp lt, v2, v3
	v9:i32 = Fcmp gt, v2, v3
	v10:i32 = Fcmp le, v2, v3
	v11:i32 = Fcmp ge, v2, v3
	v12:i32 = Fcmp eq, v4, v5
	v13:i32 = Fcmp neq, v4, v5
	v14:i32 = Fcmp lt, v4, v5
	v15:i32 = Fcmp gt, v4, v5
	v16:i32 = Fcmp le, v4, v5
	v17:i32 = Fcmp ge, v4, v5
	Jump blk_ret, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17
`,
		},
		{
			name: "float conversions", m: testcases.FloatConversions.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:f64, v3:f32)
	v4:i64 = FcvtToSint v2
	v5:i64 = FcvtToSint v3
	v6:i32 = FcvtToSint v2
	v7:i32 = FcvtToSint v3
	v8:i64 = FcvtToUint v2
	v9:i64 = FcvtToUint v3
	v10:i32 = FcvtToUint v2
	v11:i32 = FcvtToUint v3
	v12:f32 = Fdemote v2
	v13:f64 = Fpromote v3
	Jump blk_ret, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13
`,
		},
		{
			name: "non-trapping float conversions", m: testcases.NonTrappingFloatConversions.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:f64, v3:f32)
	v4:i64 = FcvtToSintSat v2
	v5:i64 = FcvtToSintSat v3
	v6:i32 = FcvtToSintSat v2
	v7:i32 = FcvtToSintSat v3
	v8:i64 = FcvtToUintSat v2
	v9:i64 = FcvtToUintSat v3
	v10:i32 = FcvtToUintSat v2
	v11:i32 = FcvtToUintSat v3
	Jump blk_ret, v4, v5, v6, v7, v8, v9, v10, v11
`,
		},
		{
			name: "loop with param and results", m: testcases.LoopBrWithParamResults.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32)
	Jump blk1, v2, v3

blk1: (v4:i32,v5:i32) <-- (blk0,blk1)
	v7:i32 = Iconst_32 0x1
	Brnz v7, blk1, v4, v5
	Jump blk3

blk2: (v6:i32) <-- (blk3)
	Jump blk_ret, v6

blk3: () <-- (blk1)
	Jump blk2, v4
`,
			expAfterPasses: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32)
	Jump fallthrough

blk1: () <-- (blk0,blk4)
	v7:i32 = Iconst_32 0x1
	Brz v7, blk3
	Jump fallthrough

blk4: () <-- (blk1)
	Jump blk1

blk3: () <-- (blk1)
	Jump fallthrough

blk2: () <-- (blk3)
	Jump blk_ret, v2
`,
		},
		{
			name:        "many_params_small_results",
			m:           testcases.ManyParamsSmallResults.Module,
			targetIndex: 0,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i64, v4:f32, v5:f64, v6:i32, v7:i64, v8:f32, v9:f64, v10:i32, v11:i64, v12:f32, v13:f64, v14:i32, v15:i64, v16:f32, v17:f64, v18:i32, v19:i64, v20:f32, v21:f64, v22:i32, v23:i64, v24:f32, v25:f64, v26:i32, v27:i64, v28:f32, v29:f64, v30:i32, v31:i64, v32:f32, v33:f64, v34:i32, v35:i64, v36:f32, v37:f64, v38:i32, v39:i64, v40:f32, v41:f64)
	Jump blk_ret, v2, v11, v20, v29
`,
			expAfterPasses: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i64, v4:f32, v5:f64, v6:i32, v7:i64, v8:f32, v9:f64, v10:i32, v11:i64, v12:f32, v13:f64, v14:i32, v15:i64, v16:f32, v17:f64, v18:i32, v19:i64, v20:f32, v21:f64, v22:i32, v23:i64, v24:f32, v25:f64, v26:i32, v27:i64, v28:f32, v29:f64, v30:i32, v31:i64, v32:f32, v33:f64, v34:i32, v35:i64, v36:f32, v37:f64, v38:i32, v39:i64, v40:f32, v41:f64)
	Jump blk_ret, v2, v11, v20, v29
`,
		},
		{
			name:        "small_params_many_results",
			m:           testcases.SmallParamsManyResults.Module,
			targetIndex: 0,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i64, v4:f32, v5:f64)
	Jump blk_ret, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5
`,
			expAfterPasses: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i64, v4:f32, v5:f64)
	Jump blk_ret, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5, v2, v3, v4, v5
`,
		},
		{
			name:        "many_params_many_results",
			m:           testcases.ManyParamsManyResults.Module,
			targetIndex: 0,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i64, v4:f32, v5:f64, v6:i32, v7:i64, v8:f32, v9:f64, v10:i32, v11:i64, v12:f32, v13:f64, v14:i32, v15:i64, v16:f32, v17:f64, v18:i32, v19:i64, v20:f32, v21:f64, v22:i32, v23:i64, v24:f32, v25:f64, v26:i32, v27:i64, v28:f32, v29:f64, v30:i32, v31:i64, v32:f32, v33:f64, v34:i32, v35:i64, v36:f32, v37:f64, v38:i32, v39:i64, v40:f32, v41:f64)
	Jump blk_ret, v41, v40, v39, v38, v37, v36, v35, v34, v33, v32, v31, v30, v29, v28, v27, v26, v25, v24, v23, v22, v21, v20, v19, v18, v17, v16, v15, v14, v13, v12, v11, v10, v9, v8, v7, v6, v5, v4, v3, v2
`,
			expAfterPasses: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i64, v4:f32, v5:f64, v6:i32, v7:i64, v8:f32, v9:f64, v10:i32, v11:i64, v12:f32, v13:f64, v14:i32, v15:i64, v16:f32, v17:f64, v18:i32, v19:i64, v20:f32, v21:f64, v22:i32, v23:i64, v24:f32, v25:f64, v26:i32, v27:i64, v28:f32, v29:f64, v30:i32, v31:i64, v32:f32, v33:f64, v34:i32, v35:i64, v36:f32, v37:f64, v38:i32, v39:i64, v40:f32, v41:f64)
	Jump blk_ret, v41, v40, v39, v38, v37, v36, v35, v34, v33, v32, v31, v30, v29, v28, v27, v26, v25, v24, v23, v22, v21, v20, v19, v18, v17, v16, v15, v14, v13, v12, v11, v10, v9, v8, v7, v6, v5, v4, v3, v2
`,
		},
		{
			name: "many_middle_values",
			m:    testcases.ManyMiddleValues.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:f32)
	v4:i32 = Iconst_32 0x1
	v5:i32 = Imul v2, v4
	v6:i32 = Iconst_32 0x2
	v7:i32 = Imul v2, v6
	v8:i32 = Iconst_32 0x3
	v9:i32 = Imul v2, v8
	v10:i32 = Iconst_32 0x4
	v11:i32 = Imul v2, v10
	v12:i32 = Iconst_32 0x5
	v13:i32 = Imul v2, v12
	v14:i32 = Iconst_32 0x6
	v15:i32 = Imul v2, v14
	v16:i32 = Iconst_32 0x7
	v17:i32 = Imul v2, v16
	v18:i32 = Iconst_32 0x8
	v19:i32 = Imul v2, v18
	v20:i32 = Iconst_32 0x9
	v21:i32 = Imul v2, v20
	v22:i32 = Iconst_32 0xa
	v23:i32 = Imul v2, v22
	v24:i32 = Iconst_32 0xb
	v25:i32 = Imul v2, v24
	v26:i32 = Iconst_32 0xc
	v27:i32 = Imul v2, v26
	v28:i32 = Iconst_32 0xd
	v29:i32 = Imul v2, v28
	v30:i32 = Iconst_32 0xe
	v31:i32 = Imul v2, v30
	v32:i32 = Iconst_32 0xf
	v33:i32 = Imul v2, v32
	v34:i32 = Iconst_32 0x10
	v35:i32 = Imul v2, v34
	v36:i32 = Iconst_32 0x11
	v37:i32 = Imul v2, v36
	v38:i32 = Iconst_32 0x12
	v39:i32 = Imul v2, v38
	v40:i32 = Iconst_32 0x13
	v41:i32 = Imul v2, v40
	v42:i32 = Iconst_32 0x14
	v43:i32 = Imul v2, v42
	v44:i32 = Iadd v41, v43
	v45:i32 = Iadd v39, v44
	v46:i32 = Iadd v37, v45
	v47:i32 = Iadd v35, v46
	v48:i32 = Iadd v33, v47
	v49:i32 = Iadd v31, v48
	v50:i32 = Iadd v29, v49
	v51:i32 = Iadd v27, v50
	v52:i32 = Iadd v25, v51
	v53:i32 = Iadd v23, v52
	v54:i32 = Iadd v21, v53
	v55:i32 = Iadd v19, v54
	v56:i32 = Iadd v17, v55
	v57:i32 = Iadd v15, v56
	v58:i32 = Iadd v13, v57
	v59:i32 = Iadd v11, v58
	v60:i32 = Iadd v9, v59
	v61:i32 = Iadd v7, v60
	v62:i32 = Iadd v5, v61
	v63:f32 = F32const 1.000000
	v64:f32 = Fmul v3, v63
	v65:f32 = F32const 2.000000
	v66:f32 = Fmul v3, v65
	v67:f32 = F32const 3.000000
	v68:f32 = Fmul v3, v67
	v69:f32 = F32const 4.000000
	v70:f32 = Fmul v3, v69
	v71:f32 = F32const 5.000000
	v72:f32 = Fmul v3, v71
	v73:f32 = F32const 6.000000
	v74:f32 = Fmul v3, v73
	v75:f32 = F32const 7.000000
	v76:f32 = Fmul v3, v75
	v77:f32 = F32const 8.000000
	v78:f32 = Fmul v3, v77
	v79:f32 = F32const 9.000000
	v80:f32 = Fmul v3, v79
	v81:f32 = F32const 10.000000
	v82:f32 = Fmul v3, v81
	v83:f32 = F32const 11.000000
	v84:f32 = Fmul v3, v83
	v85:f32 = F32const 12.000000
	v86:f32 = Fmul v3, v85
	v87:f32 = F32const 13.000000
	v88:f32 = Fmul v3, v87
	v89:f32 = F32const 14.000000
	v90:f32 = Fmul v3, v89
	v91:f32 = F32const 15.000000
	v92:f32 = Fmul v3, v91
	v93:f32 = F32const 16.000000
	v94:f32 = Fmul v3, v93
	v95:f32 = F32const 17.000000
	v96:f32 = Fmul v3, v95
	v97:f32 = F32const 18.000000
	v98:f32 = Fmul v3, v97
	v99:f32 = F32const 19.000000
	v100:f32 = Fmul v3, v99
	v101:f32 = F32const 20.000000
	v102:f32 = Fmul v3, v101
	v103:f32 = Fadd v100, v102
	v104:f32 = Fadd v98, v103
	v105:f32 = Fadd v96, v104
	v106:f32 = Fadd v94, v105
	v107:f32 = Fadd v92, v106
	v108:f32 = Fadd v90, v107
	v109:f32 = Fadd v88, v108
	v110:f32 = Fadd v86, v109
	v111:f32 = Fadd v84, v110
	v112:f32 = Fadd v82, v111
	v113:f32 = Fadd v80, v112
	v114:f32 = Fadd v78, v113
	v115:f32 = Fadd v76, v114
	v116:f32 = Fadd v74, v115
	v117:f32 = Fadd v72, v116
	v118:f32 = Fadd v70, v117
	v119:f32 = Fadd v68, v118
	v120:f32 = Fadd v66, v119
	v121:f32 = Fadd v64, v120
	Jump blk_ret, v62, v121
`,
		},
		{
			name: "recursive_fibonacci", m: testcases.FibonacciRecursive.Module,
			exp: `
signatures:
	sig0: i64i64i32_i32

blk0: (exec_ctx:i64, module_ctx:i64, v2:i32)
	v3:i32 = Iconst_32 0x2
	v4:i32 = Icmp lt_s, v2, v3
	Brz v4, blk2
	Jump blk1

blk1: () <-- (blk0)
	Return v2

blk2: () <-- (blk0)
	Jump blk3

blk3: () <-- (blk2)
	v5:i32 = Iconst_32 0x1
	v6:i32 = Isub v2, v5
	v7:i32 = Call f0:sig0, exec_ctx, module_ctx, v6
	v8:i32 = Iconst_32 0x2
	v9:i32 = Isub v2, v8
	v10:i32 = Call f0:sig0, exec_ctx, module_ctx, v9
	v11:i32 = Iadd v7, v10
	Jump blk_ret, v11
`,
			expAfterPasses: `
signatures:
	sig0: i64i64i32_i32

blk0: (exec_ctx:i64, module_ctx:i64, v2:i32)
	v3:i32 = Iconst_32 0x2
	v4:i32 = Icmp lt_s, v2, v3
	Brz v4, blk2
	Jump fallthrough

blk1: () <-- (blk0)
	Return v2

blk2: () <-- (blk0)
	Jump fallthrough

blk3: () <-- (blk2)
	v5:i32 = Iconst_32 0x1
	v6:i32 = Isub v2, v5
	v7:i32 = Call f0:sig0, exec_ctx, module_ctx, v6
	v8:i32 = Iconst_32 0x2
	v9:i32 = Isub v2, v8
	v10:i32 = Call f0:sig0, exec_ctx, module_ctx, v9
	v11:i32 = Iadd v7, v10
	Jump blk_ret, v11
`,
		},
		{
			name: "memory_store_basic", m: testcases.MemoryStoreBasic.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32)
	v4:i64 = Iconst_64 0x4
	v5:i64 = UExtend v2, 32->64
	v6:i64 = Uload32 module_ctx, 0x10
	v7:i64 = Iadd v5, v4
	v8:i32 = Icmp lt_u, v6, v7
	ExitIfTrue v8, exec_ctx, memory_out_of_bounds
	v9:i64 = Load module_ctx, 0x8
	v10:i64 = Iadd v9, v5
	Store v3, v10, 0x0
	v11:i32 = Load v10, 0x0
	Jump blk_ret, v11
`,
		},
		{
			name: "memory_load_basic", m: testcases.MemoryLoadBasic.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32)
	v3:i64 = Iconst_64 0x4
	v4:i64 = UExtend v2, 32->64
	v5:i64 = Uload32 module_ctx, 0x10
	v6:i64 = Iadd v4, v3
	v7:i32 = Icmp lt_u, v5, v6
	ExitIfTrue v7, exec_ctx, memory_out_of_bounds
	v8:i64 = Load module_ctx, 0x8
	v9:i64 = Iadd v8, v4
	v10:i32 = Load v9, 0x0
	Jump blk_ret, v10
`,
		},
		{
			name:          "memory_load_basic / bounds-check elision",
			m:             testcases.MemoryLoadBasic.Module,
			boundsElision: true,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32)
	v3:i64 = UExtend v2, 32->64
	v4:i64 = Load module_ctx, 0x8
	v5:i64 = Iadd v4, v3
	v6:i32 = Load v5, 0x0
	Jump blk_ret, v6
`,
		},
		{
			name: "memory_load_basic2", m: testcases.MemoryLoadBasic2.Module,
			exp: `
signatures:
	sig1: i64i64_v

blk0: (exec_ctx:i64, module_ctx:i64, v2:i32)
	v3:i32 = Iconst_32 0x0
	v4:i32 = Icmp eq, v2, v3
	Brz v4, blk2
	Jump blk1

blk1: () <-- (blk0)
	Call f1:sig1, exec_ctx, module_ctx
	v5:i64 = Load module_ctx, 0x8
	v6:i64 = Uload32 module_ctx, 0x10
	Jump blk3

blk2: () <-- (blk0)
	Jump blk3

blk3: () <-- (blk1,blk2)
	v8:i64 = Iconst_64 0x4
	v9:i64 = UExtend v2, 32->64
	v10:i64 = Uload32 module_ctx, 0x10
	v11:i64 = Iadd v9, v8
	v12:i32 = Icmp lt_u, v10, v11
	ExitIfTrue v12, exec_ctx, memory_out_of_bounds
	v13:i64 = Load module_ctx, 0x8
	v14:i64 = Iadd v13, v9
	v15:i32 = Load v14, 0x0
	Jump blk_ret, v15
`,
			expAfterPasses: `
signatures:
	sig1: i64i64_v

blk0: (exec_ctx:i64, module_ctx:i64, v2:i32)
	v3:i32 = Iconst_32 0x0
	v4:i32 = Icmp eq, v2, v3
	Brz v4, blk2
	Jump fallthrough

blk1: () <-- (blk0)
	Call f1:sig1, exec_ctx, module_ctx
	Jump blk3

blk2: () <-- (blk0)
	Jump fallthrough

blk3: () <-- (blk1,blk2)
	v8:i64 = Iconst_64 0x4
	v9:i64 = UExtend v2, 32->64
	v10:i64 = Uload32 module_ctx, 0x10
	v11:i64 = Iadd v9, v8
	v12:i32 = Icmp lt_u, v10, v11
	ExitIfTrue v12, exec_ctx, memory_out_of_bounds
	v13:i64 = Load module_ctx, 0x8
	v14:i64 = Iadd v13, v9
	v15:i32 = Load v14, 0x0
	Jump blk_ret, v15
`,
		},
		{
			name: "imported_function_call", m: testcases.ImportedFunctionCall.Module,
			exp: `
signatures:
	sig1: i64i64i32i32_i32

blk0: (exec_ctx:i64, module_ctx:i64, v2:i32)
	Store module_ctx, exec_ctx, 0x8
	v3:i64 = Load module_ctx, 0x8
	v4:i64 = Load module_ctx, 0x10
	v5:i32 = CallIndirect v3:sig1, exec_ctx, v4, v2, v2
	Jump blk_ret, v5
`,
		},
		{
			name: "memory_loads", m: testcases.MemoryLoads.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32)
	v3:i64 = Iconst_64 0x4
	v4:i64 = UExtend v2, 32->64
	v5:i64 = Uload32 module_ctx, 0x10
	v6:i64 = Iadd v4, v3
	v7:i32 = Icmp lt_u, v5, v6
	ExitIfTrue v7, exec_ctx, memory_out_of_bounds
	v8:i64 = Load module_ctx, 0x8
	v9:i64 = Iadd v8, v4
	v10:i32 = Load v9, 0x0
	v11:i64 = Iconst_64 0x8
	v12:i64 = UExtend v2, 32->64
	v13:i64 = Iadd v12, v11
	v14:i32 = Icmp lt_u, v5, v13
	ExitIfTrue v14, exec_ctx, memory_out_of_bounds
	v15:i64 = Load v9, 0x0
	v16:f32 = Load v9, 0x0
	v17:f64 = Load v9, 0x0
	v18:i64 = Iconst_64 0x13
	v19:i64 = UExtend v2, 32->64
	v20:i64 = Iadd v19, v18
	v21:i32 = Icmp lt_u, v5, v20
	ExitIfTrue v21, exec_ctx, memory_out_of_bounds
	v22:i32 = Load v9, 0xf
	v23:i64 = Iconst_64 0x17
	v24:i64 = UExtend v2, 32->64
	v25:i64 = Iadd v24, v23
	v26:i32 = Icmp lt_u, v5, v25
	ExitIfTrue v26, exec_ctx, memory_out_of_bounds
	v27:i64 = Load v9, 0xf
	v28:f32 = Load v9, 0xf
	v29:f64 = Load v9, 0xf
	v30:i32 = Sload8 v9, 0x0
	v31:i32 = Sload8 v9, 0xf
	v32:i32 = Uload8 v9, 0x0
	v33:i32 = Uload8 v9, 0xf
	v34:i32 = Sload16 v9, 0x0
	v35:i32 = Sload16 v9, 0xf
	v36:i32 = Uload16 v9, 0x0
	v37:i32 = Uload16 v9, 0xf
	v38:i64 = Sload8 v9, 0x0
	v39:i64 = Sload8 v9, 0xf
	v40:i64 = Uload8 v9, 0x0
	v41:i64 = Uload8 v9, 0xf
	v42:i64 = Sload16 v9, 0x0
	v43:i64 = Sload16 v9, 0xf
	v44:i64 = Uload16 v9, 0x0
	v45:i64 = Uload16 v9, 0xf
	v46:i64 = Sload32 v9, 0x0
	v47:i64 = Sload32 v9, 0xf
	v48:i64 = Uload32 v9, 0x0
	v49:i64 = Uload32 v9, 0xf
	Jump blk_ret, v10, v15, v16, v17, v22, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49
`,
		},
		{
			name: "globals_get",
			m:    testcases.GlobalsGet.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64)
	v2:i32 = Load module_ctx, 0x10
	v3:i64 = Load module_ctx, 0x20
	v4:f32 = Load module_ctx, 0x30
	v5:f64 = Load module_ctx, 0x40
	v6:v128 = Load module_ctx, 0x50
	Jump blk_ret, v2, v3, v4, v5, v6
`,
		},
		{
			name: "globals_set",
			m:    testcases.GlobalsSet.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64)
	v2:i32 = Iconst_32 0x1
	Store v2, module_ctx, 0x10
	v3:i64 = Iconst_64 0x2
	Store v3, module_ctx, 0x20
	v4:f32 = F32const 3.000000
	Store v4, module_ctx, 0x30
	v5:f64 = F64const 4.000000
	Store v5, module_ctx, 0x40
	v6:v128 = Vconst 000000000000000a 0000000000000014
	Store v6, module_ctx, 0x50
	Jump blk_ret, v2, v3, v4, v5, v6
`,
		},
		{
			name: "globals_mutable",
			m:    testcases.GlobalsMutable.Module,
			exp: `
signatures:
	sig1: i64i64_v

blk0: (exec_ctx:i64, module_ctx:i64)
	v2:i32 = Load module_ctx, 0x10
	v3:i64 = Load module_ctx, 0x20
	v4:f32 = Load module_ctx, 0x30
	v5:f64 = Load module_ctx, 0x40
	Call f1:sig1, exec_ctx, module_ctx
	v6:i32 = Load module_ctx, 0x10
	v7:i64 = Load module_ctx, 0x20
	v8:f32 = Load module_ctx, 0x30
	v9:f64 = Load module_ctx, 0x40
	Jump blk_ret, v2, v3, v4, v5, v6, v7, v8, v9
`,
			expAfterPasses: `
signatures:
	sig1: i64i64_v

blk0: (exec_ctx:i64, module_ctx:i64)
	v2:i32 = Load module_ctx, 0x10
	v3:i64 = Load module_ctx, 0x20
	v4:f32 = Load module_ctx, 0x30
	v5:f64 = Load module_ctx, 0x40
	Call f1:sig1, exec_ctx, module_ctx
	v6:i32 = Load module_ctx, 0x10
	v7:i64 = Load module_ctx, 0x20
	v8:f32 = Load module_ctx, 0x30
	v9:f64 = Load module_ctx, 0x40
	Jump blk_ret, v2, v3, v4, v5, v6, v7, v8, v9
`,
		},
		{
			name: "imported_memory_grow",
			m:    testcases.ImportedMemoryGrow.Module,
			exp: `
signatures:
	sig0: i64i64_i32
	sig2: i64i32_i32

blk0: (exec_ctx:i64, module_ctx:i64)
	Store module_ctx, exec_ctx, 0x8
	v2:i64 = Load module_ctx, 0x18
	v3:i64 = Load module_ctx, 0x20
	v4:i32 = CallIndirect v2:sig0, exec_ctx, v3
	v5:i64 = Load module_ctx, 0x8
	v6:i64 = Load v5, 0x0
	v7:i64 = Load module_ctx, 0x8
	v8:i64 = Load v7, 0x8
	v9:i64 = Load module_ctx, 0x8
	v10:i32 = Load v9, 0x8
	v11:i32 = Iconst_32 0x10
	v12:i32 = Ushr v10, v11
	v13:i32 = Iconst_32 0xa
	Store module_ctx, exec_ctx, 0x8
	v14:i64 = Load exec_ctx, 0x48
	v15:i32 = CallIndirect v14:sig2, exec_ctx, v13
	v16:i64 = Load module_ctx, 0x8
	v17:i64 = Load v16, 0x0
	v18:i64 = Load module_ctx, 0x8
	v19:i64 = Load v18, 0x8
	Store module_ctx, exec_ctx, 0x8
	v20:i64 = Load module_ctx, 0x18
	v21:i64 = Load module_ctx, 0x20
	v22:i32 = CallIndirect v20:sig0, exec_ctx, v21
	v23:i64 = Load module_ctx, 0x8
	v24:i64 = Load v23, 0x0
	v25:i64 = Load module_ctx, 0x8
	v26:i64 = Load v25, 0x8
	v27:i64 = Load module_ctx, 0x8
	v28:i32 = Load v27, 0x8
	v29:i32 = Iconst_32 0x10
	v30:i32 = Ushr v28, v29
	Jump blk_ret, v4, v12, v22, v30
`,
			expAfterPasses: `
signatures:
	sig0: i64i64_i32
	sig2: i64i32_i32

blk0: (exec_ctx:i64, module_ctx:i64)
	Store module_ctx, exec_ctx, 0x8
	v2:i64 = Load module_ctx, 0x18
	v3:i64 = Load module_ctx, 0x20
	v4:i32 = CallIndirect v2:sig0, exec_ctx, v3
	v9:i64 = Load module_ctx, 0x8
	v10:i32 = Load v9, 0x8
	v11:i32 = Iconst_32 0x10
	v12:i32 = Ushr v10, v11
	v13:i32 = Iconst_32 0xa
	Store module_ctx, exec_ctx, 0x8
	v14:i64 = Load exec_ctx, 0x48
	v15:i32 = CallIndirect v14:sig2, exec_ctx, v13
	Store module_ctx, exec_ctx, 0x8
	v20:i64 = Load module_ctx, 0x18
	v21:i64 = Load module_ctx, 0x20
	v22:i32 = CallIndirect v20:sig0, exec_ctx, v21
	v27:i64 = Load module_ctx, 0x8
	v28:i32 = Load v27, 0x8
	v29:i32 = Iconst_32 0x10
	v30:i32 = Ushr v28, v29
	Jump blk_ret, v4, v12, v22, v30
`,
		},
		{
			name: "memory_size_grow",
			m:    testcases.MemorySizeGrow.Module,
			exp: `
signatures:
	sig1: i64i32_i32

blk0: (exec_ctx:i64, module_ctx:i64)
	v2:i32 = Iconst_32 0x1
	Store module_ctx, exec_ctx, 0x8
	v3:i64 = Load exec_ctx, 0x48
	v4:i32 = CallIndirect v3:sig1, exec_ctx, v2
	v5:i64 = Load module_ctx, 0x8
	v6:i64 = Uload32 module_ctx, 0x10
	v7:i32 = Load module_ctx, 0x10
	v8:i32 = Iconst_32 0x10
	v9:i32 = Ushr v7, v8
	v10:i32 = Iconst_32 0x1
	Store module_ctx, exec_ctx, 0x8
	v11:i64 = Load exec_ctx, 0x48
	v12:i32 = CallIndirect v11:sig1, exec_ctx, v10
	v13:i64 = Load module_ctx, 0x8
	v14:i64 = Uload32 module_ctx, 0x10
	Jump blk_ret, v4, v9, v12
`,
			expAfterPasses: `
signatures:
	sig1: i64i32_i32

blk0: (exec_ctx:i64, module_ctx:i64)
	v2:i32 = Iconst_32 0x1
	Store module_ctx, exec_ctx, 0x8
	v3:i64 = Load exec_ctx, 0x48
	v4:i32 = CallIndirect v3:sig1, exec_ctx, v2
	v7:i32 = Load module_ctx, 0x10
	v8:i32 = Iconst_32 0x10
	v9:i32 = Ushr v7, v8
	v10:i32 = Iconst_32 0x1
	Store module_ctx, exec_ctx, 0x8
	v11:i64 = Load exec_ctx, 0x48
	v12:i32 = CallIndirect v11:sig1, exec_ctx, v10
	Jump blk_ret, v4, v9, v12
`,
		},
		{
			name: "call_indirect", m: testcases.CallIndirect.Module,
			exp: `
signatures:
	sig2: i64i64_i32

blk0: (exec_ctx:i64, module_ctx:i64, v2:i32)
	v3:i64 = Load module_ctx, 0x10
	v4:i32 = Load v3, 0x8
	v5:i32 = Icmp ge_u, v2, v4
	ExitIfTrue v5, exec_ctx, table_out_of_bounds
	v6:i64 = Load v3, 0x0
	v7:i64 = Iconst_64 0x3
	v8:i32 = Ishl v2, v7
	v9:i64 = Iadd v6, v8
	v10:i64 = Load v9, 0x0
	v11:i64 = Iconst_64 0x0
	v12:i32 = Icmp eq, v10, v11
	ExitIfTrue v12, exec_ctx, indirect_call_null_pointer
	v13:i32 = Load v10, 0x10
	v14:i64 = Load module_ctx, 0x8
	v15:i32 = Load v14, 0x8
	v16:i32 = Icmp neq, v13, v15
	ExitIfTrue v16, exec_ctx, indirect_call_type_mismatch
	v17:i64 = Load v10, 0x0
	v18:i64 = Load v10, 0x8
	Store module_ctx, exec_ctx, 0x8
	v19:i32 = CallIndirect v17:sig2, exec_ctx, v18
	Jump blk_ret, v19
`,
		},
		{
			name: "br_table", m: testcases.BrTable.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32)
	BrTable v2, [blk7, blk8, blk9, blk10, blk11, blk12, blk13]

blk1: () <-- (blk12)
	v8:i32 = Iconst_32 0x10
	Return v8

blk2: () <-- (blk11)
	v7:i32 = Iconst_32 0xf
	Return v7

blk3: () <-- (blk10)
	v6:i32 = Iconst_32 0xe
	Return v6

blk4: () <-- (blk9)
	v5:i32 = Iconst_32 0xd
	Return v5

blk5: () <-- (blk8)
	v4:i32 = Iconst_32 0xc
	Return v4

blk6: () <-- (blk7,blk13)
	v3:i32 = Iconst_32 0xb
	Return v3

blk7: () <-- (blk0)
	Jump blk6

blk8: () <-- (blk0)
	Jump blk5

blk9: () <-- (blk0)
	Jump blk4

blk10: () <-- (blk0)
	Jump blk3

blk11: () <-- (blk0)
	Jump blk2

blk12: () <-- (blk0)
	Jump blk1

blk13: () <-- (blk0)
	Jump blk6
`,
		},
		{
			name: "br_table_with_arg", m: testcases.BrTableWithArg.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32)
	BrTable v2, [blk7, blk8, blk9, blk10, blk11, blk12, blk13]

blk1: (v4:i32) <-- (blk12)
	v20:i32 = Iconst_32 0x10
	v21:i32 = Iadd v4, v20
	Return v21

blk2: (v5:i32) <-- (blk11)
	v18:i32 = Iconst_32 0xf
	v19:i32 = Iadd v5, v18
	Return v19

blk3: (v6:i32) <-- (blk10)
	v16:i32 = Iconst_32 0xe
	v17:i32 = Iadd v6, v16
	Return v17

blk4: (v7:i32) <-- (blk9)
	v14:i32 = Iconst_32 0xd
	v15:i32 = Iadd v7, v14
	Return v15

blk5: (v8:i32) <-- (blk8)
	v12:i32 = Iconst_32 0xc
	v13:i32 = Iadd v8, v12
	Return v13

blk6: (v9:i32) <-- (blk7,blk13)
	v10:i32 = Iconst_32 0xb
	v11:i32 = Iadd v9, v10
	Return v11

blk7: () <-- (blk0)
	Jump blk6, v3

blk8: () <-- (blk0)
	Jump blk5, v3

blk9: () <-- (blk0)
	Jump blk4, v3

blk10: () <-- (blk0)
	Jump blk3, v3

blk11: () <-- (blk0)
	Jump blk2, v3

blk12: () <-- (blk0)
	Jump blk1, v3

blk13: () <-- (blk0)
	Jump blk6, v3
`,

			expAfterPasses: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32)
	BrTable v2, [blk7, blk8, blk9, blk10, blk11, blk12, blk13]

blk7: () <-- (blk0)
	Jump blk6

blk8: () <-- (blk0)
	Jump fallthrough

blk5: () <-- (blk8)
	v12:i32 = Iconst_32 0xc
	v13:i32 = Iadd v3, v12
	Return v13

blk9: () <-- (blk0)
	Jump fallthrough

blk4: () <-- (blk9)
	v14:i32 = Iconst_32 0xd
	v15:i32 = Iadd v3, v14
	Return v15

blk10: () <-- (blk0)
	Jump fallthrough

blk3: () <-- (blk10)
	v16:i32 = Iconst_32 0xe
	v17:i32 = Iadd v3, v16
	Return v17

blk11: () <-- (blk0)
	Jump fallthrough

blk2: () <-- (blk11)
	v18:i32 = Iconst_32 0xf
	v19:i32 = Iadd v3, v18
	Return v19

blk12: () <-- (blk0)
	Jump fallthrough

blk1: () <-- (blk12)
	v20:i32 = Iconst_32 0x10
	v21:i32 = Iadd v3, v20
	Return v21

blk13: () <-- (blk0)
	Jump fallthrough

blk6: () <-- (blk7,blk13)
	v10:i32 = Iconst_32 0xb
	v11:i32 = Iadd v3, v10
	Return v11
`,
		},
		{
			name: "if_then_end_nesting_unreachable_if_then_else_end", m: testcases.IfThenEndNestingUnreachableIfThenElseEnd.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:f64, v3:f64, v4:f64)
	v6:i32 = Load module_ctx, 0x10
	v7:i32 = Iconst_32 0x10
	v8:i32 = Ushr v6, v7
	Brz v8, blk3
	Jump blk2

blk1: (v5:i64) <-- (blk4)
	Jump blk_ret

blk2: () <-- (blk0)
	v9:i32 = Load module_ctx, 0x10
	v10:i32 = Iconst_32 0x10
	v11:i32 = Ushr v9, v10
	Jump blk4

blk3: () <-- (blk0)
	Jump blk4

blk4: () <-- (blk2,blk3)
	v12:i64 = Iconst_64 0x0
	Jump blk1, v12
`,
			expAfterPasses: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:f64, v3:f64, v4:f64)
	v6:i32 = Load module_ctx, 0x10
	v7:i32 = Iconst_32 0x10
	v8:i32 = Ushr v6, v7
	Brz v8, blk3
	Jump fallthrough

blk2: () <-- (blk0)
	Jump blk4

blk3: () <-- (blk0)
	Jump fallthrough

blk4: () <-- (blk2,blk3)
	Jump fallthrough

blk1: () <-- (blk4)
	Jump blk_ret
`,
		},
		{
			name: "VecShuffle",
			m:    testcases.VecShuffle.Module,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:v128, v3:v128)
	v4:v128 = Shuffle.[0 1 2 3 4 5 6 7 24 25 26 27 28 29 30 31] v2, v3
	Jump blk_ret, v4
`,
		},
		{
			name: "shared local memory.fill bounds refresh",
			m: &wasm.Module{
				TypeSection: []wasm.FunctionType{{
					Params: []wasm.ValueType{wasm.ValueTypeI32, wasm.ValueTypeI32},
				}},
				FunctionSection: []wasm.Index{0},
				CodeSection: []wasm.Code{{Body: []byte{
					wasm.OpcodeLocalGet, 0,
					wasm.OpcodeI32Const, 0,
					wasm.OpcodeLocalGet, 1,
					wasm.OpcodeMiscPrefix, wasm.OpcodeMiscMemoryFill, 0,
					wasm.OpcodeEnd,
				}}},
				MemorySection: &wasm.Memory{
					Min: 1, Cap: 1, Max: 2, IsMaxEncoded: true, IsShared: true,
				},
			},
			features: api.CoreFeaturesV2 | experimental.CoreFeaturesThreads,
			exp: `
signatures:
	sig5: i64i64i64_v

blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32)
	v4:i32 = Iconst_32 0x0
	v5:i64 = UExtend v3, 32->64
	v6:i64 = UExtend v2, 32->64
	v7:i64 = Load module_ctx, 0x10
	v8:i64 = Iadd v6, v5
	v9:i32 = Icmp lt_u, v7, v8
	Brnz v9, blk1
	Jump blk2, v7

blk1: () <-- (blk0)
	v11:i64 = Iconst_64 0x10
	v12:i64 = Iadd module_ctx, v11
	v13:i64 = AtomicLoad_64, v12
	v14:i32 = Icmp lt_u, v13, v8
	ExitIfTrue v14, exec_ctx, memory_out_of_bounds
	Jump blk2, v13

blk2: (v10:i64) <-- (blk0,blk1)
	v15:i64 = Load module_ctx, 0x8
	v16:i64 = Iadd v15, v6
	v18:i64 = Iconst_64 0x0
	v19:i32 = Icmp eq, v5, v18
	Brnz v19, blk5
	Jump blk3

blk3: () <-- (blk2)
	Istore8 v4, v16, 0x0
	v20:i64 = Iconst_64 0x1
	Jump blk4, v20

blk4: (v17:i64) <-- (blk3,blk4)
	v21:i64 = Iadd v16, v17
	v22:i64 = Iconst_64 0x1fff
	v23:i64 = Isub v17, v20
	v24:i64 = Band v23, v22
	v25:i64 = Iadd v24, v20
	v26:i64 = Iadd v17, v25
	v27:i32 = Icmp lt_u, v26, v5
	v28:i64 = Isub v5, v17
	v29:i64 = Select v27, v25, v28
	v30:i64 = Load exec_ctx, 0x478
	CallIndirect v30:sig5, v21, v16, v29
	Brnz v27, blk4, v26
	Jump blk5

blk5: () <-- (blk2,blk4)
	Jump blk_ret
`,
		},
		{
			name: "shared imported memory bounds refresh",
			m: &wasm.Module{
				TypeSection: []wasm.FunctionType{{
					Params:  []wasm.ValueType{wasm.ValueTypeI32},
					Results: []wasm.ValueType{wasm.ValueTypeI32},
				}},
				ImportSection: []wasm.Import{{
					Type: wasm.ExternTypeMemory, Module: "env", Name: "memory",
					DescMem: &wasm.Memory{
						Min: 1, Cap: 1, Max: 2, IsMaxEncoded: true, IsShared: true,
					},
				}},
				ImportMemoryCount: 1,
				FunctionSection:   []wasm.Index{0},
				CodeSection: []wasm.Code{{Body: []byte{
					wasm.OpcodeLocalGet, 0,
					wasm.OpcodeI32Load, 2, 0,
					wasm.OpcodeEnd,
				}}},
			},
			features: api.CoreFeaturesV2 | experimental.CoreFeaturesThreads,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32)
	v3:i64 = Iconst_64 0x4
	v4:i64 = UExtend v2, 32->64
	v5:i64 = Load module_ctx, 0x8
	v6:i64 = Load v5, 0x8
	v7:i64 = Iadd v4, v3
	v8:i32 = Icmp lt_u, v6, v7
	Brnz v8, blk1
	Jump blk2, v6

blk1: () <-- (blk0)
	v10:i64 = Load module_ctx, 0x8
	v11:i64 = Iconst_64 0x8
	v12:i64 = Iadd v10, v11
	v13:i64 = AtomicLoad_64, v12
	v14:i32 = Icmp lt_u, v13, v7
	ExitIfTrue v14, exec_ctx, memory_out_of_bounds
	Jump blk2, v13

blk2: (v9:i64) <-- (blk0,blk1)
	v15:i64 = Load module_ctx, 0x8
	v16:i64 = Load v15, 0x0
	v17:i64 = Iadd v16, v4
	v18:i32 = Load v17, 0x0
	Jump blk_ret, v18
`,
		},
		{
			name:     "MemoryWait32",
			m:        testcases.MemoryWait32.Module,
			features: api.CoreFeaturesV2 | experimental.CoreFeaturesThreads,
			exp: `
signatures:
	sig6: i64i64i32i64_i32

blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32, v4:i64)
	Store module_ctx, exec_ctx, 0x8
	v5:i64 = Iconst_64 0xc
	v6:i64 = UExtend v2, 32->64
	v7:i64 = Load module_ctx, 0x10
	v8:i64 = Iadd v6, v5
	v9:i32 = Icmp lt_u, v7, v8
	Brnz v9, blk1
	Jump blk2, v7

blk1: () <-- (blk0)
	v11:i64 = Iconst_64 0x10
	v12:i64 = Iadd module_ctx, v11
	v13:i64 = AtomicLoad_64, v12
	v14:i32 = Icmp lt_u, v13, v8
	ExitIfTrue v14, exec_ctx, memory_out_of_bounds
	Jump blk2, v13

blk2: (v10:i64) <-- (blk0,blk1)
	v15:i64 = Load module_ctx, 0x8
	v16:i64 = Iadd v15, v6
	v17:i64 = Iconst_64 0x8
	v18:i64 = Iadd v16, v17
	v19:i64 = Iconst_64 0x3
	v20:i64 = Band v18, v19
	v21:i64 = Iconst_64 0x0
	v22:i32 = Icmp neq, v20, v21
	ExitIfTrue v22, exec_ctx, unaligned_atomic
	v23:i64 = Load exec_ctx, 0x488
	v24:i32 = CallIndirect v23:sig6, exec_ctx, v4, v3, v18
	Jump blk_ret, v24
`,
		},
		{
			name:     "MemoryWait64",
			m:        testcases.MemoryWait64.Module,
			features: api.CoreFeaturesV2 | experimental.CoreFeaturesThreads,
			exp: `
signatures:
	sig7: i64i64i64i64_i32

blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i64, v4:i64)
	Store module_ctx, exec_ctx, 0x8
	v5:i64 = Iconst_64 0x10
	v6:i64 = UExtend v2, 32->64
	v7:i64 = Load module_ctx, 0x10
	v8:i64 = Iadd v6, v5
	v9:i32 = Icmp lt_u, v7, v8
	Brnz v9, blk1
	Jump blk2, v7

blk1: () <-- (blk0)
	v11:i64 = Iconst_64 0x10
	v12:i64 = Iadd module_ctx, v11
	v13:i64 = AtomicLoad_64, v12
	v14:i32 = Icmp lt_u, v13, v8
	ExitIfTrue v14, exec_ctx, memory_out_of_bounds
	Jump blk2, v13

blk2: (v10:i64) <-- (blk0,blk1)
	v15:i64 = Load module_ctx, 0x8
	v16:i64 = Iadd v15, v6
	v17:i64 = Iconst_64 0x8
	v18:i64 = Iadd v16, v17
	v19:i64 = Iconst_64 0x7
	v20:i64 = Band v18, v19
	v21:i64 = Iconst_64 0x0
	v22:i32 = Icmp neq, v20, v21
	ExitIfTrue v22, exec_ctx, unaligned_atomic
	v23:i64 = Load exec_ctx, 0x490
	v24:i32 = CallIndirect v23:sig7, exec_ctx, v4, v3, v18
	Jump blk_ret, v24
`,
		},
		{
			name:     "MemoryNotify",
			m:        testcases.MemoryNotify.Module,
			features: api.CoreFeaturesV2 | experimental.CoreFeaturesThreads,
			exp: `
signatures:
	sig8: i64i32i64_i32

blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32)
	Store module_ctx, exec_ctx, 0x8
	v4:i64 = Iconst_64 0xc
	v5:i64 = UExtend v2, 32->64
	v6:i64 = Load module_ctx, 0x10
	v7:i64 = Iadd v5, v4
	v8:i32 = Icmp lt_u, v6, v7
	Brnz v8, blk1
	Jump blk2, v6

blk1: () <-- (blk0)
	v10:i64 = Iconst_64 0x10
	v11:i64 = Iadd module_ctx, v10
	v12:i64 = AtomicLoad_64, v11
	v13:i32 = Icmp lt_u, v12, v7
	ExitIfTrue v13, exec_ctx, memory_out_of_bounds
	Jump blk2, v12

blk2: (v9:i64) <-- (blk0,blk1)
	v14:i64 = Load module_ctx, 0x8
	v15:i64 = Iadd v14, v5
	v16:i64 = Iconst_64 0x8
	v17:i64 = Iadd v15, v16
	v18:i64 = Iconst_64 0x3
	v19:i64 = Band v17, v18
	v20:i64 = Iconst_64 0x0
	v21:i32 = Icmp neq, v19, v20
	ExitIfTrue v21, exec_ctx, unaligned_atomic
	v22:i64 = Load exec_ctx, 0x498
	v23:i32 = CallIndirect v22:sig8, exec_ctx, v3, v17
	Jump blk_ret, v23
`,
		},
		{
			name:     "AtomicRMWAdd",
			m:        testcases.AtomicRmwAdd.Module,
			features: api.CoreFeaturesV2 | experimental.CoreFeaturesThreads,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32, v4:i32, v5:i64, v6:i64, v7:i64, v8:i64)
	v9:i32 = Iconst_32 0x0
	v10:i64 = Iconst_64 0x1
	v11:i64 = UExtend v9, 32->64
	v12:i64 = Load module_ctx, 0x10
	v13:i64 = Iadd v11, v10
	v14:i32 = Icmp lt_u, v12, v13
	Brnz v14, blk1
	Jump blk2, v12

blk1: () <-- (blk0)
	v16:i64 = Iconst_64 0x10
	v17:i64 = Iadd module_ctx, v16
	v18:i64 = AtomicLoad_64, v17
	v19:i32 = Icmp lt_u, v18, v13
	ExitIfTrue v19, exec_ctx, memory_out_of_bounds
	Jump blk2, v18

blk2: (v15:i64) <-- (blk0,blk1)
	v20:i64 = Load module_ctx, 0x8
	v21:i64 = Iadd v20, v11
	v22:i32 = AtomicRmw add_8, v21, v2
	v23:i32 = Iconst_32 0x8
	v25:i64 = Iconst_64 0x2
	v26:i64 = UExtend v23, 32->64
	v27:i64 = Iadd v26, v25
	v28:i32 = Icmp lt_u, v15, v27
	Brnz v28, blk3
	Jump blk4, v15, v42, v61, v77, v98, v120

blk3: () <-- (blk2)
	v30:i64 = Iconst_64 0x10
	v31:i64 = Iadd module_ctx, v30
	v32:i64 = AtomicLoad_64, v31
	v33:i32 = Icmp lt_u, v32, v27
	ExitIfTrue v33, exec_ctx, memory_out_of_bounds
	Jump blk4, v32, v42, v61, v77, v98, v120

blk4: (v29:i64,v41:i32,v60:i64,v76:i64,v97:i64,v119:i64) <-- (blk2,blk3)
	v34:i64 = Iadd v20, v26
	v35:i64 = Iconst_64 0x1
	v36:i64 = Band v34, v35
	v37:i64 = Iconst_64 0x0
	v38:i32 = Icmp neq, v36, v37
	ExitIfTrue v38, exec_ctx, unaligned_atomic
	v39:i32 = AtomicRmw add_16, v34, v3
	v40:i32 = Iconst_32 0x10
	v43:i64 = Iconst_64 0x4
	v44:i64 = UExtend v40, 32->64
	v45:i64 = Iadd v44, v43
	v46:i32 = Icmp lt_u, v29, v45
	Brnz v46, blk5
	Jump blk6, v29

blk5: () <-- (blk4)
	v48:i64 = Iconst_64 0x10
	v49:i64 = Iadd module_ctx, v48
	v50:i64 = AtomicLoad_64, v49
	v51:i32 = Icmp lt_u, v50, v45
	ExitIfTrue v51, exec_ctx, memory_out_of_bounds
	Jump blk6, v50

blk6: (v47:i64) <-- (blk4,blk5)
	v52:i64 = Iadd v20, v44
	v53:i64 = Iconst_64 0x3
	v54:i64 = Band v52, v53
	v55:i64 = Iconst_64 0x0
	v56:i32 = Icmp neq, v54, v55
	ExitIfTrue v56, exec_ctx, unaligned_atomic
	v57:i32 = AtomicRmw add_32, v52, v41
	v58:i32 = Iconst_32 0x18
	v62:i64 = Iconst_64 0x1
	v63:i64 = UExtend v58, 32->64
	v64:i64 = Iadd v63, v62
	v65:i32 = Icmp lt_u, v47, v64
	Brnz v65, blk7
	Jump blk8, v47, v75, v96, v118

blk7: () <-- (blk6)
	v67:i64 = Iconst_64 0x10
	v68:i64 = Iadd module_ctx, v67
	v69:i64 = AtomicLoad_64, v68
	v70:i32 = Icmp lt_u, v69, v64
	ExitIfTrue v70, exec_ctx, memory_out_of_bounds
	Jump blk8, v69, v75, v96, v118

blk8: (v66:i64,v74:i64,v95:i64,v117:i64) <-- (blk6,blk7)
	v71:i64 = Iadd v20, v63
	v72:i64 = AtomicRmw add_8, v71, v60
	v73:i32 = Iconst_32 0x20
	v78:i64 = Iconst_64 0x2
	v79:i64 = UExtend v73, 32->64
	v80:i64 = Iadd v79, v78
	v81:i32 = Icmp lt_u, v66, v80
	Brnz v81, blk9
	Jump blk10, v66

blk9: () <-- (blk8)
	v83:i64 = Iconst_64 0x10
	v84:i64 = Iadd module_ctx, v83
	v85:i64 = AtomicLoad_64, v84
	v86:i32 = Icmp lt_u, v85, v80
	ExitIfTrue v86, exec_ctx, memory_out_of_bounds
	Jump blk10, v85

blk10: (v82:i64) <-- (blk8,blk9)
	v87:i64 = Iadd v20, v79
	v88:i64 = Iconst_64 0x1
	v89:i64 = Band v87, v88
	v90:i64 = Iconst_64 0x0
	v91:i32 = Icmp neq, v89, v90
	ExitIfTrue v91, exec_ctx, unaligned_atomic
	v92:i64 = AtomicRmw add_16, v87, v74
	v93:i32 = Iconst_32 0x28
	v99:i64 = Iconst_64 0x4
	v100:i64 = UExtend v93, 32->64
	v101:i64 = Iadd v100, v99
	v102:i32 = Icmp lt_u, v82, v101
	Brnz v102, blk11
	Jump blk12, v82, v116

blk11: () <-- (blk10)
	v104:i64 = Iconst_64 0x10
	v105:i64 = Iadd module_ctx, v104
	v106:i64 = AtomicLoad_64, v105
	v107:i32 = Icmp lt_u, v106, v101
	ExitIfTrue v107, exec_ctx, memory_out_of_bounds
	Jump blk12, v106, v116

blk12: (v103:i64,v115:i64) <-- (blk10,blk11)
	v108:i64 = Iadd v20, v100
	v109:i64 = Iconst_64 0x3
	v110:i64 = Band v108, v109
	v111:i64 = Iconst_64 0x0
	v112:i32 = Icmp neq, v110, v111
	ExitIfTrue v112, exec_ctx, unaligned_atomic
	v113:i64 = AtomicRmw add_32, v108, v95
	v114:i32 = Iconst_32 0x30
	v121:i64 = Iconst_64 0x8
	v122:i64 = UExtend v114, 32->64
	v123:i64 = Iadd v122, v121
	v124:i32 = Icmp lt_u, v103, v123
	Brnz v124, blk13
	Jump blk14, v103

blk13: () <-- (blk12)
	v126:i64 = Iconst_64 0x10
	v127:i64 = Iadd module_ctx, v126
	v128:i64 = AtomicLoad_64, v127
	v129:i32 = Icmp lt_u, v128, v123
	ExitIfTrue v129, exec_ctx, memory_out_of_bounds
	Jump blk14, v128

blk14: (v125:i64) <-- (blk12,blk13)
	v130:i64 = Iadd v20, v122
	v131:i64 = Iconst_64 0x7
	v132:i64 = Band v130, v131
	v133:i64 = Iconst_64 0x0
	v134:i32 = Icmp neq, v132, v133
	ExitIfTrue v134, exec_ctx, unaligned_atomic
	v135:i64 = AtomicRmw add_64, v130, v115
	Jump blk_ret, v22, v39, v57, v72, v92, v113, v135
`,
		},
		{
			name:     "AtomicRMWSub",
			m:        testcases.AtomicRmwSub.Module,
			features: api.CoreFeaturesV2 | experimental.CoreFeaturesThreads,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32, v4:i32, v5:i64, v6:i64, v7:i64, v8:i64)
	v9:i32 = Iconst_32 0x0
	v10:i64 = Iconst_64 0x1
	v11:i64 = UExtend v9, 32->64
	v12:i64 = Load module_ctx, 0x10
	v13:i64 = Iadd v11, v10
	v14:i32 = Icmp lt_u, v12, v13
	Brnz v14, blk1
	Jump blk2, v12

blk1: () <-- (blk0)
	v16:i64 = Iconst_64 0x10
	v17:i64 = Iadd module_ctx, v16
	v18:i64 = AtomicLoad_64, v17
	v19:i32 = Icmp lt_u, v18, v13
	ExitIfTrue v19, exec_ctx, memory_out_of_bounds
	Jump blk2, v18

blk2: (v15:i64) <-- (blk0,blk1)
	v20:i64 = Load module_ctx, 0x8
	v21:i64 = Iadd v20, v11
	v22:i32 = AtomicRmw sub_8, v21, v2
	v23:i32 = Iconst_32 0x8
	v25:i64 = Iconst_64 0x2
	v26:i64 = UExtend v23, 32->64
	v27:i64 = Iadd v26, v25
	v28:i32 = Icmp lt_u, v15, v27
	Brnz v28, blk3
	Jump blk4, v15, v42, v61, v77, v98, v120

blk3: () <-- (blk2)
	v30:i64 = Iconst_64 0x10
	v31:i64 = Iadd module_ctx, v30
	v32:i64 = AtomicLoad_64, v31
	v33:i32 = Icmp lt_u, v32, v27
	ExitIfTrue v33, exec_ctx, memory_out_of_bounds
	Jump blk4, v32, v42, v61, v77, v98, v120

blk4: (v29:i64,v41:i32,v60:i64,v76:i64,v97:i64,v119:i64) <-- (blk2,blk3)
	v34:i64 = Iadd v20, v26
	v35:i64 = Iconst_64 0x1
	v36:i64 = Band v34, v35
	v37:i64 = Iconst_64 0x0
	v38:i32 = Icmp neq, v36, v37
	ExitIfTrue v38, exec_ctx, unaligned_atomic
	v39:i32 = AtomicRmw sub_16, v34, v3
	v40:i32 = Iconst_32 0x10
	v43:i64 = Iconst_64 0x4
	v44:i64 = UExtend v40, 32->64
	v45:i64 = Iadd v44, v43
	v46:i32 = Icmp lt_u, v29, v45
	Brnz v46, blk5
	Jump blk6, v29

blk5: () <-- (blk4)
	v48:i64 = Iconst_64 0x10
	v49:i64 = Iadd module_ctx, v48
	v50:i64 = AtomicLoad_64, v49
	v51:i32 = Icmp lt_u, v50, v45
	ExitIfTrue v51, exec_ctx, memory_out_of_bounds
	Jump blk6, v50

blk6: (v47:i64) <-- (blk4,blk5)
	v52:i64 = Iadd v20, v44
	v53:i64 = Iconst_64 0x3
	v54:i64 = Band v52, v53
	v55:i64 = Iconst_64 0x0
	v56:i32 = Icmp neq, v54, v55
	ExitIfTrue v56, exec_ctx, unaligned_atomic
	v57:i32 = AtomicRmw sub_32, v52, v41
	v58:i32 = Iconst_32 0x18
	v62:i64 = Iconst_64 0x1
	v63:i64 = UExtend v58, 32->64
	v64:i64 = Iadd v63, v62
	v65:i32 = Icmp lt_u, v47, v64
	Brnz v65, blk7
	Jump blk8, v47, v75, v96, v118

blk7: () <-- (blk6)
	v67:i64 = Iconst_64 0x10
	v68:i64 = Iadd module_ctx, v67
	v69:i64 = AtomicLoad_64, v68
	v70:i32 = Icmp lt_u, v69, v64
	ExitIfTrue v70, exec_ctx, memory_out_of_bounds
	Jump blk8, v69, v75, v96, v118

blk8: (v66:i64,v74:i64,v95:i64,v117:i64) <-- (blk6,blk7)
	v71:i64 = Iadd v20, v63
	v72:i64 = AtomicRmw sub_8, v71, v60
	v73:i32 = Iconst_32 0x20
	v78:i64 = Iconst_64 0x2
	v79:i64 = UExtend v73, 32->64
	v80:i64 = Iadd v79, v78
	v81:i32 = Icmp lt_u, v66, v80
	Brnz v81, blk9
	Jump blk10, v66

blk9: () <-- (blk8)
	v83:i64 = Iconst_64 0x10
	v84:i64 = Iadd module_ctx, v83
	v85:i64 = AtomicLoad_64, v84
	v86:i32 = Icmp lt_u, v85, v80
	ExitIfTrue v86, exec_ctx, memory_out_of_bounds
	Jump blk10, v85

blk10: (v82:i64) <-- (blk8,blk9)
	v87:i64 = Iadd v20, v79
	v88:i64 = Iconst_64 0x1
	v89:i64 = Band v87, v88
	v90:i64 = Iconst_64 0x0
	v91:i32 = Icmp neq, v89, v90
	ExitIfTrue v91, exec_ctx, unaligned_atomic
	v92:i64 = AtomicRmw sub_16, v87, v74
	v93:i32 = Iconst_32 0x28
	v99:i64 = Iconst_64 0x4
	v100:i64 = UExtend v93, 32->64
	v101:i64 = Iadd v100, v99
	v102:i32 = Icmp lt_u, v82, v101
	Brnz v102, blk11
	Jump blk12, v82, v116

blk11: () <-- (blk10)
	v104:i64 = Iconst_64 0x10
	v105:i64 = Iadd module_ctx, v104
	v106:i64 = AtomicLoad_64, v105
	v107:i32 = Icmp lt_u, v106, v101
	ExitIfTrue v107, exec_ctx, memory_out_of_bounds
	Jump blk12, v106, v116

blk12: (v103:i64,v115:i64) <-- (blk10,blk11)
	v108:i64 = Iadd v20, v100
	v109:i64 = Iconst_64 0x3
	v110:i64 = Band v108, v109
	v111:i64 = Iconst_64 0x0
	v112:i32 = Icmp neq, v110, v111
	ExitIfTrue v112, exec_ctx, unaligned_atomic
	v113:i64 = AtomicRmw sub_32, v108, v95
	v114:i32 = Iconst_32 0x30
	v121:i64 = Iconst_64 0x8
	v122:i64 = UExtend v114, 32->64
	v123:i64 = Iadd v122, v121
	v124:i32 = Icmp lt_u, v103, v123
	Brnz v124, blk13
	Jump blk14, v103

blk13: () <-- (blk12)
	v126:i64 = Iconst_64 0x10
	v127:i64 = Iadd module_ctx, v126
	v128:i64 = AtomicLoad_64, v127
	v129:i32 = Icmp lt_u, v128, v123
	ExitIfTrue v129, exec_ctx, memory_out_of_bounds
	Jump blk14, v128

blk14: (v125:i64) <-- (blk12,blk13)
	v130:i64 = Iadd v20, v122
	v131:i64 = Iconst_64 0x7
	v132:i64 = Band v130, v131
	v133:i64 = Iconst_64 0x0
	v134:i32 = Icmp neq, v132, v133
	ExitIfTrue v134, exec_ctx, unaligned_atomic
	v135:i64 = AtomicRmw sub_64, v130, v115
	Jump blk_ret, v22, v39, v57, v72, v92, v113, v135
`,
		},
		{
			name:     "AtomicRMWAnd",
			m:        testcases.AtomicRmwAnd.Module,
			features: api.CoreFeaturesV2 | experimental.CoreFeaturesThreads,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32, v4:i32, v5:i64, v6:i64, v7:i64, v8:i64)
	v9:i32 = Iconst_32 0x0
	v10:i64 = Iconst_64 0x1
	v11:i64 = UExtend v9, 32->64
	v12:i64 = Load module_ctx, 0x10
	v13:i64 = Iadd v11, v10
	v14:i32 = Icmp lt_u, v12, v13
	Brnz v14, blk1
	Jump blk2, v12

blk1: () <-- (blk0)
	v16:i64 = Iconst_64 0x10
	v17:i64 = Iadd module_ctx, v16
	v18:i64 = AtomicLoad_64, v17
	v19:i32 = Icmp lt_u, v18, v13
	ExitIfTrue v19, exec_ctx, memory_out_of_bounds
	Jump blk2, v18

blk2: (v15:i64) <-- (blk0,blk1)
	v20:i64 = Load module_ctx, 0x8
	v21:i64 = Iadd v20, v11
	v22:i32 = AtomicRmw and_8, v21, v2
	v23:i32 = Iconst_32 0x0
	v25:i64 = Iconst_64 0xa
	v26:i64 = UExtend v23, 32->64
	v27:i64 = Iadd v26, v25
	v28:i32 = Icmp lt_u, v15, v27
	Brnz v28, blk3
	Jump blk4, v15, v44, v65, v83, v106, v130

blk3: () <-- (blk2)
	v30:i64 = Iconst_64 0x10
	v31:i64 = Iadd module_ctx, v30
	v32:i64 = AtomicLoad_64, v31
	v33:i32 = Icmp lt_u, v32, v27
	ExitIfTrue v33, exec_ctx, memory_out_of_bounds
	Jump blk4, v32, v44, v65, v83, v106, v130

blk4: (v29:i64,v43:i32,v64:i64,v82:i64,v105:i64,v129:i64) <-- (blk2,blk3)
	v34:i64 = Iadd v20, v26
	v35:i64 = Iconst_64 0x8
	v36:i64 = Iadd v34, v35
	v37:i64 = Iconst_64 0x1
	v38:i64 = Band v36, v37
	v39:i64 = Iconst_64 0x0
	v40:i32 = Icmp neq, v38, v39
	ExitIfTrue v40, exec_ctx, unaligned_atomic
	v41:i32 = AtomicRmw and_16, v36, v3
	v42:i32 = Iconst_32 0x0
	v45:i64 = Iconst_64 0x14
	v46:i64 = UExtend v42, 32->64
	v47:i64 = Iadd v46, v45
	v48:i32 = Icmp lt_u, v29, v47
	Brnz v48, blk5
	Jump blk6, v29

blk5: () <-- (blk4)
	v50:i64 = Iconst_64 0x10
	v51:i64 = Iadd module_ctx, v50
	v52:i64 = AtomicLoad_64, v51
	v53:i32 = Icmp lt_u, v52, v47
	ExitIfTrue v53, exec_ctx, memory_out_of_bounds
	Jump blk6, v52

blk6: (v49:i64) <-- (blk4,blk5)
	v54:i64 = Iadd v20, v46
	v55:i64 = Iconst_64 0x10
	v56:i64 = Iadd v54, v55
	v57:i64 = Iconst_64 0x3
	v58:i64 = Band v56, v57
	v59:i64 = Iconst_64 0x0
	v60:i32 = Icmp neq, v58, v59
	ExitIfTrue v60, exec_ctx, unaligned_atomic
	v61:i32 = AtomicRmw and_32, v56, v43
	v62:i32 = Iconst_32 0x0
	v66:i64 = Iconst_64 0x19
	v67:i64 = UExtend v62, 32->64
	v68:i64 = Iadd v67, v66
	v69:i32 = Icmp lt_u, v49, v68
	Brnz v69, blk7
	Jump blk8, v49, v81, v104, v128

blk7: () <-- (blk6)
	v71:i64 = Iconst_64 0x10
	v72:i64 = Iadd module_ctx, v71
	v73:i64 = AtomicLoad_64, v72
	v74:i32 = Icmp lt_u, v73, v68
	ExitIfTrue v74, exec_ctx, memory_out_of_bounds
	Jump blk8, v73, v81, v104, v128

blk8: (v70:i64,v80:i64,v103:i64,v127:i64) <-- (blk6,blk7)
	v75:i64 = Iadd v20, v67
	v76:i64 = Iconst_64 0x18
	v77:i64 = Iadd v75, v76
	v78:i64 = AtomicRmw and_8, v77, v64
	v79:i32 = Iconst_32 0x0
	v84:i64 = Iconst_64 0x22
	v85:i64 = UExtend v79, 32->64
	v86:i64 = Iadd v85, v84
	v87:i32 = Icmp lt_u, v70, v86
	Brnz v87, blk9
	Jump blk10, v70

blk9: () <-- (blk8)
	v89:i64 = Iconst_64 0x10
	v90:i64 = Iadd module_ctx, v89
	v91:i64 = AtomicLoad_64, v90
	v92:i32 = Icmp lt_u, v91, v86
	ExitIfTrue v92, exec_ctx, memory_out_of_bounds
	Jump blk10, v91

blk10: (v88:i64) <-- (blk8,blk9)
	v93:i64 = Iadd v20, v85
	v94:i64 = Iconst_64 0x20
	v95:i64 = Iadd v93, v94
	v96:i64 = Iconst_64 0x1
	v97:i64 = Band v95, v96
	v98:i64 = Iconst_64 0x0
	v99:i32 = Icmp neq, v97, v98
	ExitIfTrue v99, exec_ctx, unaligned_atomic
	v100:i64 = AtomicRmw and_16, v95, v80
	v101:i32 = Iconst_32 0x0
	v107:i64 = Iconst_64 0x2c
	v108:i64 = UExtend v101, 32->64
	v109:i64 = Iadd v108, v107
	v110:i32 = Icmp lt_u, v88, v109
	Brnz v110, blk11
	Jump blk12, v88, v126

blk11: () <-- (blk10)
	v112:i64 = Iconst_64 0x10
	v113:i64 = Iadd module_ctx, v112
	v114:i64 = AtomicLoad_64, v113
	v115:i32 = Icmp lt_u, v114, v109
	ExitIfTrue v115, exec_ctx, memory_out_of_bounds
	Jump blk12, v114, v126

blk12: (v111:i64,v125:i64) <-- (blk10,blk11)
	v116:i64 = Iadd v20, v108
	v117:i64 = Iconst_64 0x28
	v118:i64 = Iadd v116, v117
	v119:i64 = Iconst_64 0x3
	v120:i64 = Band v118, v119
	v121:i64 = Iconst_64 0x0
	v122:i32 = Icmp neq, v120, v121
	ExitIfTrue v122, exec_ctx, unaligned_atomic
	v123:i64 = AtomicRmw and_32, v118, v103
	v124:i32 = Iconst_32 0x0
	v131:i64 = Iconst_64 0x38
	v132:i64 = UExtend v124, 32->64
	v133:i64 = Iadd v132, v131
	v134:i32 = Icmp lt_u, v111, v133
	Brnz v134, blk13
	Jump blk14, v111

blk13: () <-- (blk12)
	v136:i64 = Iconst_64 0x10
	v137:i64 = Iadd module_ctx, v136
	v138:i64 = AtomicLoad_64, v137
	v139:i32 = Icmp lt_u, v138, v133
	ExitIfTrue v139, exec_ctx, memory_out_of_bounds
	Jump blk14, v138

blk14: (v135:i64) <-- (blk12,blk13)
	v140:i64 = Iadd v20, v132
	v141:i64 = Iconst_64 0x30
	v142:i64 = Iadd v140, v141
	v143:i64 = Iconst_64 0x7
	v144:i64 = Band v142, v143
	v145:i64 = Iconst_64 0x0
	v146:i32 = Icmp neq, v144, v145
	ExitIfTrue v146, exec_ctx, unaligned_atomic
	v147:i64 = AtomicRmw and_64, v142, v125
	Jump blk_ret, v22, v41, v61, v78, v100, v123, v147
`,
		},
		{
			name:     "AtomicRMWOr",
			m:        testcases.AtomicRmwOr.Module,
			features: api.CoreFeaturesV2 | experimental.CoreFeaturesThreads,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32, v4:i32, v5:i64, v6:i64, v7:i64, v8:i64)
	v9:i32 = Iconst_32 0x0
	v10:i64 = Iconst_64 0x1
	v11:i64 = UExtend v9, 32->64
	v12:i64 = Load module_ctx, 0x10
	v13:i64 = Iadd v11, v10
	v14:i32 = Icmp lt_u, v12, v13
	Brnz v14, blk1
	Jump blk2, v12

blk1: () <-- (blk0)
	v16:i64 = Iconst_64 0x10
	v17:i64 = Iadd module_ctx, v16
	v18:i64 = AtomicLoad_64, v17
	v19:i32 = Icmp lt_u, v18, v13
	ExitIfTrue v19, exec_ctx, memory_out_of_bounds
	Jump blk2, v18

blk2: (v15:i64) <-- (blk0,blk1)
	v20:i64 = Load module_ctx, 0x8
	v21:i64 = Iadd v20, v11
	v22:i32 = AtomicRmw or_8, v21, v2
	v23:i32 = Iconst_32 0x0
	v25:i64 = Iconst_64 0xa
	v26:i64 = UExtend v23, 32->64
	v27:i64 = Iadd v26, v25
	v28:i32 = Icmp lt_u, v15, v27
	Brnz v28, blk3
	Jump blk4, v15, v44, v65, v83, v106, v130

blk3: () <-- (blk2)
	v30:i64 = Iconst_64 0x10
	v31:i64 = Iadd module_ctx, v30
	v32:i64 = AtomicLoad_64, v31
	v33:i32 = Icmp lt_u, v32, v27
	ExitIfTrue v33, exec_ctx, memory_out_of_bounds
	Jump blk4, v32, v44, v65, v83, v106, v130

blk4: (v29:i64,v43:i32,v64:i64,v82:i64,v105:i64,v129:i64) <-- (blk2,blk3)
	v34:i64 = Iadd v20, v26
	v35:i64 = Iconst_64 0x8
	v36:i64 = Iadd v34, v35
	v37:i64 = Iconst_64 0x1
	v38:i64 = Band v36, v37
	v39:i64 = Iconst_64 0x0
	v40:i32 = Icmp neq, v38, v39
	ExitIfTrue v40, exec_ctx, unaligned_atomic
	v41:i32 = AtomicRmw or_16, v36, v3
	v42:i32 = Iconst_32 0x0
	v45:i64 = Iconst_64 0x14
	v46:i64 = UExtend v42, 32->64
	v47:i64 = Iadd v46, v45
	v48:i32 = Icmp lt_u, v29, v47
	Brnz v48, blk5
	Jump blk6, v29

blk5: () <-- (blk4)
	v50:i64 = Iconst_64 0x10
	v51:i64 = Iadd module_ctx, v50
	v52:i64 = AtomicLoad_64, v51
	v53:i32 = Icmp lt_u, v52, v47
	ExitIfTrue v53, exec_ctx, memory_out_of_bounds
	Jump blk6, v52

blk6: (v49:i64) <-- (blk4,blk5)
	v54:i64 = Iadd v20, v46
	v55:i64 = Iconst_64 0x10
	v56:i64 = Iadd v54, v55
	v57:i64 = Iconst_64 0x3
	v58:i64 = Band v56, v57
	v59:i64 = Iconst_64 0x0
	v60:i32 = Icmp neq, v58, v59
	ExitIfTrue v60, exec_ctx, unaligned_atomic
	v61:i32 = AtomicRmw or_32, v56, v43
	v62:i32 = Iconst_32 0x0
	v66:i64 = Iconst_64 0x19
	v67:i64 = UExtend v62, 32->64
	v68:i64 = Iadd v67, v66
	v69:i32 = Icmp lt_u, v49, v68
	Brnz v69, blk7
	Jump blk8, v49, v81, v104, v128

blk7: () <-- (blk6)
	v71:i64 = Iconst_64 0x10
	v72:i64 = Iadd module_ctx, v71
	v73:i64 = AtomicLoad_64, v72
	v74:i32 = Icmp lt_u, v73, v68
	ExitIfTrue v74, exec_ctx, memory_out_of_bounds
	Jump blk8, v73, v81, v104, v128

blk8: (v70:i64,v80:i64,v103:i64,v127:i64) <-- (blk6,blk7)
	v75:i64 = Iadd v20, v67
	v76:i64 = Iconst_64 0x18
	v77:i64 = Iadd v75, v76
	v78:i64 = AtomicRmw or_8, v77, v64
	v79:i32 = Iconst_32 0x0
	v84:i64 = Iconst_64 0x22
	v85:i64 = UExtend v79, 32->64
	v86:i64 = Iadd v85, v84
	v87:i32 = Icmp lt_u, v70, v86
	Brnz v87, blk9
	Jump blk10, v70

blk9: () <-- (blk8)
	v89:i64 = Iconst_64 0x10
	v90:i64 = Iadd module_ctx, v89
	v91:i64 = AtomicLoad_64, v90
	v92:i32 = Icmp lt_u, v91, v86
	ExitIfTrue v92, exec_ctx, memory_out_of_bounds
	Jump blk10, v91

blk10: (v88:i64) <-- (blk8,blk9)
	v93:i64 = Iadd v20, v85
	v94:i64 = Iconst_64 0x20
	v95:i64 = Iadd v93, v94
	v96:i64 = Iconst_64 0x1
	v97:i64 = Band v95, v96
	v98:i64 = Iconst_64 0x0
	v99:i32 = Icmp neq, v97, v98
	ExitIfTrue v99, exec_ctx, unaligned_atomic
	v100:i64 = AtomicRmw or_16, v95, v80
	v101:i32 = Iconst_32 0x0
	v107:i64 = Iconst_64 0x2c
	v108:i64 = UExtend v101, 32->64
	v109:i64 = Iadd v108, v107
	v110:i32 = Icmp lt_u, v88, v109
	Brnz v110, blk11
	Jump blk12, v88, v126

blk11: () <-- (blk10)
	v112:i64 = Iconst_64 0x10
	v113:i64 = Iadd module_ctx, v112
	v114:i64 = AtomicLoad_64, v113
	v115:i32 = Icmp lt_u, v114, v109
	ExitIfTrue v115, exec_ctx, memory_out_of_bounds
	Jump blk12, v114, v126

blk12: (v111:i64,v125:i64) <-- (blk10,blk11)
	v116:i64 = Iadd v20, v108
	v117:i64 = Iconst_64 0x28
	v118:i64 = Iadd v116, v117
	v119:i64 = Iconst_64 0x3
	v120:i64 = Band v118, v119
	v121:i64 = Iconst_64 0x0
	v122:i32 = Icmp neq, v120, v121
	ExitIfTrue v122, exec_ctx, unaligned_atomic
	v123:i64 = AtomicRmw or_32, v118, v103
	v124:i32 = Iconst_32 0x0
	v131:i64 = Iconst_64 0x38
	v132:i64 = UExtend v124, 32->64
	v133:i64 = Iadd v132, v131
	v134:i32 = Icmp lt_u, v111, v133
	Brnz v134, blk13
	Jump blk14, v111

blk13: () <-- (blk12)
	v136:i64 = Iconst_64 0x10
	v137:i64 = Iadd module_ctx, v136
	v138:i64 = AtomicLoad_64, v137
	v139:i32 = Icmp lt_u, v138, v133
	ExitIfTrue v139, exec_ctx, memory_out_of_bounds
	Jump blk14, v138

blk14: (v135:i64) <-- (blk12,blk13)
	v140:i64 = Iadd v20, v132
	v141:i64 = Iconst_64 0x30
	v142:i64 = Iadd v140, v141
	v143:i64 = Iconst_64 0x7
	v144:i64 = Band v142, v143
	v145:i64 = Iconst_64 0x0
	v146:i32 = Icmp neq, v144, v145
	ExitIfTrue v146, exec_ctx, unaligned_atomic
	v147:i64 = AtomicRmw or_64, v142, v125
	Jump blk_ret, v22, v41, v61, v78, v100, v123, v147
`,
		},
		{
			name:     "AtomicRMWXor",
			m:        testcases.AtomicRmwXor.Module,
			features: api.CoreFeaturesV2 | experimental.CoreFeaturesThreads,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32, v4:i32, v5:i64, v6:i64, v7:i64, v8:i64)
	v9:i32 = Iconst_32 0x0
	v10:i64 = Iconst_64 0x1
	v11:i64 = UExtend v9, 32->64
	v12:i64 = Load module_ctx, 0x10
	v13:i64 = Iadd v11, v10
	v14:i32 = Icmp lt_u, v12, v13
	Brnz v14, blk1
	Jump blk2, v12

blk1: () <-- (blk0)
	v16:i64 = Iconst_64 0x10
	v17:i64 = Iadd module_ctx, v16
	v18:i64 = AtomicLoad_64, v17
	v19:i32 = Icmp lt_u, v18, v13
	ExitIfTrue v19, exec_ctx, memory_out_of_bounds
	Jump blk2, v18

blk2: (v15:i64) <-- (blk0,blk1)
	v20:i64 = Load module_ctx, 0x8
	v21:i64 = Iadd v20, v11
	v22:i32 = AtomicRmw xor_8, v21, v2
	v23:i32 = Iconst_32 0x0
	v25:i64 = Iconst_64 0xa
	v26:i64 = UExtend v23, 32->64
	v27:i64 = Iadd v26, v25
	v28:i32 = Icmp lt_u, v15, v27
	Brnz v28, blk3
	Jump blk4, v15, v44, v65, v83, v106, v130

blk3: () <-- (blk2)
	v30:i64 = Iconst_64 0x10
	v31:i64 = Iadd module_ctx, v30
	v32:i64 = AtomicLoad_64, v31
	v33:i32 = Icmp lt_u, v32, v27
	ExitIfTrue v33, exec_ctx, memory_out_of_bounds
	Jump blk4, v32, v44, v65, v83, v106, v130

blk4: (v29:i64,v43:i32,v64:i64,v82:i64,v105:i64,v129:i64) <-- (blk2,blk3)
	v34:i64 = Iadd v20, v26
	v35:i64 = Iconst_64 0x8
	v36:i64 = Iadd v34, v35
	v37:i64 = Iconst_64 0x1
	v38:i64 = Band v36, v37
	v39:i64 = Iconst_64 0x0
	v40:i32 = Icmp neq, v38, v39
	ExitIfTrue v40, exec_ctx, unaligned_atomic
	v41:i32 = AtomicRmw xor_16, v36, v3
	v42:i32 = Iconst_32 0x0
	v45:i64 = Iconst_64 0x14
	v46:i64 = UExtend v42, 32->64
	v47:i64 = Iadd v46, v45
	v48:i32 = Icmp lt_u, v29, v47
	Brnz v48, blk5
	Jump blk6, v29

blk5: () <-- (blk4)
	v50:i64 = Iconst_64 0x10
	v51:i64 = Iadd module_ctx, v50
	v52:i64 = AtomicLoad_64, v51
	v53:i32 = Icmp lt_u, v52, v47
	ExitIfTrue v53, exec_ctx, memory_out_of_bounds
	Jump blk6, v52

blk6: (v49:i64) <-- (blk4,blk5)
	v54:i64 = Iadd v20, v46
	v55:i64 = Iconst_64 0x10
	v56:i64 = Iadd v54, v55
	v57:i64 = Iconst_64 0x3
	v58:i64 = Band v56, v57
	v59:i64 = Iconst_64 0x0
	v60:i32 = Icmp neq, v58, v59
	ExitIfTrue v60, exec_ctx, unaligned_atomic
	v61:i32 = AtomicRmw xor_32, v56, v43
	v62:i32 = Iconst_32 0x0
	v66:i64 = Iconst_64 0x19
	v67:i64 = UExtend v62, 32->64
	v68:i64 = Iadd v67, v66
	v69:i32 = Icmp lt_u, v49, v68
	Brnz v69, blk7
	Jump blk8, v49, v81, v104, v128

blk7: () <-- (blk6)
	v71:i64 = Iconst_64 0x10
	v72:i64 = Iadd module_ctx, v71
	v73:i64 = AtomicLoad_64, v72
	v74:i32 = Icmp lt_u, v73, v68
	ExitIfTrue v74, exec_ctx, memory_out_of_bounds
	Jump blk8, v73, v81, v104, v128

blk8: (v70:i64,v80:i64,v103:i64,v127:i64) <-- (blk6,blk7)
	v75:i64 = Iadd v20, v67
	v76:i64 = Iconst_64 0x18
	v77:i64 = Iadd v75, v76
	v78:i64 = AtomicRmw xor_8, v77, v64
	v79:i32 = Iconst_32 0x0
	v84:i64 = Iconst_64 0x22
	v85:i64 = UExtend v79, 32->64
	v86:i64 = Iadd v85, v84
	v87:i32 = Icmp lt_u, v70, v86
	Brnz v87, blk9
	Jump blk10, v70

blk9: () <-- (blk8)
	v89:i64 = Iconst_64 0x10
	v90:i64 = Iadd module_ctx, v89
	v91:i64 = AtomicLoad_64, v90
	v92:i32 = Icmp lt_u, v91, v86
	ExitIfTrue v92, exec_ctx, memory_out_of_bounds
	Jump blk10, v91

blk10: (v88:i64) <-- (blk8,blk9)
	v93:i64 = Iadd v20, v85
	v94:i64 = Iconst_64 0x20
	v95:i64 = Iadd v93, v94
	v96:i64 = Iconst_64 0x1
	v97:i64 = Band v95, v96
	v98:i64 = Iconst_64 0x0
	v99:i32 = Icmp neq, v97, v98
	ExitIfTrue v99, exec_ctx, unaligned_atomic
	v100:i64 = AtomicRmw xor_16, v95, v80
	v101:i32 = Iconst_32 0x0
	v107:i64 = Iconst_64 0x2c
	v108:i64 = UExtend v101, 32->64
	v109:i64 = Iadd v108, v107
	v110:i32 = Icmp lt_u, v88, v109
	Brnz v110, blk11
	Jump blk12, v88, v126

blk11: () <-- (blk10)
	v112:i64 = Iconst_64 0x10
	v113:i64 = Iadd module_ctx, v112
	v114:i64 = AtomicLoad_64, v113
	v115:i32 = Icmp lt_u, v114, v109
	ExitIfTrue v115, exec_ctx, memory_out_of_bounds
	Jump blk12, v114, v126

blk12: (v111:i64,v125:i64) <-- (blk10,blk11)
	v116:i64 = Iadd v20, v108
	v117:i64 = Iconst_64 0x28
	v118:i64 = Iadd v116, v117
	v119:i64 = Iconst_64 0x3
	v120:i64 = Band v118, v119
	v121:i64 = Iconst_64 0x0
	v122:i32 = Icmp neq, v120, v121
	ExitIfTrue v122, exec_ctx, unaligned_atomic
	v123:i64 = AtomicRmw xor_32, v118, v103
	v124:i32 = Iconst_32 0x0
	v131:i64 = Iconst_64 0x38
	v132:i64 = UExtend v124, 32->64
	v133:i64 = Iadd v132, v131
	v134:i32 = Icmp lt_u, v111, v133
	Brnz v134, blk13
	Jump blk14, v111

blk13: () <-- (blk12)
	v136:i64 = Iconst_64 0x10
	v137:i64 = Iadd module_ctx, v136
	v138:i64 = AtomicLoad_64, v137
	v139:i32 = Icmp lt_u, v138, v133
	ExitIfTrue v139, exec_ctx, memory_out_of_bounds
	Jump blk14, v138

blk14: (v135:i64) <-- (blk12,blk13)
	v140:i64 = Iadd v20, v132
	v141:i64 = Iconst_64 0x30
	v142:i64 = Iadd v140, v141
	v143:i64 = Iconst_64 0x7
	v144:i64 = Band v142, v143
	v145:i64 = Iconst_64 0x0
	v146:i32 = Icmp neq, v144, v145
	ExitIfTrue v146, exec_ctx, unaligned_atomic
	v147:i64 = AtomicRmw xor_64, v142, v125
	Jump blk_ret, v22, v41, v61, v78, v100, v123, v147
`,
		},
		{
			name:     "AtomicRMWXchg",
			m:        testcases.AtomicRmwXchg.Module,
			features: api.CoreFeaturesV2 | experimental.CoreFeaturesThreads,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32, v4:i32, v5:i64, v6:i64, v7:i64, v8:i64)
	v9:i32 = Iconst_32 0x0
	v10:i64 = Iconst_64 0x1
	v11:i64 = UExtend v9, 32->64
	v12:i64 = Load module_ctx, 0x10
	v13:i64 = Iadd v11, v10
	v14:i32 = Icmp lt_u, v12, v13
	Brnz v14, blk1
	Jump blk2, v12

blk1: () <-- (blk0)
	v16:i64 = Iconst_64 0x10
	v17:i64 = Iadd module_ctx, v16
	v18:i64 = AtomicLoad_64, v17
	v19:i32 = Icmp lt_u, v18, v13
	ExitIfTrue v19, exec_ctx, memory_out_of_bounds
	Jump blk2, v18

blk2: (v15:i64) <-- (blk0,blk1)
	v20:i64 = Load module_ctx, 0x8
	v21:i64 = Iadd v20, v11
	v22:i32 = AtomicRmw xchg_8, v21, v2
	v23:i32 = Iconst_32 0x0
	v25:i64 = Iconst_64 0xa
	v26:i64 = UExtend v23, 32->64
	v27:i64 = Iadd v26, v25
	v28:i32 = Icmp lt_u, v15, v27
	Brnz v28, blk3
	Jump blk4, v15, v44, v65, v83, v106, v130

blk3: () <-- (blk2)
	v30:i64 = Iconst_64 0x10
	v31:i64 = Iadd module_ctx, v30
	v32:i64 = AtomicLoad_64, v31
	v33:i32 = Icmp lt_u, v32, v27
	ExitIfTrue v33, exec_ctx, memory_out_of_bounds
	Jump blk4, v32, v44, v65, v83, v106, v130

blk4: (v29:i64,v43:i32,v64:i64,v82:i64,v105:i64,v129:i64) <-- (blk2,blk3)
	v34:i64 = Iadd v20, v26
	v35:i64 = Iconst_64 0x8
	v36:i64 = Iadd v34, v35
	v37:i64 = Iconst_64 0x1
	v38:i64 = Band v36, v37
	v39:i64 = Iconst_64 0x0
	v40:i32 = Icmp neq, v38, v39
	ExitIfTrue v40, exec_ctx, unaligned_atomic
	v41:i32 = AtomicRmw xchg_16, v36, v3
	v42:i32 = Iconst_32 0x0
	v45:i64 = Iconst_64 0x14
	v46:i64 = UExtend v42, 32->64
	v47:i64 = Iadd v46, v45
	v48:i32 = Icmp lt_u, v29, v47
	Brnz v48, blk5
	Jump blk6, v29

blk5: () <-- (blk4)
	v50:i64 = Iconst_64 0x10
	v51:i64 = Iadd module_ctx, v50
	v52:i64 = AtomicLoad_64, v51
	v53:i32 = Icmp lt_u, v52, v47
	ExitIfTrue v53, exec_ctx, memory_out_of_bounds
	Jump blk6, v52

blk6: (v49:i64) <-- (blk4,blk5)
	v54:i64 = Iadd v20, v46
	v55:i64 = Iconst_64 0x10
	v56:i64 = Iadd v54, v55
	v57:i64 = Iconst_64 0x3
	v58:i64 = Band v56, v57
	v59:i64 = Iconst_64 0x0
	v60:i32 = Icmp neq, v58, v59
	ExitIfTrue v60, exec_ctx, unaligned_atomic
	v61:i32 = AtomicRmw xchg_32, v56, v43
	v62:i32 = Iconst_32 0x0
	v66:i64 = Iconst_64 0x19
	v67:i64 = UExtend v62, 32->64
	v68:i64 = Iadd v67, v66
	v69:i32 = Icmp lt_u, v49, v68
	Brnz v69, blk7
	Jump blk8, v49, v81, v104, v128

blk7: () <-- (blk6)
	v71:i64 = Iconst_64 0x10
	v72:i64 = Iadd module_ctx, v71
	v73:i64 = AtomicLoad_64, v72
	v74:i32 = Icmp lt_u, v73, v68
	ExitIfTrue v74, exec_ctx, memory_out_of_bounds
	Jump blk8, v73, v81, v104, v128

blk8: (v70:i64,v80:i64,v103:i64,v127:i64) <-- (blk6,blk7)
	v75:i64 = Iadd v20, v67
	v76:i64 = Iconst_64 0x18
	v77:i64 = Iadd v75, v76
	v78:i64 = AtomicRmw xchg_8, v77, v64
	v79:i32 = Iconst_32 0x0
	v84:i64 = Iconst_64 0x22
	v85:i64 = UExtend v79, 32->64
	v86:i64 = Iadd v85, v84
	v87:i32 = Icmp lt_u, v70, v86
	Brnz v87, blk9
	Jump blk10, v70

blk9: () <-- (blk8)
	v89:i64 = Iconst_64 0x10
	v90:i64 = Iadd module_ctx, v89
	v91:i64 = AtomicLoad_64, v90
	v92:i32 = Icmp lt_u, v91, v86
	ExitIfTrue v92, exec_ctx, memory_out_of_bounds
	Jump blk10, v91

blk10: (v88:i64) <-- (blk8,blk9)
	v93:i64 = Iadd v20, v85
	v94:i64 = Iconst_64 0x20
	v95:i64 = Iadd v93, v94
	v96:i64 = Iconst_64 0x1
	v97:i64 = Band v95, v96
	v98:i64 = Iconst_64 0x0
	v99:i32 = Icmp neq, v97, v98
	ExitIfTrue v99, exec_ctx, unaligned_atomic
	v100:i64 = AtomicRmw xchg_16, v95, v80
	v101:i32 = Iconst_32 0x0
	v107:i64 = Iconst_64 0x2c
	v108:i64 = UExtend v101, 32->64
	v109:i64 = Iadd v108, v107
	v110:i32 = Icmp lt_u, v88, v109
	Brnz v110, blk11
	Jump blk12, v88, v126

blk11: () <-- (blk10)
	v112:i64 = Iconst_64 0x10
	v113:i64 = Iadd module_ctx, v112
	v114:i64 = AtomicLoad_64, v113
	v115:i32 = Icmp lt_u, v114, v109
	ExitIfTrue v115, exec_ctx, memory_out_of_bounds
	Jump blk12, v114, v126

blk12: (v111:i64,v125:i64) <-- (blk10,blk11)
	v116:i64 = Iadd v20, v108
	v117:i64 = Iconst_64 0x28
	v118:i64 = Iadd v116, v117
	v119:i64 = Iconst_64 0x3
	v120:i64 = Band v118, v119
	v121:i64 = Iconst_64 0x0
	v122:i32 = Icmp neq, v120, v121
	ExitIfTrue v122, exec_ctx, unaligned_atomic
	v123:i64 = AtomicRmw xchg_32, v118, v103
	v124:i32 = Iconst_32 0x0
	v131:i64 = Iconst_64 0x38
	v132:i64 = UExtend v124, 32->64
	v133:i64 = Iadd v132, v131
	v134:i32 = Icmp lt_u, v111, v133
	Brnz v134, blk13
	Jump blk14, v111

blk13: () <-- (blk12)
	v136:i64 = Iconst_64 0x10
	v137:i64 = Iadd module_ctx, v136
	v138:i64 = AtomicLoad_64, v137
	v139:i32 = Icmp lt_u, v138, v133
	ExitIfTrue v139, exec_ctx, memory_out_of_bounds
	Jump blk14, v138

blk14: (v135:i64) <-- (blk12,blk13)
	v140:i64 = Iadd v20, v132
	v141:i64 = Iconst_64 0x30
	v142:i64 = Iadd v140, v141
	v143:i64 = Iconst_64 0x7
	v144:i64 = Band v142, v143
	v145:i64 = Iconst_64 0x0
	v146:i32 = Icmp neq, v144, v145
	ExitIfTrue v146, exec_ctx, unaligned_atomic
	v147:i64 = AtomicRmw xchg_64, v142, v125
	Jump blk_ret, v22, v41, v61, v78, v100, v123, v147
`,
		},
		{
			name:     "AtomicStoreLoad",
			m:        testcases.AtomicStoreLoad.Module,
			features: api.CoreFeaturesV2 | experimental.CoreFeaturesThreads,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32, v4:i32, v5:i64, v6:i64, v7:i64, v8:i64)
	v9:i32 = Iconst_32 0x0
	v10:i64 = Iconst_64 0x1
	v11:i64 = UExtend v9, 32->64
	v12:i64 = Load module_ctx, 0x10
	v13:i64 = Iadd v11, v10
	v14:i32 = Icmp lt_u, v12, v13
	Brnz v14, blk1
	Jump blk2, v12

blk1: () <-- (blk0)
	v16:i64 = Iconst_64 0x10
	v17:i64 = Iadd module_ctx, v16
	v18:i64 = AtomicLoad_64, v17
	v19:i32 = Icmp lt_u, v18, v13
	ExitIfTrue v19, exec_ctx, memory_out_of_bounds
	Jump blk2, v18

blk2: (v15:i64) <-- (blk0,blk1)
	v20:i64 = Load module_ctx, 0x8
	v21:i64 = Iadd v20, v11
	AtomicStore_8, v21, v2
	v22:i32 = Iconst_32 0x0
	v23:i64 = Iconst_64 0x1
	v24:i64 = UExtend v22, 32->64
	v25:i64 = Iadd v24, v23
	v26:i32 = Icmp lt_u, v15, v25
	Brnz v26, blk3
	Jump blk4, v15, v36, v75, v116, v151, v196, v243

blk3: () <-- (blk2)
	v28:i64 = Iconst_64 0x10
	v29:i64 = Iadd module_ctx, v28
	v30:i64 = AtomicLoad_64, v29
	v31:i32 = Icmp lt_u, v30, v25
	ExitIfTrue v31, exec_ctx, memory_out_of_bounds
	Jump blk4, v30, v36, v75, v116, v151, v196, v243

blk4: (v27:i64,v35:i32,v74:i32,v115:i64,v150:i64,v195:i64,v242:i64) <-- (blk2,blk3)
	v32:i64 = Iadd v20, v24
	v33:i32 = AtomicLoad_8, v32
	v34:i32 = Iconst_32 0x0
	v37:i64 = Iconst_64 0xa
	v38:i64 = UExtend v34, 32->64
	v39:i64 = Iadd v38, v37
	v40:i32 = Icmp lt_u, v27, v39
	Brnz v40, blk5
	Jump blk6, v27

blk5: () <-- (blk4)
	v42:i64 = Iconst_64 0x10
	v43:i64 = Iadd module_ctx, v42
	v44:i64 = AtomicLoad_64, v43
	v45:i32 = Icmp lt_u, v44, v39
	ExitIfTrue v45, exec_ctx, memory_out_of_bounds
	Jump blk6, v44

blk6: (v41:i64) <-- (blk4,blk5)
	v46:i64 = Iadd v20, v38
	v47:i64 = Iconst_64 0x8
	v48:i64 = Iadd v46, v47
	v49:i64 = Iconst_64 0x1
	v50:i64 = Band v48, v49
	v51:i64 = Iconst_64 0x0
	v52:i32 = Icmp neq, v50, v51
	ExitIfTrue v52, exec_ctx, unaligned_atomic
	AtomicStore_16, v48, v35
	v53:i32 = Iconst_32 0x0
	v54:i64 = Iconst_64 0xa
	v55:i64 = UExtend v53, 32->64
	v56:i64 = Iadd v55, v54
	v57:i32 = Icmp lt_u, v41, v56
	Brnz v57, blk7
	Jump blk8, v41, v73, v114, v149, v194, v241

blk7: () <-- (blk6)
	v59:i64 = Iconst_64 0x10
	v60:i64 = Iadd module_ctx, v59
	v61:i64 = AtomicLoad_64, v60
	v62:i32 = Icmp lt_u, v61, v56
	ExitIfTrue v62, exec_ctx, memory_out_of_bounds
	Jump blk8, v61, v73, v114, v149, v194, v241

blk8: (v58:i64,v72:i32,v113:i64,v148:i64,v193:i64,v240:i64) <-- (blk6,blk7)
	v63:i64 = Iadd v20, v55
	v64:i64 = Iconst_64 0x8
	v65:i64 = Iadd v63, v64
	v66:i64 = Iconst_64 0x1
	v67:i64 = Band v65, v66
	v68:i64 = Iconst_64 0x0
	v69:i32 = Icmp neq, v67, v68
	ExitIfTrue v69, exec_ctx, unaligned_atomic
	v70:i32 = AtomicLoad_16, v65
	v71:i32 = Iconst_32 0x0
	v76:i64 = Iconst_64 0x14
	v77:i64 = UExtend v71, 32->64
	v78:i64 = Iadd v77, v76
	v79:i32 = Icmp lt_u, v58, v78
	Brnz v79, blk9
	Jump blk10, v58

blk9: () <-- (blk8)
	v81:i64 = Iconst_64 0x10
	v82:i64 = Iadd module_ctx, v81
	v83:i64 = AtomicLoad_64, v82
	v84:i32 = Icmp lt_u, v83, v78
	ExitIfTrue v84, exec_ctx, memory_out_of_bounds
	Jump blk10, v83

blk10: (v80:i64) <-- (blk8,blk9)
	v85:i64 = Iadd v20, v77
	v86:i64 = Iconst_64 0x10
	v87:i64 = Iadd v85, v86
	v88:i64 = Iconst_64 0x3
	v89:i64 = Band v87, v88
	v90:i64 = Iconst_64 0x0
	v91:i32 = Icmp neq, v89, v90
	ExitIfTrue v91, exec_ctx, unaligned_atomic
	AtomicStore_32, v87, v72
	v92:i32 = Iconst_32 0x0
	v93:i64 = Iconst_64 0x14
	v94:i64 = UExtend v92, 32->64
	v95:i64 = Iadd v94, v93
	v96:i32 = Icmp lt_u, v80, v95
	Brnz v96, blk11
	Jump blk12, v80, v112, v147, v192, v239

blk11: () <-- (blk10)
	v98:i64 = Iconst_64 0x10
	v99:i64 = Iadd module_ctx, v98
	v100:i64 = AtomicLoad_64, v99
	v101:i32 = Icmp lt_u, v100, v95
	ExitIfTrue v101, exec_ctx, memory_out_of_bounds
	Jump blk12, v100, v112, v147, v192, v239

blk12: (v97:i64,v111:i64,v146:i64,v191:i64,v238:i64) <-- (blk10,blk11)
	v102:i64 = Iadd v20, v94
	v103:i64 = Iconst_64 0x10
	v104:i64 = Iadd v102, v103
	v105:i64 = Iconst_64 0x3
	v106:i64 = Band v104, v105
	v107:i64 = Iconst_64 0x0
	v108:i32 = Icmp neq, v106, v107
	ExitIfTrue v108, exec_ctx, unaligned_atomic
	v109:i32 = AtomicLoad_32, v104
	v110:i32 = Iconst_32 0x0
	v117:i64 = Iconst_64 0x19
	v118:i64 = UExtend v110, 32->64
	v119:i64 = Iadd v118, v117
	v120:i32 = Icmp lt_u, v97, v119
	Brnz v120, blk13
	Jump blk14, v97

blk13: () <-- (blk12)
	v122:i64 = Iconst_64 0x10
	v123:i64 = Iadd module_ctx, v122
	v124:i64 = AtomicLoad_64, v123
	v125:i32 = Icmp lt_u, v124, v119
	ExitIfTrue v125, exec_ctx, memory_out_of_bounds
	Jump blk14, v124

blk14: (v121:i64) <-- (blk12,blk13)
	v126:i64 = Iadd v20, v118
	v127:i64 = Iconst_64 0x18
	v128:i64 = Iadd v126, v127
	AtomicStore_8, v128, v111
	v129:i32 = Iconst_32 0x0
	v130:i64 = Iconst_64 0x19
	v131:i64 = UExtend v129, 32->64
	v132:i64 = Iadd v131, v130
	v133:i32 = Icmp lt_u, v121, v132
	Brnz v133, blk15
	Jump blk16, v121, v145, v190, v237

blk15: () <-- (blk14)
	v135:i64 = Iconst_64 0x10
	v136:i64 = Iadd module_ctx, v135
	v137:i64 = AtomicLoad_64, v136
	v138:i32 = Icmp lt_u, v137, v132
	ExitIfTrue v138, exec_ctx, memory_out_of_bounds
	Jump blk16, v137, v145, v190, v237

blk16: (v134:i64,v144:i64,v189:i64,v236:i64) <-- (blk14,blk15)
	v139:i64 = Iadd v20, v131
	v140:i64 = Iconst_64 0x18
	v141:i64 = Iadd v139, v140
	v142:i64 = AtomicLoad_8, v141
	v143:i32 = Iconst_32 0x0
	v152:i64 = Iconst_64 0x22
	v153:i64 = UExtend v143, 32->64
	v154:i64 = Iadd v153, v152
	v155:i32 = Icmp lt_u, v134, v154
	Brnz v155, blk17
	Jump blk18, v134

blk17: () <-- (blk16)
	v157:i64 = Iconst_64 0x10
	v158:i64 = Iadd module_ctx, v157
	v159:i64 = AtomicLoad_64, v158
	v160:i32 = Icmp lt_u, v159, v154
	ExitIfTrue v160, exec_ctx, memory_out_of_bounds
	Jump blk18, v159

blk18: (v156:i64) <-- (blk16,blk17)
	v161:i64 = Iadd v20, v153
	v162:i64 = Iconst_64 0x20
	v163:i64 = Iadd v161, v162
	v164:i64 = Iconst_64 0x1
	v165:i64 = Band v163, v164
	v166:i64 = Iconst_64 0x0
	v167:i32 = Icmp neq, v165, v166
	ExitIfTrue v167, exec_ctx, unaligned_atomic
	AtomicStore_16, v163, v144
	v168:i32 = Iconst_32 0x0
	v169:i64 = Iconst_64 0x22
	v170:i64 = UExtend v168, 32->64
	v171:i64 = Iadd v170, v169
	v172:i32 = Icmp lt_u, v156, v171
	Brnz v172, blk19
	Jump blk20, v156, v188, v235

blk19: () <-- (blk18)
	v174:i64 = Iconst_64 0x10
	v175:i64 = Iadd module_ctx, v174
	v176:i64 = AtomicLoad_64, v175
	v177:i32 = Icmp lt_u, v176, v171
	ExitIfTrue v177, exec_ctx, memory_out_of_bounds
	Jump blk20, v176, v188, v235

blk20: (v173:i64,v187:i64,v234:i64) <-- (blk18,blk19)
	v178:i64 = Iadd v20, v170
	v179:i64 = Iconst_64 0x20
	v180:i64 = Iadd v178, v179
	v181:i64 = Iconst_64 0x1
	v182:i64 = Band v180, v181
	v183:i64 = Iconst_64 0x0
	v184:i32 = Icmp neq, v182, v183
	ExitIfTrue v184, exec_ctx, unaligned_atomic
	v185:i64 = AtomicLoad_16, v180
	v186:i32 = Iconst_32 0x0
	v197:i64 = Iconst_64 0x2c
	v198:i64 = UExtend v186, 32->64
	v199:i64 = Iadd v198, v197
	v200:i32 = Icmp lt_u, v173, v199
	Brnz v200, blk21
	Jump blk22, v173

blk21: () <-- (blk20)
	v202:i64 = Iconst_64 0x10
	v203:i64 = Iadd module_ctx, v202
	v204:i64 = AtomicLoad_64, v203
	v205:i32 = Icmp lt_u, v204, v199
	ExitIfTrue v205, exec_ctx, memory_out_of_bounds
	Jump blk22, v204

blk22: (v201:i64) <-- (blk20,blk21)
	v206:i64 = Iadd v20, v198
	v207:i64 = Iconst_64 0x28
	v208:i64 = Iadd v206, v207
	v209:i64 = Iconst_64 0x3
	v210:i64 = Band v208, v209
	v211:i64 = Iconst_64 0x0
	v212:i32 = Icmp neq, v210, v211
	ExitIfTrue v212, exec_ctx, unaligned_atomic
	AtomicStore_32, v208, v187
	v213:i32 = Iconst_32 0x0
	v214:i64 = Iconst_64 0x2c
	v215:i64 = UExtend v213, 32->64
	v216:i64 = Iadd v215, v214
	v217:i32 = Icmp lt_u, v201, v216
	Brnz v217, blk23
	Jump blk24, v201, v233

blk23: () <-- (blk22)
	v219:i64 = Iconst_64 0x10
	v220:i64 = Iadd module_ctx, v219
	v221:i64 = AtomicLoad_64, v220
	v222:i32 = Icmp lt_u, v221, v216
	ExitIfTrue v222, exec_ctx, memory_out_of_bounds
	Jump blk24, v221, v233

blk24: (v218:i64,v232:i64) <-- (blk22,blk23)
	v223:i64 = Iadd v20, v215
	v224:i64 = Iconst_64 0x28
	v225:i64 = Iadd v223, v224
	v226:i64 = Iconst_64 0x3
	v227:i64 = Band v225, v226
	v228:i64 = Iconst_64 0x0
	v229:i32 = Icmp neq, v227, v228
	ExitIfTrue v229, exec_ctx, unaligned_atomic
	v230:i64 = AtomicLoad_32, v225
	v231:i32 = Iconst_32 0x0
	v244:i64 = Iconst_64 0x38
	v245:i64 = UExtend v231, 32->64
	v246:i64 = Iadd v245, v244
	v247:i32 = Icmp lt_u, v218, v246
	Brnz v247, blk25
	Jump blk26, v218

blk25: () <-- (blk24)
	v249:i64 = Iconst_64 0x10
	v250:i64 = Iadd module_ctx, v249
	v251:i64 = AtomicLoad_64, v250
	v252:i32 = Icmp lt_u, v251, v246
	ExitIfTrue v252, exec_ctx, memory_out_of_bounds
	Jump blk26, v251

blk26: (v248:i64) <-- (blk24,blk25)
	v253:i64 = Iadd v20, v245
	v254:i64 = Iconst_64 0x30
	v255:i64 = Iadd v253, v254
	v256:i64 = Iconst_64 0x7
	v257:i64 = Band v255, v256
	v258:i64 = Iconst_64 0x0
	v259:i32 = Icmp neq, v257, v258
	ExitIfTrue v259, exec_ctx, unaligned_atomic
	AtomicStore_64, v255, v232
	v260:i32 = Iconst_32 0x0
	v261:i64 = Iconst_64 0x38
	v262:i64 = UExtend v260, 32->64
	v263:i64 = Iadd v262, v261
	v264:i32 = Icmp lt_u, v248, v263
	Brnz v264, blk27
	Jump blk28, v248

blk27: () <-- (blk26)
	v266:i64 = Iconst_64 0x10
	v267:i64 = Iadd module_ctx, v266
	v268:i64 = AtomicLoad_64, v267
	v269:i32 = Icmp lt_u, v268, v263
	ExitIfTrue v269, exec_ctx, memory_out_of_bounds
	Jump blk28, v268

blk28: (v265:i64) <-- (blk26,blk27)
	v270:i64 = Iadd v20, v262
	v271:i64 = Iconst_64 0x30
	v272:i64 = Iadd v270, v271
	v273:i64 = Iconst_64 0x7
	v274:i64 = Band v272, v273
	v275:i64 = Iconst_64 0x0
	v276:i32 = Icmp neq, v274, v275
	ExitIfTrue v276, exec_ctx, unaligned_atomic
	v277:i64 = AtomicLoad_64, v272
	Jump blk_ret, v33, v70, v109, v142, v185, v230, v277
`,
		},
		{
			name:     "AtomicCas",
			m:        testcases.AtomicCas.Module,
			features: api.CoreFeaturesV2 | experimental.CoreFeaturesThreads,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32, v3:i32, v4:i32, v5:i32, v6:i32, v7:i32, v8:i64, v9:i64, v10:i64, v11:i64, v12:i64, v13:i64, v14:i64, v15:i64)
	v16:i32 = Iconst_32 0x0
	v17:i64 = Iconst_64 0x1
	v18:i64 = UExtend v16, 32->64
	v19:i64 = Load module_ctx, 0x10
	v20:i64 = Iadd v18, v17
	v21:i32 = Icmp lt_u, v19, v20
	Brnz v21, blk1
	Jump blk2, v19

blk1: () <-- (blk0)
	v23:i64 = Iconst_64 0x10
	v24:i64 = Iadd module_ctx, v23
	v25:i64 = AtomicLoad_64, v24
	v26:i32 = Icmp lt_u, v25, v20
	ExitIfTrue v26, exec_ctx, memory_out_of_bounds
	Jump blk2, v25

blk2: (v22:i64) <-- (blk0,blk1)
	v27:i64 = Load module_ctx, 0x8
	v28:i64 = Iadd v27, v18
	v29:i32 = AtomicCas_8, v28, v2, v3
	v30:i32 = Iconst_32 0x0
	v33:i64 = Iconst_64 0xa
	v34:i64 = UExtend v30, 32->64
	v35:i64 = Iadd v34, v33
	v36:i32 = Icmp lt_u, v22, v35
	Brnz v36, blk3
	Jump blk4, v22, v52, v54, v75, v78, v96, v100, v123, v128, v152, v158

blk3: () <-- (blk2)
	v38:i64 = Iconst_64 0x10
	v39:i64 = Iadd module_ctx, v38
	v40:i64 = AtomicLoad_64, v39
	v41:i32 = Icmp lt_u, v40, v35
	ExitIfTrue v41, exec_ctx, memory_out_of_bounds
	Jump blk4, v40, v52, v54, v75, v78, v96, v100, v123, v128, v152, v158

blk4: (v37:i64,v51:i32,v53:i32,v74:i64,v77:i64,v95:i64,v99:i64,v122:i64,v127:i64,v151:i64,v157:i64) <-- (blk2,blk3)
	v42:i64 = Iadd v27, v34
	v43:i64 = Iconst_64 0x8
	v44:i64 = Iadd v42, v43
	v45:i64 = Iconst_64 0x1
	v46:i64 = Band v44, v45
	v47:i64 = Iconst_64 0x0
	v48:i32 = Icmp neq, v46, v47
	ExitIfTrue v48, exec_ctx, unaligned_atomic
	v49:i32 = AtomicCas_16, v44, v4, v5
	v50:i32 = Iconst_32 0x0
	v55:i64 = Iconst_64 0x14
	v56:i64 = UExtend v50, 32->64
	v57:i64 = Iadd v56, v55
	v58:i32 = Icmp lt_u, v37, v57
	Brnz v58, blk5
	Jump blk6, v37

blk5: () <-- (blk4)
	v60:i64 = Iconst_64 0x10
	v61:i64 = Iadd module_ctx, v60
	v62:i64 = AtomicLoad_64, v61
	v63:i32 = Icmp lt_u, v62, v57
	ExitIfTrue v63, exec_ctx, memory_out_of_bounds
	Jump blk6, v62

blk6: (v59:i64) <-- (blk4,blk5)
	v64:i64 = Iadd v27, v56
	v65:i64 = Iconst_64 0x10
	v66:i64 = Iadd v64, v65
	v67:i64 = Iconst_64 0x3
	v68:i64 = Band v66, v67
	v69:i64 = Iconst_64 0x0
	v70:i32 = Icmp neq, v68, v69
	ExitIfTrue v70, exec_ctx, unaligned_atomic
	v71:i32 = AtomicCas_32, v66, v51, v53
	v72:i32 = Iconst_32 0x0
	v79:i64 = Iconst_64 0x19
	v80:i64 = UExtend v72, 32->64
	v81:i64 = Iadd v80, v79
	v82:i32 = Icmp lt_u, v59, v81
	Brnz v82, blk7
	Jump blk8, v59, v94, v98, v121, v126, v150, v156

blk7: () <-- (blk6)
	v84:i64 = Iconst_64 0x10
	v85:i64 = Iadd module_ctx, v84
	v86:i64 = AtomicLoad_64, v85
	v87:i32 = Icmp lt_u, v86, v81
	ExitIfTrue v87, exec_ctx, memory_out_of_bounds
	Jump blk8, v86, v94, v98, v121, v126, v150, v156

blk8: (v83:i64,v93:i64,v97:i64,v120:i64,v125:i64,v149:i64,v155:i64) <-- (blk6,blk7)
	v88:i64 = Iadd v27, v80
	v89:i64 = Iconst_64 0x18
	v90:i64 = Iadd v88, v89
	v91:i64 = AtomicCas_8, v90, v74, v77
	v92:i32 = Iconst_32 0x0
	v101:i64 = Iconst_64 0x22
	v102:i64 = UExtend v92, 32->64
	v103:i64 = Iadd v102, v101
	v104:i32 = Icmp lt_u, v83, v103
	Brnz v104, blk9
	Jump blk10, v83

blk9: () <-- (blk8)
	v106:i64 = Iconst_64 0x10
	v107:i64 = Iadd module_ctx, v106
	v108:i64 = AtomicLoad_64, v107
	v109:i32 = Icmp lt_u, v108, v103
	ExitIfTrue v109, exec_ctx, memory_out_of_bounds
	Jump blk10, v108

blk10: (v105:i64) <-- (blk8,blk9)
	v110:i64 = Iadd v27, v102
	v111:i64 = Iconst_64 0x20
	v112:i64 = Iadd v110, v111
	v113:i64 = Iconst_64 0x1
	v114:i64 = Band v112, v113
	v115:i64 = Iconst_64 0x0
	v116:i32 = Icmp neq, v114, v115
	ExitIfTrue v116, exec_ctx, unaligned_atomic
	v117:i64 = AtomicCas_16, v112, v93, v97
	v118:i32 = Iconst_32 0x0
	v129:i64 = Iconst_64 0x2c
	v130:i64 = UExtend v118, 32->64
	v131:i64 = Iadd v130, v129
	v132:i32 = Icmp lt_u, v105, v131
	Brnz v132, blk11
	Jump blk12, v105, v148, v154

blk11: () <-- (blk10)
	v134:i64 = Iconst_64 0x10
	v135:i64 = Iadd module_ctx, v134
	v136:i64 = AtomicLoad_64, v135
	v137:i32 = Icmp lt_u, v136, v131
	ExitIfTrue v137, exec_ctx, memory_out_of_bounds
	Jump blk12, v136, v148, v154

blk12: (v133:i64,v147:i64,v153:i64) <-- (blk10,blk11)
	v138:i64 = Iadd v27, v130
	v139:i64 = Iconst_64 0x28
	v140:i64 = Iadd v138, v139
	v141:i64 = Iconst_64 0x3
	v142:i64 = Band v140, v141
	v143:i64 = Iconst_64 0x0
	v144:i32 = Icmp neq, v142, v143
	ExitIfTrue v144, exec_ctx, unaligned_atomic
	v145:i64 = AtomicCas_32, v140, v120, v125
	v146:i32 = Iconst_32 0x0
	v159:i64 = Iconst_64 0x38
	v160:i64 = UExtend v146, 32->64
	v161:i64 = Iadd v160, v159
	v162:i32 = Icmp lt_u, v133, v161
	Brnz v162, blk13
	Jump blk14, v133

blk13: () <-- (blk12)
	v164:i64 = Iconst_64 0x10
	v165:i64 = Iadd module_ctx, v164
	v166:i64 = AtomicLoad_64, v165
	v167:i32 = Icmp lt_u, v166, v161
	ExitIfTrue v167, exec_ctx, memory_out_of_bounds
	Jump blk14, v166

blk14: (v163:i64) <-- (blk12,blk13)
	v168:i64 = Iadd v27, v160
	v169:i64 = Iconst_64 0x30
	v170:i64 = Iadd v168, v169
	v171:i64 = Iconst_64 0x7
	v172:i64 = Band v170, v171
	v173:i64 = Iconst_64 0x0
	v174:i32 = Icmp neq, v172, v173
	ExitIfTrue v174, exec_ctx, unaligned_atomic
	v175:i64 = AtomicCas_64, v170, v147, v153
	Jump blk_ret, v29, v49, v71, v91, v117, v145, v175
`,
		},
		{
			name:     "AtomicFence",
			m:        testcases.AtomicFence.Module,
			features: api.CoreFeaturesV2 | experimental.CoreFeaturesThreads,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64)
	Fence 0
	Jump blk_ret
`,
		},
		{
			name:     "AtomicFenceNoMemory",
			m:        testcases.AtomicFenceNoMemory.Module,
			features: api.CoreFeaturesV2 | experimental.CoreFeaturesThreads,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64)
	Jump blk_ret
`,
		},
		{
			name: "bounds check in if-else",
			m: &wasm.Module{
				TypeSection:     []wasm.FunctionType{{Params: []wasm.ValueType{wasm.ValueTypeI32}}},
				FunctionSection: []wasm.Index{0},
				CodeSection: []wasm.Code{{
					Body: []byte{
						wasm.OpcodeLocalGet, 0,
						wasm.OpcodeI32Load, 0x2, 0x20, // alignment=2 (natural alignment) staticOffset=0x20
						wasm.OpcodeDrop,

						wasm.OpcodeLocalGet, 0,
						wasm.OpcodeIf, 0x40, // blockSignature:vv.
						/* */ wasm.OpcodeLocalGet, 0,
						/* */ // This bound check should be removed since it's known to be in bounds.
						/* */ wasm.OpcodeI32Load, 0x2, 0x10, // alignment=2 (natural alignment) staticOffset=0x20
						/* */ wasm.OpcodeDrop,
						wasm.OpcodeElse,
						/* */ wasm.OpcodeLocalGet, 0,
						/* */ // This bound check should be removed since it's known to be in bounds.
						/* */ wasm.OpcodeI32Load, 0x2, 0x10, // alignment=2 (natural alignment) staticOffset=0x20
						/* */ wasm.OpcodeDrop,
						/* */ // This shouldn't be removed since it's not known to be in bounds.
						/* */ wasm.OpcodeLocalGet, 0,
						/* */ wasm.OpcodeI32Load, 0x2, 0x30, // alignment=2 (natural alignment) staticOffset=0x20
						/* */ wasm.OpcodeDrop,
						/* */ // But this is known to be in bounds.
						/* */ wasm.OpcodeLocalGet, 0,
						/* */ wasm.OpcodeI32Load, 0x2, 0x25, // alignment=2 (natural alignment) staticOffset=0x20
						/* */ wasm.OpcodeDrop,
						wasm.OpcodeEnd,

						// At this point, the known bound 0x20 should be retained.
						wasm.OpcodeLocalGet, 0,
						wasm.OpcodeI32Load, 0x2, 0x15, // alignment=2 (natural alignment) staticOffset=0x20
						wasm.OpcodeDrop,

						wasm.OpcodeEnd,
					},
				}},
				MemorySection: &wasm.Memory{Min: 1},
			},
			features: api.CoreFeaturesV2,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32)
	v3:i64 = Iconst_64 0x24
	v4:i64 = UExtend v2, 32->64
	v5:i64 = Uload32 module_ctx, 0x10
	v6:i64 = Iadd v4, v3
	v7:i32 = Icmp lt_u, v5, v6
	ExitIfTrue v7, exec_ctx, memory_out_of_bounds
	v8:i64 = Load module_ctx, 0x8
	v9:i64 = Iadd v8, v4
	v10:i32 = Load v9, 0x20
	Brz v2, blk2
	Jump blk1

blk1: () <-- (blk0)
	v11:i32 = Load v9, 0x10
	Jump blk3

blk2: () <-- (blk0)
	v12:i32 = Load v9, 0x10
	v13:i64 = Iconst_64 0x34
	v14:i64 = UExtend v2, 32->64
	v15:i64 = Iadd v14, v13
	v16:i32 = Icmp lt_u, v5, v15
	ExitIfTrue v16, exec_ctx, memory_out_of_bounds
	v17:i32 = Load v9, 0x30
	v18:i32 = Load v9, 0x25
	Jump blk3

blk3: () <-- (blk1,blk2)
	v20:i64 = Load module_ctx, 0x8
	v21:i64 = UExtend v2, 32->64
	v22:i64 = Iadd v20, v21
	v23:i32 = Load v22, 0x15
	Jump blk_ret
`,
		},
		{
			name: "bounds check in loop with if-else",
			m: &wasm.Module{
				TypeSection:     []wasm.FunctionType{{Params: []wasm.ValueType{wasm.ValueTypeI32}}},
				FunctionSection: []wasm.Index{0},
				CodeSection: []wasm.Code{{
					Body: []byte{
						wasm.OpcodeLocalGet, 0,
						wasm.OpcodeI32Load, 0x2, 0x10, // staticOffset=0x20
						wasm.OpcodeDrop,

						wasm.OpcodeLoop, 0x40, // blockSignature:vv.

						/* */ wasm.OpcodeLocalGet, 0,
						// This address must be always recomputed:
						// v9 in `Load v9, 0x20` won't propagate from blk0 to blk1,
						/* */ wasm.OpcodeI32Load, 0x2, 0x20, // staticOffset=0x30

						/* */ wasm.OpcodeIf, 0x40, // blockSignature:vv.
						/* */ /* */ wasm.OpcodeLoop, 0x40, // blockSignature:vv.
						/* */ /* */ /* */ wasm.OpcodeLocalGet, 0,
						/* */ /* */ /* */ wasm.OpcodeI32Load, 0x2, 0x50, // staticOffset=0x50
						/* */ /* */ /* */ wasm.OpcodeBrIf, 2, // quit to the inner loop
						/* */ /* */ wasm.OpcodeEnd,
						/* */ wasm.OpcodeElse,
						/* */ /* */ wasm.OpcodeLocalGet, 0,
						/* */ /* */ wasm.OpcodeBrIf, 2, // quit to the outer loop
						/* */ wasm.OpcodeEnd,
						/* */ wasm.OpcodeBr, 1, // quit to the loop

						wasm.OpcodeEnd, // end loop

						wasm.OpcodeEnd,
					},
				}},
				MemorySection: &wasm.Memory{Min: 1},
			},
			features: api.CoreFeaturesV2,
			exp: `
blk0: (exec_ctx:i64, module_ctx:i64, v2:i32)
	v3:i64 = Iconst_64 0x14
	v4:i64 = UExtend v2, 32->64
	v5:i64 = Uload32 module_ctx, 0x10
	v6:i64 = Iadd v4, v3
	v7:i32 = Icmp lt_u, v5, v6
	ExitIfTrue v7, exec_ctx, memory_out_of_bounds
	v8:i64 = Load module_ctx, 0x8
	v9:i64 = Iadd v8, v4
	v10:i32 = Load v9, 0x10
	Jump blk1, v2

blk1: (v11:i32) <-- (blk0,blk6)
	v12:i64 = Iconst_64 0x24
	v13:i64 = UExtend v11, 32->64
	v14:i64 = Uload32 module_ctx, 0x10
	v15:i64 = Iadd v13, v12
	v16:i32 = Icmp lt_u, v14, v15
	ExitIfTrue v16, exec_ctx, memory_out_of_bounds
	v17:i64 = Load module_ctx, 0x8
	v18:i64 = Iadd v17, v13
	v19:i32 = Load v18, 0x20
	Brz v19, blk4
	Jump blk3

blk2: ()

blk3: () <-- (blk1)
	Jump blk6, v11

blk4: () <-- (blk1)
	Brnz v11, blk_ret
	Jump blk9

blk5: () <-- (blk7,blk9)
	Jump blk_ret

blk6: (v20:i32) <-- (blk3)
	v21:i64 = Iconst_64 0x54
	v22:i64 = UExtend v20, 32->64
	v23:i64 = Uload32 module_ctx, 0x10
	v24:i64 = Iadd v22, v21
	v25:i32 = Icmp lt_u, v23, v24
	ExitIfTrue v25, exec_ctx, memory_out_of_bounds
	v26:i64 = Load module_ctx, 0x8
	v27:i64 = Iadd v26, v22
	v28:i32 = Load v27, 0x50
	Brnz v28, blk1, v20
	Jump blk8

blk7: () <-- (blk8)
	Jump blk5

blk8: () <-- (blk6)
	Jump blk7

blk9: () <-- (blk4)
	Jump blk5
`,
		},
	} {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Just in case let's check the test module is valid.
			features := tc.features
			if features == 0 {
				features = api.CoreFeaturesV2
			}
			err := tc.m.Validate(features)
			require.NoError(t, err, "invalid test case module!")

			b := ssa.NewBuilder()

			offset := wazevoapi.NewModuleContextOffsetData(tc.m, tc.needListener)
			fc := NewFrontendCompiler(tc.m, b, &offset, tc.ensureTermination, tc.needListener, false).
				WithUnsafeBoundsCheckElision(tc.boundsElision)
			typeIndex := tc.m.FunctionSection[tc.targetIndex]
			code := &tc.m.CodeSection[tc.targetIndex]
			fc.Init(tc.targetIndex, typeIndex, &tc.m.TypeSection[typeIndex], code.LocalTypes, code.Body, tc.needListener, 0)

			fc.LowerToSSA()

			actual := fc.formatBuilder()
			require.Equal(t, tc.exp, actual)

			b.RunPasses()
			if expAfterOpt := tc.expAfterPasses; expAfterOpt != "" {
				actualAfterOpt := fc.formatBuilder()
				require.Equal(t, expAfterOpt, actualAfterOpt)
			}
		})
	}
}

func TestSignatureForListener(t *testing.T) {
	for _, tc := range []struct {
		name          string
		sig           *wasm.FunctionType
		before, after *ssa.Signature
	}{
		{
			name:   "empty",
			sig:    &wasm.FunctionType{},
			before: &ssa.Signature{Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32}},
			after:  &ssa.Signature{Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32}},
		},
		{
			name: "multi",
			sig: &wasm.FunctionType{
				Params: []wasm.ValueType{wasm.ValueTypeF64, wasm.ValueTypeI32},
				Results: []wasm.ValueType{
					wasm.ValueTypeI64, wasm.ValueTypeI32, wasm.ValueTypeF32, wasm.ValueTypeF64, wasm.ValueTypeV128,
				},
			},
			before: &ssa.Signature{
				Params: []ssa.Type{
					ssa.TypeI64, ssa.TypeI32,
					ssa.TypeF64, ssa.TypeI32,
				},
			},
			after: &ssa.Signature{
				Params: []ssa.Type{
					ssa.TypeI64, ssa.TypeI32,
					ssa.TypeI64, ssa.TypeI32, ssa.TypeF32, ssa.TypeF64, ssa.TypeV128,
				},
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			before, after := SignatureForListener(tc.sig)
			require.Equal(t, tc.before, before)
			require.Equal(t, tc.after, after)
		})
	}
}

func TestCompiler_declareSignatures(t *testing.T) {
	m := &wasm.Module{
		TypeSection: []wasm.FunctionType{
			{},
			{Params: []wasm.ValueType{wasm.ValueTypeI64, wasm.ValueTypeI32}},
			{Params: []wasm.ValueType{wasm.ValueTypeF64, wasm.ValueTypeI32}},
			{Results: []wasm.ValueType{wasm.ValueTypeI64, wasm.ValueTypeI32}},
		},
	}

	t.Run("listener=false", func(t *testing.T) {
		builder := ssa.NewBuilder()
		c := &Compiler{m: m, ssaBuilder: builder}
		c.declareSignatures(false)

		declaredSigs := builder.Signatures()
		expected := []*ssa.Signature{
			{ID: 0, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64}},
			{ID: 1, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64, ssa.TypeI64, ssa.TypeI32}},
			{ID: 2, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64, ssa.TypeF64, ssa.TypeI32}},
			{ID: 3, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64}, Results: []ssa.Type{ssa.TypeI64, ssa.TypeI32}},
			{ID: 4, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}},
			{ID: 5, Params: []ssa.Type{ssa.TypeI64}},
			{ID: 6, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32, ssa.TypeI32, ssa.TypeI64}, Results: []ssa.Type{ssa.TypeI32}},
			{ID: 7, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI64}},
			{ID: 8, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64, ssa.TypeI64}},
			{ID: 9, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64, ssa.TypeI32, ssa.TypeI64}, Results: []ssa.Type{ssa.TypeI32}},
			{ID: 10, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64, ssa.TypeI64, ssa.TypeI64}, Results: []ssa.Type{ssa.TypeI32}},
			{ID: 11, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32, ssa.TypeI64}, Results: []ssa.Type{ssa.TypeI32}},
			// EH signatures.
			{ID: 12, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64}, Results: []ssa.Type{ssa.TypeI64}},
			{ID: 13, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64}},
			{ID: 14, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64}},
			{ID: 15, Params: []ssa.Type{ssa.TypeI64}},
		}

		require.Equal(t, len(expected), len(declaredSigs))
		for i := 0; i < len(expected); i++ {
			require.Equal(t, expected[i].String(), declaredSigs[i].String(), i)
		}
	})

	t.Run("listener=false", func(t *testing.T) {
		builder := ssa.NewBuilder()
		c := &Compiler{m: m, ssaBuilder: builder}
		c.declareSignatures(true)

		declaredSigs := builder.Signatures()

		expected := []*ssa.Signature{
			{ID: 0, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64}},
			{ID: 1, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64, ssa.TypeI64, ssa.TypeI32}},
			{ID: 2, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64, ssa.TypeF64, ssa.TypeI32}},
			{ID: 3, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64}, Results: []ssa.Type{ssa.TypeI64, ssa.TypeI32}},
			// Before.
			{ID: 4, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32}},
			{ID: 5, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32, ssa.TypeI64, ssa.TypeI32}},
			{ID: 6, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32, ssa.TypeF64, ssa.TypeI32}},
			{ID: 7, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32}},
			// After.
			{ID: 8, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32}},
			{ID: 9, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32}},
			{ID: 10, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32}},
			{ID: 11, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32, ssa.TypeI64, ssa.TypeI32}},
			// Misc.
			{ID: 12, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}},
			{ID: 13, Params: []ssa.Type{ssa.TypeI64}},
			{ID: 14, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32, ssa.TypeI32, ssa.TypeI64}, Results: []ssa.Type{ssa.TypeI32}},
			{ID: 15, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI64}},
			{ID: 16, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64, ssa.TypeI64}},
			{ID: 17, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64, ssa.TypeI32, ssa.TypeI64}, Results: []ssa.Type{ssa.TypeI32}},
			{ID: 18, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64, ssa.TypeI64, ssa.TypeI64}, Results: []ssa.Type{ssa.TypeI32}},
			{ID: 19, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32, ssa.TypeI64}, Results: []ssa.Type{ssa.TypeI32}},
			// EH signatures.
			{ID: 20, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64}, Results: []ssa.Type{ssa.TypeI64}},
			{ID: 21, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64}},
			{ID: 22, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64}},
			{ID: 23, Params: []ssa.Type{ssa.TypeI64}},
		}
		require.Equal(t, len(expected), len(declaredSigs))
		for i := 0; i < len(declaredSigs); i++ {
			require.Equal(t, expected[i].String(), declaredSigs[i].String(), i)
		}
	})
}

func TestCompiler_recordKnownSafeBound(t *testing.T) {
	c := &Compiler{}
	c.recordKnownSafeBound(1, 99, 9999)
	require.Equal(t, 1, len(c.knownSafeBoundsSet))
	require.True(t, c.getKnownSafeBound(1).valid())
	require.Equal(t, uint64(99), c.getKnownSafeBound(1).bound)
	require.Equal(t, ssa.Value(9999), c.getKnownSafeBound(1).absoluteAddr)

	c.recordKnownSafeBound(1, 150, 9999)
	require.Equal(t, 1, len(c.knownSafeBoundsSet))
	require.Equal(t, uint64(150), c.getKnownSafeBound(1).bound)

	c.recordKnownSafeBound(5, 666, 54321)
	require.Equal(t, 2, len(c.knownSafeBoundsSet))
	require.Equal(t, uint64(666), c.getKnownSafeBound(5).bound)
	require.Equal(t, ssa.Value(54321), c.getKnownSafeBound(5).absoluteAddr)
}

func TestCompiler_getKnownSafeBound(t *testing.T) {
	c := &Compiler{
		knownSafeBounds: []knownSafeBound{
			{}, {bound: 2134},
		},
	}
	require.Nil(t, c.getKnownSafeBound(5))
	require.Nil(t, c.getKnownSafeBound(12345))
	require.False(t, c.getKnownSafeBound(0).valid())
	require.True(t, c.getKnownSafeBound(1).valid())
}

func TestCompiler_clearSafeBounds(t *testing.T) {
	c := &Compiler{}
	c.knownSafeBounds = []knownSafeBound{{bound: 1}, {}, {bound: 2}, {}, {}, {bound: 3}}
	c.knownSafeBoundsSet = []ssa.ValueID{0, 2, 5}
	c.clearSafeBounds()
	require.Equal(t, 0, len(c.knownSafeBoundsSet))
	require.Equal(t, []knownSafeBound{{absoluteAddr: ssa.ValueInvalid}, {}, {absoluteAddr: ssa.ValueInvalid}, {}, {}, {absoluteAddr: ssa.ValueInvalid}}, c.knownSafeBounds)
}

func TestCompiler_resetAbsoluteAddressInSafeBounds(t *testing.T) {
	c := &Compiler{}
	c.knownSafeBounds = []knownSafeBound{
		{bound: 1, absoluteAddr: ssa.Value(1)},
		{},
		{bound: 2, absoluteAddr: ssa.Value(2)},
		{},
		{},
		{bound: 3, absoluteAddr: ssa.Value(3)},
	}
	c.knownSafeBoundsSet = []ssa.ValueID{0, 2, 5}
	c.resetAbsoluteAddressInSafeBounds()
	require.Equal(t, 3, len(c.knownSafeBoundsSet))
	require.Equal(t, []knownSafeBound{
		{bound: 1, absoluteAddr: ssa.ValueInvalid},
		{},
		{bound: 2, absoluteAddr: ssa.ValueInvalid},
		{},
		{},
		{bound: 3, absoluteAddr: ssa.ValueInvalid},
	}, c.knownSafeBounds)
}

func TestKnownSafeBound_valid(t *testing.T) {
	k := &knownSafeBound{bound: 10, absoluteAddr: 12345}
	require.True(t, k.valid())
	k.bound = 0
	require.False(t, k.valid())
}

func TestCompiler_finalizeKnownSafeBoundsAtTheEndOoBlock(t *testing.T) {
	c := NewFrontendCompiler(&wasm.Module{}, ssa.NewBuilder(), nil, false, false, false)
	blk := c.ssaBuilder.AllocateBasicBlock()
	require.True(t, len(c.getKnownSafeBoundsAtTheEndOfBlocks(blk.ID()).View()) == 0)
	c.ssaBuilder.SetCurrentBlock(blk)
	c.knownSafeBoundsSet = []ssa.ValueID{0, 2, 5}
	c.knownSafeBounds = []knownSafeBound{
		{bound: 1, absoluteAddr: ssa.Value(1)},
		{},
		{bound: 2, absoluteAddr: ssa.Value(2)},
		{},
		{},
		{bound: 3, absoluteAddr: ssa.Value(3)},
	}
	c.finalizeKnownSafeBoundsAtTheEndOfBlock(blk.ID())
	require.True(t, len(c.knownSafeBoundsSet) == 0)
	finalized := c.getKnownSafeBoundsAtTheEndOfBlocks(blk.ID())
	require.Equal(t, 3, len(finalized.View()))
}

func TestCompiler_initializeCurrentBlockKnownBounds(t *testing.T) {
	t.Run("single (sealed)", func(t *testing.T) {
		c := NewFrontendCompiler(&wasm.Module{}, ssa.NewBuilder(), nil, false, false, false)
		builder := c.ssaBuilder
		child := builder.AllocateBasicBlock()
		{
			parent := builder.AllocateBasicBlock()
			builder.SetCurrentBlock(parent)
			c.recordKnownSafeBound(1, 99, 9999)
			c.recordKnownSafeBound(2, 150, 9999)
			c.recordKnownSafeBound(5, 666, 54321)
			builder.AllocateInstruction().AsJump(ssa.ValuesNil, child).Insert(builder)
			c.finalizeKnownSafeBoundsAtTheEndOfBlock(parent.ID())
		}

		// Seal the child: the absolute addresses will be propagated.
		builder.Seal(child)
		builder.SetCurrentBlock(child)
		c.initializeCurrentBlockKnownBounds()
		kb := c.getKnownSafeBound(1)
		require.True(t, kb.valid())
		require.Equal(t, uint64(99), kb.bound)
		require.Equal(t, ssa.Value(9999), kb.absoluteAddr)
		kb = c.getKnownSafeBound(2)
		require.True(t, kb.valid())
		require.Equal(t, uint64(150), kb.bound)
		require.Equal(t, ssa.Value(9999), kb.absoluteAddr)
		kb = c.getKnownSafeBound(5)
		require.True(t, kb.valid())
		require.Equal(t, uint64(666), kb.bound)
		require.Equal(t, ssa.Value(54321), kb.absoluteAddr)
	})
	t.Run("single (unsealed)", func(t *testing.T) {
		c := NewFrontendCompiler(&wasm.Module{}, ssa.NewBuilder(), nil, false, false, false)
		builder := c.ssaBuilder
		child := builder.AllocateBasicBlock()
		{
			parent := builder.AllocateBasicBlock()
			builder.SetCurrentBlock(parent)
			c.recordKnownSafeBound(1, 99, 9999)
			c.recordKnownSafeBound(2, 150, 9999)
			c.recordKnownSafeBound(5, 666, 54321)
			builder.AllocateInstruction().AsJump(ssa.ValuesNil, child).Insert(builder)
			c.finalizeKnownSafeBoundsAtTheEndOfBlock(parent.ID())
		}

		// Do not seal the child: the absolute addresses will be recomputed.
		builder.SetCurrentBlock(child)
		c.initializeCurrentBlockKnownBounds()
		kb := c.getKnownSafeBound(1)
		require.True(t, kb.valid())
		require.Equal(t, uint64(99), kb.bound)
		require.NotEqual(t, ssa.Value(9999), kb.absoluteAddr)
		kb = c.getKnownSafeBound(2)
		require.True(t, kb.valid())
		require.Equal(t, uint64(150), kb.bound)
		require.NotEqual(t, ssa.Value(9999), kb.absoluteAddr)
		kb = c.getKnownSafeBound(5)
		require.True(t, kb.valid())
		require.Equal(t, uint64(666), kb.bound)
		require.NotEqual(t, ssa.Value(54321), kb.absoluteAddr)
	})
	t.Run("multiple predecessors", func(t *testing.T) {
		c := NewFrontendCompiler(&wasm.Module{}, ssa.NewBuilder(), nil, false, false, false)
		builder := c.ssaBuilder
		child := builder.AllocateBasicBlock()
		{
			p1 := builder.AllocateBasicBlock()
			builder.SetCurrentBlock(p1)
			c.recordKnownSafeBound(1, 99, 9999)
			c.recordKnownSafeBound(2, 150, 9999)
			c.recordKnownSafeBound(5, 666, 54321)
			c.recordKnownSafeBound(592131, 666, 54321)
			builder.AllocateInstruction().AsJump(ssa.ValuesNil, child).Insert(builder)
			c.finalizeKnownSafeBoundsAtTheEndOfBlock(p1.ID())
		}
		{
			p2 := builder.AllocateBasicBlock()
			builder.SetCurrentBlock(p2)
			c.recordKnownSafeBound(1, 100, 999419)
			c.recordKnownSafeBound(2, 4, 9991239)
			c.recordKnownSafeBound(5, 555, 54341221)
			c.recordKnownSafeBound(6, 666, 54321)
			c.recordKnownSafeBound(7, 666, 54321)
			builder.AllocateInstruction().AsJump(ssa.ValuesNil, child).Insert(builder)
			c.finalizeKnownSafeBoundsAtTheEndOfBlock(p2.ID())
		}
		{
			p3 := builder.AllocateBasicBlock()
			builder.SetCurrentBlock(p3)
			c.recordKnownSafeBound(1, 1, 999419)
			c.recordKnownSafeBound(2, 11111, 9991239)
			c.recordKnownSafeBound(5, 5551231, 54341221)
			c.recordKnownSafeBound(7, 666, 54321)
			c.recordKnownSafeBound(60, 666, 54321)
			builder.AllocateInstruction().AsJump(ssa.ValuesNil, child).Insert(builder)
			c.finalizeKnownSafeBoundsAtTheEndOfBlock(p3.ID())
		}

		builder.SetCurrentBlock(child)
		c.initializeCurrentBlockKnownBounds()
		for _, tc := range []struct {
			id    ssa.ValueID
			valid bool
			bound uint64
		}{
			{id: 0, valid: false},
			{id: 1, valid: true, bound: 1},
			{id: 2, valid: true, bound: 4},
			{id: 3, valid: false},
			{id: 4, valid: false},
			{id: 5, valid: true, bound: 555},
			{id: 6, valid: false},
			{id: 7, valid: false},
			{id: 60, valid: false},
			{id: 592131, valid: false},
		} {
			t.Run(fmt.Sprintf("id=%d", tc.id), func(t *testing.T) {
				kb := c.getKnownSafeBound(tc.id)
				require.Equal(t, tc.valid, kb.valid())
				if kb.valid() {
					require.Equal(t, tc.bound, kb.bound)
					require.Equal(t, ssa.ValueInvalid, kb.absoluteAddr)
				}
			})
		}
	})
}
