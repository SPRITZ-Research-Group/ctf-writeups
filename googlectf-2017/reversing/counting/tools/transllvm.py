#!/usr/bin/python3

import sys
import struct
import llvmlite.ir as ll
import llvmlite.binding as llvm

# VM register -> index in register array
REGS_MAP = {
	0: 0,
	1: 1,
	2: 2,
	3: 3,
	4: 4
}

# Constant zero register
ZERO_REG = 25

# Maximum number of pass-by-pointer return registers
MAX_DST_REGS = 1

class Instruction:
	# Increment r[opnd]
	# Goto n1
	OPCODE_INC  = 0
	# If r[opnd] != 0:
	# 	Decrement r[opnd]
	# 	Goto n1
	# Else:
	# 	Goto n2
	OPCODE_CDEC = 1
	# Call n1 (return registers 0...opnd-1)
	# Goto n2
	OPCODE_CALL = 2

	def __init__(self, instr_raw):
		(self.opcode, self.opnd, self.n1, self.n2) = struct.unpack('<4I', instr_raw)

def disassemble(code):
	num = struct.unpack('<I', code[:4])[0]
	disasm = []
	for i in range(num):
		instr = Instruction(code[4+i*16:4+(i+1)*16])
		if instr.n1 >= num:
			instr.n1 = -1
		if instr.n2 >= num:
			instr.n2 = -1
		disasm.append(instr)
	return disasm

# Types
t_void = ll.VoidType()
t_int = ll.IntType(64)
t_int_ptr = ll.PointerType(t_int)

# Helpers
int_const = lambda val : ll.Constant(t_int, val)

def translate_call(module, disasm, target, n_dst_regs, scratch, bldr, regs, funcs):
	translate_function(module, disasm, target, n_dst_regs, funcs)

	args = scratch[:n_dst_regs] + regs
	regs[0] = bldr.call(funcs[target], args)
	for i in range(n_dst_regs):
		regs[i+1] = bldr.load(args[i])

def translate_function(module, disasm, start, n_dst_regs, funcs):
	if start in funcs:
		return

	# int64_t sub_X([int64_t *r1], int64_t r0, ...)
	t_sub = ll.FunctionType(t_int, (t_int_ptr,)*n_dst_regs + (t_int,)*len(REGS_MAP))
	f = ll.Function(module, t_sub, name='sub_{}'.format(start))
	f.linkage = 'internal'
	bldr = ll.IRBuilder(f.append_basic_block())
	scratch = [bldr.alloca(t_int) for i in range(MAX_DST_REGS)]
	regs = list(f.args[n_dst_regs:])

	funcs[start] = f
	translate_r(module, disasm, start, n_dst_regs, scratch, bldr, regs, funcs, {})

def translate_r(module, disasm, start, n_dst_regs, scratch, bldr, regs, funcs, blocks):
	i = start
	terminate_func = True
	while i >= 0:
		if i in blocks:
			# Branch to already translated block, we're done
			bldr.branch(blocks[i]['blk'])
			for j in range(len(regs)):
				blocks[i]['phi'][j].add_incoming(regs[j], bldr.block)
			terminate_func = False
			break

		# Branch to new instruction block
		blk = bldr.append_basic_block()
		bldr.branch(blk)
		pred_blk = bldr.block
		bldr.position_at_start(blk)
		blocks[i] = { 'blk': bldr.block, 'phi': [] }
		for j in range(len(regs)):
			phi = bldr.phi(t_int)
			phi.add_incoming(regs[j], pred_blk)
			blocks[i]['phi'].append(phi)
			regs[j] = phi

		instr = disasm[i]
		if instr.opcode == instr.OPCODE_INC:
			reg_idx = REGS_MAP[instr.opnd]
			# reg += 1; goto n1;
			regs[reg_idx] = bldr.add(regs[reg_idx], int_const(1))
			i = instr.n1
		elif instr.opcode == instr.OPCODE_CDEC:
			# if (reg != 0) { reg -= 1; goto n1; }; goto n2;
			if instr.opnd != ZERO_REG:
				reg_idx = REGS_MAP[instr.opnd]
				cond_nz = bldr.icmp_unsigned('!=', regs[reg_idx], int_const(0))
				with bldr.if_then(cond_nz):
					regs_new = list(regs)
					regs_new[reg_idx] = bldr.sub(regs[reg_idx], int_const(1))
					translate_r(module, disasm, instr.n1, n_dst_regs, scratch, bldr, regs_new, funcs, blocks)
			i = instr.n2
		elif instr.opcode == instr.OPCODE_CALL:
			# r[0...opnd-1] = n1(...); goto n2;
			translate_call(module, disasm, instr.n1, instr.opnd-1, scratch, bldr, regs, funcs)
			i = instr.n2

	if terminate_func:
		# Store destination registers
		for i in range(n_dst_regs):
			bldr.store(regs[i+1], bldr.function.args[i])
		# Return regs[0]
		bldr.ret(regs[0])

	return funcs

def translate(disasm):
	module = ll.Module(name='code')

	# Create int64 entry(int64 x)
	t_entry = ll.FunctionType(t_int, (t_int,))
	f = ll.Function(module, t_entry, name='entry')
	bldr = ll.IRBuilder(f.append_basic_block())
	scratch = [bldr.alloca(t_int) for i in range(MAX_DST_REGS)]
	regs = [f.args[0]] + [int_const(0)]*(len(REGS_MAP)-1)
	funcs = {}
	# Return sub_0(x)
	translate_call(module, disasm, 0, 0, scratch, bldr, regs, funcs)
	bldr.ret(regs[0])

	return module

with open(sys.argv[1], 'rb') as f:
	code = f.read()

disasm = disassemble(code)
module = translate(disasm)

llvm.initialize()
llvm.initialize_native_target()
llvm.initialize_native_asmprinter()

llvm_module = llvm.parse_assembly(str(module))

tm = llvm.Target.from_default_triple().create_target_machine()

pmb = llvm.PassManagerBuilder()
pmb.inlining_threshold = 10000

mpm = llvm.ModulePassManager()
pmb.populate(mpm)
mpm.add_dead_arg_elimination_pass()
mpm.add_cfg_simplification_pass()
tm.add_analysis_passes(mpm)
mpm.run(llvm_module)

print(llvm_module)

with llvm.create_mcjit_compiler(llvm_module, tm) as ee:
	ee.finalize_object()
	obj = tm.emit_object(llvm_module)

with open(sys.argv[2], 'wb') as f:
	f.write(obj)
