.text
.global _STUB_ENTRY, _STUB_END, _call_addr, _orig_code, _jump_back
_STUB_ENTRY:
	stp	x0, x1, [sp, #-16]!
	stp	x2, x3, [sp, #-16]!
	stp	x4, x5, [sp, #-16]!
	stp	x6, x7, [sp, #-16]!
	stp	x8, x9, [sp, #-16]!
	stp	x10, x11, [sp, #-16]!
	stp	x12, x13, [sp, #-16]!
	stp	x14, x15, [sp, #-16]!
	stp	x16, x17, [sp, #-16]!
	stp	x18, x19, [sp, #-16]!
	stp	x20, x21, [sp, #-16]!
	stp	x22, x23, [sp, #-16]!
	stp	x24, x25, [sp, #-16]!
	stp	x26, x27, [sp, #-16]!
	stp	x28, x29, [sp, #-16]!
	# LR should be saved too, or it will be overwritten by bl*.
	stp     x29, x30, [sp, #-16]!

	# Jump to _call_addr and return.
	# variant of LDR to load PC relative data
	# Literal addressing means that the address is the value of the 64-bit
	# program counter for this instruction plus a 19-bit signed word
	# offset. For example
	# 40:	58000268 	ldr	x8, 8c <_call_addr>
	# ...
	# 000000000000008c <_call_addr>:
	# relation: 8c == 0x40 + 0x26*2
	ldr x8, _call_addr
	cbz x8, _restore
	blr x8

_restore:
	ldp	x29, x30, [SP], #16
	ldp	x28, x29, [SP], #16
	ldp	x26, x27, [SP], #16
	ldp	x24, x25, [SP], #16
	ldp	x22, x23, [SP], #16
	ldp	x20, x21, [SP], #16
	ldp	x18, x19, [SP], #16
	ldp	x16, x17, [SP], #16
	ldp	x14, x15, [SP], #16
	ldp	x12, x13, [SP], #16
	ldp	x10, x11, [SP], #16
	ldp	x8, x9, [SP], #16
	ldp	x6, x7, [SP], #16
	ldp	x4, x5, [SP], #16
	ldp	x2, x3, [SP], #16
	ldp	x0, x1, [SP], #16

_orig_code:
	.long 0

_jump_back:
	.long 0

_call_addr:
	.long 0
	.long 0

_STUB_END:
