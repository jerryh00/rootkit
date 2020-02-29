#include <linux/vmalloc.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/slab.h>

#include "hook.h"

/* Global symbol from assembly code. */
extern void _STUB_ENTRY(void);
extern void _STUB_END(void);
extern void _call_addr(void);
extern void _orig_code(void);
extern void _jump_back(void);

#define INSR_SIZE 4

enum hook_type {
	INSERT_FUNC = 0,
	REPLACE_FUNC,
	REPLACE_INSR
};

struct hook_info {
	struct list_head list;

	int hook_type;
	int *hook_addr;
	int *payload;

#define HOOK_INSR_LEN 1
	int code[HOOK_INSR_LEN];

	/*
	 * If the hooked instruction is a function entry, the original
	 * function can be called by orig_func.
	 */
	int *orig_func;

	int *exec_mem;
	unsigned long exec_mem_size;
};

LIST_HEAD(hook_infos);

static void dump_hook_info(const struct hook_info *p)
{
	int i;

	printk("Dumping hook information@%px\n", p);
	printk("hook type: %d\n", p->hook_type);
	printk("hook address: %px\n", p->hook_addr);
	printk("payload address: %px\n", p->payload);
	printk("original code:\n");
	for (i = 0; i < HOOK_INSR_LEN; i++) {
		printk("%08x\n", p->code[i]);
	}
	printk("new entry for original function: %px\n", p->orig_func);
	printk("trampoline entry: %px\n", p->exec_mem);
	printk("trampoline size: %lu\n", p->exec_mem_size);
}

void dump_hook_infos(void)
{
	struct list_head *ptr;
	struct hook_info *hi;

	printk("Dumping all hook information\n");
	list_for_each(ptr, &hook_infos) {
		hi = list_entry(ptr, struct hook_info, list);
		dump_hook_info(hi);
	}
}

static int (*aarch64_insn_patch_text_fptr)(void *addrs[], u32 insns[], int cnt);
static void * (*module_alloc_fptr)(unsigned long size);

static int lookup_kernel_name(void)
{
	aarch64_insn_patch_text_fptr = (void *)kallsyms_lookup_name("aarch64_insn_patch_text");
	if (aarch64_insn_patch_text_fptr == NULL) {
		printk(KERN_INFO "kallsyms_lookup_name failed\n");
		return -1;
	}
	printk("aarch64_insn_patch_text_fptr=%px\n", aarch64_insn_patch_text_fptr);

	module_alloc_fptr = (void *)kallsyms_lookup_name("module_alloc");
	if (module_alloc_fptr == NULL) {
		printk(KERN_INFO "kallsyms_lookup_name failed\n");
		return -1;
	}

	return 0;
}

static int bl_imm(ulong src, ulong target)
{
	int insr;

	insr = ((0x5 << 26) |
		(((target - src)/INSR_SIZE) & ((1UL<<26)-1)));

	return insr;
}

void *make_orig_func(const int *orig_func)
{
	int *exec_func_mem;
	unsigned long exec_mem_size;

	if (orig_func == NULL) {
		return NULL;
	}

#define NUM_FUNC_ENTRY_JMP_INSRS 2
	exec_mem_size = NUM_FUNC_ENTRY_JMP_INSRS * INSR_SIZE;
	exec_func_mem = module_alloc_fptr(exec_mem_size);
	if (exec_func_mem == NULL) {
		printk(KERN_INFO "module_alloc_fptr failed\n");
		return NULL;
	}
	printk("exec_func_mem: %px\n", exec_func_mem);

	exec_func_mem[0] = orig_func[0];
	exec_func_mem[1] = bl_imm((ulong)&exec_func_mem[1],
				  (ulong)&orig_func[1]);

	return exec_func_mem;
}

void unmake_orig_func(void *func)
{
	vfree(func);
}

static void init_hook_info(struct hook_info *p, int *hook_addr,
			 int *payload, int hook_type)
{
	printk("hook_addr=%px\n", hook_addr);
	if (hook_addr == NULL) {
		return;
	}
	memcpy(p->code, hook_addr, HOOK_INSR_LEN * INSR_SIZE);
	p->orig_func = make_orig_func(hook_addr);
	p->hook_addr = hook_addr;
	p->payload = payload;
	p->hook_type = hook_type;

	dump_hook_info(p);
}

static int build_stub(struct hook_info *p)
{
	int *exec_mem;
	unsigned long exec_mem_size;
	/* call_func offset within stub.o */
	int call_func_offset = (_call_addr - _STUB_ENTRY)/INSR_SIZE;
	ulong call_addr = (ulong)p->payload;

	exec_mem_size = PAGE_SIZE;
	exec_mem = module_alloc_fptr(exec_mem_size);
	if (exec_mem == NULL) {
		printk(KERN_INFO "module_alloc_fptr failed\n");
		return -1;
	}
	printk("exec_mem: %px\n", exec_mem);
	memcpy(exec_mem, _STUB_ENTRY, (_STUB_END - _STUB_ENTRY));
	printk("call_func_offset=%d\n", call_func_offset);
	exec_mem[call_func_offset+1] = (call_addr >> 32) & 0xFFFFFFFF;
	exec_mem[call_func_offset] = (call_addr) & 0xFFFFFFFF;
	printk("call_addr: %px\n", *(void **)&exec_mem[call_func_offset]);

	p->exec_mem_size = exec_mem_size;
	p->exec_mem = exec_mem;

	return 0;
}

static void build_old_function(const struct hook_info *p)
{
	int orig_code_offset = (_orig_code - _STUB_ENTRY)/INSR_SIZE;
	int jump_back_offset = (_jump_back - _STUB_ENTRY)/INSR_SIZE;
	int *exec_mem = p->exec_mem;
	ulong hook_addr = (ulong)p->hook_addr;

	printk("orig_code_offset=%d\n", orig_code_offset);
	memcpy(&exec_mem[orig_code_offset], p->code, HOOK_INSR_LEN * INSR_SIZE);
	printk("orig_code addr: %px\n", &exec_mem[orig_code_offset]);

	/* b (hook_addr + 4) */
	exec_mem[jump_back_offset] = bl_imm((ulong)&exec_mem[jump_back_offset],
					    hook_addr + 4);
	printk("exec_mem[jump_back_offset]=%08x\n", exec_mem[jump_back_offset]);
}

static void rebuild_hook_target(const struct hook_info *p)
{
	ulong hook_addr = (ulong)p->hook_addr;
	ulong payload;
	int jmp_insr[HOOK_INSR_LEN];
	void *dest_addr[HOOK_INSR_LEN];

	switch (p->hook_type) {
	case INSERT_FUNC:
		payload = (ulong)p->exec_mem;
		break;
	case REPLACE_FUNC:
		payload = (ulong)p->payload;
		break;
	default:
		printk("Unsupported hook type: %d\n", p->hook_type);
		return;
	}
	/* b payload */
	jmp_insr[0] = bl_imm(hook_addr, payload);
	printk("jmp_insr[0]=%08x\n", jmp_insr[0]);

	dest_addr[0] = (void *)hook_addr;
	aarch64_insn_patch_text_fptr(dest_addr, jmp_insr, HOOK_INSR_LEN);
	printk("Hooked(jmp insr): %08x\n", *(int *)hook_addr);
}

void *insert_function(ulong addr, ulong payload)
{
	struct hook_info *hi;

	hi = kzalloc(sizeof (*hi), GFP_KERNEL);
	if (hi == NULL) {
		printk("kzalloc failed.\n");
		return NULL;
	}
	init_hook_info(hi, (void *)addr, (void *)payload, INSERT_FUNC);
	if (build_stub(hi) < 0) {
		kfree(hi);
		return NULL;
	}
	build_old_function(hi);
	rebuild_hook_target(hi);

	list_add_tail(&hi->list, &hook_infos);

	return hi->orig_func;
}

static void recover_function(const struct hook_info *p)
{
	void *dest_addr[HOOK_INSR_LEN];

	dest_addr[0] = p->hook_addr;

	/* Unhook. */
	aarch64_insn_patch_text_fptr(dest_addr, (u32 *)&p->code, HOOK_INSR_LEN);
}

static struct hook_info *find_hook_info(ulong addr)
{
	struct list_head *ptr;
	struct hook_info *hi;

	list_for_each(ptr, &hook_infos) {
		hi = list_entry(ptr, struct hook_info, list);
		if (hi->hook_addr == (void *)addr) {
			return hi;
		}
	}

	return NULL;
}

void uninsert_function(ulong addr)
{
	struct hook_info *hi;

	hi = find_hook_info(addr);
	if (hi == NULL) {
		return;
	}

	recover_function(hi);

	if (hi->exec_mem != NULL) {
		vfree(hi->exec_mem);
	}
	if (hi->orig_func != NULL) {
		vfree(hi->orig_func);
	}

	list_del(&hi->list);
	kfree(hi);
}

void unreplace_function(ulong addr)
{
	struct hook_info *hi;

	hi = find_hook_info(addr);
	if (hi == NULL) {
		return;
	}

	recover_function(hi);

	if (hi->orig_func != NULL) {
		vfree(hi->orig_func);
	}

	list_del(&hi->list);
	kfree(hi);
}

void *replace_function(ulong addr, ulong payload)
{
	struct hook_info *hi;

	if (addr == payload) {
		printk(KERN_INFO "%s: source and target are same.\n",
		       __FUNCTION__);
		return NULL;
	}

	hi = kzalloc(sizeof (*hi), GFP_KERNEL);
	if (hi == NULL) {
		printk("kzalloc failed.\n");
		return NULL;
	}

	init_hook_info(hi, (void *)addr, (void *)payload, REPLACE_FUNC);
	rebuild_hook_target(hi);

	list_add_tail(&hi->list, &hook_infos);

	return hi->orig_func;
}

int hook_init(void)
{
	printk(KERN_INFO "hook init.\n");
	printk("hook_init=%px\n", hook_init);

	if (lookup_kernel_name() < 0) {
		return -1;
	}

	return 0;
}

void hook_exit(void)
{
	printk(KERN_INFO "hook exit.\n");
}
