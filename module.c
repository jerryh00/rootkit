#include <linux/module.h>

#include "hook.h"
#include "hide.h"

static ulong call_addr;
module_param(call_addr, ulong, 0644);
MODULE_PARM_DESC(call_addr, "the address to call");

static ulong hook_addr;
module_param(hook_addr, ulong, 0644);
MODULE_PARM_DESC(hook_addr, "the address to hook");

static void (*sysrq_handle_xxxx)(int key);

static int init_mod(void)
{
	int ret;
	void *orig_func;
	void *func_entry;

	printk(KERN_INFO "rk module init.\n");
	ret = hook_init();
	if (ret < 0) {
		return -1;
	}

	ret = hide_init();
	if (ret < 0) {
		return -1;
	}

	ret = hide_module("rk");
	if (ret < 0) {
		printk("hide module failed..\n");
		hook_exit();
		return -1;
	}

	ret = hide_module("hello");
	if (ret < 0) {
		printk("hide module failed..\n");
		hook_exit();
		return -1;
	}

	if ((void *)hook_addr == NULL || (void *)call_addr == NULL) {
		return 0;
	}

	orig_func = insert_function(hook_addr, call_addr);
	if (orig_func == NULL) {
		hook_exit();
		return -1;
	}
	dump_hook_infos();

	printk("Trigger hooked function.\n");
	sysrq_handle_xxxx = (void (*)(int key))hook_addr;
	sysrq_handle_xxxx(0);

	printk("I am back.\n");

	printk("Trigger original function.\n");
	sysrq_handle_xxxx = (void (*)(int key))orig_func;
	sysrq_handle_xxxx(0);

	uninsert_function(hook_addr);
	dump_hook_infos();

	func_entry = make_orig_func((void *)hook_addr);
	if (func_entry == NULL) {
		hook_exit();
		return -1;
	}
	orig_func = replace_function(hook_addr, (ulong)func_entry);
	if (orig_func == NULL) {
		unmake_orig_func(func_entry);
		hook_exit();
		return -1;
	}
	dump_hook_infos();

	printk("Trigger replacement function.\n");
	sysrq_handle_xxxx = (void (*)(int key))hook_addr;
	sysrq_handle_xxxx(0);

	printk("I am back again.\n");

	dump_hook_infos();

	return 0;
}

static void exit_mod(void)
{
	printk(KERN_INFO "rk module exit.\n");
	unreplace_function(hook_addr);
	unhide_module("rk");
	unhide_module("hello");
	hide_exit();
	dump_hook_infos();
	hook_exit();
}

module_init(init_mod);
module_exit(exit_mod);

MODULE_LICENSE("GPL");
