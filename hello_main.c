#include <linux/module.h>

static int init_hello(void)
{
	printk("%s: for hide module test.\n", __FUNCTION__);

	return 0;
}

static void exit_hello(void)
{
	printk("%s: for hide module test.\n", __FUNCTION__);
}

module_init(init_hello);
module_exit(exit_hello);

MODULE_LICENSE("GPL");
