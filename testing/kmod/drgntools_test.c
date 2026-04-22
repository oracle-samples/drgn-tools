// Copyright (c) 2026, Oracle and/or its affiliates.
// Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
#include <linux/module.h>

static int __init drgntools_init(void)
{
	printk(KERN_INFO "drgntools_test: hello world\n");
	return 0;
}

static void __exit drgntools_exit(void)
{
}

module_init(drgntools_init);
module_exit(drgntools_exit);

MODULE_AUTHOR("Stephen Brennan <stephen.s.brennan@oracle.com>");
MODULE_DESCRIPTION("Testing fixtures for drgn-tools");
MODULE_LICENSE("UPL");
