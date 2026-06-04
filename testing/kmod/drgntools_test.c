// Copyright (c) 2026, Oracle and/or its affiliates.
// Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
#define pr_fmt(fmt) "drgntools_test: " fmt

#include <linux/completion.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/rwsem.h>
#include <linux/semaphore.h>
#include <linux/seq_file.h>
#include <linux/version.h>

struct drgn_tools_test_object {
	int foo;
	const char *bar;
};

struct drgn_tools_test_object drgn_tools_test_object_data = { 5, "foobar" };
EXPORT_SYMBOL(drgn_tools_test_object_data);

static int lsmod_test_int = -42;
static unsigned int lsmod_test_uint = 4242;
static long lsmod_test_long = -420000;
static unsigned long lsmod_test_ulong = 420000;
static bool lsmod_test_true = true;
static bool lsmod_test_false;
static char *lsmod_test_charp = "drgn \"tools\" \\ lsmod";
static char *lsmod_test_null_charp;
static char lsmod_test_string[32] = "fixed string";
static int lsmod_test_array_num = 3;
static int lsmod_test_array[4] = { 10, 20, -30, 40 };

module_param(lsmod_test_int, int, 0444);
module_param(lsmod_test_uint, uint, 0444);
module_param(lsmod_test_long, long, 0444);
module_param(lsmod_test_ulong, ulong, 0444);
module_param(lsmod_test_true, bool, 0444);
module_param(lsmod_test_false, bool, 0444);
module_param(lsmod_test_charp, charp, 0444);
module_param(lsmod_test_null_charp, charp, 0444);
module_param_string(
	lsmod_test_string, lsmod_test_string, sizeof(lsmod_test_string), 0444);
module_param_array(lsmod_test_array, int, &lsmod_test_array_num, 0444);

DEFINE_MUTEX(lockmod_mutex);
DECLARE_RWSEM(lockmod_rwsem);
DECLARE_COMPLETION(lockmod_completion);

/*
 * 48380368dec14 ("Change DEFINE_SEMAPHORE() to take a number argument")
 * in v6.4.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0) || (defined(RHEL_MAJOR) && RHEL_MAJOR == 9)
DEFINE_SEMAPHORE(lockmod_sem, 1);
#else
DEFINE_SEMAPHORE(lockmod_sem);
#endif

static DECLARE_COMPLETION(lockmod_doexit);
static DECLARE_COMPLETION(lockmod_ready);
static bool lockmod_locked;
static struct proc_dir_entry *lockmod_pde;

/*
 * A proc file used to unlock the mutex, semaphore, and rwsem. This allows the
 * lock waiter kthreads to exit and the module to be removed manually.
 */
static int lockmod_seq_show(struct seq_file *seq, void *offset)
{
	seq_printf(seq, "done\n");
	return 0;
}

static int lockmod_open(struct inode *inode, struct file *file)
{
	if (lockmod_locked) {
		complete(&lockmod_doexit);
		pr_info("sent signal to unlock\n");
	}
	return single_open(file, lockmod_seq_show, NULL);
}

static int lockmod_release(struct inode *inode, struct file *file)
{
	return seq_release(inode, file);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
static const struct file_operations lockmod_fops = {
	.owner = THIS_MODULE,
	.open = lockmod_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = lockmod_release,
};
#else
static const struct proc_ops lockmod_fops = {
	.proc_open = lockmod_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = lockmod_release,
};
#endif

static int lockmod_owner(void *unused)
{
	pr_info("[owner] hello\n");
	__module_get(THIS_MODULE);
	mutex_lock(&lockmod_mutex);
	down(&lockmod_sem);
	down_write(&lockmod_rwsem);
	lockmod_locked = true;

	complete(&lockmod_ready);

	pr_info("[owner] ready and waiting to exit\n");
	wait_for_completion(&lockmod_doexit);
	pr_info("[owner] time to exit\n");

	lockmod_locked = false;
	up_write(&lockmod_rwsem);
	up(&lockmod_sem);
	mutex_unlock(&lockmod_mutex);
	module_put(THIS_MODULE);
	complete(&lockmod_completion);
	return 0;
}

/* Kthreads to exercise different mutex locking functions. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#define MUTEX_CASES                                                            \
	X(lock, mutex_lock(&lockmod_mutex))                                    \
	X(lock_nested, mutex_lock_nested(&lockmod_mutex, 0))                   \
	X(lock_io, mutex_lock_io(&lockmod_mutex))                              \
	X(lock_io_nested, mutex_lock_io_nested(&lockmod_mutex, 0))             \
	X(lock_killable,                                                       \
	  do {                                                                 \
	  } while (mutex_lock_killable(&lockmod_mutex) < 0))                   \
	X(lock_killable_nested,                                                \
	  do {                                                                 \
	  } while (mutex_lock_killable_nested(&lockmod_mutex, 0) < 0))         \
	X(lock_interruptible,                                                  \
	  do {                                                                 \
	  } while (mutex_lock_interruptible(&lockmod_mutex) < 0))              \
	X(lock_interruptible_nested,                                           \
	  do {                                                                 \
	  } while (mutex_lock_interruptible_nested(&lockmod_mutex, 0) < 0))
#else
#define MUTEX_CASES                                                            \
	X(lock, mutex_lock(&lockmod_mutex))                                    \
	X(lock_nested, mutex_lock_nested(&lockmod_mutex, 0))                   \
	X(lock_killable,                                                       \
	  do {                                                                 \
	  } while (mutex_lock_killable(&lockmod_mutex) < 0))                   \
	X(lock_killable_nested,                                                \
	  do {                                                                 \
	  } while (mutex_lock_killable_nested(&lockmod_mutex, 0) < 0))         \
	X(lock_interruptible,                                                  \
	  do {                                                                 \
	  } while (mutex_lock_interruptible(&lockmod_mutex) < 0))              \
	X(lock_interruptible_nested,                                           \
	  do {                                                                 \
	  } while (mutex_lock_interruptible_nested(&lockmod_mutex, 0) < 0))
#endif

#define X(kind, lock_code)                                                     \
	static int do_mutex_##kind(void *unused)                               \
	{                                                                      \
		__module_get(THIS_MODULE);                                     \
		lock_code;                                                     \
		mutex_unlock(&lockmod_mutex);                                  \
		module_put(THIS_MODULE);                                       \
		return 0;                                                      \
	}
MUTEX_CASES
#undef X

#define SEM_CASES                                                              \
	X(down, down(&lockmod_sem))                                           \
	X(down_interruptible,                                                 \
	  do {                                                                 \
	  } while (down_interruptible(&lockmod_sem) < 0))                      \
	X(down_killable,                                                      \
	  do {                                                                 \
	  } while (down_killable(&lockmod_sem) < 0))                           \
	X(down_timeout,                                                       \
	  do {                                                                 \
	  } while (down_timeout(&lockmod_sem, 86400 * HZ)))

#define X(kind, lock_code)                                                     \
	static int do_sem_##kind(void *unused)                                 \
	{                                                                      \
		__module_get(THIS_MODULE);                                     \
		lock_code;                                                     \
		up(&lockmod_sem);                                              \
		module_put(THIS_MODULE);                                       \
		return 0;                                                      \
	}
SEM_CASES
#undef X

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
#define RWSEM_CASES                                                            \
	X(down_read, down_read(&lockmod_rwsem), up_read)                      \
	X(down_read_nested, down_read_nested(&lockmod_rwsem, 0), up_read)     \
	X(down_read_interruptible,                                             \
	  do {                                                                 \
	  } while (down_read_interruptible(&lockmod_rwsem) < 0),               \
	  up_read)                                                             \
	X(down_read_killable,                                                  \
	  do {                                                                 \
	  } while (down_read_killable(&lockmod_rwsem) < 0), up_read)           \
	X(down_read_killable_nested,                                           \
	  do {                                                                 \
	  } while (down_read_killable_nested(&lockmod_rwsem, 0) < 0),          \
	  up_read)                                                             \
	X(down_write, down_write(&lockmod_rwsem), up_write)                    \
	X(down_write_nested, down_write_nested(&lockmod_rwsem, 0), up_write)  \
	X(down_write_killable,                                                 \
	  do {                                                                 \
	  } while (down_write_killable(&lockmod_rwsem) < 0), up_write)         \
	X(down_write_killable_nested,                                          \
	  do {                                                                 \
	  } while (down_write_killable_nested(&lockmod_rwsem, 0) < 0),         \
	  up_write)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#define RWSEM_CASES                                                            \
	X(down_read, down_read(&lockmod_rwsem), up_read)                      \
	X(down_read_nested, down_read_nested(&lockmod_rwsem, 0), up_read)     \
	X(down_read_killable,                                                  \
	  do {                                                                 \
	  } while (down_read_killable(&lockmod_rwsem) < 0), up_read)           \
	X(down_write, down_write(&lockmod_rwsem), up_write)                    \
	X(down_write_nested, down_write_nested(&lockmod_rwsem, 0), up_write)  \
	X(down_write_killable,                                                 \
	  do {                                                                 \
	  } while (down_write_killable(&lockmod_rwsem) < 0), up_write)         \
	X(down_write_killable_nested,                                          \
	  do {                                                                 \
	  } while (down_write_killable_nested(&lockmod_rwsem, 0) < 0),         \
	  up_write)
#else
#define RWSEM_CASES                                                            \
	X(down_read, down_read(&lockmod_rwsem), up_read)                      \
	X(down_read_nested, down_read_nested(&lockmod_rwsem, 0), up_read)     \
	X(down_write, down_write(&lockmod_rwsem), up_write)                    \
	X(down_write_nested, down_write_nested(&lockmod_rwsem, 0), up_write)
#endif

#define X(kind, lock_code, upfn)                                               \
	static int do_rwsem_##kind(void *unused)                               \
	{                                                                      \
		__module_get(THIS_MODULE);                                     \
		lock_code;                                                     \
		upfn(&lockmod_rwsem);                                         \
		module_put(THIS_MODULE);                                       \
		return 0;                                                      \
	}
RWSEM_CASES
#undef X

#define COMPLETION_CASES                                                       \
	X(wait, wait_for_completion(&lockmod_completion))                      \
	X(wait_io, wait_for_completion_io(&lockmod_completion))                \
	X(wait_killable, wait_for_completion_killable(&lockmod_completion)) \
	X(wait_interruptible, wait_for_completion_interruptible(&lockmod_completion)) \
	X(wait_timeout, wait_for_completion_timeout(&lockmod_completion, 86400 * HZ)) \
	X(wait_io_timeout, wait_for_completion_io_timeout(&lockmod_completion, 86400 * HZ)) \
	X(wait_killable_timeout, wait_for_completion_killable_timeout(&lockmod_completion, 86400 * HZ)) \
	X(wait_interruptible_timeout, wait_for_completion_interruptible_timeout(&lockmod_completion, 86400 * HZ))

#define X(kind, lock_code)                                                     \
	static int do_completion_##kind(void *unused)                          \
	{                                                                      \
		__module_get(THIS_MODULE);                                     \
		lock_code;                                                     \
		module_put(THIS_MODULE);                                       \
		return 0;                                                      \
	}
COMPLETION_CASES
#undef X

#define WARN_ON_BAD_KTHREAD(task, name)                                        \
	do {                                                                   \
		if (IS_ERR(task))                                               \
			pr_warn("failed to start %s: %ld\n", name, PTR_ERR(task)); \
	} while (0)

static int __init drgntools_init(void)
{
	struct task_struct *task;

	lockmod_pde = proc_create("lockmod_test", 0444, NULL, &lockmod_fops);
	if (!lockmod_pde)
		return -ENOENT;

	pr_info("[init] starting owner thread\n");
	task = kthread_run(lockmod_owner, NULL, "lockmod-owner");
	if (IS_ERR(task)) {
		proc_remove(lockmod_pde);
		lockmod_pde = NULL;
		return PTR_ERR(task);
	}

	pr_info("[init] waiting until owner is ready\n");
	wait_for_completion(&lockmod_ready);
	pr_info("[init] owner is ready: launching kthreads\n");

#define X(kind, lock_code)                                                     \
	task = kthread_run(&do_mutex_##kind, NULL,                            \
			   "lockmod-mutex_" #kind);                             \
	WARN_ON_BAD_KTHREAD(task, "lockmod-mutex_" #kind);
	MUTEX_CASES
#undef X

#define X(kind, lock_code)                                                     \
	task = kthread_run(&do_sem_##kind, NULL, "lockmod-sem_" #kind);       \
	WARN_ON_BAD_KTHREAD(task, "lockmod-sem_" #kind);
	SEM_CASES
#undef X

#define X(kind, lock_code, upfn)                                               \
	task = kthread_run(&do_rwsem_##kind, NULL,                            \
			   "lockmod-rwsem_" #kind);                             \
	WARN_ON_BAD_KTHREAD(task, "lockmod-rwsem_" #kind);
	RWSEM_CASES
#undef X

#define X(kind, lock_code)                                                      \
	task = kthread_run(&do_completion_##kind, NULL,                         \
			   "lockmod-completion_" #kind);                        \
	WARN_ON_BAD_KTHREAD(task, "lockmod-completion_" #kind);
	COMPLETION_CASES
#undef X


	pr_info("[init] module initialized\n");
	return 0;
}

static void __exit drgntools_exit(void)
{
	proc_remove(lockmod_pde);
	lockmod_pde = NULL;
	pr_info("successful exit\n");
}

module_init(drgntools_init);
module_exit(drgntools_exit);

MODULE_AUTHOR("Stephen Brennan <stephen.s.brennan@oracle.com>");
MODULE_DESCRIPTION("Testing fixtures for drgn-tools");
MODULE_LICENSE("GPL");
