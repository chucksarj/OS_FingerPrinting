#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/if.h>

#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <asm/uaccess.h>
#include <net/sock.h>

#include <linux/moduleparam.h>

#include "common.h"
#include "handle.h"

#define OSFP             "osfp"
#define OSFP_STATS       "stats"

extern int prn_opt;

static struct nf_hook_ops nfho;

struct proc_dir_entry *root = NULL;
struct proc_dir_entry *pde = NULL;

void osfp_stats(struct seq_file *s) {
    extern void print_stats(struct seq_file *);

    print_stats(s);
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
static unsigned int hook_func(void *ptr, 
        struct sk_buff *skb, const struct nf_hook_state *state) {
    
    unsigned char *pkt_ptr = (unsigned char *)eth_hdr(skb);

    skb->mark = handle_packet(pkt_ptr);

    return NF_ACCEPT;
}
#else
static unsigned int hook_func(unsigned int hooknum,
        struct sk_buff *skb, const struct net_device *in,
        const struct net_device *out, int (*okfn) (struct sk_buff *)) {

    const int len = 128;
    unsigned char data[len];

    skb_copy_bits(skb, 0, data, (skb->len > len) ? len : skb->len);

    skb->mark = handle_ip(0, data);

    return NF_ACCEPT;
}
#endif

static inline void install_nf_hooks(void) {
    nfho.hook       = osfp_hook;
    nfho.hooknum    = NF_INET_PRE_ROUTING;
    nfho.pf         = PF_INET;
    nfho.priority   = NF_IP_PRI_FIRST;

    nf_register_hook(&nfho);
}

static inline void uninstall_nf_hooks(void) {
    nf_unregister_hook(&nfho);
}

static int show_osfp_stats(struct seq_file *s, void *v) {
    osfp_stats(s);
    return 0;
}

static void *c_start(struct seq_file *m, loff_t *pos) {
    unsigned long i = *pos;

    return i < 1 ? (void *) (i + 1) : NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos) {
    ++*pos;
    return c_start(m, pos);
}

static void c_stop(struct seq_file *m, void *v) {
    return;
}

struct seq_operations osfp_op = {
    .start = c_start,
    .next = c_next,
    .stop = c_stop,
    .show = show_osfp_stats,
};

static int osfp_open(struct inode *inode, struct file *file) {
    return seq_open(file, &osfp_op);
}

static inline int osfp_str_cmp(char *dummy, char *str) {
    if (strncmp(dummy, str, strlen(str)) == 0) {
        return 1;
    }
    return 0;
}

static ssize_t osfp_write(struct file *file, const char *ubuf, size_t count, loff_t *off) {
    char dummy[20];
    int rv;

    memset(dummy, 0, sizeof(dummy));

    rv = copy_from_user(dummy, ubuf, count);

    if (osfp_str_cmp(dummy, "prn")) {
        prn_opt = 1;
    } else if (osfp_str_cmp(dummy, "nprn")) {
        prn_opt = 0;
    } else {
        printk("%s: Unknown option %s\n", OSFP, dummy);
    }

    return count;
}

static struct file_operations osfp_file_ops = {
    .owner      = THIS_MODULE,
    .open       = osfp_open,
    .read       = seq_read,
    .write      = osfp_write,
    .llseek     = seq_lseek,
    .release    = seq_release,
};

static inline int proc_init(void) {
    struct proc_dir_entry *proc_file = NULL;

    root = init_net.proc_net;

    pde = proc_mkdir(OSFP, root);
    if (!pde) {
        printk("%s: Unable to create dir %s\n", OSFP, OSFP);
        goto nomem;
    }

    proc_file = proc_create(OSFP_STATS, 0644, pde, &osfp_file_ops);
    if (!proc_file) {
        printk("%s: Unable to create %s\n", OSFP, OSFP_STATS);
        remove_proc_entry(OSFP, root);
        goto nomem;
    }

    return 0;

nomem:
    return -ENOMEM;
}

static inline void proc_fini(void) {
    remove_proc_entry(OSFP_STATS, pde);
    remove_proc_entry(OSFP, root);
}

static int __init start(void) {
    if (osfp_init() < 0) {
        return -1;
    }

    if (proc_init() < 0) {
        osfp_fini();
        return -1;
    }

    install_nf_hooks();

    printk("%s: Loaded OS fingerprint module\n", OSFP);

    return 0;
}

static void __exit end(void) {
    uninstall_nf_hooks();

    osfp_fini();

    proc_fini();

    printk("%s: Unloaded OS fingerprint module\n", OSFP);
}

module_init(start);
module_exit(end);

