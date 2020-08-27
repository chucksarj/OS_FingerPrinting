#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>	/* Necessary because we use the proc fs */
#include <asm/uaccess.h>	/* for copy_from_user */

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

#define NIP6(addr) \
    ntohs((addr).s6_addr16[0]), \
    ntohs((addr).s6_addr16[1]), \
    ntohs((addr).s6_addr16[2]), \
    ntohs((addr).s6_addr16[3]), \
    ntohs((addr).s6_addr16[4]), \
    ntohs((addr).s6_addr16[5]), \
    ntohs((addr).s6_addr16[6]), \
    ntohs((addr).s6_addr16[7])

#define BUFSIZE                 800
#define PROCFS_NAME             "fingerprint"
#define PROCFS_STATS            "stats"
#define TCPOPT_NOP              1
#define TCPOPT_MAXSEG           2
#define TCPOPT_WINDOW           3
#define TCPOPT_SACK             4
#define TCPOPT_SEL_SACK         5
#define TCPOPT_TIME_STAMP       8
#define MAX_OS                  6
#define MAX_OPT_LEN             536
#define OSFP                    "osfp"
#define OSFP_STATS              "stats"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arjun Loganathan");
MODULE_DESCRIPTION("Linux Kernel Module: Netfilter");
MODULE_VERSION("0.01");

static int udp_count;
static int tcp_count;
static int ip_count;
static int unk_count;
static int win_count;
static int vis_count;
static int mac_count;
static int lin_count;
static int rh_count;

typedef struct {
    unsigned char kind;
    unsigned char size;
} tcp_option_t;

typedef struct {
    int optLen;
    unsigned char *tcpOpt;
    int sport;
    int dport;
} tFpData;

enum ostype {
    UNKNOWN,
    WINDOWS,
    VISTA,
    MAC,
    LINUX,
    REDHAT
};

static char *os[MAX_OS] = {
    "Unknown",
    "Windows",
    "Vista",
    "Mac",
    "Linux",
    "RedHat",
};

char *getOsName(int fp) {
    if ((fp >= 0) && (fp < MAX_OS)) {
        return os[fp];
    }

    return "";
}

int getOsId(int optLen, unsigned char *tcpOpt) {
    int fp = UNKNOWN;
    int flag = 0;

    // Windows
    // 8 [0 SEG] [4 NOP] [5 NOP] [6 SACK]

    // Vista and above
    // 12 [0 SEG] [4 NOP] [5 WIN] [8 NOP] [9 NOP] [10 SACK]

    // Mac
    // 24 [0 SEG] [4 NOP] [5 WIN] [8 NOP] [9 NOP] [10 TS] [20 SACK]

    // Linux
    // 20 [0 SEG] [4 SACK] [6 TS] [16 NOP] [17 WIN]

    // RedHat
    // 20 [0 SEG] [4 NOP] [5 NOP] [6 TS] [16 NOP] [17 WIN]

    if ((optLen == 8) && (tcpOpt[0] == TCPOPT_MAXSEG) && 
            (tcpOpt[4] == TCPOPT_NOP) && 
            (tcpOpt[5] == TCPOPT_NOP) && 
            (tcpOpt[6] == TCPOPT_SACK)) {

        fp = WINDOWS;
        
        win_count++;
        flag = 1;
    } else if ((optLen == 12) && (tcpOpt[0] == TCPOPT_MAXSEG) && 
            (tcpOpt[4] == TCPOPT_NOP) &&
            (tcpOpt[5] == TCPOPT_WINDOW) &&
            (tcpOpt[8] == TCPOPT_NOP) &&
            (tcpOpt[9] == TCPOPT_NOP) &&
            (tcpOpt[10] == TCPOPT_SACK)) {
        
        fp = VISTA;
        
        vis_count++;
        flag = 1;
    } else if ((optLen == 24) && (tcpOpt[0] == TCPOPT_MAXSEG) && 
            (tcpOpt[4] == TCPOPT_NOP) && 
            (tcpOpt[5] == TCPOPT_WINDOW) && 
            (tcpOpt[8] == TCPOPT_NOP) && 
            (tcpOpt[9] == TCPOPT_NOP) &&
            (tcpOpt[10] == TCPOPT_TIME_STAMP) &&
            (tcpOpt[20] == TCPOPT_SACK)) {
        
        fp = MAC;
        
        mac_count++;
        flag = 1;
    } else if ((optLen == 20) && (tcpOpt[0] == TCPOPT_MAXSEG) &&
            (tcpOpt[4] == TCPOPT_SACK) &&
            (tcpOpt[6] == TCPOPT_TIME_STAMP) &&
            (tcpOpt[16] == TCPOPT_NOP) &&
            (tcpOpt[17] == TCPOPT_WINDOW)) {
        
        fp = LINUX;
        
        lin_count++;
        flag = 1;
    } else if ((optLen == 20) && (tcpOpt[0] == TCPOPT_MAXSEG) &&
            (tcpOpt[4] == TCPOPT_NOP) &&(tcpOpt[5] == TCPOPT_NOP) &&
            (tcpOpt[6] == TCPOPT_TIME_STAMP) &&
            (tcpOpt[16] == TCPOPT_NOP) &&
            (tcpOpt[17] == TCPOPT_WINDOW)) {
        
        fp = REDHAT;

        rh_count++;
        flag = 1;
    }
    
    if (!flag) {
        unk_count++;
    }

    return fp;
}

void printOpts(tFpData *fpd) {
    unsigned int i = 0;
    tcp_option_t *o;
    int fp;
    
    fp = getOsId(fpd->optLen, fpd->tcpOpt);
    
    printk("Source Port = %u Dest Port = %u Opt_len = %u OS = %s\n",
            fpd->sport, fpd->dport, fpd->optLen, getOsName(fp));

    while ((i < fpd->optLen) && (i < MAX_OPT_LEN)) {
        if (fpd->tcpOpt[i] == 0) {
            break;
        }
        
        o = (tcp_option_t *)&fpd->tcpOpt[i];
        
        if (i > 0) {
            printk(",");
        }
        
        switch (o->kind) {
            case TCPOPT_NOP:
                printk("[%d NOP]", i);
                i++;
                continue;
                break;
            case TCPOPT_MAXSEG:
                printk("[%d SEG]", i);
                break;
            case TCPOPT_WINDOW:
                printk("[%d WIN %d]", i, fpd->tcpOpt[i + 2]);
                break;
            case TCPOPT_SACK:
                printk("[%d SACK]", i);
                break;
            case TCPOPT_SEL_SACK:
                printk("[%d SS]", i);
                break;
            case TCPOPT_TIME_STAMP:
                printk("[%d TS]", i);
                break;
            default:
                printk("[%d unknown %d %d]", i, o->kind, fpd->optLen);
                break;
        }
        
        if (o->size) {
            i += o->size;
        } else {
            printk("Inv_Sz");
            break;
        }
    }
    
    printk("\n");
}

static ssize_t myread(struct file *file, char __user *ubuf, size_t count, loff_t *ppos) {
    char buf[BUFSIZE];
    int len = 0;

    if (*ppos > 0) {
        return 0;
    }

    len += sprintf(buf, "Packet count statistics:\n");
    len += sprintf(buf + len, "IP_total = %d UDP_count = %d TCP_count = %d\n\n", 
            ip_count, udp_count, tcp_count);
    len += sprintf(buf + len, "Packet OS statistics:\n");
    len += sprintf(buf + len, "Unknown %d Windows %d Vista %d Mac %d Linux %d RedHat %d\n", 
            unk_count, win_count, vis_count, mac_count, lin_count, rh_count);
    
    if (copy_to_user(ubuf,buf,len)) {
        return -EFAULT;
    }

    *ppos = len;
    return len;
}

static struct file_operations myops = {
    .owner = THIS_MODULE,
    .read = myread,
};

/* function to be called by hook. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
static unsigned int hook_func(void *ptr, 
        struct sk_buff *skb, const struct nf_hook_state *state) {
#else
static unsigned int hook_func(unsigned int hooknum,
        struct sk_buff *skb, const struct net_device *in,
        const struct net_device *out, int (*okfn) (struct sk_buff *)) {
#endif

        tFpData fpd;
        struct udphdr *udp_header;
        struct tcphdr *tcp_header;
        unsigned char *opt_arr;
        int length;

        struct iphdr *ip_header = (skb != 0)?(struct iphdr *)skb_network_header(skb):0;

        if (ip_header->protocol == 17) {
            udp_header = udp_hdr(skb);

            udp_count++;
        } else if (ip_header->protocol == 6) {
            tcp_header = tcp_hdr(skb);
            
            if ((tcp_header->syn) && !(tcp_header->ack)) {
                length = (tcp_header->doff * 4) - sizeof(struct tcphdr);
                opt_arr = (unsigned char *)(tcp_header + 1);

                fpd.sport = ntohs(tcp_header->source);
                fpd.dport = ntohs(tcp_header->dest);
                fpd.optLen = length;
                fpd.tcpOpt = opt_arr;

                printk("Source IP: %d.%d.%d.%d | Dest IP: %d.%d.%d.%d\n", 
                        NIPQUAD(ip_header->saddr), NIPQUAD(ip_header->daddr));
                
                printOpts(&fpd);
            }

            tcp_count++;
        }

        ip_count++;
        
        return NF_ACCEPT;
    }

    static struct nf_hook_ops nfho = {
        .hook       = hook_func,
        .hooknum    = 1,                    /* NF_IP_LOCAL_IN */
        .pf         = PF_INET,
        .priority   = NF_IP_PRI_FIRST,
    };

    static int __init init_nf(void) {
        printk(KERN_INFO "Register netfilter module.\n");

        udp_count = 0;
        tcp_count = 0;
        ip_count = 0;
        unk_count = 0;
        win_count = 0;
        vis_count = 0;
        mac_count = 0;
        lin_count = 0;
        rh_count = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
        nf_register_net_hook(&init_net, &nfho);
        
        ent = proc_create(PROCFS_NAME, 0666, NULL, &myops);
        if (ent == NULL) {
            printk(KERN_ALERT "Error: Could not initialize /proc/%s\n", PROCFS_NAME);
            return -ENOMEM;
        }
#else
        nf_register_hook(&nfho);
        
        root = init_net.proc_net;
        
        pde = proc_mkdir(OSFP, root);
        if (!pde) {
            printk("Unable to create dir: %s\n", OSFP);

            return -ENOMEM;
        }

        ent = proc_create(PROCFS_NAME, 0664, pde, &myops);
        if (!ent) {
              
            printk("Unable to create dir: %s\n", PROCFS_NAME);
            remove_proc_entry(OSFP, root);

            return -ENOMEM;
        }

#endif

        return 0;
    }

    static void __exit exit_nf(void) {
        printk(KERN_INFO "Unregister netfilter module.\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
        nf_unregister_net_hook(&init_net, &nfho);
        proc_remove(ent);
#else
        nf_unregister_hook(&nfho);
        remove_proc_entry(PROCFS_NAME, pde);
        remove_proc_entry(OSFP, root);
#endif

    }

    module_init(init_nf);
    module_exit(exit_nf);
