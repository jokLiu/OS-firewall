#define BUFFERSIZE 900

#define PROC_ENTRY_FILENAME "firewallExtension"

static int Device_Open = 0;  /* Is device open?
 * Used to prevent multiple access to device */

static int access_validity(char *program, int port);

struct firewall_rule {
  char *device;
  int size;
  int port;
  struct firewall_rule *next;
} ;

/* mutex for opening and closing a device */
DEFINE_MUTEX (devLock);

/* firewall rules */
struct firewall_rule* rules; 

static struct proc_dir_entry *Our_Proc_File;

/* read-write semaphore 
*  important when replacing the old rules
*  in order not to cause race condition */
static struct rw_semaphore rwsem;

/* make IP4-addresses readable */
#define NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]

struct nf_hook_ops *reg;

/* the firewall hook - called for each outgoing packet */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 3, 0)
#error "Kernel version < 4.4 not supported!"
/* kernels < 4.4 need another firewallhook! */
#endif

/* deallocate the memory */
static void dealloc(struct firewall_rule *rules){
    struct firewall_rule *temp;
    while(rules){
        temp = rules;
        rules = rules->next;
        kfree(temp->device);
        kfree(temp);
    }
}
