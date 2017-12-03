#include <linux/module.h>  /* Needed by all modules */
#include <linux/kernel.h>  /* Needed for KERN_ALERT */
#include <linux/netfilter.h> 
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/compiler.h>
#include <net/tcp.h>
#include <asm/uaccess.h>
#include <linux/namei.h>
#include <linux/version.h>
#include "firewallExtension.h"


MODULE_DESCRIPTION ("Extensions to the firewall") ;
MODULE_LICENSE("GPL");


unsigned int FirewallExtensionHook (void *priv, 
  struct sk_buff *skb,
  const struct nf_hook_state *state) {

  struct tcphdr *tcp;
  struct tcphdr _tcph;
  struct sock *sk;
  struct mm_struct *mm;

  //-------------------
  struct path path;
  pid_t mod_pid;
  char *program;
  int port;
  char *buf;
  char cmdlineFile[BUFFERSIZE];
  int res;

  //-----------------

  sk = skb->sk;
  if (!sk) {
    /* firewall: netfilter called with empty socket */
    return NF_ACCEPT;
  }

  if (sk->sk_protocol != IPPROTO_TCP) {
    /* firewall: netfilter called with non-TCP-packet */
    return NF_ACCEPT;
  }

  /* get the tcp-header for the packet */
  tcp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(struct tcphdr), &_tcph);
  if (!tcp) {
    /* Could not get tcp-header meaning non TCP pacekt */
    return NF_ACCEPT;
  }

  if (tcp->syn) {
    //------------------------
    // Find the full path to the executable
    //------------------------

    /* current is pre-defined pointer to task structure of currently 
    running task */
    mod_pid = current->pid;
    snprintf (cmdlineFile, BUFFERSIZE, "/proc/%d/exe", mod_pid);
    res = kern_path (cmdlineFile, LOOKUP_FOLLOW, &path);
    if (res) {
      // TODO drop or not drop
      return -EFAULT;
    }

    /* get the full program path that called it */
    buf = (char *)kcalloc(100, sizeof(char), GFP_KERNEL);
    program = d_path(&path, buf, 100*sizeof(char));

    path_put(&path);

    if (in_irq() || in_softirq() || !(mm = get_task_mm(current))) {
      return NF_ACCEPT;
    }
    mmput(mm);

    /* get the port of the connection */
    port = ntohs (tcp->dest);

    /* if not valid connection, drop it */
    if(!access_validity(program, port)){
      tcp_done (sk);  /*terminate Connectionction immediately */
      return NF_DROP;
    }

    /* free the buffer as it is no longer needed */
    kfree(buf);

  }

  /* otherwise accept the connection */
  return NF_ACCEPT;    
}

static struct nf_hook_ops firewallExtension_ops = {
 .hook    = FirewallExtensionHook,
 .pf      = PF_INET,
 .priority = NF_IP_PRI_FIRST,
 .hooknum = NF_INET_LOCAL_OUT
};



/* check whether the connection should be dropped or accepted
*  based on the firewall rules */
static int access_validity(char *program, int port){
  struct firewall_rule *head;
  int validity = 1;

  /* lock the read semaphore */
  down_read(&rwsem);

  head = rules;

  /* loop until the exact rule is found or 
  *  until the are no more rules */
  while(head){

    /* if an exact port is found then there must
       be a rule for the exact program, if not then drop 
       the connection. */
    if(port == head->port){
      if(strcmp(program, head->device)==0){
        validity = 1;
        break;
      }
      validity = 0;
    }
    head = head->next;
  }

  /* release the lock */
  up_read(&rwsem);
  return validity;
}



/*
* kernel write replaces the old rules with the new ones passed
* if they satisfy the conditions, otherwise old rules are left
* unchanged.
*/
static ssize_t kernelWrite (struct file *file, 
  const char __user *buffer, size_t 
  count, loff_t *offset) {

  int errno;
  struct firewall_rule *head, *temp, *r;
  char* filename ;

  r = kmalloc(sizeof(struct firewall_rule), GFP_KERNEL);
  head = r;

  errno = copy_from_user(r, (void *)buffer, sizeof(struct firewall_rule));
  if( errno != 0){
    head = NULL;
    goto end;
  }

  filename = kcalloc(r->size + 1, sizeof(char), GFP_KERNEL);
  errno = copy_from_user(filename, (void *)r->device, r->size + 1);

  /* should never happen */
  if( errno != 0){
    head = r;
    head->device = NULL;
    head->next = NULL;
    goto end;
  }

  r->device = filename;

  if(errno != 0) 
    return -EINVAL;

  while(errno == 0){
    temp = kmalloc(sizeof(struct firewall_rule), GFP_KERNEL);
    errno = copy_from_user(temp, (void *)r->next, sizeof(struct firewall_rule)); 
    if(errno != 0){
      kfree(temp);
      break;
    }
    filename = kcalloc(temp->size + 1, sizeof(char), GFP_KERNEL);
    errno = copy_from_user(filename, (void *)temp->device, temp->size + 1);
    if( errno != 0){
      kfree(filename);
      break;
    }

    temp->device = filename;

    r->next = temp;
    r=r->next;     
  }
  r->next=NULL;

end:
  /* save the pointer to the current rules for 
     the latter deallocation */
  temp = rules;

  /* replace the rules while holding a lock */
  down_write(&rwsem);
  rules = head;
  up_write(&rwsem);

  /* deallocate the old rules */
  dealloc(temp);
  return 0;  
}

/* 
* kernel read for reading from the proc file.
* When the read is called all we do is list the current 
* rules of the firewall. 
*/
static ssize_t kernelRead(struct file *filp, /* see include/linux/fs.h   */
         char *buffer,  /* buffer to fill with data */
         size_t length, /* length of the buffer */
loff_t * offset) {
  struct firewall_rule *head;
  
  /* lock the read semaphore */
  down_read(&rwsem);

  head = rules;
  while(head){
    printk(KERN_INFO "Firewall rule: %d %s\n", head->port, head->device);
    head = head->next;
  }

  /* release the lock */
  up_read(&rwsem);
  return 0;

}


/*
*  The file is opened 
*/
static int procfs_open(struct inode *inode, struct file *file)
{
  /* only a signle process can open the file at the same time*/
  mutex_lock (&devLock);
  if (Device_Open) {
    mutex_unlock (&devLock);
    return -EAGAIN;
  }
  Device_Open++;
  mutex_unlock (&devLock);

  try_module_get(THIS_MODULE);
  return 0; /* success */
}

/*
*  The proc file is closed
*/
static int procfs_close(struct inode *inode, struct file *file)
{
  mutex_lock (&devLock);
  Device_Open--;         /* We're now ready for our next caller */
  mutex_unlock (&devLock);

  module_put(THIS_MODULE);
  return 0;  /* success */        
}

static const struct file_operations File_Ops_4_Our_Proc_File = {
  .owner = THIS_MODULE,
  .write = kernelWrite,
  .read = kernelRead,
  .open = procfs_open,
  .release = procfs_close,
};




int init_module(void)
{
  int errno;

  /* init our rules */
  rules = NULL;

    /* create the /proc file */
  Our_Proc_File = proc_create_data (PROC_ENTRY_FILENAME, 0644, NULL, 
    &File_Ops_4_Our_Proc_File, NULL);

  /* check if the /proc file was created successfuly */
  if (Our_Proc_File == NULL){
    printk(KERN_ALERT "Error: Could not initialize /proc/%s\n",
      PROC_ENTRY_FILENAME);
    return -1;
  }

  errno = nf_register_hook (&firewallExtension_ops); /* register the hook */
  if (errno) {
    printk (KERN_INFO "Firewall extension could not be registered!\n");
  } 

  /* initialise the read-write semaphore */
  init_rwsem(&rwsem);

  /* A non 0 return means init_module failed; module can't be loaded. */
  return errno;
}


void cleanup_module(void)
{
  remove_proc_entry(PROC_ENTRY_FILENAME, NULL);
  nf_unregister_hook (&firewallExtension_ops); /* restore everything to normal */
  dealloc(rules);
}  
