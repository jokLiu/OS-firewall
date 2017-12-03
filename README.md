# Firewall module

Extension to the linux firewall which makes it possible to
specify which programs are allowed use which outgoing port. 

It consists of two parts- a user space program and a kernel
module. 

## Firewall rules

A firewall rule consists of a port number and a filename (the full path) of a program separated by a space, meaning that the corresponding program is allowed to make outgoing connections on this TCP-port. If there is no rule for a given port, any program is allowed to make outgoing connections on this port. A connection is not allowed when rules for the port exist, but the program trying to establish the connection is not in the list of allowed programs. 

The kernel module processes the packets and maintains the firewall rules, and displays the firewall rules via _printk_ in _/var/log/kern.log_. The output:
```
Firewall rule: <port> <program>
```
## Userspace configuration

The user space program  _firewallSetup_, has commands firstly for triggering the listing of the firewall rules in _/var/log/kern.log_, and secondly for setting the firewall rules. A new set of firewall rules overrides the old set. The file _/proc/firewallExtension_ is used for communication between the user program and the kernel.

There are two ways of calling the user space program.

```
firewallSetup L
```

This way of calling the user space program causes the firewall rules to be displayed in _/var/log/kern.log_ 

The second way of calling the program is

```
firewallSetup W <filename>
```

where _<filename>_ is the name of the file containing the firewall
rules.  This file contains one firewall rule per line. _firewallSetup_
checks whether the filename in the firewall rule denotes an
existing executable file. If there is any error in the syntax or any
filename is not an executable file, this program aborts with
appropriate error messages.
