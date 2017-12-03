#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

struct firewall_rule {
  char *device;
  int size;
  int port;
  struct firewall_rule *next;
} ;

/* deallocate the memory */
static void dealloc(struct firewall_rule *rules){
    struct firewall_rule *temp;
    while(rules){
        temp = rules;
        rules = rules->next;
        free(temp->device);
        free(temp);
    }
}

int main (int argc, char **argv) {

    char *filename; /* the name of the device */
    FILE *rules_file; /* rules file descriptor */
    int fd;
    int num_vars;
    int bytes_read;
    char *line = NULL;
    struct firewall_rule *rules = NULL;
    struct firewall_rule *head = NULL;
    struct firewall_rule *temp = NULL;
    int port;
    char *rule;
    size_t len = 0;
    int first_check = 0;


    /* ioctl  can be performed only on opened device */
    fd = open ("/proc/firewallExtension", O_RDWR);
    if (fd < 0) {
        fprintf (stderr, "Could not open file /proc/firewallExtension, exiting!\n");
        exit (1);
    }

    /* if we want to display the rules in the kernel */
    if(strncmp(argv[1], "L", 1) == 0){
        read(fd, NULL, 0);
    }

    /* if new rules have to be passed to the kernel */
    else if(strncmp(argv[1], "W", 1) == 0){

        /* open the file for reading the rules */
        filename = argv[2];
        rules_file = fopen(filename, "r+");
        if (!rules_file) {
            fprintf (stderr, "Could not open file %s, exiting!\n", filename);
            exit (1);
        }

        // line = calloc(4097, sizeof(char));
        while ((bytes_read = getline(&line, &len, rules_file)) != -1) {
            rule = calloc(bytes_read, sizeof(char));
            num_vars = sscanf(line, "%d %s\n", &port, rule);

            /* if it was impossible to get poth variables
               the format is wrong, abort */
            if(num_vars != 2) {
                fprintf(stderr, "ERROR: Ill-formed file\n");
                free(line);
                free(rule);
                dealloc(head);
                fclose (rules_file);
                exit(1);
            }

            /* check if the program acutally exists */
            if(access(rule, F_OK) == -1 ) {
                fprintf(stderr, "ERROR: Ill-formed file\n");
                free(line);
                free(rule);
                dealloc(head);
                fclose (rules_file);
                exit(1);
            }

            /* check if the program is executable */
            if(access(rule, X_OK) == -1) {
                fprintf(stderr, "ERROR: Cannot execute file\n");
                free(line);
                free(rule);
                dealloc(head);
                fclose (rules_file);
                exit(1);
            }

            /* allocate some memory for a single firewall rule */
            temp = malloc(sizeof(struct firewall_rule));
            if(!temp){
                fprintf(stderr, "Error! Failed to malloc\n");
                free(line);
                free(rule);
                dealloc(head);
                fclose (rules_file);
                exit(1);
            }

            /* initialize the new firewall rule */
            temp->port = port;
            temp->device = rule;
            temp->size = strlen(rule);
            temp->next = NULL;

            /* if it is the first element in the rule
             * we initailise the head to point to it */
            if(first_check == 0){
                rules = temp;
                head = temp;
                first_check=1;
                continue;
            }

            rules->next = temp;
            rules = rules->next;
        }
        /* write to the file */
        write(fd, head, sizeof(head));

        /* do the actual cleanup */
        fclose (rules_file);
        free(line);
        dealloc(head);
    } else {
        printf("ERROR: file does not exist\n");
    }

    close(fd);
    return 0;
}

