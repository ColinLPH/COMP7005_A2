#ifndef A1_CLIENT_H
#define A1_CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define DOMAIN_PATH "/tmp/dompath"
#define SLEEP_TIMER 3

struct file_info {
    int filefd;
    uint8_t file_name_size;
    uint8_t *file_name;
    off_t file_size;
};

struct file_info_list {
    char *file_path;
    struct file_info *file_info_struct;
    struct file_info_list *next;
};

void print_list(struct file_info_list *head);

int run_client(int argc, char *argv[]);
int creat_socket(void);
int parse_args(int argc, char *argv[], struct file_info_list *head);
int check_files(struct file_info_list *head);
void get_file_infos(struct file_info_list *head);
uint8_t *sanitize_file_name(char *file_path);
int do_send_all(struct file_info_list *head);
int connect_to_server(int sockfd);
void send_file_content(int src_fd, int dest_fd, size_t count);
void setup_socket_address(struct sockaddr_un *addr);
void free_file_info_list(struct file_info_list *head);

#endif //A1_CLIENT_H
