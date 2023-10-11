#ifndef A1_CLIENT_H
#define A1_CLIENT_H

#include <inttypes.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <wordexp.h>

#define SLEEP_TIMER 3
#define DEFAULT_ARGS_NUM 4
#define FILE_INDEX 3
#define PORT_INDEX 2
#define IP_INDEX 1

struct client_opts
{
    char *dest_ip;
    in_port_t dest_port;
    int domain;
};

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
int creat_socket(struct client_opts *opts);
int parse_args(int argc, char *argv[], struct file_info_list *head, struct client_opts *opts);
int get_address_domain(const char *addr);
in_port_t parse_in_port_t(const char *str);
int get_files(int argc, char *argv[], struct file_info_list *head);
int check_files(struct file_info_list *head);
void get_file_infos(struct file_info_list *head);
uint8_t *sanitize_file_name(char *file_path);
int do_send_all(struct file_info_list *head, struct client_opts *opts);
int connect_to_server(int sockfd, struct client_opts *opts);
void free_client_opts(struct client_opts *opts);
void send_file_content(int src_fd, int dest_fd, size_t count);
void setup_socket_address(struct sockaddr_un *addr, struct client_opts *opts);
void free_file_info_list(struct file_info_list *head);

#endif //A1_CLIENT_H
