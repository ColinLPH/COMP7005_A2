#ifndef A1_SERVER_H
#define A1_SERVER_H

#include <ctype.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <wordexp.h>


#define DOMAIN_PATH "/tmp/dompath"
#define SERVER_BACKLOG 5
#define SERVER_ARGS 4
#define DIR_INDEX 3
#define PORT_INDEX 2
#define IP_INDEX 1

struct server_options
{
    char *host_ip;
    int domain;
    char *dir_path;
    in_port_t host_port;
};

struct file_info {
    int filefd;
    uint8_t file_name_size;
    char *file_name;
    off_t file_size;
};

int run_server(int argc, char *argv[]);
int parse_args(struct server_options *opts, int argc, char *argv[]);
int set_domain(struct server_options *opts);
in_port_t parse_in_port_t(const char *str);
int is_valid_char(char c);
void sanitize_path(char *path);
int make_dir(char *dir_path);
int creat_socket(int domain, int type, int options);
int do_bind(int bindfd, struct server_options *opts);
int do_listen(int bindfd, int backlog);
//void handle_connection(int acceptfd, struct sockaddr_storage *client_addr, struct server_options *opts);
void handle_data_in(int client_fd, struct server_options *opts, fd_set *readfds, int *client_sockets, size_t i);
int create_file(struct server_options *opts, struct file_info *file);
void copy_paste(int src_fd, int dest_fd, int64_t count);
char *generate_file_name(char *dir_path, char *file_name);
void socket_close(int fd);
static void setup_signal_handler(void);

#endif //A1_SERVER_H
