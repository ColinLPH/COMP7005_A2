#ifndef A1_SERVER_H
#define A1_SERVER_H

#include <ctype.h>
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

#define DOMAIN_PATH "/tmp/dompath"
#define SERVER_BACKLOG 5

struct server_options
{
    char *dir_path;
};

struct file_info {
    int filefd;
    uint8_t file_name_size;
    char *file_name;
    off_t file_size;
};

int run_server(int argc, char *argv[]);
int parse_args(struct server_options *opts, int argc, char *argv[]);
int is_valid_char(char c);
void sanitize_path(char *path);
int make_dir(char *dir_path);
int creat_socket(void);
int do_bind(int bindfd);
int do_listen(int bindfd, int backlog);
void handle_connection(int acceptfd, struct sockaddr_storage *client_addr, struct server_options *opts);
int create_file(struct server_options *opts, struct file_info *file);
void copy_paste(int src_fd, int dest_fd, int64_t count);
char *generate_file_name(char *dir_path, char *file_name);
static void setup_signal_handler(void);

#endif //A1_SERVER_H
