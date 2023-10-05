#include "server.h"

static volatile sig_atomic_t exit_flag = 0;

int run_server(int argc, char *argv[])
{
    //parse args, create directory to store files
    //sock, bind, listen, accept
    struct server_options opts;
    int bindfd;

    unlink(DOMAIN_PATH);

    memset(&opts, 0, sizeof(struct server_options));

    if(parse_args(&opts, argc, argv) == -1)
    {
        return -1;
    }

    if(make_dir(opts.dir_path) == -1)
    {
        free(opts.dir_path);
        return -1;
    }

    bindfd = creat_socket();
    if(bindfd == -1)
    {
        free(opts.dir_path);
        return -1;
    }

    if(do_bind(bindfd) == -1)
    {
        free(opts.dir_path);
        return -1;
    }

    if(do_listen(bindfd, SERVER_BACKLOG) == -1)
    {
        free(opts.dir_path);
        return -1;
    }

    setup_signal_handler();
    while(!exit_flag)
    {
        int acceptfd;
        struct sockaddr_storage client_addr;
        socklen_t client_addr_len;

        client_addr_len = sizeof(client_addr);
        acceptfd = accept(bindfd, (struct sockaddr *)&client_addr, &client_addr_len);
        if(acceptfd == -1)
        {
            if(exit_flag)
            {
                break;
            }
            perror("Error accepting incoming connection!\n");
            continue;
        }
        printf("Going to handle connection...\n");
        handle_connection(acceptfd, &client_addr, &opts);
        close(acceptfd);
    }

    free(opts.dir_path);
    close(bindfd);
    unlink(DOMAIN_PATH);

    return 0;
}

int parse_args(struct server_options *opts, int argc, char *argv[])
{
    if(argc == 1)
    {
        perror("Must provide a directory to store files in\n");
        return -1;
    }
    if(argc > 2)
    {
        perror("Must provide only one directory to store files in\n");
        return -1;
    }
    char *path = strdup(argv[1]);
    printf("Pre-Sanitized Path: %s\n", path);
    sanitize_path(path);
    printf("Sanitized Path: %s\n", path);
    opts->dir_path = path;
    return 0;

}

int is_valid_char(const char c) {
    return isalnum(c) || c == '_' || c == '-' || c == '/' || c == '.';
}

void sanitize_path(char *path)
{
    //change path so that it's a valid dir path
    size_t len = strlen(path);
    for(size_t i = 0; i < len; ++i)
    {
        if(is_valid_char(path[i]) == 0)
        {
            path[i] = '-';
        }
    }
}

int make_dir(char *dir_path)
{
    printf("Creating dir: %s\n", dir_path);
    if(mkdir(dir_path, S_IRWXU) == -1)
    {
        if(errno != EEXIST)
        {
            perror("Error creating directory\n");
            return -1;
        }
        printf("Directory already exists, moving on\n");

    }
    return 0;
}

int creat_socket(void)
{
    int sockfd;

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);

    if(sockfd == -1)
    {
        perror("Socket creation failed");
        return -1;
    }

    return sockfd;
}

int do_bind(int bindfd)
{

    struct sockaddr_un addr;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, DOMAIN_PATH, sizeof(addr.sun_path) - 1);
    addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';
     if(bind(bindfd, (struct sockaddr*)&addr, sizeof(addr)) == -1)
     {
         perror("bind");
         return -1;
     }

     printf("Bound to domain socket: %s\n", DOMAIN_PATH);
     return 0;

}

int do_listen(int bindfd, int backlog)
{
    if(listen(bindfd, backlog) == -1)
    {
        perror("Listen failed\n");
        close(bindfd);
        return -1;
    }
    printf("Listening for incoming connections...\n");
    return 0;
}

void handle_connection(int acceptfd, struct sockaddr_storage *client_addr, struct server_options *opts)
{
    struct file_info file;
    ssize_t rbytes;

    //read file_name_size
    while(!exit_flag)
    {
        memset(&file, 0, sizeof(struct file_info));
        rbytes = read(acceptfd, &file.file_name_size, 1);
        if(rbytes <= 0)
        {
            break;
        }
        printf("-------------------------------------------\n");
        printf("File name size: %d\n", file.file_name_size);

        //read file_name
        file.file_name = malloc(file.file_name_size+1);
        if(file.file_name == NULL)
        {
            printf("error malloc-ing\n");
            return;
        }
        read(acceptfd, file.file_name, file.file_name_size);
        file.file_name[file.file_name_size] = '\0';
        printf("File name: %s\n", file.file_name);

        //read file_size
        read(acceptfd, &file.file_size, sizeof(file.file_size));
        printf("File size: %lld\n", file.file_size);

        //create file
        printf("Creating file...\n");
        create_file(opts, &file);
        //copy file content over to created file
        copy_paste(acceptfd, file.filefd, file.file_size);
        printf("File contents copied\n");
        close(file.filefd);
        free(file.file_name);
    }
    printf("Client disconnected\n");

}

int create_file(struct server_options *opts, struct file_info *file)
{
    char *final_path;
    final_path = generate_file_name(opts->dir_path, file->file_name);

    file->filefd = open(final_path, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU);
    if(file->filefd == -1)
    {
        printf("Failed to create file, file path: %s\n", final_path);
        free(final_path);
        return -1;
    }
    printf("Created file with path: %s\n", final_path);
    free(final_path);

    return 0;
}

char *generate_file_name(char *dir_path, char *file_name)
{
    char *final_path;
    size_t dir_len;
    size_t file_len;
    size_t final_len;

    dir_len = strlen(dir_path);
    file_len = strlen(file_name);

    final_len = dir_len + file_len + 2;
    final_path = malloc(final_len);

    strcpy(final_path, dir_path);
    final_path[dir_len] = '/';
    strcpy(&final_path[dir_len+1], file_name);

    printf("Final file path: %s\n", final_path);

    return final_path;
}

void copy_paste(int src_fd, int dest_fd, int64_t count)
{
    char *buffer;
    ssize_t rbytes;
    ssize_t index;

    buffer = malloc(count);

    if(buffer == NULL)
    {
        perror("malloc\n");
        return;
    }

    rbytes = 0;
    index = 0;
    while(rbytes < count)
    {
        count -= rbytes;
        index += rbytes;
        rbytes = read(src_fd, &buffer[index], count);
        if(rbytes == -1)
        {
            perror("read\n");
        }
        ssize_t wbytes;

        wbytes = write(dest_fd, buffer, rbytes);

        if(wbytes == -1)
        {
            perror("write\n");
        }
    }

    if(rbytes == -1)
    {
        perror("read\n");
    }

    free(buffer);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void sigint_handler(int signum)
{
    exit_flag = 1;
}
#pragma GCC diagnostic pop

static void setup_signal_handler(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if(sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}
