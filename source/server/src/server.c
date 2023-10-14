#include <arpa/inet.h>
#include "server.h"

/* things to change
    - take in new args
    - change to tcp
    - implement i/o multiplexing
*/
static volatile sig_atomic_t exit_flag = 0;

int run_server(int argc, char *argv[])
{
    //parse args, create directory to store files
    //sock, bind, listen, accept
    struct server_options opts;
    int bindfd;
    int *client_sockets = NULL;
    size_t max_clients = 0;
    int max_fd, activity, new_socket, sd;
    int addrlen;
    struct sockaddr_un address;
    fd_set readfds;

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

    bindfd = creat_socket(opts.domain, SOCK_STREAM, 0);
    if(bindfd == -1)
    {
        free(opts.dir_path);
        return -1;
    }

    if(do_bind(bindfd, &opts) == -1)
    {
        free(opts.dir_path);
        return -1;
    }

    if(do_listen(bindfd, SOMAXCONN) == -1)
    {
        free(opts.dir_path);
        return -1;
    }
    free(opts.host_ip);
    setup_signal_handler();
    while(!exit_flag)
    {
        // Clear the socket set
        FD_ZERO(&readfds);

        // Add the server socket to the set
        FD_SET((unsigned int)bindfd, &readfds);
        max_fd = bindfd;

        // Add the client sockets to the set
        for(size_t i = 0; i < max_clients; i++)
        {
            sd = client_sockets[i];

            if(sd > 0)
            {
                FD_SET((unsigned int)sd, &readfds);
            }

            if(sd > max_fd)
            {
                max_fd = sd;
            }
        }

        // Use select to monitor sockets for read readiness
        activity = select(max_fd + 1, &readfds, NULL, NULL, NULL);

        if(activity < 0)
        {
            perror("Select error");
            return -1;
        }

        // Handle new client connections
        if(FD_ISSET((unsigned int)bindfd, &readfds))
        {
            if((new_socket = accept(bindfd, (struct sockaddr *) &address, (socklen_t * ) & addrlen)) == -1)
            {
                perror("Accept error");
                return -1;
            }

            printf("New connection established\n");

            // Increase the size of the client_sockets array
            max_clients++;
            client_sockets = (int *)realloc(client_sockets, sizeof(int) * max_clients);
            client_sockets[max_clients - 1] = new_socket;
        }

        // Handle incoming data from existing clients
        for(size_t i = 0; i < max_clients; i++)
        {
            sd = client_sockets[i];

            if(FD_ISSET((unsigned int)sd, &readfds))
            {
                //handle data in
                handle_data_in(sd, &opts, &readfds, client_sockets, i);
            }
        }

    }

    // Cleanup and close all client sockets
    for(size_t i = 0; i < max_clients; i++)
    {
        sd = client_sockets[i];
        if(sd > 0)
        {
            socket_close(sd);
        }
    }

    free_server_opts(&opts);
    // Free the client_sockets array
    free(client_sockets);
    socket_close(bindfd);
    printf("Server exited successfully.\n");
    return 0;
}

int parse_args(struct server_options *opts, int argc, char *argv[])
{
    if(argc != SERVER_ARGS)
    {
        printf("Usage: ./server/build <ip4 or ip6 addr to bind to> <port> <dir to store in>\n");
        return -1;
    }

    opts->host_ip = strdup(argv[IP_INDEX]);
    if(set_domain(opts) == -1)
    {
        free(opts->host_ip);
        return -1;
    }

    char *path = argv[DIR_INDEX];
    printf("Pre-Sanitized Path: %s\n", path);
    sanitize_path(path);
    printf("Sanitized Path: %s\n", path);
    opts->dir_path = path;

    opts->host_port = parse_in_port_t(argv[PORT_INDEX]);

    printf("---------------------------- Server Options ----------------------------\n");
    printf("Server IP Address: %s\n", opts->host_ip);
    printf("Server Domain: %d\n", opts->domain);
    printf("Server Port: %hu\n", opts->host_port);
    printf("Server Directory: %s\n", opts->dir_path);
    printf("---------------------------- Server Options ----------------------------\n");

    return 0;

}

int set_domain(struct server_options *opts)
{
    if(opts->host_ip == NULL)
    {
        printf("no host ip\n");
        return -1;
    }
    if(strrchr(opts->host_ip, ':') != NULL)
    {
        printf("IPv4\n");
        opts->domain = AF_INET6;
        return 0;
    }
    else if(strrchr(opts->host_ip, '.') != NULL)
    {
        printf("IPv6\n");
        opts->domain = AF_INET;
        return 0;
    }
    else
    {
        printf("neither a ipv4 nor a ipv6 address\n");
        return -1;
    }
}

in_port_t parse_in_port_t(const char *str)
{
    char *endptr;
    uintmax_t parsed_value;

    parsed_value = strtoumax(str, &endptr, 10);

    if (errno != 0)
    {
        perror("Error parsing in_port_t");
        exit(EXIT_FAILURE);
    }

    // Check if there are any non-numeric characters in the input string
    if (*endptr != '\0')
    {
        printf("Invalid characters in input.\n");
    }

    // Check if the parsed value is within the valid range for in_port_t
    if (parsed_value > UINT16_MAX)
    {
        printf("in_port_t value out of range.\n");
    }

    return (in_port_t)parsed_value;
}

int is_valid_char(const char c) {
    return isalnum(c) || c == '_' || c == '-' || c == '/' || c == '.';
}

void sanitize_path(char *path)
{
    wordexp_t p;

    //change path so that it's a valid dir path
    size_t len = strlen(path);

    for(size_t i = 0; i < len; ++i)
    {
        if(is_valid_char(path[i]) == 0)
        {
            path[i] = '-';
        }
    }

    if(wordexp(path, &p, 0) != 0)
    {
        printf("bad wordexp\n");
    }
    printf("expanded str: %s\n", p.we_wordv[0]);
    path = strdup(p.we_wordv[0]);
    wordfree(&p);
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

int creat_socket(int domain, int type, int options)
{
    int sockfd;

    sockfd = socket(domain, type, options);

    if(sockfd == -1)
    {
        perror("Socket creation failed");
        return -1;
    }

    return sockfd;
}

int do_bind(int bindfd, struct server_options *opts)
{
    struct sockaddr_in ipv4_addr;
    struct sockaddr_in6 ipv6_addr;

    memset(&ipv4_addr, 0, sizeof(ipv4_addr));
    memset(&ipv6_addr, 0, sizeof(ipv6_addr));

    if(opts->domain == AF_INET)
    {
        if(inet_pton(opts->domain, opts->host_ip, &ipv4_addr.sin_addr) != 1)
        {
            perror("Invalid IP address");
            return -1;
        }
        ipv4_addr.sin_family = AF_INET;
        ipv4_addr.sin_port = htons(opts->host_port);
        if(bind(bindfd, (struct sockaddr *)&ipv4_addr, sizeof(ipv4_addr)) == -1)
        {
            perror("Binding failed");
            return -1;
        }
    }
    else if(opts->domain == AF_INET6)
    {
        if(inet_pton(opts->domain, opts->host_ip, &ipv6_addr.sin6_addr) != 1)
        {
            perror("Invalid IP address");
            return -1;
        }
        ipv6_addr.sin6_family = AF_INET6;
        ipv6_addr.sin6_port = htons(opts->host_port);
        if(bind(bindfd, (struct sockaddr *)&ipv6_addr, sizeof(ipv6_addr)) == -1)
        {
            perror("Binding failed");
            return -1;
        }
    }
    else
    {
        fprintf(stderr, "Invalid domain: %d\n", opts->domain);
        return -1;
    }

    printf("Bound to socket: %s:%u\n", opts->host_ip, opts->host_port);
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

void handle_data_in(int client_fd, struct server_options *opts, fd_set *readfds, int *client_sockets, size_t i)
{
    struct file_info file;
    ssize_t rbytes;

        memset(&file, 0, sizeof(struct file_info));
        rbytes = read(client_fd, &file.file_name_size, 1);
        if(rbytes <= 0)
        {
              // Connection closed or error
              printf("Client %d disconnected\n", client_fd);
              close(client_fd);
              FD_CLR((unsigned int)client_fd, readfds); // Remove the closed socket from the set
              client_sockets[i] = 0;

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
        rbytes = read(client_fd, file.file_name, file.file_name_size);
        if(rbytes <= 0)
        {
            // Connection closed or error
            printf("Client %d disconnected\n", client_fd);
            close(client_fd);
            FD_CLR((unsigned int)client_fd, readfds); // Remove the closed socket from the set
            client_sockets[i] = 0;
        }
        file.file_name[file.file_name_size] = '\0';
        printf("File name: %s\n", file.file_name);

        //read file_size
        rbytes = read(client_fd, &file.file_size, sizeof(file.file_size));
        if(rbytes <= 0)
        {
            // Connection closed or error
            printf("Client %d disconnected\n", client_fd);
            close(client_fd);
            FD_CLR((unsigned int)client_fd, readfds); // Remove the closed socket from the set
            client_sockets[i] = 0;

        }
        printf("File size: %lld\n", file.file_size);

        //create file
        printf("Creating file...\n");
        create_file(opts, &file);
        //copy file content over to created file
        copy_paste(client_fd, file.filefd, file.file_size);
        printf("File contents copied\n");
        close(file.filefd);
        free(file.file_name);
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

void socket_close(int fd)
{
    if (close(fd) == -1)
    {
        perror("Error closing socket");
        exit(EXIT_FAILURE);
    }
}

void free_server_opts(struct server_options *opts)
{
    free(opts->dir_path);
    free(opts->host_ip);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void sigint_handler(int signum)
{
    printf("\nsigint_handler triggered\n");
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
