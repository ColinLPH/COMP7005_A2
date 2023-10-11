#include <arpa/inet.h>
#include "client.h"

int run_client(int argc, char *argv[])
{
    struct file_info_list *head;
    struct client_opts opts;
    int check;

    head = malloc(sizeof (struct file_info_list)); // DECISION: throw this into a function?
    head->file_info_struct = NULL;
    head->next = NULL;
    head->file_path = NULL;

    memset(&opts, 0, sizeof(struct client_opts));

    check = parse_args(argc, argv, head, &opts); //parse args
    if(check == -1)
    {
        free_file_info_list(head);
        free_client_opts(&opts);
        return check;
    }

    printf("checking files\n");
    check = check_files(head); //check if all files can be opened
    if (check != 0)
    {
        free_client_opts(&opts);
        free_file_info_list(head);
        return -1;
    }
    get_file_infos(head); //compile all the data
    print_list(head);
    check = do_send_all(head, &opts);
    if (check != 0)
    {
        printf("Failed to send files\n");
        free_client_opts(&opts);
        free_file_info_list(head);
        return -1;
    }

    free_file_info_list(head);
    free_client_opts(&opts);
    printf("All files written successfully\n");

    return 0;
}

int parse_args(int argc, char *argv[], struct file_info_list *head, struct client_opts *opts)
{
    //tokenize argv
    //get all the file names
    //store them all into head and all the nexts
    if (argc < DEFAULT_ARGS_NUM)
    {
        printf("Usage: ./client <ip 4 or 6 address to connect to> <port> <files>\n");
        return -1;
    }

    opts->dest_ip = strdup(argv[IP_INDEX]);
    opts->domain = get_address_domain(opts->dest_ip);
    opts->dest_port = parse_in_port_t(argv[PORT_INDEX]);

    if (get_files(argc, argv, head) == -1)
    {
        printf("wordexp failed\n");
        return -1;
    }

    return 0;

}

int get_address_domain(const char *address)
{
    int domain;

    if(strstr(address, ":"))
    {
        domain = AF_INET6;
    }
    else if (strstr(address, "."))
    {
        domain = AF_INET;
    }
    else
    {
        fprintf(stderr, "Invalid IP address \"%s\"\n", address);
        exit(EXIT_FAILURE);
    }

    return domain;

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

int get_files(int argc, char *argv[], struct file_info_list *head)
{
    struct file_info_list *current_node;
    wordexp_t p;
    int ret;

    current_node = head;

    //check if first file arg is expandable
    ret = wordexp(argv[FILE_INDEX], &p, 0);
    if(ret == -1)
    {
        return -1;
    }

    //copy first "expanded" file arg into head->file_path
    current_node->file_path = strdup(p.we_wordv[0]);
    if(p.we_wordc > 1) //if first arg was expandable, iterate thru expanded first arg and store into linked list
    {
        for(size_t i = 1; i < p.we_wordc; ++i)
        {
            current_node->next = malloc(sizeof(struct file_info_list));
            current_node = current_node->next;
            current_node->file_path = strdup(p.we_wordv[i]);
            current_node->file_info_struct = NULL;
            current_node->next = NULL;
        }
    }
    wordfree(&p);

    if(argc > DEFAULT_ARGS_NUM)
    {
        //repeat for rest of file args
        for(int i = FILE_INDEX+1; i < argc; ++i)
        {
            ret = wordexp(argv[i], &p, 0);
            if(ret == 0)
            {
                for (size_t j = 0; j < p.we_wordc; ++j) {
                    current_node->next = malloc(sizeof(struct file_info_list));
                    current_node = current_node->next;
                    current_node->file_path = strdup(p.we_wordv[j]);
                    current_node->file_info_struct = NULL;
                    current_node->next = NULL;
                }
                wordfree(&p);
            }
            else
            {
                return -1;
            }
        }
    }

    return 0;
}

int check_files(struct file_info_list *head)
{
    //check if every file can be opened, return 0 if yes, -1 if no
    //or maybe return the file so that it can be displayed
    struct file_info_list *file_to_check;
    int fd;

    file_to_check = head;
    while(file_to_check != NULL)
    {
        fd = open(file_to_check->file_path, O_RDONLY);
        printf("opening file: %s\n", file_to_check->file_path);
        if(fd == -1)
        {
            printf("failed to open file: %s\n", file_to_check->file_path);
            return -1;
        }
        file_to_check->file_info_struct = malloc(sizeof(struct file_info));
        file_to_check->file_info_struct->filefd = fd;
        file_to_check = file_to_check->next;
    }

    return 0;
}

void get_file_infos(struct file_info_list *head)
{
    struct file_info_list *node;

    node = head;
    while(node != NULL)
    {
        node->file_info_struct->file_name = sanitize_file_name(node->file_path);
        node->file_info_struct->file_name_size = strlen((char *) node->file_info_struct->file_name);

        struct stat st;
        fstat(node->file_info_struct->filefd, &st); //get file size
        node->file_info_struct->file_size = st.st_size;
        node = node->next;
    }

}

uint8_t *sanitize_file_name(char *file_path)
{
    uint8_t *sanitized_name;
    const char *slash = strrchr(file_path, '/');

    if(slash == NULL)
    {
        sanitized_name = (uint8_t *) strdup(file_path);
    }
    else
    {
        sanitized_name = (uint8_t *) strdup(slash+1);
    }

    return sanitized_name;
}

int do_send_all(struct file_info_list *head, struct client_opts *opts)
{
    int sockfd;
    int ret;
    struct file_info_list *node_to_send;
    node_to_send = head;
    sockfd = creat_socket(opts); // socket
    if (sockfd == -1)
    {
        printf("Failed to create socket, closing program\n");
        return -1;
    }

    ret = connect_to_server(sockfd, opts); // connect
    while(node_to_send != NULL)
    {
        if(ret == -1)
        {
            printf("Failed to connect to server, closing program\n");
            return -1;
        }
        send(sockfd, &node_to_send->file_info_struct->file_name_size, 1, 0);
        send(sockfd, node_to_send->file_info_struct->file_name, node_to_send->file_info_struct->file_name_size, 0);
        send(sockfd, &node_to_send->file_info_struct->file_size, sizeof(off_t), 0);
        send_file_content(node_to_send->file_info_struct->filefd, sockfd, node_to_send->file_info_struct->file_size);
        node_to_send = node_to_send->next;

    }
    close(sockfd);
    return 0;
}

int creat_socket(struct client_opts *opts)
{
    int sockfd;

    sockfd = socket(opts->domain, SOCK_STREAM, 0);

    return sockfd;
}

int connect_to_server(int sockfd, struct client_opts *opts)
{
    struct sockaddr_un addr;
    int ret;

    setup_socket_address(&addr, opts);

    ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if(ret == -1)
    {
        printf("Connection failed, trying again in %d seconds...\n", SLEEP_TIMER);
        sleep(SLEEP_TIMER);
        ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
        if (ret == -1)
        {
            return -1;
        }
    }

    printf("Connected to socket: %s:%u\n", opts->dest_ip, opts->dest_port);
    return 0;
}

void setup_socket_address(struct sockaddr_un *addr, struct client_opts *opts)
{
    memset(addr, 0, sizeof(*addr));

    if(inet_pton(opts->domain, opts->dest_ip, &addr) != 1)
    {
        perror("Invalid IP address");
        exit(EXIT_FAILURE);
    }

    if(opts->domain == AF_INET)
    {
        struct sockaddr_in *ipv4_addr;

        ipv4_addr = (struct sockaddr_in *)&addr;
        ipv4_addr->sin_family = AF_INET;
        ipv4_addr->sin_port = htons(opts->dest_port);
    }
    else if(opts->domain == AF_INET6)
    {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr = (struct sockaddr_in6 *)&addr;
        ipv6_addr->sin6_family = AF_INET6;
        ipv6_addr->sin6_port = htons(opts->dest_port);
    }
    else
    {
        fprintf(stderr, "Invalid domain: %d\n", opts->domain);
        exit(EXIT_FAILURE);
    }
}

void send_file_content(int src_fd, int dest_fd, size_t count)
{
    char *buffer;
    ssize_t rbytes;

    buffer = malloc(count);

    if(buffer == NULL)
    {
        perror("malloc\n");
    }

    while((rbytes = read(src_fd, buffer, count)) > 0)
    {
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

void free_file_info_list(struct file_info_list *head)
{
    struct file_info_list * node_to_delete = NULL;

    while(head != NULL)
    {
        node_to_delete = head;
        head = head->next;
        if(node_to_delete->file_path != NULL)
        {
            free(node_to_delete->file_path);
        }
        if(node_to_delete->file_info_struct != NULL)
        {
            if(node_to_delete->file_info_struct->file_name != NULL)
            {
                free(node_to_delete->file_info_struct->file_name);
            }
            close(node_to_delete->file_info_struct->filefd);
            free(node_to_delete->file_info_struct);
        }
        if(node_to_delete != NULL)
        {
            free(node_to_delete);
        }
    }
}

void free_client_opts(struct client_opts *opts)
{
    if(opts->dest_ip != NULL)
    {
        free(opts->dest_ip);
    }
}

void print_list(struct file_info_list *head)
{
    struct file_info_list *node_to_print;
    node_to_print = head;
    while(node_to_print != NULL && node_to_print->file_info_struct != NULL)
    {
        printf("____________________________________\n");
        printf("File Path: %s\n", node_to_print->file_path);
        printf("File fd: %d\n", node_to_print->file_info_struct->filefd);
        printf("File Name: %s\n", node_to_print->file_info_struct->file_name);
        printf("File Name Size: %hhu\n", node_to_print->file_info_struct->file_name_size);
        printf("File Size: %llu\n", node_to_print->file_info_struct->file_size);
        node_to_print = node_to_print->next;
    }
}
