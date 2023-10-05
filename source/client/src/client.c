#include "client.h"

int run_client(int argc, char *argv[])
{
    struct file_info_list *head;
    int check;

    head = malloc(sizeof (struct file_info_list)); // DECISION: throw this into a function?
    head->file_info_struct = NULL;
    head->next = NULL;
    head->file_path = NULL;

    check = parse_args(argc, argv, head); //parse args
    if(check == -1)
    {
        printf("At least one file must be provided\n");
        free_file_info_list(head);
        return check;
    }

    printf("checking files\n");
    check = check_files(head); //check if all files can be opened
    if (check != 0)
    {
        printf("Error: the file \"%s\" could not be opened\n", argv[check]);
        free_file_info_list(head);
        return -1;
    }
    get_file_infos(head); //compile all the data
    print_list(head);
    check = do_send_all(head);
    if (check != 0)
    {
        printf("Failed to send files\n");
        free_file_info_list(head);
        return -1;
    }

    free_file_info_list(head);
    printf("All files written successfully\n");

    return 0;
}

int parse_args(int argc, char *argv[], struct file_info_list *head)
{
    //tokenize argv
    //get all the file names
    //store them all into head and all the nexts
    if (argc == 1)
    {
        //no files were passed
        return -1;
    }

    head->file_path = strdup(argv[1]);
    if (argc > 2)
    {
        printf("more file paths detected\n");
        struct file_info_list *current_node;
        int num;

        current_node = head;
        num = 2;
        while(num != argc)
        {
            current_node->next = malloc(sizeof(struct file_info_list));
            current_node = current_node->next;
            current_node->file_path = strdup(argv[num]);
            current_node->file_info_struct = NULL;
            current_node->next = NULL;
            ++num;
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
    int num;

    num = 0;
    file_to_check = head;
    while(file_to_check != NULL)
    {
        fd = open(file_to_check->file_path, O_RDONLY);
        printf("opening file: %s\n", file_to_check->file_path);
        ++num;
        if(fd == -1)
        {
            return num;
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

int do_send_all(struct file_info_list *head)
{
    int sockfd;
    int ret;
    struct file_info_list *node_to_send;
    node_to_send = head;
    sockfd = creat_socket(); // socket
    if (sockfd == -1)
    {
        printf("Failed to create socket, closing program\n");
        return -1;
    }

    ret = connect_to_server(sockfd); // connect
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

int creat_socket(void)
{
    int sockfd;

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);

    return sockfd;
}

int connect_to_server(int sockfd)
{
    struct sockaddr_un addr;
    int ret;

    setup_socket_address(&addr);

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

    printf("Connected to %s\n", DOMAIN_PATH);
    return 0;
}

void setup_socket_address(struct sockaddr_un *addr)
{
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    strncpy(addr->sun_path, DOMAIN_PATH, sizeof(addr->sun_path) - 1);
    addr->sun_path[sizeof(addr->sun_path) - 1] = '\0';
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
            free(node_to_delete->file_info_struct);
        }
        if(node_to_delete != NULL)
        {
            free(node_to_delete);
        }
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
