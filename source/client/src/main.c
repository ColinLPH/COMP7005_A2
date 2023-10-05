#include "client.h"

int main(int argc, char *argv[])
{
    int ret = run_client(argc, argv);
    if(ret == -1)
    {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
