#include "server.h"

int main(int argc, char *argv[]) {
    if(run_server(argc, argv) == -1)
    {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
