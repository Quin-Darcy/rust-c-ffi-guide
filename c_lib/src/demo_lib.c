#include <stdlib.h>
#include "../include/demo_lib.h"

char* allocate_buffer(int size)
{
    if (size <= 0) {
        return NULL;
    }

    return (char*)malloc(size);
}

int fill_buffer(char* buffer, int size)
{
    if (buffer == NULL || size <= 0) {
        return -1;
    }

    for (int i = 0; i < size; i++) {
        buffer[i] = (char)(i % 256);
    }

    return size;
}

int free_buffer(char* buffer)
{
    if (buffer == NULL) {
        return -1;
    }

    free(buffer);
    return 0;
}
