#include <unistd.h>
#include <stdio.h>

int main(void) {
    if (setuid(0) != 0) {
        perror("setuid failed");
        return 1;
    }
    printf("meow! this process got uid = 0! and exited\n");
    return 0;
}