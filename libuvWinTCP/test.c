#include <stdio.h>

int main(int argc, char **argv) {
    // Print the program name (first argument)
    printf("Program name: %s\n", argv[0]);

    // Print the number of command-line arguments
    printf("Argument count: %d\n", argc);

    // Print additional command-line arguments (if any)
    for (int i = 1; i < argc; i++) {
        printf("Argument %d: %s\n", i, argv[i]);
    }

    // Your socket programming code can follow here...

    return 0;
}
