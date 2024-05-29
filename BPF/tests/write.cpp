#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("Started\n");
    FILE *file = fopen("example.txt", "w");
    printf("Opened\n");
    if (file == NULL) {
        printf("Error creating file\n");
        return 1;
    }
    fprintf(file, "File writing example program\n");
    printf("Written\n");
    fclose(file);
    printf("Closed\n");
    
    return 0;
}