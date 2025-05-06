#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Ackermann function (complex recursion)
int ackermann(int m, int n) {
    if (m == 0) return n + 1;
    if (n == 0) return ackermann(m - 1, 1);
    return ackermann(m - 1, ackermann(m, n - 1));
}

// Hybrid bubble/quick sort
void bubble_sort(int* arr, int size) {
    for (int i = 0; i < size - 1; i++)
        for (int j = 0; j < size - i - 1; j++)
            if (arr[j] > arr[j + 1]) {
                int t = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = t;
            }
}

// Dynamic 2D array + pointer manipulation
int** create_matrix(int rows, int cols) {
    int** mat = malloc(rows * sizeof(int*));
    for (int i = 0; i < rows; i++)
        mat[i] = malloc(cols * sizeof(int));
    return mat;
}

void fill_matrix(int** mat, int rows, int cols) {
    int val = 0;
    for (int i = 0; i < rows; i++)
        for (int j = 0; j < cols; j++)
            mat[i][j] = val++;
}

void free_matrix(int** mat, int rows) {
    for (int i = 0; i < rows; i++)
        free(mat[i]);
    free(mat);
}

// File I/O + String Ops
void process_file() {
    FILE* f = fopen("testfile.txt", "w");
    for (int i = 0; i < 50; i++)
        fprintf(f, "Line %d\n", i);
    fclose(f);

    f = fopen("testfile.txt", "r");
    char buffer[128];
    int lines = 0;
    while (fgets(buffer, sizeof(buffer), f)) {
        lines++;
    }
    fclose(f);
    printf("Lines read: %d\n", lines);
}

void pointer_playground() {
    int x = 42;
    int* px = &x;
    int** ppx = &px;
    **ppx = **ppx + 10;
    printf("Pointer value: %d\n", x);
}

void string_ops() {
    char name[50] = "Hello";
    strcat(name, ", ");
    strcat(name, "world!");
    printf("%s\n", name);
}

int main() {
    // Ackermann (limited depth for performance)
    printf("Ack(2, 2): %d\n", ackermann(2, 2));

    // Sorting
    int arr[10] = {9, 2, 7, 5, 6, 3, 8, 1, 4, 0};
    bubble_sort(arr, 10);

    // Matrix
    int** matrix = create_matrix(10, 10);
    fill_matrix(matrix, 10, 10);
    free_matrix(matrix, 10);

    // File & string
    process_file();
    string_ops();
    pointer_playground();

    return 0;
}
