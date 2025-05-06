#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SIZE 100

// Matrix multiplication
void matrix_multiply(int A[SIZE][SIZE], int B[SIZE][SIZE], int C[SIZE][SIZE]) {
    for (int i = 0; i < SIZE; i++)
        for (int j = 0; j < SIZE; j++) {
            C[i][j] = 0;
            for (int k = 0; k < SIZE; k++)
                C[i][j] += A[i][k] * B[k][j];
        }
}

// Bubble Sort
void bubble_sort(int arr[], int n) {
    for (int i = 0; i < n-1; i++)
        for (int j = 0; j < n-i-1; j++)
            if (arr[j] > arr[j+1]) {
                int temp = arr[j];
                arr[j] = arr[j+1];
                arr[j+1] = temp;
            }
}

// String Concatenation
void concat_strings(char *dest, const char *src1, const char *src2) {
    strcpy(dest, src1);
    strcat(dest, src2);
}

// Sieve of Eratosthenes
void sieve(int n) {
    int prime[n+1];
    memset(prime, 1, sizeof(prime));
    for (int p = 2; p*p <= n; p++) {
        if (prime[p]) {
            for (int i = p*p; i <= n; i += p)
                prime[i] = 0;
        }
    }
}

// Linked List Operations
typedef struct Node {
    int data;
    struct Node* next;
} Node;

void append(Node** head_ref, int new_data) {
    Node* new_node = (Node*)malloc(sizeof(Node));
    Node* last = *head_ref;
    new_node->data = new_data;
    new_node->next = NULL;
    if (*head_ref == NULL) {
        *head_ref = new_node;
        return;
    }
    while (last->next != NULL)
        last = last->next;
    last->next = new_node;
}

void print_list(Node* node) {
    while (node != NULL) {
        printf("%d -> ", node->data);
        node = node->next;
    }
    printf("NULL\n");
}

// Main Function
int main() {
    // Matrix test
    int A[SIZE][SIZE], B[SIZE][SIZE], C[SIZE][SIZE];
    for (int i = 0; i < SIZE; i++)
        for (int j = 0; j < SIZE; j++) {
            A[i][j] = i + j;
            B[i][j] = i - j;
        }
    matrix_multiply(A, B, C);

    // Sorting test
    int arr[SIZE];
    for (int i = 0; i < SIZE; i++)
        arr[i] = SIZE - i;
    bubble_sort(arr, SIZE);

    // String test
    char result[200];
    concat_strings(result, "Hello, ", "World!");

    // Sieve test
    sieve(100);

    // Linked list test
    Node* head = NULL;
    for (int i = 0; i < 10; i++)
        append(&head, i);
    print_list(head);

    return 0;
}
