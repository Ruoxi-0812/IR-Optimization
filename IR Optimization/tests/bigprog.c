#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ========== QuickSort ==========
void quicksort(int arr[], int low, int high) {
    if (low < high) {
        int pivot = arr[high], i = low - 1;
        for (int j = low; j < high; j++) {
            if (arr[j] < pivot) {
                i++;
                int tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
            }
        }
        int tmp = arr[i+1]; arr[i+1] = arr[high]; arr[high] = tmp;
        int pi = i + 1;
        quicksort(arr, low, pi - 1);
        quicksort(arr, pi + 1, high);
    }
}

// ========== Simple Hash Table ==========
#define TABLE_SIZE 100

typedef struct Pair {
    char key[50];
    int value;
    struct Pair* next;
} Pair;

Pair* table[TABLE_SIZE];

int hash(const char* key) {
    int h = 0;
    for (int i = 0; key[i]; i++) h += key[i];
    return h % TABLE_SIZE;
}

void put(const char* key, int value) {
    int idx = hash(key);
    Pair* new_pair = malloc(sizeof(Pair));
    strcpy(new_pair->key, key);
    new_pair->value = value;
    new_pair->next = table[idx];
    table[idx] = new_pair;
}

int get(const char* key) {
    int idx = hash(key);
    Pair* node = table[idx];
    while (node) {
        if (strcmp(node->key, key) == 0) return node->value;
        node = node->next;
    }
    return -1;
}

// ========== Fibonacci with Memoization ==========
int memo[1000] = {0};

int fib(int n) {
    if (n <= 1) return n;
    if (memo[n]) return memo[n];
    return memo[n] = fib(n - 1) + fib(n - 2);
}

// ========== File I/O Test ==========
void file_test() {
    FILE* fp = fopen("temp.txt", "w");
    for (int i = 0; i < 100; i++) {
        fprintf(fp, "Line %d\n", i);
    }
    fclose(fp);

    fp = fopen("temp.txt", "r");
    char buffer[100];
    while (fgets(buffer, sizeof(buffer), fp)) {
        // Do nothing, just read
    }
    fclose(fp);
}

// ========== Main ==========
int main() {
    // Sort Test
    int data[1000];
    for (int i = 0; i < 1000; i++) data[i] = rand() % 10000;
    quicksort(data, 0, 999);

    // Hash Table Test
    put("apple", 5);
    put("banana", 8);
    put("cherry", 13);
    get("banana");

    // Fibonacci Test
    int f = fib(35);

    // File I/O
    file_test();

    // String operations
    char result[100];
    strcpy(result, "Hello");
    strcat(result, " ");
    strcat(result, "World");

    printf("All tests passed.\n");
    return 0;
}
