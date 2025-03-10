#include <stdio.h>
#include <stdlib.h>
#include <math.h>

int unused_function(int a) {
    return a * a;
}

int fibonacci(int n) {
    if (n <= 1) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

double average(int arr[], int size) {
    int sum = 0;
    for (int i = 0; i < size; i++) {
        sum += arr[i];
    }
    return (double)sum / size;
}

int main() {
    int x = 10;
    int y = 20;

    int redundant1 = x + y;  
    int redundant2 = redundant1 * 2; 
    int z = x + y;  

    printf("Sum of %d and %d is: %d\n", x, y, z);

    int size = 5;
    int* arr = (int*)malloc(size * sizeof(int));
    for (int i = 0; i < size; i++) {
        arr[i] = i + 1;
    }

    double avg = average(arr, size);
    printf("Average of array: %.2f\n", avg);

    int fib = fibonacci(5);
    printf("Fibonacci(5): %d\n", fib);

    if (x > y && y > 0) { 
        printf("This branch is unreachable.\n");
    }

    for (int i = 0; i < 0; i++) {  
        printf("This will never print.\n");
    }

    if (x == y) {
        printf("%d equals %d\n", x, y);
    } else if (x > y) {
        printf("%d is greater than %d\n", x, y);
    } else {
        printf("%d is less than %d\n", x, y);
    }
    
    free(arr);

    return 0;
}
