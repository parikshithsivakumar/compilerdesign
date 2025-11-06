#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void risky_delete(const char *file) {}

int compute(int a, int b) {
    int x = a + b;
    int y = x * 2;
    int z = x + 0;
    int total = 0;
    int limit = 5;
    int unused_var = 42; // dead code

    for (int i = 0; i < limit; i++) {
        total = total + (a + b);
    }
    return total + y + z;
}