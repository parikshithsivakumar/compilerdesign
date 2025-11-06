
int test_optimizations(int a, int b) {
    int x = a + b;
    int y = a + b;   // redundant
    int z = 3 * 4;   // constant foldable
    int w = z;       // dead code
    for (int i = 0; i < 10; i++) {
        int p = a + b;  // loop invariant
    }
    return x + y;
}
