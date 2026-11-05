/* The target. Documented behaviour:
 *   total = sum(values[i] * (i + 1))
 *   verdict = "tamper" when total is a multiple of 7, else "clean"
 *   prints "<total> <verdict>", exits 0
 *   exits 2 with no arguments
 */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    long total = 0;
    for (int i = 1; i < argc; i++) {
        total += strtol(argv[i], NULL, 10) * (i + 1);
    }
    printf("%ld %s\n", total, (total % 7 == 0) ? "tamper" : "clean");
    return 0;
}
