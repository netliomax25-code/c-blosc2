#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <blosc2.h>

/* Test for dictionary-enabled compression with insufficient output buffer.
 * Reproduces an OOB write that occurred when dict_training is enabled and
 * destsize is too small.
 */

int main(void) {
    // Allocate 1 MiB source
    size_t srcsize = 1024 * 1024;
    uint8_t* src = (uint8_t*)malloc(srcsize);
    if (!src) {
        fprintf(stderr, "Failed to allocate source buffer\n");
        return 1;
    }
    memset(src, 42, srcsize);

    // Test with increasingly small destination buffers
    int test_destsize[] = {40, 64, 256, 1024};
    int num_tests = sizeof(test_destsize) / sizeof(test_destsize[0]);
    int pass_count = 0;

    for (int t = 0; t < num_tests; t++) {
        int destsize = test_destsize[t];
        uint8_t* dest = (uint8_t*)malloc(destsize);
        if (!dest) {
            fprintf(stderr, "Failed to allocate dest buffer for test %d\n", t);
            continue;
        }

        // Configure blosc context with dictionary enabled
        blosc2_cparams cparams = BLOSC2_CPARAMS_DEFAULTS;
        cparams.compcode = BLOSC_LZ4;
        cparams.clevel = 5;
        cparams.use_dict = 1;
        cparams.nthreads = 1;

        blosc2_context* ctx = blosc2_create_cctx(cparams);
        if (!ctx) {
            fprintf(stderr, "Failed to create context for test %d\n", t);
            free(dest);
            continue;
        }

        // Attempt compression with small dest buffer
        int rc = blosc2_compress_ctx(ctx, src, srcsize, dest, destsize);

        // Verify result: must return BLOSC2_ERROR_WRITE_BUFFER when buffer is too small
        // ASAN should not detect any heap-buffer-overflow
        if (rc == BLOSC2_ERROR_WRITE_BUFFER) {
            fprintf(stdout, "Test %d (destsize=%d): PASS (rc=%d)\n", t, destsize, rc);
            pass_count++;
        } else {
            fprintf(stdout, "Test %d (destsize=%d): FAIL (rc=%d)\n", t, destsize, rc);
        }

        blosc2_free_ctx(ctx);
        free(dest);
    }

    free(src);

    if (pass_count == num_tests) {
        fprintf(stdout, "All tests passed\n");
        return 0;
    } else {
        fprintf(stdout, "Some tests failed: %d/%d\n", pass_count, num_tests);
        return 1;
    }
}
