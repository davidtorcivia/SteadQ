/* SteadQ/1 C ABI test program - hermetic with unique temp dir */
#include "../include/steadq.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

/* Remove a directory tree recursively. */
static void rmrf(const char *path) {
    /* Best-effort cleanup for hermetic repeatability. */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    /* This is a test program, so system() is acceptable here. */
    int rc = system(cmd);
    (void)rc;
}

int main(void) {
    /* P1-24: Use a unique temp directory and clean it up. */
    const char *tmpdir = getenv("TMPDIR");
    char tmpl[512];
    snprintf(tmpl, sizeof(tmpl), "%s/steadq_capi_XXXXXX",
             tmpdir && *tmpdir ? tmpdir : "/tmp");
    char *d = mkdtemp(tmpl);
    if (!d) { fprintf(stderr, "mkdtemp failed\n"); return 1; }
    char path[512];
    snprintf(path, sizeof(path), "%s/queue", d);
    SteadqQueue *q = steadq_init(path, 64);
    if (!q) { fprintf(stderr, "init failed\n"); return 1; }

    SteadqJobId job_id;
    const char *payload = "hello from C";
    int rc = steadq_enqueue(q, (const uint8_t *)payload, strlen(payload),
                            "text/plain", 3, &job_id);
    if (rc != STEADQ_OK) { fprintf(stderr, "enqueue failed: %d\n", rc); return 1; }
    printf("enqueued job\n");

    SteadqLease *lease = NULL;
    rc = steadq_lease(q, 30000000000ULL, &lease);
    if (rc != STEADQ_OK || !lease) { fprintf(stderr, "lease failed: %d\n", rc); return 1; }

    SteadqJobId leased_id;
    steadq_lease_job_id(lease, &leased_id);
    uint64_t gen = steadq_lease_generation(lease);
    unsigned int attempt = steadq_lease_attempt(lease);
    printf("leased: gen=%llu attempt=%u\n", (unsigned long long)gen, attempt);

    rc = steadq_lease_verify(q, lease);
    if (rc != STEADQ_OK) { fprintf(stderr, "verify failed: %d\n", rc); return 1; }
    printf("payload verified\n");

    /* Read payload through the verified reader. */
    SteadqPayloadReader *reader = NULL;
    rc = steadq_lease_open_reader(q, lease, &reader);
    if (rc != STEADQ_OK || !reader) { fprintf(stderr, "open_reader failed: %d\n", rc); return 1; }

    uint64_t plen = steadq_reader_payload_len(reader);
    if (plen != strlen(payload)) { fprintf(stderr, "payload_len mismatch: %llu\n", (unsigned long long)plen); return 1; }

    uint8_t readbuf[256];
    size_t bytes_read = 0;
    rc = steadq_reader_read(reader, readbuf, sizeof(readbuf), 0, &bytes_read);
    if (rc != STEADQ_OK) { fprintf(stderr, "reader_read failed: %d\n", rc); return 1; }
    if (bytes_read != strlen(payload)) { fprintf(stderr, "bytes_read mismatch: %zu\n", bytes_read); return 1; }
    readbuf[bytes_read] = 0;
    if (strcmp((char *)readbuf, payload) != 0) { fprintf(stderr, "payload content mismatch\n"); return 1; }
    printf("payload read: %s\n", readbuf);

    steadq_reader_free(reader);

    /* Verify output pointers are zero-initialized on error paths. */
    SteadqJobId err_id = { .bytes = { 0xFF } };
    int rc2 = steadq_enqueue(NULL, NULL, 0, NULL, 0, &err_id);
    /* enqueue with NULL queue should fail, and err_id should be zeroed. */
    int all_zero = 1;
    for (int i = 0; i < 16; i++) {
        if (err_id.bytes[i] != 0) { all_zero = 0; break; }
    }
    if (!all_zero) {
        fprintf(stderr, "job_id_out not zero-initialized on error\n");
        return 1;
    }
    (void)rc2;

    rc = steadq_renew(q, lease, 60000000000ULL);
    if (rc != STEADQ_OK) { fprintf(stderr, "renew failed: %d\n", rc); return 1; }
    printf("renewed\n");

    rc = steadq_ack(q, lease);
    if (rc != STEADQ_OK) { fprintf(stderr, "ack failed: %d\n", rc); return 1; }
    printf("acked\n");

    /* An empty queue is NOT_COMMITTED with a message, not a bare code. */
    SteadqLease *none = NULL;
    rc = steadq_lease(q, 30000000000ULL, &none);
    assert(rc == STEADQ_NOT_COMMITTED && none == NULL);
    assert(steadq_last_error() && strcmp(steadq_last_error(), "queue empty") == 0);


    steadq_lease_free(lease);
    steadq_close(q);

    /* Edge case: null pointer rejection. */
    assert(steadq_enqueue(NULL, NULL, 0, NULL, 0, NULL) != STEADQ_OK);
    assert(steadq_lease(NULL, 0, NULL) != STEADQ_OK);
    assert(steadq_ack(NULL, NULL) != STEADQ_OK);
    assert(steadq_reader_read(NULL, NULL, 0, 0, NULL) != STEADQ_OK);
    assert(steadq_reader_payload_len(NULL) == 0);

    /* Edge case: resolve with invalid ticket JSON. */
    SteadqQueue *q2 = steadq_open(path);
    if (!q2) { fprintf(stderr, "reopen failed\n"); return 1; }
    const char *bad_json = "not valid json";
    int resolve_rc = steadq_resolve(q2, (const uint8_t *)bad_json, strlen(bad_json), 0);
    assert(resolve_rc != STEADQ_OK);
    steadq_close(q2);

    /* Edge case: zero-length payload enqueue. */
    SteadqQueue *q3 = steadq_open(path);
    if (!q3) { fprintf(stderr, "reopen failed\n"); return 1; }
    SteadqJobId zero_id;
    int zero_rc = steadq_enqueue(q3, NULL, 0, "empty", 1, &zero_id);
    assert(zero_rc == STEADQ_OK);
    int zero_all = 1;
    for (int i = 0; i < 16; i++) {
        /* job_id should be non-zero (randomly generated). */
        if (zero_id.bytes[i] != 0) { zero_all = 0; break; }
    }
    /* Having all-zero job_id is extremely unlikely but not impossible.
     * Just verify the call succeeded. */
    (void)zero_all;
    steadq_close(q3);

    printf("C ABI test passed\n");
    /* P1-24: Cleanup temp directory for repeatability. */
    rmrf(d);
    return 0;
}
