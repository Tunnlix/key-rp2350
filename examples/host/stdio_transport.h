#ifndef CTAPHID_HOST_STDIO_TRANSPORT_H
#define CTAPHID_HOST_STDIO_TRANSPORT_H

/* Run the host-only binary report loop. stdin/stdout carry unprefixed 64-byte
 * CTAPHID reports (no OS HID report-ID byte); diagnostics use stderr.
 * Returns zero on clean EOF, nonzero on truncated input or transport failure. */
int ctaphid_host_run_stdio(const char *presence_control_directory, const char *storage_directory);

#endif
