#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "uv.h"
#include "logdigest.h"

#define DEFAULT_PORT 7000
#define DEFAULT_IP "140.92.164.67" // Change this to your server IP if needed
#define SEND_INTERVAL_MS 1000      // Adjust the interval as needed, 1 milisecond per 1 xml writing for default

uv_loop_t *loop;
uv_tcp_t client_socket;
struct sockaddr_in dest;
uv_timer_t send_timer; // Declare timer variable


void global_sender(uv_stream_t *stream, const char *origin, const char *timestamp, const char *msg) {
    // Combine log->msg, log->origin, log->timestamp into a packet
    char combined_msg[1024]; // Adjust the buffer size as needed
    snprintf(combined_msg, sizeof(combined_msg), "%s - %s - %s", origin, timestamp, msg);

    // Prepare the buffer and write request for sending
    uv_buf_t buffer = uv_buf_init(combined_msg, strlen(combined_msg));
    uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
    req->data = combined_msg;

    uv_write(req, stream, &buffer, 1, NULL);
}

// Multilog handler to get and send new log data
void multilog_handler(ld_multilog_t *log) {
    if (log->origin && log->timestamp && log->msg) {
        // Call global_sender to send the packet with the client_socket stream
        global_sender((uv_stream_t *)&client_socket, log->origin, log->timestamp, log->msg);
    }
}

void on_close(uv_handle_t *handle) {
    free(handle);
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char *)malloc(suggested_size);
    buf->len = suggested_size;
}

void on_read(uv_stream_t *server, ssize_t nread, const uv_buf_t *buf) {
    if (nread > 0) {
        printf("Received message from server: %.*s\n", (int)nread, buf->base);
    } else {
        if (nread != UV_EOF) {
            fprintf(stderr, "Read error %s\n", uv_err_name(nread));
        }
        uv_close((uv_handle_t *)server, on_close);
    }

    free(buf->base);
}


void on_connect(uv_connect_t *connection, int status) {
    if (status < 0) {
        fprintf(stderr, "Connection error %s\n", uv_strerror(status));
        uv_close((uv_handle_t *)&client_socket, on_close); // Close connecting socket when connection fails
        return;
    }

    printf("Client connected to server %s:%d\n", DEFAULT_IP, DEFAULT_PORT);

    uv_read_start(connection->handle, alloc_buffer, on_read);
}

int main() {
    loop = uv_default_loop();

    uv_tcp_init(loop, &client_socket); // Initialize client socket 

    uv_ip4_addr(DEFAULT_IP, DEFAULT_PORT, &dest);

    // Initialize logDigest
    ld_init();

    // Set the log callbacks
    ld_set_multilog_callback(multilog_handler);

    uv_connect_t *connect_req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
    uv_tcp_connect(connect_req, &client_socket, (const struct sockaddr *)&dest, on_connect);

    // Watch the desired log file
    ld_watch_multilog("/home/vboxuser/Projects/LogDigestLibuv_linux/multiLogCollector/multi.log");

    for (;;) {
        ld_poll();
        uv_run(loop, UV_RUN_NOWAIT);
    }

    ld_shutdown();

    free(connect_req);

    return 0;
}
