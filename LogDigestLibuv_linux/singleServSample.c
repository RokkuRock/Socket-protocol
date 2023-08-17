#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h> // Include this for creating the output directory
#include "uv.h"

#define DEFAULT_PORT 7000
#define DEFAULT_BACKLOG 128

uv_loop_t *loop;
struct sockaddr_in addr;

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;

void free_write_req(uv_write_t *req) {
    write_req_t *wr = (write_req_t *)req;
    free(wr->buf.base);
    free(wr);
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char *)malloc(suggested_size);
    buf->len = suggested_size;
}

void on_close(uv_handle_t *handle) {
    free(handle);
}

void echo_write(uv_write_t *req, int status) {
    if (status) {
        fprintf(stderr, "Write error %s\n", uv_strerror(status));
    }
    free_write_req(req);
}

void process_xml_and_write(const char *xml_data, size_t xml_data_len) {
    static int file_number = 1; // To keep track of the file number for unique filenames
    char filename[100];
    snprintf(filename, sizeof(filename), "/home/vboxuser/Projects/TCP/output/output%d.xml", file_number++);

    // Create the output directory if it doesn't exist
    struct stat st = {0};
    if (stat("/home/vboxuser/Projects/TCP/output", &st) == -1) {
        mkdir("/home/vboxuser/Projects/TCP/output", 0700);
    }

    FILE *file = fopen(filename, "ab"); // Open the file for writing in binary mode and append mode
    if (file) {
        fwrite(xml_data, 1, xml_data_len, file); // Write the received XML data to the file
        fclose(file);                            // Close the file
        printf("Log file %s transmission completed!\n", filename);
    } else {
        fprintf(stderr, "Failed to open the file for writing.\n");
    }
}

void echo_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
    if (nread > 0) {
        printf("Received call from client: %.*s\n", (int)nread, buf->base);
        process_xml_and_write(buf->base, nread);
        free(buf->base); // Free the received buffer after processing the data
        return;
    }

    if (nread < 0) {
        if (nread == UV_EOF) {
            // Client closed the connection gracefully
            uv_close((uv_handle_t *)client, on_close);
        } else if (nread == UV_ECONNRESET) {
            // Connection reset by client
            fprintf(stderr, "Connection reset by client.\n");
            uv_close((uv_handle_t *)client, on_close);
        } else {
            // Other read error
            fprintf(stderr, "Read error %s\n", uv_err_name(nread));
            uv_close((uv_handle_t *)client, on_close);
        }
    }
}

void on_new_connection(uv_stream_t *server, int status) {
    if (status < 0) {
        fprintf(stderr, "New connection error %s\n", uv_strerror(status));
        // error!
        return;
    }

    uv_tcp_t *client = (uv_tcp_t *)malloc(sizeof(uv_tcp_t));
    uv_tcp_init(loop, client);
    if (uv_accept(server, (uv_stream_t *)client) == 0) {
        uv_read_start((uv_stream_t *)client, alloc_buffer, echo_read);
        printf("New connection established\n");
    } else {
        uv_close((uv_handle_t *)client, on_close);
    }
}

void on_wait_timeout(uv_timer_t *handle) {
    printf("No client message received in one minute. Sleeping...\n");
}

int main() {
    loop = uv_default_loop();

    uv_tcp_t server;
    uv_tcp_init(loop, &server);

    uv_ip4_addr("0.0.0.0", DEFAULT_PORT, &addr);

    uv_tcp_bind(&server, (const struct sockaddr *)&addr, 0);
    int r = uv_listen((uv_stream_t *)&server, DEFAULT_BACKLOG, on_new_connection);
    if (r) {
        fprintf(stderr, "Listen error %s\n", uv_strerror(r));
        return 1;
    }

    printf("Server listening on port %d...\n", DEFAULT_PORT);

    uv_timer_t wait_timer;
    uv_timer_init(loop, &wait_timer);
    uv_timer_start(&wait_timer, on_wait_timeout, 60000, 60000); // Start the timer with 1-minute intervals

    uv_run(loop, UV_RUN_DEFAULT);

    return 0;
}