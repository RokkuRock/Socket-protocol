#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "uv.h"

#define DEFAULT_PORT 7000
const char* DEFAULT_IP = "127.0.0.1"; // Change this to your server IP if needed

uv_loop_t *loop;
uv_tcp_t client_socket;
struct sockaddr_in dest;

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;

void on_close(uv_handle_t* handle) {
    free(handle);
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char*)malloc(suggested_size);
    buf->len = suggested_size;
}

void echo_write(uv_write_t *req, int status) {
    if (status) {
        fprintf(stderr, "Write error %s\n", uv_strerror(status));
    }
    free(req);
}

void on_read(uv_stream_t* server, ssize_t nread, const uv_buf_t* buf) {
    if (nread > 0) {
        printf("Received message from server: %.*s\n", (int)nread, buf->base);

        // If we received the completion message, close the client
        if (strstr(buf->base, "Log file transmission completed!") != NULL) {
            uv_close((uv_handle_t*)server, on_close);
        }
    } else {
        if (nread != UV_EOF) {
            fprintf(stderr, "Read error %s\n", uv_err_name(nread));
        }
        uv_close((uv_handle_t*)server, on_close);
    }

    free(buf->base);
}

void write_xml(uv_stream_t* server) {
    // Fix the XML data to be well-formed
    char* xml_data = "<Event><EventID>12345</EventID><Source>Application</Source><Message>Sample event log message</Message></Event>";

    uv_buf_t buffer = uv_buf_init(xml_data, strlen(xml_data));
    uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
    uv_write(req, server, &buffer, 1, echo_write);
}

void on_connect(uv_connect_t* connection, int status) {
    if (status < 0) {
        fprintf(stderr, "Connection error %s\n", uv_strerror(status));
        return;
    }

    printf("Client connected to server %s:%d\n", DEFAULT_IP, DEFAULT_PORT);

    // Start sending XML data to the server
    write_xml(connection->handle);
    // Sleep to keep the connection for 10 seconds after xml processing
    uv_sleep(10000);
}

int main() {
    loop = uv_default_loop();

    uv_tcp_t socket;
    uv_tcp_init(loop, &socket);

    dest.sin_addr.s_addr = inet_addr(DEFAULT_IP);

    dest.sin_port = htons(DEFAULT_PORT);
    dest.sin_family = AF_INET;

    uv_connect_t* connect_req = (uv_connect_t*)malloc(sizeof(uv_connect_t));
    connect_req->data = (void*)connect_req; // Storing the pointer for cleanup
    uv_tcp_connect(connect_req, &socket, (const struct sockaddr*)&dest, on_connect);

    uv_read_start((uv_stream_t*)&socket, alloc_buffer, on_read); // Start reading the server's response

    uv_run(loop, UV_RUN_DEFAULT);

    return 0;
}
