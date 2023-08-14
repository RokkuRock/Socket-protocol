#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "uv.h"

#define DEFAULT_PORT 7000
#define DEFAULT_IP "127.0.0.1" // Change this to your  server IP if needed
#define SEND_INTERVAL_MS 1     // Adjust the interval as needed, 1 milisecond per 1 xml writing for default

uv_loop_t *loop;
uv_tcp_t client_socket;
struct sockaddr_in dest;
uv_timer_t send_timer; // Declare timer variable 


typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;

void on_close(uv_handle_t *handle) {
    free(handle);
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char *)malloc(suggested_size);
    buf->len = suggested_size;
}

void echo_write(uv_write_t *req, int status) {
    if (status) {
        fprintf(stderr, "Write error %s\n", uv_strerror(status));
    }
    free(req);
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

void stop_and_cleanup() {
    uv_timer_stop(&send_timer); // Stop the timer
    uv_close((uv_handle_t *)&client_socket, on_close); // Release the timer resource
}

void send_xml_data(uv_timer_t *handle) {
    char *xml_data = "<xml>Some XML data goes here.</xml>";
    size_t xml_data_len = strlen(xml_data);

    uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
    uv_buf_t buffer = uv_buf_init(xml_data, xml_data_len);
    uv_write(req, (uv_stream_t *)handle->data, &buffer, 1, echo_write); // Use handle->data
}

void on_connect(uv_connect_t *connection, int status) {
    if (status < 0) {
        fprintf(stderr, "Connection error %s\n", uv_strerror(status));
        uv_close((uv_handle_t *)&client_socket, on_close); // Close connecting socket when connection fails
        return;
    }
    
    printf("Client connected to server %s:%d\n", DEFAULT_IP, DEFAULT_PORT);

    // Start the timer to send XML data every 1 second
    uv_timer_init(loop, &send_timer);
    uv_timer_start(&send_timer, send_xml_data, 0, SEND_INTERVAL_MS *1000); // Multiply 1 millisecond a thousand times to 1 second;
    send_timer.data = connection->handle;

    uv_read_start(connection->handle, alloc_buffer, on_read);
}

int main() {
    loop = uv_default_loop();

    uv_tcp_t socket;
    uv_tcp_init(loop, &socket);

    uv_ip4_addr(DEFAULT_IP, DEFAULT_PORT, &dest);

    uv_connect_t *connect_req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
    uv_tcp_connect(connect_req, &socket, (const struct sockaddr *)&dest, on_connect);

    uv_run(loop, UV_RUN_DEFAULT);

    // Stop and release the timer resource when the program terminates 
    uv_timer_stop(&send_timer);
    free(connect_req);

    return 0;
}
