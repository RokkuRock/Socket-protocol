#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "uv.h"
#include "logdigest.h"
#include "cJSON.h"
#include <unistd.h> // For access() function

#define SEND_INTERVAL_MS 1000      // Adjust the interval as needed, 1 milisecond per 1 xml writing for default

uv_loop_t *loop;
uv_tcp_t client_socket;
struct sockaddr_in dest;
uv_timer_t send_timer; // Declare timer variable
cJSON *config_root;
const char *json_filename = "/home/vboxuser/Projects/AutoLogDigest_linux/serverConfig/serverConfig.json"; //serverConfig Directory Monitoring
char *IP;
int PORT;

void load_config() {
    // Read JSON config file
    FILE *json_file = fopen(json_filename, "r");
    if (!json_file) {
        fprintf(stderr, "Unable to open JSON file: %s\n", json_filename);
        exit(1);
    }

    fseek(json_file, 0, SEEK_END);
    long file_size = ftell(json_file);
    fseek(json_file, 0, SEEK_SET);

    char *json_data = (char *)malloc(file_size + 1);
    fread(json_data, 1, file_size, json_file);
    fclose(json_file);

    json_data[file_size] = '\0';

    // Parse JSON config
    config_root = cJSON_Parse(json_data);
    free(json_data);

    if (!config_root) {
        fprintf(stderr, "JSON parsing error: %s\n", cJSON_GetErrorPtr());
        exit(1);
    }
    
    // Get IP and Port from config
    IP = strdup(cJSON_GetObjectItemCaseSensitive(config_root, "IP")->valuestring);
    PORT = cJSON_GetObjectItemCaseSensitive(config_root, "Port")->valueint;
}

void global_sender(uv_stream_t *stream, const char *origin, const char *timestamp, const char *msg) {
    // Combine log->msg, log->origin, log->timestamp into a packet
    size_t combined_msg_len = strlen(origin) + strlen(timestamp) + strlen(msg) + 6;
    char *combined_msg = (char *)malloc(combined_msg_len);
    snprintf(combined_msg, combined_msg_len, "%s - %s - %s", origin, timestamp, msg);

    // Prepare the buffer and write request for sending
    uv_buf_t buffer = uv_buf_init(combined_msg, combined_msg_len);
    uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
    req->data = combined_msg;

    uv_write(req, stream, &buffer, 1, NULL);
}

// Multilog handler to get and send new log data
void multilog_handler(ld_multilog_t *log) {
    if (log->origin && log->timestamp && log->msg) {
        // Copy log data into local variables
        char *origin = strdup(log->origin);
        char *timestamp = strdup(log->timestamp);
        char *msg = strdup(log->msg);

        // Call global_sender with local variables
        global_sender((uv_stream_t *)&client_socket, origin, timestamp, msg);

        // Free the copied data
        free(origin);
        free(timestamp);
        free(msg);
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
        exit(1);
    }

    printf("Client connected to server %s:%d\n", IP, PORT);

    uv_read_start(connection->handle, alloc_buffer, on_read);
}

int main() {
    loop = uv_default_loop();

    // Load JSON config
    load_config();

    uv_tcp_init(loop, &client_socket); // Initialize client socket 

    uv_ip4_addr(IP, PORT, &dest);

    // Initialize logDigest
    ld_init();

    // Set the log callbacks
    ld_set_multilog_callback(multilog_handler);

    uv_connect_t *connect_req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
    uv_tcp_connect(connect_req, &client_socket, (const struct sockaddr *)&dest, on_connect);

    // Watch the desired log file
    ld_watch_multilog("/home/vboxuser/Projects/AutoLogDigest_linux/multiLogCollector/multi.log");

    for (;;) {
        ld_poll();
        uv_run(loop, UV_RUN_NOWAIT);
    }

    ld_shutdown();

    free(connect_req);
    free(IP);
    cJSON_Delete(config_root); // Free cJSON object

    return 0;
}
