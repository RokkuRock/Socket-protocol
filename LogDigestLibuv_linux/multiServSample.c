#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "uv.h"

#define DEFAULT_PORT 7000
#define DEFAULT_BACKLOG 128
#define THREAD_POOL_SIZE 20

uv_loop_t *loop;
struct sockaddr_in addr;

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;

// Define a struct to hold thread-specific data
typedef struct {
    uv_thread_t thread;
    uv_mutex_t mutex;
    uv_cond_t cond;
    uv_async_t async;
    uv_tcp_t *current_client;
} thread_data_t;

typedef struct {
    uv_loop_t *loop;
    int pool_size;
    thread_data_t thread_pool[THREAD_POOL_SIZE];
} thread_manager_t;

thread_manager_t thread_manager;

void dummy(void *arg)
{
    puts("dummy callback");
}

void thread_manager_init(thread_manager_t *manager, int pool_size) {
    manager->loop = uv_default_loop();
    manager->pool_size = pool_size;

    for (int i = 0; i < pool_size; ++i) {
        uv_mutex_init(&manager->thread_pool[i].mutex);
        uv_cond_init(&manager->thread_pool[i].cond);
        uv_thread_create(&manager->thread_pool[i].thread, dummy, NULL); //on_new_connection will be in charge of asynchronous processing so there's no need for thread_entry
    }
}

void thread_manager_free(thread_manager_t *manager, int pool_size) {
    for (int i = 0; i < manager->pool_size; ++i) {
        uv_close((uv_handle_t *)&manager->thread_pool[i].async, NULL);
        uv_thread_join(&manager->thread_pool[i].thread);
        uv_cond_destroy(&manager->thread_pool[i].cond);
        uv_mutex_destroy(&manager->thread_pool[i].mutex);
    }
}

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
    uv_tcp_t *client = (uv_tcp_t *)handle;
    thread_manager_t *manager = (thread_manager_t *)client->loop->data;

    // Clean up client resources
    free(client);
}
uv_mutex_t file_mutex;

void process_xml_and_write(const char *xml_data, size_t xml_data_len) {
    static int file_number = 1;
    char filename[100];
    
    uv_mutex_lock(&file_mutex); // Use mutex_lock to lock the accessibility during processing xml

    snprintf(filename, sizeof(filename), "/home/vboxuser/Projects/TCP/output/output%d.xml", file_number++);
    
    // Create the output directory if it doesn't exist
    struct stat st = {0};
    if (stat("/home/vboxuser/Projects/TCP/output", &st) == -1) {
        mkdir("/home/vboxuser/Projects/TCP/output", 0700);
    }
    
    FILE *file = fopen(filename, "ab");
    if (file) {
        fwrite(xml_data, 1, xml_data_len, file);
        fclose(file);
        printf("Log file %s transmission completed!\n", filename);
    } else {
        fprintf(stderr, "Failed to open the file for writing.\n");
    }
    
    uv_mutex_unlock(&file_mutex); // unlock when the xml writing is finished
    free((void *)xml_data); // Release buf->base memory space here without double freeing and conversion casting from const to void
}

void echo_write(uv_write_t *req, int status) {
    if (status) {
        fprintf(stderr, "Write error %s\n", uv_strerror(status));
    }
    free_write_req(req);
}

void echo_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
    if (nread > 0) {
        printf("Received call from client: %.*s\n", (int)nread, buf->base);
        process_xml_and_write(buf->base, nread);
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
        if (client) {
            uv_close((uv_handle_t *)client, on_close);
        }
    }
}


void on_wait_timeout(uv_timer_t *handle) {
    printf("No client message received in one minute. Sleeping...\n");
}



int main() {
    loop = uv_default_loop();
    
    uv_mutex_init(&file_mutex);

    // Activate thread_manager service for Deafult 20 threads
    thread_manager_init(&thread_manager, THREAD_POOL_SIZE);
    
    // Set thread pool data for the server to use when accepting connections
    uv_tcp_t server;
    uv_tcp_init(loop, &server);
    thread_manager.loop = loop; // Set the loop in thread_manager for initializing
    server.data = &thread_manager; // Pass thread manager instance to the server

    
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
    uv_timer_start(&wait_timer, on_wait_timeout, 60000, 60000);

    uv_run(loop, UV_RUN_DEFAULT);
    uv_mutex_destroy(&file_mutex); // Destroy the mutex to release memory space

    // Clean up and destroy the thread manager
    thread_manager_free(&thread_manager, THREAD_POOL_SIZE);

    return 0;
}