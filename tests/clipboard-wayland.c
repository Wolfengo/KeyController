// Synthetic clipboard compositor for original wl-paste integration tests.
// It accepts one inherited socketpair endpoint and never opens a desktop socket.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <wayland-server.h>
#include "data-control-server.h"

static struct wl_display *display;
static const char *mode, *marker;
static int output_fd = -1;
static size_t written;
static struct wl_event_source *writer;
static const char sample[] = "KeyController test \xf0\x9f\x94\x91";

static void finish_write(void) {
    if (writer) wl_event_source_remove(writer);
    writer = NULL;
    if (output_fd >= 0) close(output_fd);
    output_fd = -1;
}

static int write_ready(int fd, uint32_t mask, void *data) {
    (void)mask; (void)data;
    char buffer[4096];
    memset(buffer, 'x', sizeof buffer);
    const char *bytes = !strcmp(mode, "oversize") ? buffer : sample;
    size_t total = !strcmp(mode, "oversize") ? 65536 : sizeof sample - 1;
    size_t remaining = total - written;
    size_t amount = remaining > sizeof buffer ? sizeof buffer : remaining;
    if (bytes == sample) bytes += written;
    ssize_t count = write(fd, bytes, amount);
    if (count < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
    if (count <= 0) { finish_write(); return 0; }
    written += (size_t)count;
    if (written == total) finish_write();
    return 0;
}

static int write_trickle(void *data) {
    (void)data;
    ssize_t count = write(output_fd, "x", 1);
    if (count < 0 && errno != EAGAIN && errno != EINTR) {
        finish_write();
        return 0;
    }
    wl_event_source_timer_update(writer, 20);
    return 0;
}

static void destroy_resource(struct wl_client *client, struct wl_resource *resource) {
    (void)client;
    wl_resource_destroy(resource);
}

static void receive(struct wl_client *client, struct wl_resource *resource,
                    const char *mime, int fd) {
    (void)client; (void)resource;
    if (strcmp(mime, "text/plain;charset=utf-8") || output_fd >= 0) {
        close(fd);
        return;
    }
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return;
    }
    int marker_fd = open(marker, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (marker_fd >= 0) {
        (void)write(marker_fd, "received", 8);
        close(marker_fd);
    }
    output_fd = fd;
    struct wl_event_loop *loop = wl_display_get_event_loop(display);
    if (!strcmp(mode, "trickle") || !strcmp(mode, "cancel")) {
        writer = wl_event_loop_add_timer(loop, write_trickle, NULL);
        wl_event_source_timer_update(writer, 20);
    } else {
        writer = wl_event_loop_add_fd(loop, fd, WL_EVENT_WRITABLE, write_ready, NULL);
    }
}

static const struct zwlr_data_control_offer_v1_interface offer_impl = {
    .receive = receive, .destroy = destroy_resource,
};
static const struct zwlr_data_control_device_v1_interface device_impl = {
    .destroy = destroy_resource,
};

static void get_device(struct wl_client *client, struct wl_resource *manager,
                       uint32_t id, struct wl_resource *seat) {
    (void)seat;
    uint32_t version = wl_resource_get_version(manager);
    struct wl_resource *device = wl_resource_create(client, &zwlr_data_control_device_v1_interface, version, id);
    struct wl_resource *offer = wl_resource_create(client, &zwlr_data_control_offer_v1_interface, 1, 0);
    wl_resource_set_implementation(device, &device_impl, NULL, NULL);
    wl_resource_set_implementation(offer, &offer_impl, NULL, NULL);
    zwlr_data_control_device_v1_send_data_offer(device, offer);
    zwlr_data_control_offer_v1_send_offer(offer, "text/plain;charset=utf-8");
    zwlr_data_control_device_v1_send_selection(device, offer);
    if (version >= 2) zwlr_data_control_device_v1_send_primary_selection(device, NULL);
}

static const struct zwlr_data_control_manager_v1_interface manager_impl = {
    .get_data_device = get_device, .destroy = destroy_resource,
};

static void bind_manager(struct wl_client *client, void *data, uint32_t version, uint32_t id) {
    (void)data;
    struct wl_resource *resource = wl_resource_create(client, &zwlr_data_control_manager_v1_interface, version, id);
    wl_resource_set_implementation(resource, &manager_impl, NULL, NULL);
}

static const struct wl_seat_interface seat_impl = {.release = destroy_resource};

static void bind_seat(struct wl_client *client, void *data, uint32_t version, uint32_t id) {
    (void)data;
    struct wl_resource *resource = wl_resource_create(client, &wl_seat_interface, version, id);
    wl_resource_set_implementation(resource, &seat_impl, NULL, NULL);
    wl_seat_send_capabilities(resource, 0);
    if (version >= 2) wl_seat_send_name(resource, "keycontroller-synthetic-seat");
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    pid_t parent = getppid();
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) return 3;
    signal(SIGPIPE, SIG_IGN);
    mode = argv[2]; marker = argv[3];
    display = wl_display_create();
    if (!display) return 4;
    if (!wl_global_create(display, &wl_seat_interface, 7, NULL, bind_seat) ||
        !wl_global_create(display, &zwlr_data_control_manager_v1_interface, 2, NULL, bind_manager) ||
        !wl_client_create(display, atoi(argv[1]))) return 5;
    wl_display_run(display);
    finish_write();
    wl_display_destroy_clients(display);
    wl_display_destroy(display);
    return 0;
}
