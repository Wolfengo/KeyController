// Listener connects only to the private bus supplied by the test runner.
#include <atspi/atspi.h>
#include <stdio.h>
#include <string.h>

static GString *inserted, *removed;
static unsigned events;

static void callback(AtspiEvent *event, void *unused) {
  (void)unused;
  if (G_VALUE_HOLDS_STRING(&event->any_data)) {
    const char *text = g_value_get_string(&event->any_data);
    if (strstr(event->type, "insert")) g_string_append(inserted, text ? text : "");
    if (strstr(event->type, "delete")) g_string_append(removed, text ? text : "");
    ++events;
  }
  g_boxed_free(ATSPI_TYPE_EVENT, event);
}

static gboolean finish(void *unused) {
  (void)unused;
  printf("a11y_text_events=%u inserted_marker=%d removed_marker=%d\n", events,
         strstr(inserted->str, "kc_audit_FAKE_input") != NULL,
         strstr(removed->str, "kc_audit_FAKE_input") != NULL);
  fflush(stdout);
  atspi_event_quit();
  return G_SOURCE_REMOVE;
}

int main(void) {
  inserted = g_string_new("");
  removed = g_string_new("");
  if (atspi_init() != 0) return 2;
  GError *error = NULL;
  AtspiEventListener *listener = atspi_event_listener_new(callback, NULL, NULL);
  if (!atspi_event_listener_register(listener, "object:text-changed", &error)) return 3;
  puts("listener_ready=1");
  fflush(stdout);
  g_timeout_add(3000, finish, NULL);
  atspi_event_main();
  g_object_unref(listener);
  atspi_exit();
  g_string_free(inserted, TRUE);
  g_string_free(removed, TRUE);
  return 0;
}
