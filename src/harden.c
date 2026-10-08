#define _GNU_SOURCE
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

// exec resets PR_SET_DUMPABLE. Apply it before the external program's main,
// then receive its secret descriptors over the otherwise empty startup socket.
__attribute__((constructor)) static void ssh_keys_harden(void) {
    struct rlimit limit = {0, 0};
    if (setrlimit(RLIMIT_CORE, &limit) || prctl(PR_SET_DUMPABLE, 0) ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        _exit(125);
    if (!getenv("SSH_KEYS_HARDEN_STAGE")) return;
    unsetenv("SSH_KEYS_HARDEN_STAGE");
    if (write(30, "R", 1) != 1) _exit(125);
    int destinations[8], descriptors[8];
    _Alignas(struct cmsghdr) char control[CMSG_SPACE(sizeof descriptors)];
    struct iovec io = {.iov_base = destinations, .iov_len = sizeof destinations};
    struct msghdr message = {.msg_iov = &io, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof control};
    ssize_t bytes = recvmsg(30, &message, MSG_CMSG_CLOEXEC);
    if (bytes <= 0 || bytes % sizeof(int) || message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) _exit(125);
    size_t count = bytes / sizeof(int);
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    if (!header || header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
        header->cmsg_len != CMSG_LEN(count * sizeof(int))) _exit(125);
    memcpy(descriptors, CMSG_DATA(header), count * sizeof(int));
    // All received FDs are duplicated above the destination range first.
    for (size_t i = 0; i < count; i++) {
        int copy = fcntl(descriptors[i], F_DUPFD_CLOEXEC, 32);
        if (copy < 0) _exit(125);
        close(descriptors[i]);
        descriptors[i] = copy;
    }
    for (size_t i = 0; i < count; i++) {
        if (destinations[i] < 0 || destinations[i] > 9 ||
            dup2(descriptors[i], destinations[i]) < 0) _exit(125);
        if (destinations[i] >= 3 &&
            fcntl(destinations[i], F_SETFD, FD_CLOEXEC) < 0) _exit(125);
        close(descriptors[i]);
    }
    close(30);
}

// OpenSSH forks a nondumpable child, connects stdout to its private pipe, then
// calls execlp for askpass. Serve our internal request in that child WITHOUT
// exec: another exec would reset dumpability and expose both the secret FD
// and the freshly created output pipe before a constructor could run.
// Secret FDs are CLOEXEC above, so a changed OpenSSH launch path fails closed.
static void internal_askpass(void) __attribute__((noreturn));
static void internal_askpass(void) {
    if (prctl(PR_GET_DUMPABLE) != 0) _exit(125);
    unsigned char secret[8193];
    size_t length = 0;
    int failed = 0;
    // Loading uses one supplied passphrase attempt. The memfd open-file
    // offset is shared by OpenSSH's forked askpass children: a retry sees EOF
    // and returns an empty answer instead of repeating bcrypt until timeout.
    // ssh-keygen still needs repeatable reads for new-password confirmation.
    const char *once = getenv("SSH_KEYS_ASKPASS_ONCE");
    int consume = once && !strcmp(once, "1");
    while (length < sizeof secret) {
        ssize_t n = consume ? read(4, secret + length, sizeof secret - length)
                            : pread(4, secret + length, sizeof secret - length, length);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { failed = 1; break; }
        if (!n) break;
        length += n;
    }
    if (length > 1023 || memchr(secret, 0, length) ||
        memchr(secret, '\n', length) || memchr(secret, '\r', length)) failed = 1;
    if (!failed) secret[length++] = '\n';
    size_t sent = 0;
    while (!failed && sent < length) {
        ssize_t n = write(STDOUT_FILENO, secret + sent, length - sent);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { failed = 1; break; }
        sent += n;
    }
    explicit_bzero(secret, sizeof secret);
    _exit(failed ? 125 : 0);
}

int execlp(const char *file, const char *arg, ...) {
    const char *internal = getenv("SSH_KEYS_INTERNAL_ASKPASS");
    const char *askpass = getenv("SSH_ASKPASS");
    if (internal && !strcmp(internal, "1") && askpass && !strcmp(file, askpass))
        internal_askpass();
    // Preserve ordinary execlp behavior for other subprocesses. No allocation
    // or dynamic symbol lookup is needed in the post-fork child.
    char *args[128];
    size_t count = 0;
    args[count++] = (char *)arg;
    va_list ap;
    va_start(ap, arg);
    while (args[count - 1]) {
        if (count == sizeof args / sizeof args[0]) {
            va_end(ap);
            errno = E2BIG;
            return -1;
        }
        args[count++] = va_arg(ap, char *);
    }
    va_end(ap);
    return execvp(file, args);
}
