/* io_uring part of the coverage test: execution A opens a TCP connection to 127.0.0.1:62001,
 * then execution B (and, for control, A) sends tags through io_uring operations, inline and
 * forced to the io-wq worker (IOSQE_ASYNC). Results as JSON lines on stdout. */
#include <liburing.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

static void mark(const char *who) {
        char p[64];
        snprintf(p, sizeof p, "/run/agentctx/begin/%s", who);
        int fd = open(p, O_RDONLY);
        if (fd >= 0) close(fd);
}
static struct io_uring ring;
static void run(const char *name, int op, int fd, unsigned flags) {
        char buf[64];
        int n = snprintf(buf, sizeof buf, "%s\n", name);
        struct io_uring_sqe *s = io_uring_get_sqe(&ring);
        struct iovec iov = {buf, (size_t)n};
        struct msghdr mh = {0};
        mh.msg_iov = &iov; mh.msg_iovlen = 1;
        if (op == 0) io_uring_prep_send(s, fd, buf, n, 0);
        else if (op == 1) io_uring_prep_send_zc(s, fd, buf, n, 0, 0);
        else if (op == 2) io_uring_prep_write(s, fd, buf, n, 0);
        else io_uring_prep_sendmsg(s, fd, &mh, 0);
        s->flags |= flags;
        io_uring_submit(&ring);
        struct io_uring_cqe *c;
        int res = 0, more = 1;
        while (more) {   /* send_zc posts a result and then a notification */
                io_uring_wait_cqe(&ring, &c);
                if (!(c->flags & IORING_CQE_F_NOTIF)) res = c->res;
                more = (c->flags & IORING_CQE_F_MORE) != 0;
                io_uring_cqe_seen(&ring, c);
        }
        printf("{\"test\":\"%s\",\"res\":%d}\n", name, res);
        fflush(stdout);
        usleep(50000);
}
int main(void) {
        io_uring_queue_init(8, &ring, 0);
        mark("A");
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(62001)};
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (connect(fd, (struct sockaddr *)&a, sizeof a)) { perror("connect"); return 1; }
        run("U_A_send_inline_control", 0, fd, 0);
        run("U_A_send_async_control", 0, fd, IOSQE_ASYNC);
        mark("B");
        run("U_B_send_inline", 0, fd, 0);
        run("U_B_send_async", 0, fd, IOSQE_ASYNC);
        run("U_B_send_zc", 1, fd, 0);
        run("U_B_write", 2, fd, 0);
        run("U_B_write_async", 2, fd, IOSQE_ASYNC);
        run("U_B_sendmsg", 3, fd, 0);
        return 0;
}
