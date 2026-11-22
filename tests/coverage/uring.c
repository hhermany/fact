/* io_uring part of the coverage test. Usage: uring FAMILY HOST PORT IFACE, with FAMILY a label
 * (v4, v6, v4mapped), HOST a literal address, IFACE markers or cred. Execution A opens a TCP
 * connection to HOST:PORT, then execution B (and, for control, A) sends tags through io_uring
 * operations, inline and forced to the io-wq worker (IOSQE_ASYNC). Tags are padded to 48 bytes,
 * as in client.py. Results as JSON lines on stdout. */
#include <liburing.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

static const char *fam;
static int cred;
static void ident(const char *who) {
        if (cred) {   /* execution credential: prctl(PR_FACT, FACT_SET, id) */
                prctl(0x46414354, 1, (unsigned long)who, 0, 0);
                return;
        }
        char p[64];
        snprintf(p, sizeof p, "/run/agentctx/begin/%s", who);
        int fd = open(p, O_RDONLY);
        if (fd >= 0) close(fd);
}
static struct io_uring ring;
static void run(const char *name, int op, int fd, unsigned flags) {
        char t[64], buf[64];
        snprintf(t, sizeof t, "%s/%s", fam, name);
        int n = snprintf(buf, sizeof buf, "%-47s\n", t);
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
int main(int argc, char **argv) {
        if (argc < 5) { fprintf(stderr, "usage: uring FAMILY HOST PORT IFACE\n"); return 2; }
        fam = argv[1];
        cred = !strcmp(argv[4], "cred");
        int port = atoi(argv[3]);
        struct sockaddr_storage ss = {0};
        socklen_t alen;
        int af = strchr(argv[2], ':') ? AF_INET6 : AF_INET;
        if (af == AF_INET6) {
                struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&ss;
                a6->sin6_family = AF_INET6; a6->sin6_port = htons(port);
                inet_pton(AF_INET6, argv[2], &a6->sin6_addr);
                alen = sizeof *a6;
        } else {
                struct sockaddr_in *a4 = (struct sockaddr_in *)&ss;
                a4->sin_family = AF_INET; a4->sin_port = htons(port);
                inet_pton(AF_INET, argv[2], &a4->sin_addr);
                alen = sizeof *a4;
        }
        io_uring_queue_init(8, &ring, 0);
        ident("A");
        int fd = socket(af, SOCK_STREAM, 0);
        if (connect(fd, (struct sockaddr *)&ss, alen)) { perror("connect"); return 1; }
        run("U_A_send_inline_control", 0, fd, 0);
        run("U_A_send_async_control", 0, fd, IOSQE_ASYNC);
        ident("B");
        run("U_B_send_inline", 0, fd, 0);
        run("U_B_send_async", 0, fd, IOSQE_ASYNC);
        run("U_B_send_zc", 1, fd, 0);
        run("U_B_write", 2, fd, 0);
        run("U_B_write_async", 2, fd, IOSQE_ASYNC);
        run("U_B_sendmsg", 3, fd, 0);
        return 0;
}
