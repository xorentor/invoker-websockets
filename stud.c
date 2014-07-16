/**
  * Copyright 2011 Bump Technologies, Inc. All rights reserved.
  *
  * Redistribution and use in source and binary forms, with or without modification, are
  * permitted provided that the following conditions are met:
  *
  *    1. Redistributions of source code must retain the above copyright notice, this list of
  *       conditions and the following disclaimer.
  *
  *    2. Redistributions in binary form must reproduce the above copyright notice, this list
  *       of conditions and the following disclaimer in the documentation and/or other materials
  *       provided with the distribution.
  *
  * THIS SOFTWARE IS PROVIDED BY BUMP TECHNOLOGIES, INC. ``AS IS'' AND ANY EXPRESS OR IMPLIED
  * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
  * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL BUMP TECHNOLOGIES, INC. OR
  * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
  * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
  * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  *
  * The views and conclusions contained in the software and documentation are those of the
  * authors and should not be interpreted as representing official policies, either expressed
  * or implied, of Bump Technologies, Inc.
  *
  **/

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <pwd.h>
#include <limits.h>
#include <syslog.h>
#include <stdarg.h>

#include <ctype.h>
#include <sched.h>
#include <signal.h>

#include <ev.h>
#include <libcouchbase/couchbase.h>

#include "ringbuffer.h"
#include "configuration.h"
#include "couchbase/common.h"

#ifndef MSG_NOSIGNAL
# define MSG_NOSIGNAL 0
#endif
#ifndef AI_ADDRCONFIG
# define AI_ADDRCONFIG 0
#endif

/* For Mac OS X */
#ifndef TCP_KEEPIDLE
# ifdef TCP_KEEPALIVE
#  define TCP_KEEPIDLE TCP_KEEPALIVE
# endif
#endif
#ifndef SOL_TCP
# define SOL_TCP IPPROTO_TCP
#endif

/* Globals */
static struct ev_loop *loop;
static struct addrinfo *backaddr;
static pid_t master_pid;
static ev_io listener;
static int listener_socket;
static int child_num;
static pid_t *child_pids;

#ifdef USE_SHARED_CACHE
static ev_io shcupd_listener;
static int shcupd_socket;
struct addrinfo *shcupd_peers[MAX_SHCUPD_PEERS+1];
static unsigned char shared_secret[SHA_DIGEST_LENGTH];
#endif /*USE_SHARED_CACHE*/

int create_workers;
stud_config *CONFIG;

static char tcp_proxy_line[128] = "";

/* What agent/state requests the shutdown--for proper half-closed
 * handling */
typedef enum _SHUTDOWN_REQUESTOR {
    SHUTDOWN_HARD,
    SHUTDOWN_CLEAR
} SHUTDOWN_REQUESTOR;


/*
 * Proxied State
 *
 * All state associated with one proxied connection
 */
typedef struct proxystate {
    ev_io ev_r_clear;                   /* Clear stream write event */
    ev_io ev_w_clear;                   /* Clear stream read event */

    int fd_up;                          /* Upstream (client) socket */
    int fd_down;                        /* Downstream (backend) socket */

    int want_shutdown:1;                /* Connection is half-shutdown */
    int handshaked:1;                   /* Initial handshake happened */
    int clear_connected:1;              /* Clear stream is connected  */
    int renegotiation:1;                /* Renegotation is occuring */

    struct sockaddr_storage remote_ip;  /* Remote ip returned from `accept` */
} proxystate;

#define LOG(...)                                            \
    do {                                                    \
      if (!CONFIG->QUIET) fprintf(stdout, __VA_ARGS__);     \
      if (CONFIG->SYSLOG) syslog(LOG_INFO, __VA_ARGS__);    \
    } while(0)

#define ERR(...)                                            \
    do {                                                    \
      fprintf(stderr, __VA_ARGS__);                         \
      if (CONFIG->SYSLOG) syslog(LOG_ERR, __VA_ARGS__);     \
    } while(0)

#define NULL_DEV "/dev/null"

/* Set a file descriptor (socket) to non-blocking mode */
void setnonblocking(int fd) {
    int flag = 1;

    assert(ioctl(fd, FIONBIO, &flag) == 0);
}

/* set a tcp socket to use TCP Keepalive */
static void settcpkeepalive(int fd) {
    int optval = 1;
    socklen_t optlen = sizeof(optval);

    if(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) {
        ERR("Error activating SO_KEEPALIVE on client socket: %s", strerror(errno));
    }

    optval = CONFIG->TCP_KEEPALIVE_TIME;
    optlen = sizeof(optval);
#ifdef TCP_KEEPIDLE
    if(setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &optval, optlen) < 0) {
        ERR("Error setting TCP_KEEPIDLE on client socket: %s", strerror(errno));
    }
#endif
}

static void fail(const char* s) {
    perror(s);
    exit(1);
}

void die (char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    exit(1);
}

static void prepare_proxy_line(struct sockaddr* ai_addr) {
    tcp_proxy_line[0] = 0;
    char tcp6_address_string[INET6_ADDRSTRLEN];

    if (ai_addr->sa_family == AF_INET) {
        struct sockaddr_in* addr = (struct sockaddr_in*)ai_addr;
        size_t res = snprintf(tcp_proxy_line,
                sizeof(tcp_proxy_line),
                "PROXY %%s %%s %s %%hu %hu\r\n",
                inet_ntoa(addr->sin_addr),
                ntohs(addr->sin_port));
        assert(res < sizeof(tcp_proxy_line));
    }
    else if (ai_addr->sa_family == AF_INET6 ) {
      struct sockaddr_in6* addr = (struct sockaddr_in6*)ai_addr;
      inet_ntop(AF_INET6,&(addr->sin6_addr),tcp6_address_string,INET6_ADDRSTRLEN);
      size_t res = snprintf(tcp_proxy_line,
                            sizeof(tcp_proxy_line),
                            "PROXY %%s %%s %s %%hu %hu\r\n",
                            tcp6_address_string,
                            ntohs(addr->sin6_port));
      assert(res < sizeof(tcp_proxy_line));
    }
    else {
        ERR("The --write-proxy mode is not implemented for this address family.\n");
        exit(1);
    }
}

/* Create the bound socket in the parent process */
static int create_main_socket() {
    struct addrinfo *ai, hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    const int gai_err = getaddrinfo(CONFIG->FRONT_IP, CONFIG->FRONT_PORT,
                                    &hints, &ai);
    if (gai_err != 0) {
        ERR("{getaddrinfo}: [%s]\n", gai_strerror(gai_err));
        exit(1);
    }

    int s = socket(ai->ai_family, SOCK_STREAM, IPPROTO_TCP);

    if (s == -1)
      fail("{socket: main}");

    int t = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(int));
#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &t, sizeof(int));
#endif
    setnonblocking(s);

    if (bind(s, ai->ai_addr, ai->ai_addrlen)) {
        fail("{bind-socket}");
    }

#ifndef NO_DEFER_ACCEPT
#if TCP_DEFER_ACCEPT
    int timeout = 1;
    setsockopt(s, IPPROTO_TCP, TCP_DEFER_ACCEPT, &timeout, sizeof(int) );
#endif /* TCP_DEFER_ACCEPT */
#endif

    prepare_proxy_line(ai->ai_addr);

    freeaddrinfo(ai);
    listen(s, CONFIG->BACKLOG);

    return s;
}

void safe_enable_io(struct client_s *c, ev_io *w) {
    if (!c->want_shutdown)
        ev_io_start(loop, w);
}


static void shutdown_proxy(struct client_s *c, SHUTDOWN_REQUESTOR req) {
    (void)req;
    if( c ) {
        ev_io_stop(loop, &c->ev_r);
        ev_io_stop(loop, &c->ev_w);

        close(c->fd);

        free(c);
    }
}

static void handle_socket_errno(struct client_s *ps, int backend) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return;

    if (errno == ECONNRESET)
        ERR("{%s} Connection reset by peer\n", backend ? "backend" : "client");
    else if (errno == ETIMEDOUT)
        ERR("{%s} Connection to backend timed out\n", backend ? "backend" : "client");
    else if (errno == EPIPE)
        ERR("{%s} Broken pipe to backend (EPIPE)\n", backend ? "backend" : "client");
    else
        perror("{backend} [errno]");
    shutdown_proxy(ps, SHUTDOWN_CLEAR);
}

/* Read some data from the backend when libev says data is available--
 * write it into the upstream buffer and make sure the write event is
 * enabled for the upstream socket */
static void clear_read(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    struct client_s *c = (struct client_s *)w->data;

    if (c->want_shutdown) {
        ev_io_stop(loop, &c->ev_r);
        return;
    }
    int fd = w->fd;
    char * buf = ringbuffer_write_ptr(&c->rb_in);
    t = recv(fd, buf, RING_DATA_LEN, 0);

    if (t > 0) {
        ringbuffer_write_append(&c->rb_in, t);
        if (ringbuffer_is_full(&c->rb_in)) {
            ev_io_stop(loop, &c->ev_r);
        }
        /*
        if (ps->handshaked)
            safe_enable_io(ps, &ps->ev_w_ssl);
        */
        //printf( "rb write0 t: %d\n", t );
        //char *out = ringbuffer_write_ptr(&c->rb_out);
        //memcpy( out, "h", 1 );
        //ringbuffer_write_append(&c->rb_out, 1);
        //printf( "received bytes %d\n", t );
        net_stack( c ); 

        //storage_put( c, "asdf", "asdf", 4 );
        //safe_enable_io(c, &c->ev_w);
    }
    else if (t == 0) {
        //LOG("{%s} Connection closed\n", "client");
        shutdown_proxy(c, SHUTDOWN_CLEAR);
    }
    else {
        assert(t == -1);
        handle_socket_errno(c, 0);
    }
}
/* Write some data, previously received on the secure upstream socket,
 * out of the downstream buffer and onto the backend socket */
static void clear_write(struct ev_loop *loop, ev_io *w, int revents) {
    (void)revents;
    int t;
    struct client_s *c = (struct client_s *)w->data;
    int fd = w->fd;
    int sz;

    assert(!ringbuffer_is_empty(&c->rb_out));

    //printf( "write\n" );

    char *next = ringbuffer_read_next(&c->rb_out, &sz);
    t = send(fd, next, sz, MSG_NOSIGNAL);

    if (t > 0) {
        if (t == sz) {
            ringbuffer_read_pop(&c->rb_out);
            /*
            if (ps->handshaked)
                safe_enable_io(ps, &ps->ev_r_ssl);
            */
            if (ringbuffer_is_empty(&c->rb_out)) {
                if (c->want_shutdown) {
                    shutdown_proxy(c, SHUTDOWN_HARD);
                    return; // dealloc'd
                }
                ev_io_stop(loop, &c->ev_w);
            }
        }
        else {
            ringbuffer_read_skip(&c->rb_out, t);
        }
    }
    else {
        assert(t == -1);
        handle_socket_errno(c, 0);
    }
}

static void handle_accept(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    (void) loop;
    struct sockaddr_storage addr;
    socklen_t sl = sizeof(addr);

    int client = accept(w->fd, (struct sockaddr *) &addr, &sl);
    if (client == -1) {
        switch (errno) {
        case EMFILE:
            ERR("{client} accept() failed; too many open files for this process\n");
            break;

        case ENFILE:
            ERR("{client} accept() failed; too many open files for this system\n");
            break;

        default:
            assert(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN);
            break;
        }
        return;
    }

    int flag = 1;
    int ret = setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag) );
    if (ret == -1) {
      perror("Couldn't setsockopt on client (TCP_NODELAY)\n");
    }
#ifdef TCP_CWND
    int cwnd = 10;
    ret = setsockopt(client, IPPROTO_TCP, TCP_CWND, &cwnd, sizeof(cwnd));
    if (ret == -1) {
      perror("Couldn't setsockopt on client (TCP_CWND)\n");
    }
#endif

    setnonblocking(client);
    settcpkeepalive(client);

    struct client_s *cs;
    cs = malloc( sizeof( struct client_s ) );
    if (cs == NULL) {
        ERR("unable to allocate memory for struct client_s\n");
        exit(1);
    }

    memset( cs, 0, sizeof( struct client_s ) );
    cs->loop = loop;
    cs->fd = client;
    ringbuffer_init( &cs->rb_in );
    ringbuffer_init( &cs->rb_out );
    cs->ev_r.data = cs;
    cs->ev_w.data = cs;
    cs->dbinstance = (lcb_t )w->data;
    //printf( "cs %x\n", &cs->inbound );

    ev_io_init(&cs->ev_r, clear_read, client, EV_READ);
    ev_io_init(&cs->ev_w, clear_write, client, EV_WRITE);


    ev_io_start(loop, &cs->ev_r);
}

static void check_ppid(struct ev_loop *loop, ev_timer *w, int revents) {
    (void) revents;
    pid_t ppid = getppid();
    if (ppid != master_pid) {
        ERR("{core} Process %d detected parent death, closing listener socket.\n", child_num);
        ev_timer_stop(loop, w);
        ev_io_stop(loop, &listener);
        close(listener_socket);
    }

}

/* Set up the child (worker) process including libev event loop, read event
 * on the bound socket, etc */
static void handle_connections() {
    lcb_t dbinstance;

    LOG("{core} Process %d online\n", child_num);

    /* child cannot create new children... */
    create_workers = 0;

#if defined(CPU_ZERO) && defined(CPU_SET)
    cpu_set_t cpus;

    CPU_ZERO(&cpus);
    CPU_SET(child_num, &cpus);

    int res = sched_setaffinity(0, sizeof(cpus), &cpus);
    if (!res)
        LOG("{core} Successfully attached to CPU #%d\n", child_num);
    else
        ERR("{core-warning} Unable to attach to CPU #%d; do you have that many cores?\n", child_num);
#endif
    loop = ev_default_loop(EVFLAG_AUTO);

    dbinstance = couchbase_init(loop, "localhost:8091", "default", NULL);
/*
    if( dbinstance=storage_init(loop, "localhost:8091", "default", NULL) == NULL ) {
        ERR("{core-error} db instance has failed to create for process %d\n", child_num);
    }
*/
    ev_timer timer_ppid_check;
    ev_timer_init(&timer_ppid_check, check_ppid, 1.0, 1.0);
    ev_timer_start(loop, &timer_ppid_check);

    ev_io_init(&listener, handle_accept, listener_socket, EV_READ);
    //listener.data = default_ctx;
    listener.data = dbinstance;
    ev_io_start(loop, &listener);

    ev_loop(loop, 0);
    ERR("{core} Child %d exiting.\n", child_num);
    exit(1);
}

void change_root() {
    if (chroot(CONFIG->CHROOT) == -1)
        fail("chroot");
    if (chdir("/"))
        fail("chdir");
}

void drop_privileges() {
    if (setgid(CONFIG->GID))
        fail("setgid failed");
    if (setuid(CONFIG->UID))
        fail("setuid failed");
}

void init_globals() {
    /* backaddr */
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    const int gai_err = getaddrinfo(CONFIG->BACK_IP, CONFIG->BACK_PORT,
                                    &hints, &backaddr);
    if (gai_err != 0) {
        ERR("{getaddrinfo}: [%s]", gai_strerror(gai_err));
        exit(1);
    }

#ifdef USE_SHARED_CACHE
    if (CONFIG->SHARED_CACHE) {
        /* cache update peers addresses */
        shcupd_peer_opt *spo = CONFIG->SHCUPD_PEERS;
        struct addrinfo **pai = shcupd_peers;

        while (spo->ip) {
            memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_flags = 0;
            const int gai_err = getaddrinfo(spo->ip,
                                spo->port ? spo->port : CONFIG->SHCUPD_PORT, &hints, pai);
            if (gai_err != 0) {
                ERR("{getaddrinfo}: [%s]", gai_strerror(gai_err));
                exit(1);
            }
            spo++;
            pai++;
        }
    }
#endif
    /* child_pids */
    if ((child_pids = calloc(CONFIG->NCORES, sizeof(pid_t))) == NULL)
        fail("calloc");

    if (CONFIG->SYSLOG)
        openlog("stud", LOG_CONS | LOG_PID | LOG_NDELAY, CONFIG->SYSLOG_FACILITY);
}

/* Forks COUNT children starting with START_INDEX.
 * Each child's index is stored in child_num and its pid is stored in child_pids[child_num]
 * so the parent can manage it later. */
void start_children(int start_index, int count) {
    /* don't do anything if we're not allowed to create new children */
    if (!create_workers) return;

    printf( "start children\n" );

    for (child_num = start_index; child_num < start_index + count; child_num++) {
        int pid = fork();
        if (pid == -1) {
            ERR("{core} fork() failed: %s; Goodbye cruel world!\n", strerror(errno));
            exit(1);
        }
        else if (pid == 0) { /* child */
            handle_connections();
            exit(0);
        }
        else { /* parent. Track new child. */
            child_pids[child_num] = pid;
        }
    }
}

/* Forks a new child to replace the old, dead, one with the given PID.*/
void replace_child_with_pid(pid_t pid) {
    int i;

    /* find old child's slot and put a new child there */
    for (i = 0; i < CONFIG->NCORES; i++) {
        if (child_pids[i] == pid) {
            start_children(i, 1);
            return;
        }
    }

    ERR("Cannot find index for child pid %d", pid);
}

/* Manage status changes in child processes */
static void do_wait(int __attribute__ ((unused)) signo) {

    int status;
    int pid = wait(&status);

    if (pid == -1) {
        if (errno == ECHILD) {
            ERR("{core} All children have exited! Restarting...\n");
            start_children(0, CONFIG->NCORES);
        }
        else if (errno == EINTR) {
            ERR("{core} Interrupted wait\n");
        }
        else {
            fail("wait");
        }
    }
    else {
        if (WIFEXITED(status)) {
            ERR("{core} Child %d exited with status %d. Replacing...\n", pid, WEXITSTATUS(status));
            replace_child_with_pid(pid);
        }
        else if (WIFSIGNALED(status)) {
            ERR("{core} Child %d was terminated by signal %d. Replacing...\n", pid, WTERMSIG(status));
            replace_child_with_pid(pid);
        }
    }
}

static void sigh_terminate (int __attribute__ ((unused)) signo) {
    /* don't create any more children */
    create_workers = 0;

    /* are we the master? */
    if (getpid() == master_pid) {
        LOG("{core} Received signal %d, shutting down.\n", signo);

        /* kill all children */
        int i;
        for (i = 0; i < CONFIG->NCORES; i++) {
            /* LOG("Stopping worker pid %d.\n", child_pids[i]); */
            if (child_pids[i] > 1 && kill(child_pids[i], SIGTERM) != 0) {
                ERR("{core} Unable to send SIGTERM to worker pid %d: %s\n", child_pids[i], strerror(errno));
            }
        }
        /* LOG("Shutdown complete.\n"); */
    }

    /* this is it, we're done... */
    exit(0);
}

void init_signals() {
    struct sigaction act;

    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = SIG_IGN;

    /* Avoid getting PIPE signal when writing to a closed file descriptor */
    if (sigaction(SIGPIPE, &act, NULL) < 0)
        fail("sigaction - sigpipe");

    /* We don't care if someone stops and starts a child process with kill (1) */
    act.sa_flags = SA_NOCLDSTOP;

    act.sa_handler = do_wait;

    /* We do care when child processes change status */
    if (sigaction(SIGCHLD, &act, NULL) < 0)
        fail("sigaction - sigchld");

    /* catch INT and TERM signals */
    act.sa_flags = 0;
    act.sa_handler = sigh_terminate;
    if (sigaction(SIGINT, &act, NULL) < 0) {
        ERR("Unable to register SIGINT signal handler: %s\n", strerror(errno));
        exit(1);
    }
    if (sigaction(SIGTERM, &act, NULL) < 0) {
        ERR("Unable to register SIGTERM signal handler: %s\n", strerror(errno));
        exit(1);
    }
}

void daemonize () {
    /* go to root directory */
    if (chdir("/") != 0) {
        ERR("Unable change directory to /: %s\n", strerror(errno));
        exit(1);
    }

    /* let's make some children, baby :) */
    pid_t pid = fork();
    if (pid < 0) {
        ERR("Unable to daemonize: fork failed: %s\n", strerror(errno));
        exit(1);
    }

    /* am i the parent? */
    if (pid != 0) {
        printf("{core} Daemonized as pid %d.\n", pid);
        exit(0);
    }

    /* close standard streams */
    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    /* reopen standard streams to null device */
    stdin = fopen(NULL_DEV, "r");
    if (stdin == NULL) {
        ERR("Unable to reopen stdin to %s: %s\n", NULL_DEV, strerror(errno));
        exit(1);
    }
    stdout = fopen(NULL_DEV, "w");
    if (stdout == NULL) {
        ERR("Unable to reopen stdout to %s: %s\n", NULL_DEV, strerror(errno));
        exit(1);
    }
    stderr = fopen(NULL_DEV, "w");
    if (stderr == NULL) {
        ERR("Unable to reopen stderr to %s: %s\n", NULL_DEV, strerror(errno));
        exit(1);
    }

    /* this is child, the new master */
    pid_t s = setsid();
    if (s < 0) {
        ERR("Unable to create new session, setsid(2) failed: %s :: %d\n", strerror(errno), s);
        exit(1);
    }

    LOG("Successfully daemonized as pid %d.\n", getpid());
}

/* Process command line args, create the bound socket,
 * spawn child (worker) processes, and respawn if any die */
int main(int argc, char **argv) {
    // initialize configuration
    CONFIG = config_new();

    // parse command line
    config_parse_cli(argc, argv, CONFIG);

    create_workers = 1;

    init_signals();

    init_globals();

    listener_socket = create_main_socket();

    if (CONFIG->CHROOT && CONFIG->CHROOT[0])
        change_root();

    if (CONFIG->UID || CONFIG->GID)
        drop_privileges();

    /* should we daemonize ?*/
    if (CONFIG->DAEMONIZE) {
        /* disable logging to stderr */
        CONFIG->QUIET = 1;
        CONFIG->SYSLOG = 1;

        /* become a daemon */
        daemonize();
    }

    master_pid = getpid();

    start_children(0, CONFIG->NCORES);

    for (;;) {
        /* Sleep and let the children work.
         * Parent will be woken up if a signal arrives */
        pause();
    }

    exit(0); /* just a formality; we never get here */
}
