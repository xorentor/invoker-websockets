#ifndef COMMON_H
#define COMMON_H

#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/fcntl.h> // fcntl
#include <unistd.h> // close
#include <errno.h>
#include <ev.h>
#include <libcouchbase/couchbase.h>

#include "config.h"
#include "../ringbuffer.h"  // stud rb
#include "ringbuffer.h"     // cb rb

#define BUFFER_SIZE (8*1024)

#define CASE1( m ) *m
#define CASE2( m ) *(uint16_t*)m
#define CASE4( m ) *(uint32_t*)m
#define CASE8( m ) *(uint64_t*)m

#define NET_WRITE( c, out, s, len )\
    out = ringbuffer_write_ptr( &c->rb_out );\
    memcpy( out, &s, len );\
    ringbuffer_write_append( &c->rb_out, len );\
    safe_enable_io( c, &c->ev_w );

#define HSDONE_F    1 

struct client_s {
    struct ev_io ev_r;      // read
    struct ev_io ev_w;      // write
    struct ev_loop *loop;   // main loop
    int fd; 
    lcb_t dbinstance;
    unsigned int flags;

    ringbuffer rb_in;     // read
    ringbuffer rb_out;    // write

    /* 
     * couchbase:
     *
     * when a callback is ran, post-callback methods are invoked,
     * set them to NULL if not needed respectively before every couchbase call
     */
    void (*post_set)( struct client_s *client, void *data );
    void *post_set_data;
    void (*post_get)( struct client_s *client, const void *bytes, const int nbytes, void *data );
    void (*post_get_fail)( struct client_s *client, void *data );
    void *post_get_data;
    void (*post_arithmetic)( struct client_s *client, const uint64_t uid, void *data );
    void *post_arithmetic_data;

    char net_buf[ BUFFER_SIZE ];
    int net_len;
    char hs[ 1024 ];    // handshake buffer
    int hs_len;

    int want_shutdown:1;
};

struct server_s {
    struct ev_io io;
    lcb_t handle;
};

void setnonblocking( int fd );
void safe_enable_io( struct client_s *c, ev_io *w );
int net_stack( struct client_s *c );
int router_reply( struct client_s *c );
lcb_t couchbase_init(struct ev_loop *loop, const char *host, const char *bucket, const char *password);
void couchbase_arithmetic( struct client_s *client, const char *key, const int nkey, const int delta, 
    const void *post_cb, void *data );
void couchbase_set( struct client_s *client, const char *key, const int nkey, const void *val, const int nval, const void *post_set_cb, void *data );
void couchbase_get( struct client_s *client, const char *key, const int nkey, const void *post_get_cb, const void *post_get_fail_cb, void *cb_data );


#endif
