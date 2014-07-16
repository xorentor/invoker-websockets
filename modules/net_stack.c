#include "common.h"

#include "ws.h"

static int msg_parse( struct client_s *c, char *buf, const int len ) {
    char *out;

    printf( "%s\n", __FUNCTION__ );

    // handshake
    if( c->flags & HSDONE_F ) {
        if( ws_parse( c, buf, len ) != NULL ) {

        }
    } else {
        if( handshake( c, buf, len ) == 0 ) {
            c->flags |= HSDONE_F;
            NET_WRITE( c, out, c->hs, c->hs_len );
        }
    }

    return 0;
}

int net_stack( struct client_s *c ) {
    int sz;
    char *next;

    printf( "%s\n", __FUNCTION__ );
    next = ringbuffer_read_next(&c->rb_in, &sz);

    if( c->net_len + sz > BUFFER_SIZE ) { 
        // stop ev read
        // return;
    }

    memcpy( c->net_buf + c->net_len, next, sz );
    c->net_len += sz;
    ringbuffer_read_pop( &c->rb_in );
/*
    for( i = 0; i < sz; i++ ) {
        printf( " %x", next[i] );
    }
    printf( "next %x %x %x %d:\n", next[sz-1], next[sz-2], next[sz-4], sz );
*/
    
    msg_parse( c, c->net_buf, c->net_len );
    c->net_len = 0;    // prepare for a new packet

    return 0;
}
