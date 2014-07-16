#include "common.h"

#include "sha1.h"
#include "base64.h"
#include "ws.h"

#define WS_MAGIC	"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_MAGIC_LEN	36
#define SWSKEY		"Sec-WebSocket-Key: "
#define SWSKEY_LEN	19
#define NETKEY_LEN	24	// really?
#define WS_HANDSHAKE	"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n"

static char *hsresponse( char *hs, int *hs_len, char *inputkey, const int key_len );

int handshake( struct client_s *c, char *buf, const int n ) {
    char key[ 64 ]; // 64?
    char *s = buf;
    char *e = buf+n;

    memset( key, 0, sizeof(key) );
    printf( "%s\n", __FUNCTION__ );

    while( s < e ) {
        if( memcmp( s, SWSKEY, SWSKEY_LEN ) == 0 ) {
            s += SWSKEY_LEN;
            memcpy( key, s, NETKEY_LEN );
            if( hsresponse( c->hs, &c->hs_len, key, NETKEY_LEN ) == NULL ) {
                return -1;
            }
            return 0;
        }
        s++;
    }

    return -2;
}

char *ws_parse( struct client_s *c, char *buf, const int n ) {
    int i, j;
    int has_mask, length;
    char mask[4];   
    char *tmp; 

    printf( "%s\n", __FUNCTION__ );
    has_mask = buf[1] & 0x80 ? 1 : 0;
    length = buf[1] & 0x7f;

    if( length > n ) {
        return NULL;
    }

    memcpy( mask, buf+2, sizeof(mask) );
    tmp = buf;

    if( has_mask ) {
        tmp = tmp+6;
        for( i = 0, j = 0; i < n-6; i++, j++ ) {
            tmp[j] = tmp[i] ^ mask[j % 4];
        }
    } else {
        tmp = tmp+2;
    }
 
    return tmp;
}

static char *hsresponse( char *hs, int *hs_len, char *inputkey, const int key_len ) {
    SHA1Context sha;
    int i, length = WS_MAGIC_LEN + key_len;
    char key[length], sha1Key[20];
    char *acceptKey = NULL;
    uint32_t number;

    printf( "%s\n", __FUNCTION__ );
    memset( key, 0, length );
    memset( sha1Key, 0, 20 );

	memcpy( key, inputkey, key_len );
	memcpy( key+key_len, WS_MAGIC, WS_MAGIC_LEN );	

    SHA1Reset( &sha );
    SHA1Input( &sha, (const unsigned char*) key, length );

    if( !SHA1Result(&sha) ) {
        return NULL;
    }

    for( i = 0; i < 5; i++ ) {
        number = ntohl(sha.Message_Digest[i]);
        memcpy(sha1Key+(4*i), (unsigned char *) &number, 4);
    }

    if( base64_encode_alloc((const char *) sha1Key, 20, &acceptKey) == 0 ) {
        return NULL;
    }
    
    sprintf( hs, WS_HANDSHAKE, acceptKey );
    *hs_len = strlen( hs );
/*
    for( i = 0; i < 200; i++ ) {
        printf( "[%d %c]", handshake[i], handshake[i] );
    }
*/
    //printf( "%s\n", handshake );

    return hs;
}
