#ifndef WS_H_
#define WS_H_

int handshake( struct client_s *c, char *buf, const int n );
char *ws_parse( struct client_s *c, char *buf, const int n );

#endif
