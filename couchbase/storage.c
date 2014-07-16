/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "common.h"

#undef fail
#define fail(msg)                   \
    printf("%s\n", msg);   

#define POST_CB(c, s, sd, g, gf, gd, a, ad)\
    c->post_set = s;\
    c->post_set_data = sd;\
    c->post_get = g;\
    c->post_get_fail = gf;\
    c->post_get_data = gd;\
    c->post_arithmetic = a;\
    c->post_arithmetic_data = ad;

static void
error_callback(lcb_t instance, lcb_error_t err, const char *errinfo)
{
    fprintf(stderr, "%s (0x%x): %s\n", lcb_strerror(instance, err), err, errinfo);
    fail("libcouchbase error");
}

static void 
arithmetic_callback(lcb_t instance, const void *cookie,
                     lcb_error_t error,
                     const lcb_arithmetic_resp_t *resp)
{
    struct client_s *c;
    c = (struct client_s *)cookie;
    // TODO: is this atomic?
    // TODO: what about lifetime of resp?
    if( c->post_arithmetic ) {
        c->post_arithmetic( c, resp->v.v0.value, c->post_arithmetic_data );
    } 
    /*
    if (error == LCB_SUCCESS) {
        c = (struct client_s *)cookie;
    
            printf( "value %ld", resp->v.v0.value );
        
    } else {
    printf( "ar error\n" );
    }
    */
    (void)resp;
}

static void 
set_callback(lcb_t instance, const void *cookie,
                 lcb_storage_t operation, lcb_error_t error,
                 const lcb_store_resp_t *resp)
{
    struct client_s *client = (struct client_s *)cookie;

    // TODO: check lifetime of resp

    if( client->post_set != NULL ) {
        client->post_set( client, client->post_set_data );
    }

    (void)operation;
    (void)resp; 
}

static void get_callback(lcb_t instance, const void *cookie, lcb_error_t error,
                         const lcb_get_resp_t *item)
{
    struct client_s *client = (struct client_s *)cookie;

    printf( "get callback err %d\n", error );

    if (error == LCB_SUCCESS) {
        if( client->post_get != NULL ) {
            client->post_get( client, item->v.v0.bytes, item->v.v0.nbytes, client->post_get_data );
        }
    } else if( 0xd == error ) {     // key doesn't exist
        printf( "0xd error\n" );
        if( client->post_get_fail ) {
            client->post_get_fail( client, client->post_get_data );
        }
    } else {
        // TODO: reply to client 
        printf("GET ERROR: %s (0x%x)\n",
                lcb_strerror(instance, error), error);
    }
    //(void)cookie; // is it safe to void this?
}

lcb_t couchbase_init(struct ev_loop *loop, const char *host, const char *bucket, const char *password)
{
    struct lcb_create_st opts;
    struct lcb_create_io_ops_st io_opts;
    lcb_t handle;
    lcb_error_t err;

    io_opts.version = 1;
    io_opts.v.v1.sofile = NULL;
    io_opts.v.v1.symbol = "lcb_create_libev_io_opts";
    io_opts.v.v1.cookie = loop;

    opts.version = 0;
    opts.v.v0.host = host;
    opts.v.v0.bucket = bucket;
    opts.v.v0.user = bucket;
    opts.v.v0.passwd = password;

    err = lcb_create_io_ops(&opts.v.v0.io, &io_opts);
    if (err != LCB_SUCCESS) {
        error_callback(NULL, err, "failed to create IO object");
        return NULL;
    }
    err = lcb_create(&handle, &opts);
    if (err != LCB_SUCCESS) {
        error_callback(NULL, err, "failed to create connection object");
        return NULL;
    }

    (void)lcb_set_error_callback(handle, error_callback);
    (void)lcb_set_store_callback(handle, set_callback);
    (void)lcb_set_get_callback(handle, get_callback);
    (void)lcb_set_arithmetic_callback(handle, arithmetic_callback);

    err = lcb_connect(handle);
    if (err != LCB_SUCCESS) {
        error_callback(handle, err, "failed to connect to the server");
        return NULL;
    }

    return handle;
}

void couchbase_arithmetic( struct client_s *client, const char *key, const int nkey, const int delta, 
        const void *post_cb, void *cb_data ) 
{ 
    lcb_error_t err;

    lcb_arithmetic_cmd_t arithmetic;
	bzero(&arithmetic, sizeof(arithmetic));
    arithmetic.version = 0;
    arithmetic.v.v0.key = key;
    arithmetic.v.v0.nkey = nkey;
    arithmetic.v.v0.initial = 0;
    arithmetic.v.v0.create = 1;
    arithmetic.v.v0.delta = delta;
    const lcb_arithmetic_cmd_t* commands[] = { &arithmetic };

    POST_CB( client, NULL, NULL, NULL, NULL, NULL, post_cb, cb_data );
    err = lcb_arithmetic(client->dbinstance, client, 1, commands);
    if (err != LCB_SUCCESS) {
        error_callback(client->dbinstance, err, "failed to schedule arithmetic operation");
    } 
}

void couchbase_get( struct client_s *client, const char *key, const int nkey, const void *post_get_cb, const void *post_get_fail_cb, void *cb_data )
{
    lcb_error_t err;
    lcb_get_cmd_t cmd;
    const lcb_get_cmd_t *commands[] = { &cmd };

    memset(&cmd, 0, sizeof(cmd));
    cmd.v.v0.key = key;
    cmd.v.v0.nkey = nkey;

    POST_CB( client, NULL, NULL, post_get_cb, post_get_fail_cb, cb_data, NULL, NULL );
    err = lcb_get( client->dbinstance, client, 1, commands);
    if (err != LCB_SUCCESS) {
        printf( "err %d\n", err );
        return;
    }
}

void couchbase_set( struct client_s *client, const char *key, const int nkey, const void *val, const int nval, const void *post_set_cb, void *data )
{
    lcb_error_t err;
    lcb_store_cmd_t cmd;
    const lcb_store_cmd_t *cmds[] = { &cmd };

    memset(&cmd, 0, sizeof(cmd));
    cmd.version = 0;
    cmd.v.v0.key = key;
    cmd.v.v0.nkey = nkey;
    cmd.v.v0.bytes = val;
    cmd.v.v0.nbytes = nval;
    cmd.v.v0.operation = LCB_SET;

    POST_CB( client, post_set_cb, data, NULL, NULL, NULL, NULL, NULL );

    err = lcb_store(client->dbinstance, client, 1, cmds);
    if (err != LCB_SUCCESS) {
        error_callback( client->dbinstance, err, "failed to schedule store operation" );
    }
}
