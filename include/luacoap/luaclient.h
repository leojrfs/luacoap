#ifndef LUA_COAP_CLIENT_HH__
#define LUA_COAP_CLIENT_HH__

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <libnyoci/libnyoci.h>
#include <luacoap/listener.h>
#include <luacoap/client.h>

#define CLIENT_MT_NAME "coap_client"
#define COAP_METHOD_OBSERVE 5

// Just keeps the nyoci client
typedef struct { nyoci_t nyoci; } lcoap_client;

/**
 *  Register the CoAP client table.
 */
void register_client_table(lua_State *L);

#endif /* ifndef LUA_COAP_CLIENT_HH__ */
