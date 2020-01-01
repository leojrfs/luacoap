#include <luacoap/luacoap.h>

static int coap_create_client(lua_State *L) {
  lcoap_client *cud;
  cud = (lcoap_client *)lua_newuserdata(L, sizeof(lcoap_client));
  luaL_getmetatable(L, CLIENT_MT_NAME);
  lua_setmetatable(L, -2);

  // Creates the client
  cud->nyoci = nyoci_create();
  nyoci_plat_bind_to_port(cud->nyoci, NYOCI_SESSION_TYPE_UDP, 61616);
  return 1;
}

static const struct luaL_Reg luacoap_map[] = {{"Client", coap_create_client},
                                              {NULL, NULL}};

int luaopen_coap(lua_State *L) {
  // Declare the client metatable
  register_client_table(L);

  // Register the listener object
  register_listener_table(L);

  // Register the coap library
  #if LUA_VERSION_NUM == 501
  luaL_register(L, CLIENT_MT_NAME, luacoap_map);  // for Lua 5.1
  #else
  luaL_newlib(L, luacoap_map);                    // for Lua 5.2 and above
  #endif

  #if LUA_VERSION_NUM == 501
  lua_setglobal(L, CLIENT_MT_NAME);               // for Lua 5.1
  luaL_register(L, CLIENT_MT_NAME, luacoap_map);  // for Lua 5.1
  #else
  luaL_setfuncs(L, luacoap_map, 0);               // for Lua 5.2 and above
  #endif

  lua_pushnumber(L, COAP_TRANS_TYPE_CONFIRMABLE);
  lua_setfield(L, -2, "CON");
  lua_pushnumber(L, COAP_TRANS_TYPE_NONCONFIRMABLE);
  lua_setfield(L, -2, "NON");

  return 1;
}
