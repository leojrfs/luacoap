# luacoap

This project is a simple lua binding to the 
[Nyoci](https://github.com/darconeous/libnyoci) CoAP stack. The current version only 
implements some client calls.

### Building

To build this project, cmake and lua are required, plus a few development libraries:
```bash
export LUA_VERSION=$(lua -e 'print(string.sub(_VERSION, 5))')

sudo apt update
sudo apt install -y git cmake libtool autoconf-archive openssl libssl-dev lua${LUA_VERSION}-dev
```

To perform the actual build of luacoap, execute:
```bash
git clone https://github.com/vwout/luacoap
mkdir -p luacoap/build
cd luacoap/build
cmake ..
make
```
the output is `coap.so`, a shared library that can be loaded into lua.

To use it in lua using `require("coap")` install this module with:
```bash
sudo make install
```
and you can use it independently of your location.

Alternatively, you can download and install the [debian 
package](https://github.com/vwout/luacoap/raw/master/downloads/luacoap-0.2.0-Linux.deb).


### Usage

Currently it is only possible to send GET, PUT and POST request using the CoAP 
client.

#### Example

```lua
coap = require("coap")
client = coap.Client()

function callback(playload)
  print(playload)
end

client:get(coap.CON, "coap://coap.me/test", callback)
```

The library also supports DTLS. Use the scheme ```çoaps``` and the identity and psk in the url, e.g. ```coaps://identity:psk@server/path```.

The current available functions are

```lua
client:get([ ConnectionType ,] url [, ContentType, Payload ], [ callback ])
client:put([ ConnectionType ,] url [, ContentType, Payload ], [ callback ])
client:post([ ConnectionType ,] url [, ContentType, Payload ], [ callback ])
client:observe([ ConnectionType ,] url [, ContentType, Payload ], [ callback ])
```

where:

* ConnectionType is either `coap.CON` or `coap.NON` for confirmable or non-confirmable, 
* url is the address to the resource
* ContentType is any of the CoAP supported content types
* Payload is the data you want to send
* callback is a function that will be executed when the response arrives

##### Observe Request

The observe request is different from the others since it returns a `listener` 
object. This object can be used to control the subscription to the target 
resource. The `listener` object implements the following methods.

```lua
listener:callback()   -- Executes the callback function provided to the client
listener:listen()     -- Starts observing the resource
listener:stop()       -- Stops the observation
listener:pause()      -- Suspends the observation
listener:continue()   -- Resumes the observation
```
