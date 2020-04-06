#include <luacoap/client.h>
#include <openssl/ssl.h>
#include <libnyoci/url-helpers.h>

#ifndef MIN
#if defined(__GCC_VERSION__)
#define MIN(a, \
		b) ({ __typeof__(a)_a = (a); __typeof__(b)_b = (b); _a < \
			  _b ? _a : _b; })
#else
#define MIN(a,b)	((a)<(b)?(a):(b))	// NAUGHTY!...but compiles
#endif
#endif


static bool observe;
static int gRet;
static sig_t previous_sigint_handler;
static void signal_interrupt(int sig) {
  gRet = ERRORCODE_INTERRUPT;
  signal(SIGINT, previous_sigint_handler);
}

#define MAX_NYOCI_LEN 128
char gClientPskIdentity[MAX_NYOCI_LEN] = {0};
uint8_t gClientPsk[MAX_NYOCI_LEN] = {0};

static nyoci_status_t resend_get_request(void* context);
static nyoci_status_t get_response_handler(int statuscode, void* context);

request_t create_request(request_t request, coap_code_t method, int get_tt,
                         const char* url, coap_content_type_t ct,
                         const char* payload, size_t payload_length, bool obs,
                         void* data, void* (*cb)(void*, const char*, size_t)) {

  memset(request, 0, sizeof(request_s));
  request->outbound_code = method;
  request->outbound_tt = get_tt;
  request->expected_code = COAP_RESULT_205_CONTENT;

  if (url) {
    request->url = (char*)malloc(strlen(url)+1);
    if (request->url) {
      memcpy(request->url, url, strlen(url)+1);
    }
  }
  if (payload && (payload_length > 0)) {
    request->content = (char*)malloc(payload_length);
    if (request->content) {
      memcpy(request->content, payload, payload_length);
      request->content_len = payload_length;
    }
  }

  request->ct = ct;
  request->timeout = obs ? CMS_DISTANT_FUTURE : 30 * MSEC_PER_SEC;
  request->data = data;
  request->callback = cb;

  return request;
}

static unsigned int nyocictl_plat_tls_client_psk_cb(
  void* context,
  const char *hint,
  char *identity, unsigned int max_identity_len,
  unsigned char *psk, unsigned int max_psk_len
)
{
  strncpy(identity, gClientPskIdentity, MIN(max_identity_len, strlen(gClientPskIdentity)));

  max_psk_len = MIN(max_psk_len, strlen(gClientPsk));
  memcpy(psk, gClientPsk, max_psk_len);

  return max_psk_len;
}

int is_coap_dtls(const char *url)
{
  return !strncmp(url, COAP_URI_SCHEME_COAPS, strlen(COAP_URI_SCHEME_COAPS));
}

void setup_coap_dtls(nyoci_t nyoci, const char *url)
{
  char* url_parsed = strdup(url);
  struct url_components_s components = {0};
  
  if (url_parsed)
  {
    url_parse(url_parsed, &components);

    if (components.host)
    {
      if (strncmp(components.protocol, COAP_URI_SCHEME_COAPS, 5) == 0)
      {       
        if (nyoci_plat_tls_set_context(nyoci, NYOCI_PLAT_TLS_DEFAULT_CONTEXT) == NYOCI_STATUS_OK)
        {
          if (components.port)
          {
            if (nyoci_plat_bind_to_port(nyoci, NYOCI_SESSION_TYPE_DTLS, strtol(components.port, NULL, 0)) != NYOCI_STATUS_OK)
            {
              if (nyoci_plat_bind_to_port(nyoci, NYOCI_SESSION_TYPE_DTLS, 0) != NYOCI_STATUS_OK)
              {
                printf("ERROR: Unable to bind to ssl port! \"%s\" (%d)\n", strerror(errno), errno);
              }
            }
          }
        }
        else
        {
          printf("ERROR: Unable to set ssl context!\n");
        }

        if (components.username)
        {
          strncpy(gClientPskIdentity, components.username, MIN(strlen(components.username), MAX_NYOCI_LEN));
        }

        if (components.password)
        {
          strncpy(gClientPsk, components.password, MIN(strlen(components.password), MAX_NYOCI_LEN));
        }
        
        if (gClientPskIdentity[0] != 0 || gClientPsk[0] != 0)
        {
          nyoci_plat_tls_set_client_psk_callback(nyoci, &nyocictl_plat_tls_client_psk_cb, NULL);
        } 
      }
    }
    else
    {
      printf("Url parsing failed, or the url does not contain a host. It's invalid either way.\n");
    }

    free(url_parsed);
  }
  else
  {
    printf("Unable to create temporary url object.\n");
  }
}

int send_request(nyoci_t nyoci, request_t request)
{
  gRet = ERRORCODE_INPROGRESS;
  observe = false;

  nyoci_status_t status = 0;
  struct nyoci_transaction_s transaction;
  previous_sigint_handler = signal(SIGINT, &signal_interrupt);

  transaction.active = 0;
  nyoci_transaction_end(nyoci, &transaction);

  int flags = NYOCI_TRANSACTION_ALWAYS_INVALIDATE;
  nyoci_transaction_init(&transaction, flags, (void*)&resend_get_request,
                        (void*)&get_response_handler, request);

  status = nyoci_transaction_begin(nyoci, &transaction, 30 * MSEC_PER_SEC);

  if (is_coap_dtls(request->url))
  {
    setup_coap_dtls(nyoci, request->url);
  }

  if (status) {
    fprintf(stderr, "nyoci_begin_transaction_old() returned %d(%s).\n", status,
            nyoci_status_to_cstr(status));
    return false;
  }

  while (ERRORCODE_INPROGRESS == gRet) {
    if (nyoci) {
      nyoci_plat_wait(nyoci, 1000);
    }
    if (nyoci) {
      nyoci_plat_process(nyoci);
    }
  }

  if (nyoci) {
    nyoci_transaction_end(nyoci, &transaction);
  } else {
    fprintf(stderr, "nyoci pointer invalid\n");
  }
  signal(SIGINT, previous_sigint_handler);
  return gRet;
}

int setup_observe_request(nyoci_t nyoci, request_t request,
                           nyoci_transaction_t t) {
  gRet = ERRORCODE_INPROGRESS;
  observe = true;

  int flags = NYOCI_TRANSACTION_ALWAYS_INVALIDATE | NYOCI_TRANSACTION_OBSERVE | NYOCI_TRANSACTION_KEEPALIVE;

  nyoci_transaction_end(nyoci, t);
  nyoci_transaction_init(t, flags, (void*)&resend_get_request,
                        (void*)&get_response_handler, request);

  return 0;
}

static nyoci_status_t resend_get_request(void* context) {
  request_s* request = (request_s*)context;
  nyoci_status_t status = 0;

  status = nyoci_outbound_begin(nyoci_get_current_instance(),
                               request->outbound_code, request->outbound_tt);
  require_noerr(status, bail);

  status = nyoci_outbound_set_uri(request->url, 0);
  require_noerr(status, bail);

  if (request->content) {
    status =
        nyoci_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, request->ct);
    require_noerr(status, bail);

    status =
        nyoci_outbound_append_content(request->content, request->content_len);
    require_noerr(status, bail);
  }

  status = nyoci_outbound_send();

  if (status && status != NYOCI_STATUS_WAIT_FOR_DNS && status != NYOCI_STATUS_WAIT_FOR_SESSION)
  {
    fprintf(stderr, "nyoci_outbound_send() returned error %d(%s).\n", status,
            nyoci_status_to_cstr(status));
  }

bail:
  return status;
}

static nyoci_status_t get_response_handler(int statuscode, void* context) {
  const char* content = nyoci_inbound_get_content_ptr();
  coap_size_t content_length = nyoci_inbound_get_content_len();

  if (statuscode >= 0) {
    if (content_length > (nyoci_inbound_get_packet_length() - 4)) {
      fprintf(stderr,
              "INTERNAL ERROR: CONTENT_LENGTH LARGER THAN "
              "PACKET_LENGTH-4!(content_length=%u, packet_length=%u)\n",
              content_length, nyoci_inbound_get_packet_length());
      gRet = ERRORCODE_UNKNOWN;
      goto bail;
    }

    if (!coap_verify_packet((void*)nyoci_inbound_get_packet(),
                            nyoci_inbound_get_packet_length())) {
      fprintf(stderr, "INTERNAL ERROR: CALLBACK GIVEN INVALID PACKET!\n");
      gRet = ERRORCODE_UNKNOWN;
      goto bail;
    }
  }

  if (statuscode == NYOCI_STATUS_TRANSACTION_INVALIDATED) {
    gRet = 0;
  }

  if (((statuscode < COAP_RESULT_200) || (statuscode >= COAP_RESULT_400)) &&
      (statuscode != NYOCI_STATUS_TRANSACTION_INVALIDATED) &&
      (statuscode != HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_PARTIAL_CONTENT))) {
    if (observe && statuscode == NYOCI_STATUS_TIMEOUT) {
      gRet = 0;
    } else {
      gRet = (statuscode == NYOCI_STATUS_TIMEOUT) ? ERRORCODE_TIMEOUT
                                                 : ERRORCODE_COAP_ERROR;
      fprintf(stderr, "get: Result code = %d (%s)\n", statuscode,
              (statuscode < 0) ? nyoci_status_to_cstr(statuscode)
                               : coap_code_to_cstr(statuscode));
    }
  }

  if ((statuscode > 0) && content && content_length) {
    coap_option_key_t key;
    const uint8_t* value;
    coap_size_t value_len;
    bool last_block = true;

    while ((key = nyoci_inbound_next_option(&value, &value_len)) !=
           COAP_OPTION_INVALID) {
      if (key == COAP_OPTION_BLOCK2) {
        last_block = !(value[value_len - 1] & (1 << 3));
      } else if (key == COAP_OPTION_OBSERVE) {
      }
    }

    // TODO: Think better about this
    if (context) {
      request_t req = (request_t)context;

      if (req && req->callback && req->data) {
        req->callback(req->data, content, content_length);
      } else {
        fprintf(stderr, "INTERNAL ERROR: callback not set or data missing\n");
      }
    }
  }

bail:
  return NYOCI_STATUS_OK;
}
