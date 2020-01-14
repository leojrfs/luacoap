#include <luacoap/client.h>
#include <openssl/ssl.h>
#include <curl/urlapi.h>

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
  request->url = url;
  request->content = payload;
  request->content_len = payload_length;
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

void check_coaps(nyoci_t nyoci, request_t request)
{
  CURLU *c_h = curl_url();
  if (c_h)
  {
    CURLUcode res = curl_url_set(c_h, CURLUPART_URL, request->url, CURLU_NON_SUPPORT_SCHEME);
    if (CURLUE_OK == res)
    {
      char *scheme;
      if (CURLUE_OK == curl_url_get(c_h, CURLUPART_SCHEME, &scheme, 0))
      {
        if (strncmp(scheme, COAP_URI_SCHEME_COAPS, 5) == 0)
        {
          curl_free(scheme);
          
          if (nyoci_plat_tls_set_context(nyoci, NYOCI_PLAT_TLS_DEFAULT_CONTEXT) == NYOCI_STATUS_OK)
          {
            char* port;
            if (CURLUE_OK == curl_url_get(c_h, CURLUPART_PORT, &port, 0))
            {
              if (nyoci_plat_bind_to_port(nyoci, NYOCI_SESSION_TYPE_DTLS, strtol(port, NULL, 0)) != NYOCI_STATUS_OK)
              {
                if (nyoci_plat_bind_to_port(nyoci, NYOCI_SESSION_TYPE_DTLS, 0) != NYOCI_STATUS_OK)
                {
                  printf("ERROR: Unable to bind to ssl port! \"%s\" (%d)\n", strerror(errno), errno);
                }
              }

              curl_free(port);
            }
          }
          else
          {
            printf("ERROR: Unable to set ssl context!\n");
          }

          char *user;
          if (CURLUE_OK == curl_url_get(c_h, CURLUPART_USER, &user, 0))
          {
            strncpy(gClientPskIdentity, user, MIN(strlen(user), MAX_NYOCI_LEN));
            curl_free(user);

            // Clear user-part
            curl_url_set(c_h, CURLUPART_USER, NULL, 0);
          }

          char *pass;
          if (CURLUE_OK == curl_url_get(c_h, CURLUPART_PASSWORD, &pass, 0))
          {
            strncpy(gClientPsk, pass, MIN(strlen(pass), MAX_NYOCI_LEN));
            curl_free(pass);

            // Clear pass-part
            curl_url_set(c_h, CURLUPART_PASSWORD, NULL, 0);
          }

          /*
          char *url_no_creds;
          if (CURLUE_OK == curl_url_get(c_h, CURLUPART_URL, &url_no_creds, 0))
          {
            // TODO: Replace coap URL with variant without credentials?
            curl_free(url_no_creds);
          }*/
        }

        if (gClientPskIdentity[0] != 0 || gClientPsk[0] != 0)
        {
          nyoci_plat_tls_set_client_psk_callback(nyoci, &nyocictl_plat_tls_client_psk_cb, NULL);
        }
      }
    }
    else
    {
      printf("Failed to parse url (%d): %s\n", res, request->url);
    }
    
    curl_url_cleanup(c_h);
  }
  else
  {
    printf("Unable to create CURL object.\n");
  }
}

int send_request(nyoci_t nyoci, request_t request)
{
  gRet = ERRORCODE_INPROGRESS;
  observe = false;

  nyoci_status_t status = 0;
  struct nyoci_transaction_s transaction;
  previous_sigint_handler = signal(SIGINT, &signal_interrupt);

  int flags = NYOCI_TRANSACTION_ALWAYS_INVALIDATE;

  nyoci_transaction_end(nyoci, &transaction);
  nyoci_transaction_init(&transaction, flags, (void*)&resend_get_request,
                        (void*)&get_response_handler, request);

  status = nyoci_transaction_begin(nyoci, &transaction, 30 * MSEC_PER_SEC);

  check_coaps(nyoci, request);

  if (status) {
    fprintf(stderr, "nyoci_begin_transaction_old() returned %d(%s).\n", status,
            nyoci_status_to_cstr(status));
    return false;
  }

  while (ERRORCODE_INPROGRESS == gRet) {
    nyoci_plat_wait(nyoci, 1000);
    nyoci_plat_process(nyoci);
  }

  nyoci_transaction_end(nyoci, &transaction);
  signal(SIGINT, previous_sigint_handler);
  return gRet;
}

int setup_observe_request(nyoci_t nyoci, request_t request,
                           nyoci_transaction_t t) {
  gRet = ERRORCODE_INPROGRESS;
  observe = true;

  int flags = NYOCI_TRANSACTION_ALWAYS_INVALIDATE | NYOCI_TRANSACTION_OBSERVE;

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

      if (req->callback) {
        req->callback(req->data, content, content_length);
      }
    }
  }

bail:
  return NYOCI_STATUS_OK;
}
