#include "httpc.h"

#include <curl/curl.h>

const char *ssoossh_httpc_version(void)
{
    return curl_version();
}
