package Test::OpenSSL;
use strict;
use warnings;
use DynaLoader;
use Path::Tiny;
use Inline 'C', 'config', inc => '-I' . path (__FILE__)->parent->parent->parent->parent->child ('local/common/include')->absolute->stringify;

our $ref = DynaLoader::dl_load_file ("libssl.so", 0x01);

1;

__DATA__
__C__
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/ocsp.h>

int p_SSL_set_tlsext_status_ocsp_resp_data (int ssl, unsigned char *res, int len) {
  unsigned char *p = OPENSSL_malloc (len);
  memcpy (p, res, len);
  return SSL_set_tlsext_status_ocsp_resp ((void *) ssl, p, len);
}
