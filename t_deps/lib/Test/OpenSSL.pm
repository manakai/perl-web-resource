package Test::OpenSSL;
use strict;
use warnings;
use DynaLoader;
use Inline 'C';

our $ref = DynaLoader::dl_load_file ("libssl.so", 0x01);

1;

__DATA__
__C__
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/ocsp.h>

/* OCSP_RESPONSE *                      OCSP_BASICRESP *  */
int p_OCSP_response_create (int status, int bs) {
  return OCSP_response_create (status, bs);
}

/*                                              OCSP_RESPONSE * */
int p_SSL_set_tlsext_status_ocsp_resp (int ssl, int res) {
  int len = i2d_OCSP_RESPONSE (res, NULL);
  return SSL_set_tlsext_status_ocsp_resp ((void *) ssl, (unsigned char *) res, len);
}

int p_SSL_set_tlsext_status_ocsp_resp_data (int ssl, unsigned char *res, int len) {
  unsigned char *p = OPENSSL_malloc (len);
  memcpy (p, res, len);
  return SSL_set_tlsext_status_ocsp_resp ((void *) ssl, p, len);
}

unsigned char * hoge (unsigned char * foo) {
  int len = 3;
  unsigned char *p = OPENSSL_malloc (len);
  memcpy (p, foo, len);
  return p;
}

/*
unsigned char * get_ocsp_resp_data (int ssl) {
  unsinged char *resp;
  SSL_get_tlsext_status_ocsp_resp ((void *) ssl, &resp);
  return resp;
}
*/

                           /* OCSP_RESPONSE * */
void p_OCSP_response_free (int resp) {
  OCSP_RESPONSE_free (resp);
}

                              /* OCSP_BASICRESP*, OCSP_CERTID* */
int p_OCSP_basic_add1_status (int rsp, int cid, int status, int reason,
                              int revtime, int thisupd, int nextupd) {
                              /* ASN1_TIME* x3 */
  return OCSP_basic_add1_status (rsp, cid, status, reason,
                                 revtime, thisupd, nextupd);
}

/*
int OCSP_basic_add1_cert(OCSP_BASICRESP *resp, X509 *cert);
int OCSP_basic_sign(OCSP_BASICRESP *brsp, 
    X509 *signer, EVP_PKEY *key, const EVP_MD *dgst,
    STACK_OF(X509) *certs, unsigned long flags);
*/

int get_certid (int cert, int issuer) {
             /* CERT*, CERT* */
  /* OCSP_CERTID* or NULL */
  return OCSP_cert_to_id (EVP_sha1 (), cert, issuer);
}

int find_issuer (int ctx, int cert) {
  X509_STORE *store = SSL_CTX_get_cert_store (ctx);
  X509_STORE_CTX *stx = X509_STORE_CTX_new ();
  if (!stx || !store) return NULL;
  X509 *issuer = NULL;
  if (X509_STORE_CTX_init (stx, store, cert, NULL)) {
    int ok = X509_STORE_CTX_get1_issuer (&issuer, stx, cert);
    /* failed unless ok > 0 */
  }
  X509_STORE_CTX_free (stx);
  return issuer;
}
