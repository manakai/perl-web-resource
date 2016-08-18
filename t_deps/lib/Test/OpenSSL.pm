package Test::OpenSSL;
use strict;
use warnings;

# #define SSL_set_tlsext_status_ocsp_resp(ssl, arg, arglen) \
# SSL_ctrl(ssl,SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP,arglen, (void *)arg)
sub p_SSL_set_tlsext_status_ocsp_resp_data ($$$) {
  return Net::SSLeay::ctrl ($_[0], 71, $_[2], ''.$_[1]);
}

1;
