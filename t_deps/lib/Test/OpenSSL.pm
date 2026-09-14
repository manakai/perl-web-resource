package Test::OpenSSL;
use strict;
use warnings;

## Added by Net::SSLeay 1.82 (31 October Heisei 29)
sub p_SSL_set_tlsext_status_ocsp_resp_data ($$$) {
  my $x = '' . $_[1];
  return Net::SSLeay::set_tlsext_status_ocsp_resp ($_[0], $x);
}

1;

## License: Public Domain.
