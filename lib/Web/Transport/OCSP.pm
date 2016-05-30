package Web::Transport::OCSP;
use strict;
use warnings;
our $VERSION = '1.0';
use Web::Transport::ASN1;
use Web::DateTime::Parser;

## Internal methods.  Don't use from external applications.

sub parse_response_byte_string ($$) {
  my $result = {};

  my $seq = Web::Transport::ASN1::decode_der ($_[1], depth => 1);
  return undef unless defined $seq and @$seq and
                      $seq->[0]->[0] eq 'SEQUENCE';
  $seq = $seq->[0];

  ## OCSPResponse members
  if (@{$seq->[1]} and $seq->[1]->[0]->[0] eq 'ENUMERATED') { # responseStatus
    $result->{response_status} = $seq->[1]->[0]->[1];
  }
  if (@{$seq->[1]} > 1 and
      $seq->[1]->[1]->[0] eq 'contextual' and
      $seq->[1]->[1]->[1] == 0) {
    $seq = Web::Transport::ASN1::decode_der ($seq->[1]->[1]->[2], depth => 1);
    return $result unless defined $seq and @$seq and
                          $seq->[0]->[0] eq 'SEQUENCE';
    $seq = $seq->[0];
  } else {
    return $result;
  }

  ## ResponseBytes members
  if (@{$seq->[1]} > 1) {
    if ($seq->[1]->[0]->[0] eq 'oid') {
      $result->{response_type} = $seq->[1]->[0]->[1];
    }
  }
  if (defined $result->{response_type} and
      $result->{response_type} eq '1.3.6.1.5.5.7.48.1.1' and # id-pkix-ocsp-basic
      $seq->[1]->[1]->[0] eq 'bytes') {
    $seq = Web::Transport::ASN1::decode_der ($seq->[1]->[1]->[1], depth => 4);
    return $result unless defined $seq and @$seq and
                          $seq->[0]->[0] eq 'SEQUENCE';
    $seq = $seq->[0];
  } else {
    return $result;
  }

  ## BasicOCSPResponse members
  if (@{$seq->[1]} and $seq->[1]->[0]->[0] eq 'SEQUENCE') { # tbsResponseData
    ## ResponseData members
    $result->{response_version} = 1; # default
    if (@{$seq->[1]->[0]->[1]} and
        $seq->[1]->[0]->[1]->[0]->[0] eq 'contextual' and
        $seq->[1]->[0]->[1]->[0]->[1] == 0) {
      my $version = shift @{$seq->[1]->[0]->[1]};
      if (defined $version) {
        my $v = Web::Transport::ASN1::decode_der ($version->[2]);
        $result->{response_version} = $v->[1];
      } else {
        delete $result->{response_version};
      }
    }
    my ($responder_id, $produced_at, $reses) = @{$seq->[1]->[0]->[1]};
    if (defined $produced_at and $produced_at->[0] eq 'GeneralizedTime') {
      $result->{produced} = $produced_at->[1];
    }

    if (defined $reses and $reses->[0] eq 'SEQUENCE') {
      $seq = $reses->[1];
    } else {
      return $result;
    }
  } else {
    return $result;
  }

  for my $res (@$seq) {
    ## SingleResponse members
    my ($cert_id, $cert_status, $this_update, @opt) = @{$res->[1]};

    next unless defined $cert_id and $cert_id->[0] eq 'SEQUENCE unparsed';
    $cert_id = $cert_id->[1];

    my $r = {cert_id => $cert_id};

    if (defined $cert_status and $cert_status->[0] eq 'contextual') {
      if ($cert_status->[1] == 0) {
        $r->{cert_status} = 'good';
      } elsif ($cert_status->[1] == 1) {
        $r->{cert_status} = 'revoked';
        my $info = Web::Transport::ASN1::decode_der ($cert_status->[2], depth => 1);
        if (defined $info and $info->[0]->[0] eq 'GeneralizedTime') {
          $r->{revocation_time} = $info->[0]->[1];
        }
      } elsif ($cert_status->[1] == 2) {
        $r->{cert_status} = 'unknown';
      }
    }

    if (defined $this_update and $this_update->[0] eq 'GeneralizedTime') {
      $r->{this_update} = $this_update->[1];
    }

    for (@opt) {
      if ($_->[0] eq 'contextual' and $_->[1] == 0) {
        if (not defined $r->{next_update}) {
          my $v = Web::Transport::ASN1::decode_der ($_->[2]);
          if (defined $v and @$v and $v->[0]->[0] eq 'GeneralizedTime') {
            $r->{next_update} = $v->[0]->[1];
          } else {
            last;
          }
        }
      }
    }

    if (defined $result->{responses}->{$cert_id}) { # duplicate
      delete $result->{responses}->{$cert_id};
      return $result;
    } else {
      $result->{responses}->{$cert_id} = $r;
    }
  } # $res

  return $result;
} # parse_response_byte_string

sub check_cert_id_with_response ($$$$) {
  my (undef, $res, $cert_id, $now) = @_;

  my $r = $res->{responses}->{$cert_id};
  if (not defined $r) {
    return "The stapled OCSP response is not applicable to the certificate";
  }

  if (defined $r->{cert_status} and $r->{cert_status} eq 'good') {
    #
  } elsif (defined $r->{cert_status} and $r->{cert_status} eq 'revoked') {
    return "The certificate is revoked at |$r->{revocation_time}| according to the stapled OCSP response";
  } else {
    return "Unknown stapled OCSP certificate status |$r->{cert_status}|";
  }

  my $parser = Web::DateTime::Parser->new;
  $parser->onerror (sub { });
  if (defined $r->{this_update}) {
    my $min = $parser->parse_pkix_generalized_time_string ($r->{this_update});
    if (defined $min) {
      if ($min->to_unix_number <= $now) {
        #
      } else {
        return "Stapled OCSP response not in effect until |$r->{this_update}|";
      }
    } else {
      return "Invalid stapled OCSP response |thisUpdate| value";
    }
  } else {
    return "Invalid stapled OCSP response |thisUpdate| value";
  }

  if (defined $r->{next_update}) {
    my $max = $parser->parse_pkix_generalized_time_string ($r->{next_update});
    if (defined $max) {
      if ($now < $max->to_unix_number) {
        #
      } else {
        return "Stale stapled OCSP response |$r->{next_update}|";
      }
    } else {
      return "Invalid stapled OCSP response |nextUpdate| value |$r->{next_update}|";
    }
  }

  return undef;
} # check_cert_id_with_response

sub x509_has_must_staple ($$) {
  my $x509 = $_[1];
  my $tlsext_oid = Net::SSLeay::OBJ_txt2obj ('1.3.6.1.5.5.7.1.24', 1);
  my $index = 0;
  {
    my $ext = Net::SSLeay::X509_get_ext ($x509, $index);
    last unless $ext;

    my $oid = Net::SSLeay::X509_EXTENSION_get_object ($ext);
    if (Net::SSLeay::OBJ_cmp ($oid, $tlsext_oid) == 0) {
      my $d = Net::SSLeay::X509_EXTENSION_get_data ($ext);
      my $data = Net::SSLeay::P_ASN1_STRING_get ($d);
      if ($data eq "\x30\x03\x02\x01\x05") {
        return 1;
      }
    }
    
    $index++;
    redo;
  }
  return 0;
} # x509_has_must_staple

1;
