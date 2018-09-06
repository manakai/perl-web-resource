package Web::Transport::PKI::Parser;
use strict;
use warnings;
our $VERSION = '1.0';
use Net::SSLeay;
use Web::Transport::NetSSLeayError;
use Web::Transport::Base64;
use Web::Transport::ASN1;
use Web::Transport::PKI::RSAKey;
use Web::Transport::PKI::Certificate;

sub new ($) {
  return bless {}, $_[0];
} # new

## Not implemented.
sub onerror { }

sub parse_pem ($$) {
  my ($self, $s) = @_;
  my $result = [];
  while ($s =~ m{(-----BEGIN ([A-Z0-9][\x20-\x7E]*[A-Z0-9])-----[\x0D\x0A]+([^-]*?)[\x0D\x0A]+-----END [A-Z0-9][\x20-\x7E]*[A-Z0-9]-----)}gs) {
    my $type = $2;
    if ($type eq 'CERTIFICATE' or
        $type eq 'X509 CERTIFICATE' or
        $type eq 'X.509 CERTIFICATE') {
      my $data = decode_web_base64 $3;
      my $cert = $self->parse_certificate_der ($data);
      push @$result, $cert if defined $cert;
    } elsif ($type eq 'PRIVATE KEY') {
      my $rsa = $self->_parse_private_key_pem ($1);
      push @$result, $rsa if defined $rsa;
    }
  }
  return $result;
} # parse_pem

sub _parse_private_key_pem ($$) {
  my ($self, undef) = @_;

  my $bio = Net::SSLeay::BIO_new (Net::SSLeay::BIO_s_mem ())
      or die Web::Transport::NetSSLeayError->new_current;
  Net::SSLeay::BIO_write ($bio, $_[1])
      or die Web::Transport::NetSSLeayError->new_current;

  my $privkey = Net::SSLeay::PEM_read_bio_PrivateKey ($bio, sub {
    my ($max_passwd_size, $rwflag, $data) = @_;
    return '';
  }) or die Web::Transport::NetSSLeayError->new_current;
  
  return Web::Transport::PKI::RSAKey->_new_pkey ($privkey);
} # _parse_private_key_pem

sub parse_certificate_der ($$) {
  my ($self, $bytes) = @_;

  my $decoded = Web::Transport::ASN1::decode_der $bytes, depth => 10;

  my $certificate = Web::Transport::ASN1->read_sequence ([
    {name => 'tbsCertificate', types => {SEQUENCE => 1}},
    {name => 'signatureAlgorithm', types => {SEQUENCE => 1}},
    {name => 'signatureValue', types => {bytes => 1}},
  ], $decoded->[0]);
  return undef unless defined $certificate;

  $certificate->{signatureAlgorithm} = Web::Transport::ASN1->read_sequence ([
    ## AlgorithmIdentifeir
    {name => 'algorithm', types => {oid => 1}},
    {name => 'parameters', optional => 1, any => 1},
  ], $certificate->{signatureAlgorithm});

  $certificate->{tbsCertificate} = Web::Transport::ASN1->read_sequence ([
    {name => 'version', seq => 0},
    {name => 'serialNumber', types => {int => 1, bigint => 1}},
    {name => 'signature', types => {SEQUENCE => 1}},
    {name => 'issuer', types => {SEQUENCE => 1}},
    {name => 'validity', types => {SEQUENCE => 1}},
    {name => 'subject', types => {SEQUENCE => 1}},
    {name => 'subjectPublicKeyInfo', types => {SEQUENCE => 1}},
    {name => 'issuerUniqueID', seq => 1},
    {name => 'subjectUniqueID', seq => 2},
    {name => 'extensions', seq => 3},
  ], $certificate->{tbsCertificate});

  $certificate->{tbsCertificate}->{validity} = Web::Transport::ASN1->read_sequence ([
    {name => 'notBefore', types => {UTCTime => 1, GeneralizedTime => 1}},
    {name => 'notAfter', types => {UTCTime => 1, GeneralizedTime => 1}},
  ], $certificate->{tbsCertificate}->{validity});

  my $exts = $certificate->{tbsCertificate}->{extensions};
  if (defined $exts and $exts->[0] eq 'contextual') {
    my $decoded = Web::Transport::ASN1::decode_der $exts->[2], depth => 10;
    $exts = [];
    if (defined $decoded and $decoded->[0]->[0] eq 'SEQUENCE') {
      for (@{$decoded->[0]->[1]}) {
        my $v = Web::Transport::ASN1->read_sequence ([
          {name => 'extnID', types => {oid => 1}},
          {name => 'critical', types => {BOOLEAN => 1}, optional => 1},
          {name => 'extnValue', types => {bytes => 1}},
        ], $_);
        next unless defined $v and defined $v->{extnID};
        push @$exts, [$v->{extnID}->[1],
                      $v->{critical}->[1],
                      $v->{extnValue}->[1] // ''];
      }
    }
  } else {
    $exts = [];
  }
  $certificate->{tbsCertificate}->{extensions} = $exts;

  return Web::Transport::PKI::Certificate->_new ($certificate, \$bytes);
} # parse_certificate_der

1;

=head1 LICENSE

Copyright 2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
