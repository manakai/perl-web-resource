package Web::Transport::PKI::RSAKey;
use strict;
use warnings;
our $VERSION = '1.0';
use Net::SSLeay;
use Web::Transport::NetSSLeayError;

push our @CARP_NOT, qw(Web::Transport::NetSSLeayError);

sub _new ($$) {
  return bless {rsa => $_[1]}, $_[0];
} # _new

sub _new_pkey ($$) {
  return bless {pkey => $_[1]}, $_[0];
} # _new_pkey

sub to_net_ssleay_pkey ($) {
  my $self = $_[0];

  unless (defined $self->{pkey}) {
    $self->{pkey} = Net::SSLeay::EVP_PKEY_new ()
        or Web::Transport::NetSSLeayError->new_current;
    Net::SSLeay::EVP_PKEY_assign_RSA ($self->{pkey}, $self->{rsa})
        or Web::Transport::NetSSLeayError->new_current;
  }

  return $self->{pkey};
} # to_net_ssleay_pkey

sub to_pem ($) {
  my $self = $_[0];
  return Net::SSLeay::PEM_get_string_PrivateKey $self->to_net_ssleay_pkey;
} # to_pem

sub DESTROY ($) {
  my $self = $_[0];

  Net::SSLeay::EVP_PKEY_free ($self->{pkey})
      if defined $self->{pkey};

  Net::SSLeay::RSA_free ($self->{rsa})
      if defined $self->{rsa} and not defined $self->{pkey};
} # DESTROY

1;

=head1 LICENSE

Copyright 2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
