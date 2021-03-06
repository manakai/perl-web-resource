package Web::Transport::DefaultCertificateManager;
use strict;
use warnings;
our $VERSION = '2.0';
use Path::Tiny;
use Promise;
use Web::Transport::TypeError;

my $CertsPath = path (__FILE__)->parent->parent->parent->parent->child
    ('data/tls-certs.pem');

push our @CARP_NOT, qw(
  Promise
  Web::Transport::TypeError
);

sub new ($$) {
  my ($class, $args) = @_;
  return bless {map { $_ => $args->{$_} } qw(
    ca_file ca_path ca_cert
    key_file key
    cert_file cert cert_password
  )}, $class;
} # new

sub prepare ($;%) {
  my ($self, %args) = @_;
  return Promise->resolve->then (sub {
    if ($args{server}) {
      die Web::Transport::TypeError->new ("Bad |cert|") unless
          defined $self->{cert} or defined $self->{cert_file};
      die Web::Transport::TypeError->new ("Bad |key|") unless
          defined $self->{key} or defined $self->{key_file};
    }
    return undef;
  });
} # prepare

sub to_anyevent_tls_args_sync ($) {
  my $self = $_[0];
  my $v = {map { $_ => $self->{$_} } grep { defined $self->{$_} } qw(
    ca_file ca_path ca_cert
    key_file key
    cert_file cert cert_password
  )};

  for (qw(ca_cert key cert)) {
    if (UNIVERSAL::can ($v->{$_}, 'to_pem')) { # or throw
      $v->{$_} = $v->{$_}->to_pem; # or throw
    }
  }

  # XXX should SSL_CERT_FILE and SSL_CERT_DIR environment variables be
  # supported?

  if (not defined $v->{ca_cert} and
      not defined $v->{ca_file}) {
    $v->{ca_file} = $CertsPath;
  }

  return $v;
} # to_anyevent_tls_args_sync

sub to_anyevent_tls_args_for_host_sync ($$) {
  return undef;
} # to_anyevent_tls_args_for_host_sync

1;

=head1 LICENSE

Copyright 2018-2020 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
