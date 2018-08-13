use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Web::Transport::PKI::Generator;

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  $gen->create_rsa_key->then (sub {
    my $rsa = $_[0];

    test {
      like $rsa->to_pem, qr{^-----BEGIN PRIVATE KEY-----\x0D?\x0A[A-Za-z0-9/+=\x0D\x0A]+\x0D?\x0A-----END PRIVATE KEY-----\x0D?\x0A$};
    } $c;

    done $c;
    undef $c;
  });
} n => 1, name => 'to_pem';

run_tests;

=head1 LICENSE

Copyright 2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
