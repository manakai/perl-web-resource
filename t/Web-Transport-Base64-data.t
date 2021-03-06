use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use JSON::PS;
use Web::Transport::Base64;
use Web::Encoding;

my $TestDataPath = path (__FILE__)->parent->parent->child
    ('t_deps/tests/base64');

for my $path ($TestDataPath->children (qr/^encode-.+\.json$/)) {
  test {
    my $c = shift;
    for my $t (@{json_bytes2perl $path->slurp}) {
      my $bytes = join '', map { pack 'C', $_ } @{$t->[0]};
      test {
        is encode_web_base64 $bytes, $t->[1];
        ok ! utf8::is_utf8 $bytes;
      } $c, name => $t->[0];
    }
    done $c;
  } name => ['encode', $path];
}

for my $path ($TestDataPath->children (qr/^encodeu-.+\.json$/)) {
  test {
    my $c = shift;
    for my $t (@{json_bytes2perl $path->slurp}) {
      my $bytes = join '', map { pack 'C', $_ } @{$t->[0]};
      test {
        is encode_web_base64url $bytes, $t->[1];
        ok ! utf8::is_utf8 $bytes;
      } $c, name => $t->[0];
    }
    done $c;
  } name => ['encode_web_base64url', $path];
}

sub b ($) {
  return undef unless defined $_[0];
  return join ',', @{$_[0]};
} # b

for my $path ($TestDataPath->children (qr/^decode-.+\.json$/)) {
  test {
    my $c = shift;
    for my $t (@{json_bytes2perl $path->slurp}) {
      test {
        my $encoded = encode_web_utf8 $t->[0];
        my $decoded = decode_web_base64 $encoded;
        $decoded = defined $decoded ? [map { ord $_ } split //, $decoded] : undef;
        is b $decoded, b $t->[1];
        ok ! utf8::is_utf8 $decoded;
      } $c, name => $t->[0];
    }
    done $c;
  } name => ['decode', $path];
}

for my $path ($TestDataPath->children (qr/^decodeu-.+\.json$/)) {
  test {
    my $c = shift;
    for my $t (@{json_bytes2perl $path->slurp}) {
      test {
        my $encoded = encode_web_utf8 $t->[0];
        my $decoded = decode_web_base64url $encoded;
        $decoded = defined $decoded ? [map { ord $_ } split //, $decoded] : undef;
        is b $decoded, b $t->[1];
        ok ! utf8::is_utf8 $decoded;
      } $c, name => $t->[0];
    }
    done $c;
  } name => ['decode_web_base64url', $path];
}

run_tests;

=head1 LICENSE

Copyright 2018-2019 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
