use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use JSON::PS;
use Web::Transport::Base64;
use Web::Encoding;

test {
  my $c = shift;
  is encode_web_base64 undef, '';
  done $c;
} n => 1, name => 'encode undef';

test {
  my $c = shift;
  eval {
    encode_web_base64 "\x{100}";
  };
  like $@, qr{^Wide character in subroutine entry at \Q@{[__FILE__]}\E line @{[__LINE__-2]}};
  done $c;
} n => 1, name => 'encode utf8';

test {
  my $c = shift;
  eval {
    encode_web_base64 substr "\x{FF}\x{100}", 0, 1;
  };
  like $@, qr{^Wide character in subroutine entry at \Q@{[__FILE__]}\E line @{[__LINE__-2]}};
  done $c;
} n => 1, name => 'encode utf8';

test {
  my $c = shift;
  is decode_web_base64 undef, '';
  done $c;
} n => 1, name => 'decode undef';

test {
  my $c = shift;
  is decode_web_base64 ("\x{FF}\x{100}"), undef;
  done $c;
} n => 1, name => 'decode utf8';

test {
  my $c = shift;
  is decode_web_base64 (substr "abcd\x{100}", 0, 4), "\x69\xB7\x1D";
  done $c;
} n => 1, name => 'decode utf8';

test {
  my $c = shift;
  "ab cd" =~ /(.+)/;
  is decode_web_base64 $1, "\x69\xB7\x1D";
  done $c;
} n => 1, name => 'decode';

run_tests;

=head1 LICENSE

Copyright 2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
