use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Web::Transport::NetSSLeayError;

test {
  my $c = shift;
  ok $Web::DOM::Error::L1ObjectClass->{'Web::Transport::NetSSLeayError'};
  done $c;
} n => 1, name => 'Perl Error Object Interface Level 1';

run_tests;

=head1 LICENSE

Copyright 2017-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
