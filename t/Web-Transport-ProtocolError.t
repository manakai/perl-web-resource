use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Web::Transport::ProtocolError;

test {
  my $c = shift;
  ok $Web::DOM::Error::L1ObjectClass->{'Web::Transport::ProtocolError'};
  ok $Web::DOM::Error::L1ObjectClass->{'Web::Transport::ProtocolError::HTTPParseError'};
  ok $Web::DOM::Error::L1ObjectClass->{'Web::Transport::ProtocolError::WebSocketClose'};
  done $c;
}  n => 3;

run_tests;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
