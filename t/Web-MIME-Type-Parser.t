use strict;
use warnings;
use Path::Tiny;
use lib path (__FILE__)->parent->parent->child ('lib')->stringify;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib')->stringify;
use Test::More;
use Test::HTCT::Parser;
use Test::X1;
use Web::MIME::Type::Parser;
use Web::Encoding;

test {
  my $c = shift;
  my $parser = Web::MIME::Type::Parser->new;
  my $mt = $parser->parse_string (undef);
  is $mt, undef;
  done $c;
} n => 1, name => 'parse_string undef';

test {
  my $c = shift;
  my $parser = Web::MIME::Type::Parser->new;
  my $mt = $parser->parse_string (encode_web_utf8 'text/plain');
  is $mt->mime_type_portion, 'text/plain';
  done $c;
} n => 1, name => 'parse_string bytes';

test {
  my $c = shift;
  my $parser = Web::MIME::Type::Parser->new;
  my $mt = $parser->parse_string (substr "text/plain;x=\xFF\x{100}", 0, 10);
  is $mt->mime_type_portion, 'text/plain';
  done $c;
} n => 1, name => 'parse_string chars';

run_tests;

=head1 LICENSE

Copyright 2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
