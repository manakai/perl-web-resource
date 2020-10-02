use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Web::Transport::Response;

test {
  my $c = shift;
  my $res = bless {headers => [
    ['Hoge', 'abc', 'hoge'],
    ['Foo', 'X', 'foo'],
    ['HOGE', 'zzz', 'hoge'],
    ['bac', '', 'bac'],
    ['xyz', '', 'xyz'],
    ['xyz', '0', 'xyz'],
  ]}, 'Web::Transport::Response';
  is $res->header ('hoge'), 'abc, zzz';
  is $res->header ('hoGE'), 'abc, zzz';
  is $res->header ('hoge'), 'abc, zzz';
  is_deeply $res->header_all ('HOGE'), ['abc', 'zzz'];
  is_deeply $res->header_all ('hoGE'), ['abc', 'zzz'];
  is_deeply $res->header_all ('hoge'), ['abc', 'zzz'];
  is $res->header ('foO'), 'X';
  is_deeply $res->header_all ('foO'), ['X'];
  is $res->header ('bac'), '';
  is_deeply $res->header_all ('bac'), [''];
  is $res->header ('xyz'), ', 0';
  is_deeply $res->header_all ('xyz'), ['', '0'];
  is $res->header ('foo2'), undef;
  is_deeply $res->header_all ('foo2'), [];
  is $res->header (':'), undef;
  is_deeply $res->header_all (':'), [];
  done $c;
} n => 16, name => 'header';

run_tests;

=head1 LICENSE

Copyright 2016-2020 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
