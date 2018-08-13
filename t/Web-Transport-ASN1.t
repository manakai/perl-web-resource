use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Web::Transport::ASN1;

for my $test (
  [undef, undef, undef, undef],
  ['', undef, undef, undef],
  [0, undef, undef, undef],
  [1, undef, undef, undef],
  [rand, undef, undef, undef],
  ['2.5.4.3' => '2.5.4.3', 'CN', 'commonName'],
  ['CN' => '2.5.4.3', 'CN', 'commonName'],
  ['commonName' => '2.5.4.3', 'CN', 'commonName'],
  ['iso', '1.0', 'ISO', 'iso'],
  ['2.23.140.1.2.1', '2.23.140.1.2.1', undef, undef],
  ['a b c', undef, undef, undef],
) {
  test {
    my $c = shift;
    my $def = Web::Transport::ASN1->find_oid ($test->[0]);
    is $def->{oid}, $test->[1];
    is $def->{short_name}, $test->[2];
    is $def->{long_name}, $test->[3];
    done $c;
  } n => 3, name => [$test->[0]];
}

run_tests;

=head1 LICENSE

Copyright 2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
