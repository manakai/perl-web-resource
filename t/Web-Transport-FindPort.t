use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::X1;
use Test::More;
use Web::Transport::FindPort;

test {
    my $c = shift;
    ok !Web::Transport::FindPort::is_listenable_port(0);

    # A well-known port
    ok !Web::Transport::FindPort::is_listenable_port(70);

    # bad port
    ok !Web::Transport::FindPort::is_listenable_port(6667);
    done $c;
} n => 3, name => 'is_listenable_port ng';

test {
    my $c = shift;
    my $p1 = Web::Transport::FindPort::find_listenable_port;
    ok !Web::Transport::FindPort::is_listenable_port($p1);
    done $c;
} n => 1, name => 'is_listenable_port locked';

test {
    my $c = shift;
    my $p1 = find_listenable_port;
    ok $p1;
    ok $p1 > 1023;

    my $p2 = find_listenable_port;
    ok $p2;
    ok $p2 > 1023;
    isnt $p2, $p1;

    my $p3 = find_listenable_port;
    ok $p3;
    ok $p3 > 1023;
    isnt $p3, $p1;
    isnt $p3, $p2;
    done $c;
} n => 9, name => 'find_listenable_port exported';

test {
  my $c = shift;
  my $got = {};

  for (1..100) {
    my $p = Web::Transport::FindPort::find_listenable_port;
    ok $p, $p;
    ok $p > 1023;
    ok not $got->{$p}++;
  }

  done $c;
} n => 3*100, name => 'find_listenable_port';

run_tests;

=head1 LICENSE

Copyright 2010 Hatena <http://www.hatena.ne.jp/>

Copyright 2020 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
