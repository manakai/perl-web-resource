use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Web::URL;
use Web::Transport::ConstProxyManager;

for (
  [],
  [{protocol => 'tcp'}],
  [{protocol => 'unix', path => '/tmp/foo/bar'}],
) {
  my ($in, @expected) = @_;
  test {
    my $c = shift;
    my $pm = Web::Transport::ConstProxyManager->new_from_arrayref ($in);
    isa_ok $pm, 'Web::Transport::ConstProxyManager';
    is ref $in, 'ARRAY';

    my @p;

    my $u0 = Web::URL->parse_string ("https://test1/");
    my $p0 = $pm->get_proxies_for_url ($u0);
    isa_ok $p0, 'Promise';
    push @p, $p0->then (sub {
      my $a0 = shift;
      test {
        is_deeply $a0, $in;
      } $c;
    }, sub {
      test { ok 0 } $c;
    });

    Promise->all (\@p)->then (sub {
      done $c;
      undef $c;
    });
  } n => 4;
}

test {
  my $c = shift;
  my $in = [{host => 'hoge.test', port => 42}];
  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref ($in);
  isa_ok $pm, 'Web::Transport::ConstProxyManager';
  is ref $in, 'ARRAY';

  my @p;

  my $u0 = Web::URL->parse_string ("https://test1/");
  my $p0 = $pm->get_proxies_for_url ($u0);
  isa_ok $p0, 'Promise';
  push @p, $p0->then (sub {
    my $a0 = shift;
    test {
      is 0+@{$a0}, 1;
      isa_ok $a0->[0]->{host}, 'Web::Host';
      is $a0->[0]->{host}->to_ascii, 'hoge.test';
      is $a0->[0]->{port}, 42;
    } $c;
  }, sub {
    test { ok 0 } $c;
  });

  Promise->all (\@p)->then (sub {
    done $c;
    undef $c;
  });
} n => 7;

test {
  my $c = shift;
  my $in = [{host => '127.0.0.4', port => 42}];
  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref ($in);
  isa_ok $pm, 'Web::Transport::ConstProxyManager';
  is ref $in, 'ARRAY';

  my @p;

  my $u0 = Web::URL->parse_string ("https://test1/");
  my $p0 = $pm->get_proxies_for_url ($u0);
  isa_ok $p0, 'Promise';
  push @p, $p0->then (sub {
    my $a0 = shift;
    test {
      is 0+@{$a0}, 1;
      isa_ok $a0->[0]->{host}, 'Web::Host';
      is $a0->[0]->{host}->to_ascii, '127.0.0.4';
      is $a0->[0]->{port}, 42;
    } $c;
  }, sub {
    test { ok 0 } $c;
  });

  Promise->all (\@p)->then (sub {
    done $c;
    undef $c;
  });
} n => 7;

test {
  my $c = shift;
  my $in = [{host => Web::Host->parse_string ('hoge.test'), port => 42}];
  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref ($in);
  isa_ok $pm, 'Web::Transport::ConstProxyManager';
  is ref $in, 'ARRAY';

  my @p;

  my $u0 = Web::URL->parse_string ("https://test1/");
  my $p0 = $pm->get_proxies_for_url ($u0);
  isa_ok $p0, 'Promise';
  push @p, $p0->then (sub {
    my $a0 = shift;
    test {
      is 0+@{$a0}, 1;
      isa_ok $a0->[0]->{host}, 'Web::Host';
      is $a0->[0]->{host}->to_ascii, 'hoge.test';
      is $a0->[0]->{port}, 42;
    } $c;
  }, sub {
    test { ok 0 } $c;
  });

  Promise->all (\@p)->then (sub {
    done $c;
    undef $c;
  });
} n => 7;

test {
  my $c = shift;
  my $in = [{host => 'in:valid', port => 42}];
  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref ($in);
  isa_ok $pm, 'Web::Transport::ConstProxyManager';
  is ref $in, 'ARRAY';

  my @p;

  my $u0 = Web::URL->parse_string ("https://test1/");
  my $p0 = $pm->get_proxies_for_url ($u0);
  isa_ok $p0, 'Promise';
  push @p, $p0->then (sub {
    my $a0 = shift;
    test {
      is 0+@{$a0}, 1;
      is $a0->[0]->{host}, undef;
      is $a0->[0]->{port}, 42;
    } $c;
  }, sub {
    test { ok 0 } $c;
  });

  Promise->all (\@p)->then (sub {
    done $c;
    undef $c;
  });
} n => 6;

run_tests;

=head1 LICENSE

Copyright 2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
