use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Web::Host;
use Web::Transport::PlatformResolver;

test {
  my $c = shift;
  my $host = Web::Host->parse_string ('192.168.20.4');
  my $resolver = Web::Transport::PlatformResolver->new;
  my $p = $resolver->resolve ($host);
  isa_ok $p, 'Promise';
  $p->then (sub {
    my $resolved = $_[0];
    test {
      ok $resolved->is_ip;
      is $resolved->stringify, $host->stringify;
    } $c;
    done $c;
    undef $c;
  });
} n => 3, name => 'input is an IPv4 address';

test {
  my $c = shift;
  my $host = Web::Host->parse_string ('[::4]');
  my $resolver = Web::Transport::PlatformResolver->new;
  my $p = $resolver->resolve ($host);
  isa_ok $p, 'Promise';
  $p->then (sub {
    my $resolved = $_[0];
    test {
      ok $resolved->is_ip;
      is $resolved->stringify, $host->stringify;
    } $c;
    done $c;
    undef $c;
  });
} n => 3, name => 'input is an IPv6 address';

test {
  my $c = shift;
  my $host = Web::Host->parse_string ('localhost');
  my $resolver = Web::Transport::PlatformResolver->new;
  my $p = $resolver->resolve ($host);
  isa_ok $p, 'Promise';
  $p->then (sub {
    my $resolved = $_[0];
    test {
      ok $resolved->is_ip;
      ok $resolved->stringify eq '127.0.0.1' ||
         $resolved->stringify eq '[::1]';
      ## In theory there can be a system where "localhost" can't be
      ## resolved or can be resolved but not '127.0.0.1'.
    } $c;
    done $c;
    undef $c;
  });
} n => 3, name => 'input is a domain';

run_tests;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
