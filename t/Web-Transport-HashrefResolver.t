use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use AbortController;
use Web::Host;
use Web::Transport::HashrefResolver;

test {
  my $c = shift;
  my $host = Web::Host->parse_string ('192.168.20.4');
  my $resolver = Web::Transport::HashrefResolver->new_from_hashref ({});
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
} n => 3, name => 'input is an IPv4 address (unchanged)';

test {
  my $c = shift;
  my $host = Web::Host->parse_string ('[::4]');
  my $resolver = Web::Transport::HashrefResolver->new_from_hashref ({});
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
} n => 3, name => 'input is an IPv6 address (unchanged)';

test {
  my $c = shift;
  my $host = Web::Host->parse_string ('google.com');
  my $resolver = Web::Transport::HashrefResolver->new_from_hashref ({});
  my $p = $resolver->resolve ($host);
  isa_ok $p, 'Promise';
  $p->then (sub {
    my $resolved = $_[0];
    test {
      is $resolved, undef;
    } $c;
    done $c;
    undef $c;
  });
} n => 2, name => 'input is a domain (not resolved)';

test {
  my $c = shift;
  my $host = Web::Host->parse_string ('google.com');
  my $host2 = Web::Host->parse_string ('192.168.10.5');
  my $resolver = Web::Transport::HashrefResolver->new_from_hashref ({
    'google.com' => $host2,
  });
  my $p = $resolver->resolve ($host);
  isa_ok $p, 'Promise';
  $p->then (sub {
    my $resolved = $_[0];
    test {
      is $resolved, $host2;
    } $c;
    done $c;
    undef $c;
  });
} n => 2, name => 'input is a domain (resolved)';

test {
  my $c = shift;
  my $host = Web::Host->parse_string ('10.0.0.51');
  my $host2 = Web::Host->parse_string ('192.168.10.5');
  my $resolver = Web::Transport::HashrefResolver->new_from_hashref ({
    '10.0.0.51' => $host2,
  });
  my $p = $resolver->resolve ($host);
  isa_ok $p, 'Promise';
  $p->then (sub {
    my $resolved = $_[0];
    test {
      is $resolved, $host2;
    } $c;
    done $c;
    undef $c;
  });
} n => 2, name => 'input is an IPv4 address (resolved)';

test {
  my $c = shift;
  my $host = Web::Host->parse_string ('[::5]');
  my $host2 = Web::Host->parse_string ('192.168.10.5');
  my $resolver = Web::Transport::HashrefResolver->new_from_hashref ({
    '[::5]' => $host2,
  });
  my $p = $resolver->resolve ($host);
  isa_ok $p, 'Promise';
  $p->then (sub {
    my $resolved = $_[0];
    test {
      is $resolved, $host2;
    } $c;
    done $c;
    undef $c;
  });
} n => 2, name => 'input is an IPv6 address (resolved)';

test {
  my $c = shift;
  my $host = Web::Host->parse_string ('google.com');
  my $host2 = Web::Host->parse_string ('192.168.10.5.test');
  my $resolver = Web::Transport::HashrefResolver->new_from_hashref ({
    'google.com' => $host2,
  });
  my $p = $resolver->resolve ($host);
  isa_ok $p, 'Promise';
  $p->catch (sub {
    my $error = $_[0];
    test {
      is $error->name, 'TypeError', $error;
    } $c;
  })->finally (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'resolved into a domain';

test {
  my $c = shift;
  my $host = Web::Host->parse_string ('google.com');
  my $host2 = Web::Host->parse_string ('192.168.10.5.test');
  my $resolver = Web::Transport::HashrefResolver->new_from_hashref ({
    'google.com' => 3134,
  });
  my $p = $resolver->resolve ($host);
  isa_ok $p, 'Promise';
  $p->catch (sub {
    my $error = $_[0];
    test {
      ok $error, $error;
    } $c;
  })->finally (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'resolved into a bad value';

test {
  my $c = shift;
  my $host = Web::Host->parse_string ('google.com');
  my $host2 = Web::Host->parse_string ('192.168.10.5.test');
  my $resolver = Web::Transport::HashrefResolver->new_from_hashref ({
    'google.com' => '',
  });
  my $p = $resolver->resolve ($host);
  isa_ok $p, 'Promise';
  $p->catch (sub {
    my $error = $_[0];
    test {
      ok $error, $error;
    } $c;
  })->finally (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'resolved into an empty';

test {
  my $c = shift;
  my $host = Web::Host->parse_string ('google.com');
  my $host2 = Web::Host->parse_string ('192.168.10.5.test');
  my $resolver = Web::Transport::HashrefResolver->new_from_hashref ({
    'google.com' => undef,
  });
  my $p = $resolver->resolve ($host);
  isa_ok $p, 'Promise';
  $p->then (sub {
    my $resolved = $_[0];
    test {
      is $resolved, undef;
    } $c;
  })->finally (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'resolved into an undef';

run_tests;

=head1 LICENSE

Copyright 2019 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
