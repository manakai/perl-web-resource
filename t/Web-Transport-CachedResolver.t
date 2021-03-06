use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use AbortController;
use Web::Host;
use Web::Transport::PlatformResolver;
use Web::Transport::CachedResolver;
use Web::DateTime::Clock;

test {
  my $c = shift;
  my $host = Web::Host->parse_string ('192.168.20.4');
  my $r1 = Web::Transport::PlatformResolver->new;
  my $resolver = Web::Transport::CachedResolver->new_from_resolver_and_clock
      ($r1, Web::DateTime::Clock->monotonic_clock);
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
  my $r1 = Web::Transport::PlatformResolver->new;
  my $resolver = Web::Transport::CachedResolver->new_from_resolver_and_clock
      ($r1, Web::DateTime::Clock->monotonic_clock);
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
  my $r1 = Web::Transport::PlatformResolver->new;
  my $resolver = Web::Transport::CachedResolver->new_from_resolver_and_clock
      ($r1, Web::DateTime::Clock->monotonic_clock);
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

{
  package CustomResolver;
  sub resolve {
    my $v = $_[0]->{$_[1]->stringify};
    return Promise->resolve->then (sub {
      return Web::Host->parse_string ($v) if defined $v;
      return $v;
    });
  }
}

test {
  my $c = shift;
  my $r1 = bless {
    'hoge.test' => '1.2.3.4',
  }, 'CustomResolver';
  my $resolver = Web::Transport::CachedResolver->new_from_resolver_and_clock
      ($r1, Web::DateTime::Clock->monotonic_clock);
  $resolver->resolve (Web::Host->parse_string ('hoge.test'))->then (sub {
    my $resolved = $_[0];
    test {
      ok $resolved->is_ip;
      is $resolved->stringify, '1.2.3.4';
    } $c;
    done $c;
    undef $c;
  });
} n => 2, name => 'input is a domain, custom resolver, found';

test {
  my $c = shift;
  my $r1 = bless {
  }, 'CustomResolver';
  my $resolver = Web::Transport::CachedResolver->new_from_resolver_and_clock
      ($r1, Web::DateTime::Clock->monotonic_clock);
  $resolver->resolve (Web::Host->parse_string ('hoge.test'))->then (sub {
    my $resolved = $_[0];
    test {
      is $resolved, undef;
    } $c;
    done $c;
    undef $c;
  });
} n => 1, name => 'input is a domain, custom resolver, not found';

test {
  my $c = shift;
  my $r1 = bless {
    'hoge.test' => '1.2.3.4',
  }, 'CustomResolver';
  my $time = 1;
  my $clock = sub { return $time };
  my $resolver = Web::Transport::CachedResolver->new_from_resolver_and_clock
      ($r1, $clock);
  $resolver->resolve (Web::Host->parse_string ('hoge.test'))->then (sub {
    my $resolved = $_[0];
    test {
      is $resolved->stringify, '1.2.3.4';
    } $c;
    $time = 50;
    return $resolver->resolve (Web::Host->parse_string ('hoge.test'));
  })->then (sub {
    my $resolved = $_[0];
    test {
      is $resolved->stringify, '1.2.3.4';
    } $c;
    $time = 100;
    $r1->{'hoge.test'} = '4.5.6.7';
    return $resolver->resolve (Web::Host->parse_string ('hoge.test'));
  })->then (sub {
    my $resolved = $_[0];
    test {
      is $resolved->stringify, '4.5.6.7';
    } $c;
    done $c;
    undef $c;
  });
} n => 3, name => 'input is a domain, custom resolver, cache';

test {
  my $c = shift;
  my $r1 = bless {
    'hoge.test' => '1.2.3.4',
  }, 'CustomResolver';
  my $time = 1;
  my $clock = sub { return $time };
  my $resolver = Web::Transport::CachedResolver->new_from_resolver_and_clock
      ($r1, $clock);
  $resolver->resolve (Web::Host->parse_string ('hoge.test'))->then (sub {
    my $resolved = $_[0];
    test {
      is $resolved->stringify, '1.2.3.4';
    } $c;
    $time = 50;
    $r1->{'hoge.test'} = '4.5.6.7';
    return $resolver->resolve (Web::Host->parse_string ('hoge.test'), no_cache => 1);
  })->then (sub {
    my $resolved = $_[0];
    test {
      is $resolved->stringify, '4.5.6.7';
    } $c;
    $time = 100;
    $r1->{'hoge.test'} = '8.9.0.1';
    return $resolver->resolve (Web::Host->parse_string ('hoge.test'));
  })->then (sub {
    my $resolved = $_[0];
    test {
      is $resolved->stringify, '4.5.6.7';
    } $c;
    done $c;
    undef $c;
  });
} n => 3, name => 'input is a domain, custom resolver, cache, no_cache arg';

test {
  my $c = shift;
  my $host = Web::Host->parse_string (rand . '.foobar.com');
  my $r1 = Web::Transport::PlatformResolver->new;
  my $resolver = Web::Transport::CachedResolver->new_from_resolver_and_clock
      ($r1, Web::DateTime::Clock->monotonic_clock);
  my $ac = AbortController->new;
  my $p = $resolver->resolve ($host, signal => $ac->signal);
  $ac->abort;
  isa_ok $p, 'Promise';
  $p->then (sub {
    my $resolved = $_[0];
    test {
      is $resolved, undef, 'Resolved to undef';
      ok 1;
      ok 1;
      ok 1;
    } $c;
  }, sub {
    my $e = $_[0];
    test {
      is $e->name, 'AbortError';
      is $e->message, 'Aborted';
      is $e->file_name, __FILE__;
      is $e->line_number, __LINE__-16;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 5, name => 'resolve abort';

test {
  my $c = shift;
  my $host = Web::Host->parse_string (rand . '.foobar.com');
  my $r1 = Web::Transport::PlatformResolver->new;
  my $resolver = Web::Transport::CachedResolver->new_from_resolver_and_clock
      ($r1, Web::DateTime::Clock->monotonic_clock);
  my $ac = AbortController->new;
  $ac->abort;
  my $p = $resolver->resolve ($host, signal => $ac->signal);
  isa_ok $p, 'Promise';
  $p->then (sub {
    my $resolved = $_[0];
    test {
      ok 0;
    } $c;
  }, sub {
    my $e = $_[0];
    test {
      is $e->name, 'AbortError';
      is $e->message, 'Aborted';
      is $e->file_name, __FILE__;
      is $e->line_number, __LINE__-14;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 5, name => 'resolve abort';

test {
  my $c = shift;
  {
    package test::TestResolver1;
    our $X = 0;
    sub resolve ($$;%) {
      die "test resolver error" unless $X++;
      return Web::Host->parse_string ('1.2.3.4');
    }
  }
  my $host = Web::Host->parse_string (rand . '.foobar.com');
  my $r1 = bless {}, 'test::TestResolver1';
  my $resolver = Web::Transport::CachedResolver->new_from_resolver_and_clock
      ($r1, Web::DateTime::Clock->monotonic_clock);
  return $resolver->resolve ($host)->then (sub {
    my $resolved = $_[0];
    test {
      ok 0;
    } $c;
  }, sub {
    my $e = $_[0];
    test {
      like $e, qr/^test resolver error/;
    } $c;
    return $resolver->resolve ($host);
  })->then (sub {
    my $resolved = $_[0];
    test {
      is $resolved->to_ascii, '1.2.3.4';
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'resolve abort';

run_tests;

=head1 LICENSE

Copyright 2016-2019 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
