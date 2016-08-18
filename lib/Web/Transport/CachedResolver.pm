package Web::Transport::CachedResolver;
use strict;
use warnings;
our $VERSION = '1.0';
use Promise;
use Web::Host;
use AnyEvent::Util qw(fork_call);

use constant DEBUG => $ENV{WEBUA_DEBUG} || 0;

sub new_from_resolver_and_clock ($$$) {
  return bless {resolver => $_[1], cache => {},
                clock => $_[2]}, $_[0];
} # new_from_resolver_and_clock

my $CacheMaxAge = 60;

sub resolve ($$;%) {
  my ($self, $host, %args) = @_;

  my $cached = $args{no_cache} ? undef : $self->{cache}->{$host->stringify};
  if (defined $cached) {
    my $now = $self->{clock}->();
    if (defined $cached and $cached->[1] + $CacheMaxAge > $now) {
      if (DEBUG > 1) {
        if (defined $cached->[0]) {
          warn sprintf "%s: Using cache of |%s|: |%s| (age %.3f s)\n",
              __PACKAGE__, $host->stringify,
              $cached->[0]->stringify, $now - $cached->[1];
        } else {
          warn sprintf "%s: Using cache of |%s|: null (age %.3f s)\n",
              __PACKAGE__, $host->stringify, $now - $cached->[1];
        }
      }
      return Promise->resolve ($cached->[0]);
    }

    if (defined $cached and defined $cached->[2]) {
      my $clock;
      my $time1;
      if (DEBUG > 1) {
        require Web::DateTime::Clock;
        $clock = Web::DateTime::Clock->realtime_clock;
        $time1 = $clock->();
        warn sprintf "%s: Waiting for cache of |%s|...\n",
            __PACKAGE__, $host->stringify;
      }
      return $cached->[2]->then (sub {
        if (DEBUG > 1) {
          if (defined $_[0]) {
            warn sprintf "%s: Using cache: |%s| (elapsed %.3f s)\n",
                __PACKAGE__, $_[0]->stringify, $clock->() - $time1;
          } else {
            warn sprintf "%s: Using cache: null (elapsed %.3f s)\n",
                __PACKAGE__, $clock->() - $time1;
          }
        }
        return $_[0];
      });
    }

    warn sprintf "%s: |%s| is not cached\n", __PACKAGE__, $host->stringify
        if DEBUG > 1;
  } # $cached

  my $p = $self->{resolver}->resolve ($host)->then (sub {
    my $now = $self->{clock}->();
    $self->{cache}->{$host->stringify} = [
      $_[0],
      $now,
    ];
    return $_[0];
  });
  $self->{cache}->{$host->stringify} = [undef, 0, $p];
  return $p;
} # resolve

1;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut