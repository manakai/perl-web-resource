package Web::Transport::CachedResolver;
use strict;
use warnings;
our $VERSION = '2.0';
use Promise;
use Web::Host;
use AnyEvent::Util qw(fork_call);

sub new_from_resolver_and_clock ($$$) {
  return bless {resolver => $_[1], cache => {},
                clock => $_[2]}, $_[0];
} # new_from_resolver_and_clock

my $CacheMaxAge = 60;

sub resolve ($$;%) {
  my ($self, $host, %args) = @_;
  my $DEBUG = $args{debug} || 0;

  my $cached = $args{no_cache} ? undef : $self->{cache}->{$host->stringify};
  if (defined $cached) {
    my $now = $self->{clock}->();
    if (defined $cached and $cached->[1] + $CacheMaxAge > $now) {
      if ($DEBUG > 1) {
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
      if ($DEBUG > 1) {
        warn sprintf "%s: Waiting for cache of |%s|...\n",
            __PACKAGE__, $host->stringify;
      }
      return $cached->[2]->then (sub {
        if ($DEBUG > 1) {
          if (defined $_[0]) {
            warn sprintf "%s: Using cache: |%s| (elapsed %.3f s)\n",
                __PACKAGE__, $_[0]->stringify, $self->{clock}->() - $now;
          } else {
            warn sprintf "%s: Using cache: null (elapsed %.3f s)\n",
                __PACKAGE__, $self->{clock}->() - $now;
          }
        }
        return $_[0];
      });
    }

    warn sprintf "%s: |%s| is not cached\n", __PACKAGE__, $host->stringify
        if $DEBUG > 1;
  } # $cached

  my $p = $self->{resolver}->resolve ($host, signal => $args{signal}, debug => $args{debug})->then (sub {
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

Copyright 2016-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
