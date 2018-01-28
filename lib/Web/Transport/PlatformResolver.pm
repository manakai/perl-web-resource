package Web::Transport::PlatformResolver;
use strict;
use warnings;
our $VERSION = '2.0';
use Promise;
use Web::Host;
use AnyEvent::Util qw(fork_call);

sub new ($) {
  return bless {}, $_[0];
} # new

sub resolve ($$;%) {
  my (undef, $host, %args) = @_;
  return Promise->resolve ($host) if $host->is_ip;
  return Promise->new (sub {
    my ($ok, $ng) = @_;

    my $aborted = 0;
    my $signal = delete $args{signal};
    if (defined $signal) {
      if ($signal->aborted) {
        my $error = $signal->manakai_error;
        return $ng->($error);
      } else {
        $signal->manakai_onabort (sub {
          $ng->($signal->manakai_error);
          undef $signal;
          $aborted = 1;
          $ok = $ng = sub { };
        });
      }
    }

    my $clock;
    my $time1;
    if ($args{debug}) {
      require Web::DateTime::Clock;
      $clock = Web::DateTime::Clock->monotonic_clock;
      $time1 = $clock->();
      warn sprintf "%s: Resolving |%s|...\n", __PACKAGE__, $host->stringify;
    }
    fork_call { scalar gethostbyname $_[0] } $host->stringify, sub {
      my $r = defined $_[0] ? Web::Host->new_from_packed_addr ($_[0]) : undef;
      if ($args{debug}) {
        if (defined $r) {
          warn sprintf "%s: Result: |%s| (elapsed %.3f s)\n",
              __PACKAGE__, $r->stringify, $clock->() - $time1;
        } else {
          warn sprintf "%s: Result: null (elapsed %.3f s)\n",
              __PACKAGE__, $clock->() - $time1;
        }
      }
      $signal->manakai_onabort (undef) if defined $signal;
      undef $signal;
      return if $aborted;
      if (defined $r and $r->is_ipv4 and $r->text_addr =~ /^0\./) { # 0.0.0.0/8
        $r = undef;
      }
      $ok->($r);
    };
  });
} # resolve

1;

=head1 LICENSE

Copyright 2016-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
