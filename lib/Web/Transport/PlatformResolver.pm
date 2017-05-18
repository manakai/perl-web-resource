package Web::Transport::PlatformResolver;
use strict;
use warnings;
our $VERSION = '1.0';
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
      if (defined $r and $r->is_ipv4 and $r->text_addr =~ /^0\./) { # 0.0.0.0/8
        $r = undef;
      }
      $ok->($r);
    };
  });
} # resolve

1;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
