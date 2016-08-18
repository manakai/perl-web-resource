use strict;
use warnings;
use Web::Encoding;
use Web::Host;
use Web::Transport::PlatformResolver;
use Web::Transport::CachedResolver;
use Web::DateTime::Clock;

my $input = decode_web_utf8 shift;
my $input_host = Web::Host->parse_string ($input) // die "Bad input |$input|";

warn "Resolving |@{[$input_host->stringify]}|...\n";

my $r1 = Web::Transport::PlatformResolver->new;
my $r2 = Web::Transport::CachedResolver->new_from_resolver_and_clock
    ($r1, Web::DateTime::Clock->monotonic_clock);

my $p1 = $r2->resolve ($input_host);
my $p2 = $r2->resolve ($input_host);
$p1->then (sub {
  my $output_host = $_[0];
  if (defined $output_host) {
    warn "Result: |@{[$output_host->stringify]}|\n";
  } else {
    warn "Failed\n";
  }
  return $p2->then (sub {
    #warn $_[0]->stringify if defined $_[0];
  });
})->then (sub {
  use Time::HiRes qw(usleep);
  usleep (1_000_000);
})->then (sub {
  return $r2->resolve ($input_host);
})->to_cv->recv;
