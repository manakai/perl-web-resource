package Resolver;
use strict;
use warnings;
use AnyEvent::Socket qw(format_address inet_aton);
use Promise;

sub resolve_name ($$) {
  my $name = $_[1];
  return Promise->new (sub {
    my ($ok, $ng) = @_;
    inet_aton $name, sub {
      if (defined $_[0]) {
        $ok->(format_address $_[0]);
      } else {
        $ok->(undef);
      }
    };
  });
} # resolve_name

1;
