package Resolver;
use strict;
use warnings;
use AnyEvent::Socket qw(format_address inet_aton);
use Promise;

sub resolve_name ($$;%) {
  my ($class, $name, %args) = @_;
  return Promise->new (sub {
    my ($ok, $ng) = @_;
    inet_aton $name, sub {
      if (defined $_[0]) {
        $ok->($args{packed} ? $_[0] : format_address $_[0]);
      } else {
        $ok->(undef);
      }
    };
  });
} # resolve_name

1;
