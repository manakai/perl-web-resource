package Web::Transport::HashrefResolver;
use strict;
use warnings;
our $VERSION = '1.0';
use Promise;
use Web::Transport::TypeError;

push our @CARP_NOT, qw(Web::Transport::TypeError);

sub new_from_hashref ($$) {
  return bless $_[1], $_[0];
} # new_from_hashref

sub resolve ($$;%) {
  my ($self, $host, %args) = @_;
  return Promise->resolve->then (sub {
    return $self->{$host->to_ascii};
  })->then (sub {
    if (not defined $_[0]) {
      if ($host->is_ip) {
        return $host;
      } else {
        return undef;
      }
    } elsif ($_[0]->is_ip) {
      return $_[0];
    } else {
      die new Web::Transport::TypeError ("$_[0] is not an IP address");
    }
  });
} # resolve

1;

=head1 LICENSE

Copyright 2019 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
