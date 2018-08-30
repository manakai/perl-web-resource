package Web::Transport::CustomStream;
use strict;
use warnings;
our $VERSION = '4.0';
use Promise;
use Web::Transport::TypeError;

push our @CARP_NOT, qw(
  Web::Transport::TypeError
);

sub _tep ($) {
  return Promise->reject (Web::Transport::TypeError->new ($_[0]));
} # _tep

sub create ($$) {
  my ($class, $args) = @_;

  return _tep "Bad |readable|" unless defined $args->{readable};
  return _tep "Bad |writable|" unless defined $args->{writable};
  return _tep "Bad |closed|" unless defined $args->{closed};

  my $id = defined $args->{id} ? $args->{id} : (defined $args->{parent_id} ? $args->{parent_id} : $$) . '.' . ++$Web::Transport::NextID;
  my $type = defined $args->{type} ? $args->{type} : 'Custom';

  my $info = {
    type => $type,
    layered_type => (defined $args->{parent_layered_type} ? $type . '/' . $args->{parent_layered_type} : $type),
    id => $id,

    readable => $args->{readable},
    writable => $args->{writable},
    closed => $args->{closed},
  };

  ## $args->{signal} has no effect.

  return Promise->resolve->then (sub {
    return $info;
  });
} # create

1;

=head1 LICENSE

Copyright 2016-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
