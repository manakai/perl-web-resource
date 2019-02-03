package Web::Transport::AbortError;
use strict;
use warnings;
use Web::Transport::Error;
push our @ISA, qw(Web::Transport::Error);
our $VERSION = '2.0';

$Web::DOM::Error::L1ObjectClass->{(__PACKAGE__)} = 1;

sub new ($$) {
  my $self = bless {message => defined $_[1] ? ''.$_[1] : ''}, $_[0];
  $self->_set_stacktrace;
  return $self;
} # new

sub name ($) { 'AbortError' }

1;

=head1 LICENSE

Copyright 2012-2019 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
