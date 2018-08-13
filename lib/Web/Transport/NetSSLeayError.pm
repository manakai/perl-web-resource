package Web::Transport::NetSSLeayError;
use strict;
use warnings;
our $VERSION = '1.0';
push our @ISA, qw(Web::Transport::ProtocolError);
use Web::Transport::ProtocolError;
use Net::SSLeay;

$Web::DOM::Error::L1ObjectClass->{(__PACKAGE__)} = 1;

sub new_current ($) {
  my $self = $_[0]->SUPER::new ('');
  $self->{errno} = Net::SSLeay::ERR_get_error ();
  $self->{message} = Net::SSLeay::ERR_error_string ($self->{errno});
  return $self;
} # new_current

sub name ($) { 'OpenSSL error' }

1;

=head1 LICENSE

Copyright 2016-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
