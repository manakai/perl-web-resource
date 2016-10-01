package Web::Transport::UNIXDomainSocketTransport;
use strict;
use warnings;
our $VERSION = '1.0';
require utf8;
use Carp qw(croak);
use Web::Transport::TCPTransport;
push our @ISA, qw(Web::Transport::TCPTransport);

sub new ($%) {
  my $self = bless {}, shift;
  my $args = $self->{args} = {@_};
  $args->{addr} = 'unix/';
  $args->{port} = delete $args->{path};
  croak "No |file_name| specified" unless defined $args->{port};
  croak "Bad |id|" if defined $args->{id} and utf8::is_utf8 ($args->{id});
  $self->{id} = (defined $args->{id} ? $args->{id} : $$ . '.' . ++$Web::Transport::NextID);
  return $self;
} # new

sub type ($) { return 'UNIX' }
sub request_mode ($) { 'default' }

1;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
