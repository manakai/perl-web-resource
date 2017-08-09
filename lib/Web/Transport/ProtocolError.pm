package Web::Transport::ProtocolError;
use strict;
use warnings;
our $VERSION = '1.0';
use Errno qw(ECONNRESET);
use Web::DOM::Error;
use Web::DOM::Exception;
push our @ISA, qw(Web::DOM::Exception);

$Web::DOM::Error::L1ObjectClass->{(__PACKAGE__)} = 1;

## This module is not public, though instances of classes defined in
## this module might be exposed to applications.

## Returns whether the argument is a TCP reset (or equivalent) or not.
sub is_reset ($$) {
  return (UNIVERSAL::isa ($_[1], 'Streams::IOError') and
          $_[1]->errno == ECONNRESET);
} # is_reset

## Returns whether the argument is a fatal protocol error or not.
##
## Note that this method's definition of "is error" is different from
## Web::DOM::Error->is_error's.
sub is_error ($$) {
  my $error = $_[1];

  if (UNIVERSAL::isa ($error, __PACKAGE__ . '::HTTPParseError')) {
    return $error->http_fatal;
  }

  if (UNIVERSAL::isa ($error, __PACKAGE__ . '::WebSocketClose')) {
    return not $error->ws_cleanly;
  }

  return 1;
} # is_error

sub new ($$) {
  return $_[0]->SUPER::new ($_[1], 'Protocol error');
} # new

package Web::Transport::ProtocolError::HTTPParseError;
push our @ISA, qw(Web::Transport::ProtocolError);

$Web::DOM::Error::L1ObjectClass->{(__PACKAGE__)} = 1;

sub _new_non_fatal ($$) {
  return $_[0]->Web::DOM::Exception::new ($_[1], 'HTTP parse error');
} # _new_non_fatal

sub _new_fatal ($$) {
  my $self = $_[0]->Web::DOM::Exception::new ($_[1], 'HTTP parse error');
  $self->{http_fatal} = 1;
  return $self;
} # _new_fatal

sub _new_retry ($$$) {
  my $self = $_[0]->Web::DOM::Exception::new ($_[1], 'HTTP parse error');
  $self->{http_fatal} = 1;
  $self->{http_can_retry} = $_[2];
  return $self;
} # _new_retry

sub message ($) {
  my $self = $_[0];
  my $msg = $self->SUPER::message;
  $msg .= ' (non-fatal)' unless $self->{http_fatal};
  $msg .= ' (can retry)' if $self->{http_can_retry};
  return $msg;
} # message

sub http_fatal ($) { $_[0]->{http_fatal} }
sub http_can_retry ($) { $_[0]->{http_can_retry} }

package Web::Transport::ProtocolError::WebSocketClose;
push our @ISA, qw(Web::DOM::Error);

$Web::DOM::Error::L1ObjectClass->{(__PACKAGE__)} = 1;

sub new ($$$) {
  my ($class, $status, $reason, $error) = @_;
  my $self = $class->SUPER::new ('');
  $self->{ws_status} = $status;
  $self->{ws_reason} = $reason;
  $self->{ws_error} = $error; # or undef
  return $self;
} # new

sub name ($) { return 'WebSocket Close' }

sub message ($) {
  my $self = $_[0];
  my $error = $self->{ws_error};
  if (defined $error) {
    return sprintf '(%d %s) %s',
        $self->{ws_status}, $self->{ws_reason}, $error->message;
  } else {
    return sprintf '(%d %s) WebSocket closed cleanly',
        $self->{ws_status}, $self->{ws_reason};
  }
} # message

sub file_name ($) {
  my $self = $_[0];
  if (defined $self->{ws_error}) {
    return $self->{ws_error}->file_name;
  } else {
    return $self->SUPER::file_name;
  }
} # file_name

sub line_number ($) {
  my $self = $_[0];
  if (defined $self->{ws_error}) {
    return $self->{ws_error}->line_number;
  } else {
    return $self->SUPER::line_number;
  }
} # line_number

sub ws_cleanly ($) { not defined $_[0]->{ws_error} }
sub ws_status ($) { $_[0]->{ws_status} }
sub ws_reason ($) { $_[0]->{ws_reason} }

1;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
