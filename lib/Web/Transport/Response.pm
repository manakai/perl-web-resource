package Web::Transport::Response;
use strict;
use warnings;
use overload '""' => 'stringify', fallback => 1;
our $VERSION = '1.0';

sub is_network_error ($) {
  return $_[0]->{failed} && !$_[0]->{ws};
} # is_network_error

sub is_reset_error ($) {
  return $_[0]->is_network_error && $_[0]->{reset};
} # is_reset_error

sub network_error_message ($) {
  return $_[0]->{message};
} # network_error_message

sub status ($) {
  return $_[0]->{status} || 0;
} # status

## HTTP::Response compatibility
*code = \&status;

## HTTP::Response compatibility
sub is_success ($) {
  return 0 if $_[0]->{failed} || ($_[0]->{ws} && $_[0]->{ws} == 1);
  return (200 <= $_[0]->{status} and $_[0]->{status} <= 299);
} # is_success

## HTTP::Response compatibility
sub is_error ($) {
  return 1 if $_[0]->{failed};
  return (400 <= $_[0]->{status} and $_[0]->{status} <= 599);
} # is_error

sub status_text ($) {
  return defined $_[0]->{reason} ? $_[0]->{reason} : '';
} # status_text

## HTTP::Response compatibility
sub status_line ($) {
  return $_[0]->status . ' ' . $_[0]->status_text;
} # status_line

sub ws_code ($) {
  if ($_[0]->{ws} and $_[0]->{ws} == 1) {
    return $_[0]->{status};
  } else {
    return 1006;
  }
} # ws_code

sub ws_reason ($) {
  if ($_[0]->{ws} and $_[0]->{ws} == 1) {
    return $_[0]->{reason};
  } else {
    return '';
  }
} # ws_reason

sub ws_closed_cleanly ($) {
  return $_[0]->{cleanly};
} # ws_closed_cleanly

# XXX need header API

## HTTP::Response compatibility
sub header ($$) {
  my $name = $_[1];
  $name =~ tr/A-Z/a-z/; ## ASCII case-insensitive
  for (@{$_[0]->{headers}}) {
    if ($_->[2] eq $name) {
      return $_->[1];
    }
  }
  return undef;
} # header

sub body_bytes ($) {
  return undef unless defined $_[0]->{body};
  return join '', map { $$_ } @{$_[0]->{body}};
} # body_bytes

## HTTP::Response compatibility
sub content ($) {
  return '' if not defined $_[0]->{body};
  return $_[0]->body_bytes;
} # content

sub incomplete ($) {
  return $_[0]->{incomplete};
} # incomplete

## HTTP::Response compatibility
sub as_string ($) {
  my $self = $_[0];
  return 'HTTP/1.1 ' . $self->status_line . "\x0D\x0A" .
      (join '', map { "$_->[0]: $_->[1]\x0D\x0A" } @{$_[0]->{headers}}) .
      "\x0D\x0A" .
      $_[0]->content;
} # as_string

sub stringify ($) {
  my $self = $_[0];
  if ($self->{ws}) {
    if ($self->{ws} == 2) {
      return "WS handshake error: @{[$self->status_line]}";
    } else {
      return sprintf "WS closed (%d |%s| failed = %d, cleanly = %d)",
          $self->{status}, $self->{reason},
          $self->{failed} ? 1 : 0, $self->{cleanly} ? 1 : 0;
    }
  } elsif ($self->is_network_error) {
    return "Network error: @{[$self->network_error_message]}";
  } else {
    return "Response: @{[$self->status_line]}";
  }
} # stringify

1;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
