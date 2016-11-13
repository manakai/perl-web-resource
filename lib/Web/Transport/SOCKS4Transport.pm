package Web::Transport::SOCKS4Transport;
use strict;
use warnings;
our $VERSION = '2.0';
use Carp qw(croak);
use AnyEvent;
use Promise;

sub new ($%) {
  my $self = bless {}, shift;
  my $args = $self->{args} = {@_};
  my $port = $args->{port};
  croak "Bad |port|" unless defined $port and $port =~ /\A[0-9]+\z/ and $port <= 0xFFFF;
  croak "Bad |host|" unless defined $args->{host} and $args->{host}->is_ipv4;
  $self->{transport} = delete $self->{args}->{transport};
  $self->{id} = $self->{transport}->id . 'S4';
  return $self;
} # new

sub id ($) {
  return $_[0]->{id};
} # id

sub type ($) { return 'SOCKS4' }
sub layered_type ($) { return $_[0]->type . '/' . $_[0]->{transport}->layered_type }
sub request_mode ($) { 'default' }
sub info ($) { return $_[0]->{info} } # or undef

our $HandshakeTimeout ||= 30;

sub start ($$;%) {
  my $self = $_[0];
  croak "Bad state" if not defined $self->{args};
  $self->{cb} = $_[1];
  my $args = delete $self->{args};

  $self->{info} = {remote_host => $args->{host},
                   remote_port => $args->{port}};

  my ($ok0, $ng0) = @_;
  my $p0 = Promise->new (sub { ($ok0, $ng0) = @_ });

  my ($ok, $ng) = @_;
  my $p = Promise->new (sub { ($ok, $ng) = @_ });

  my $timer;
  my $timeout = $HandshakeTimeout;
  my $ontimer = sub {
    $self->{transport}->abort (message => "SOCKS4 timeout ($timeout)")
        if defined $self->{transport};
    undef $timer;
  };
  $timer = AE::timer $timeout, 0, $ontimer;

  my $last_error;
  my $data = '';
  my $process_data = sub {
    if (length $data >= 8 or $_[0]) {
      if (length $data >= 8 and substr ($data, 0, 2) eq "\x00\x5A") {
        undef $timer;
        substr ($data, 0, 8) = '';
        $self->{started} = 1;
        $self->{cb}->($self, 'open');
        $ok->();
        if (length $data) {
          $self->{cb}->($self, 'readdata', \$data);
        }
      } else {
        my $error = {failed => 1, message => 'SOCKS4 server does not return a valid reply'};
        if (length $data) {
          $error->{message} .= sprintf " (result code %d)", ord substr $data, 1, 1;
        } else {
          $error->{message} .= ' (empty)';
        }
        $self->{transport}->abort (message => $error->{message});
        $last_error ||= $error;
      }
    }
  }; # $process_data

  my $readeof_sent = 0;
  my $writeeof_sent = 0;
  return $self->{transport}->start (sub {
    my $type = $_[1];
    if ($self->{started}) {
      if ($type eq 'close') {
        $self->{cb}->('readeof', {failed => 1, message => "Read already closed"}) if $readeof_sent;
        $self->{cb}->('writeeof', {failed => 1, message => "Write already closed"}) if $writeeof_sent;
        goto &{delete $self->{cb}};
      } else {
        goto &{$self->{cb}};
      }
    }
    if ($type eq 'readdata') {
      $data .= ${$_[2]};
      $process_data->(0);
    } elsif ($type eq 'readeof') {
      $last_error = $_[2] if $_[2]->{failed};
      $process_data->(1);
      $readeof_sent = 1;
    } elsif ($type eq 'writeeof') {
      $writeeof_sent = 1;
    } elsif ($type eq 'open') {
      my $port = $args->{port};
      my $addr = $args->{host}->packed_addr;
      $self->{transport}->push_write
          (\("\x04\x01".(pack 'n', $port).$addr."\x00"));
      $self->{transport}->push_promise->then ($ok0, $ng0);
    } elsif ($type eq 'close') {
      unless ($last_error) {
        $last_error = {failed => 1, message => 'SOCKS4 server does not return a valid reply'};
      }
      $ng0->("Closed before SOCKS4 handshake sent");
      $ng->($last_error);
      delete $self->{transport};
      delete $self->{cb};
      undef $timer;
      undef $self;
    }
  })->then (sub {
    return $p0;
  })->then (sub {
    return $p;
  });
} # start

sub read_closed ($) { return $_[0]->{transport}->read_closed }
sub write_closed ($) { return $_[0]->{transport}->write_closed }
sub write_to_be_closed ($) {
  return 1 unless defined $_[0]->{transport};
  return $_[0]->{transport}->write_to_be_closed;
} # write_to_be_closed

sub push_write ($$;$$) {
  croak "Bad state" unless $_[0]->{started};
  return shift->{transport}->push_write (@_);
} # push_write

sub push_promise ($) {
  croak "Bad state" unless $_[0]->{started};
  return shift->{transport}->push_promise (@_);
} # push_promise

sub push_shutdown ($) {
  croak "Bad state" unless $_[0]->{started};
  return shift->{transport}->push_shutdown (@_);
} # push_shutdown

sub abort ($;%) {
  return shift->{transport}->abort (@_) if defined $_[0]->{transport};
} # abort

sub DESTROY ($) {
  $_[0]->abort (message => "Aborted by DESTROY of $_[0]");

  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;

} # DESTROY

1;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
