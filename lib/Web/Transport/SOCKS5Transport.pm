package Web::Transport::SOCKS5Transport;
use strict;
use warnings;
our $VERSION = '2.0';
use Carp qw(croak);
use AnyEvent;
use Promise;
use Web::Encoding qw(encode_web_utf8);

sub new ($%) {
  my $self = bless {}, shift;
  my $args = $self->{args} = {@_};
  my $port = $args->{port};
  croak "Bad |port|" unless defined $port and $port =~ /\A[0-9]+\z/ and $port <= 0xFFFF;
  croak "Bad |host|" if not defined $args->{host};
  $self->{transport} = delete $self->{args}->{transport};
  $self->{id} = $self->{transport}->id . 'S5';
  return $self;
} # new

sub id ($) {
  return $_[0]->{id};
} # id

sub type ($) { return 'SOCKS5' }
sub layered_type ($) { return $_[0]->type . '/' . $_[0]->{transport}->layered_type }
sub request_mode ($) { 'default' }
sub info ($) { return $_[0]->{info} } # or undef

sub _e4d ($) {
  return $_[0] unless $_[0] =~ /[^\x20-\x5B\x5D-\x7E]/;
  my $x = $_[0];
  $x =~ s/([^\x20-\x5B\x5D-\x7E])/sprintf '\x%02X', ord $1/ge;
  return $x;
} # _e4d

our $HandshakeTimeout ||= 30;

sub start ($$;%) {
  my $self = $_[0];
  croak "Bad state" if not defined $self->{args};
  $self->{cb} = $_[1];
  my $args = delete $self->{args};

  $self->{info} = {remote_host => $args->{host},
                   remote_port => $args->{port}};

  my $timer;
  my $timeout = $HandshakeTimeout;
  my $ontimer = sub {
    $self->{transport}->abort (message => "SOCKS5 timeout ($timeout)")
        if defined $self->{transport};
    undef $timer;
  };
  $timer = AE::timer $timeout, 0, $ontimer;

  my ($send_ok, $send_ng) = @_;
  my $send_p = Promise->new (sub { ($send_ok, $send_ng) = @_ });

  my ($receive_ok, $receive_ng) = @_;
  my $receive_p = Promise->new (sub { ($receive_ok, $receive_ng) = @_ });

  my $last_error;
  my $data = '';
  my $dest_sent = 0;
  my $process_data = sub {
    if (length $data >= 2 or $_[0]) {
      if (length $data >= 2 and substr ($data, 0, 2) eq "\x05\x00") {
        $timer = AE::timer $timeout, 0, $ontimer;
        unless ($dest_sent) {
          my $port = $args->{port};
          my $host = $args->{host};
          if ($host->is_domain) {
            $host = encode_web_utf8 $host->stringify;
            $self->{transport}->push_write
                (\("\x05\x01\x00\x03".(pack 'C', length $host).$host.(pack 'n', $port)));
          } elsif ($host->is_ipv4) {
            $self->{transport}->push_write
                (\("\x05\x01\x00\x01".$host->packed_addr.(pack 'n', $port)));
          } elsif ($host->is_ipv6) {
            $self->{transport}->push_write
                (\("\x05\x01\x00\x04".$host->packed_addr.(pack 'n', $port)));
          } else { # never
            $send_ng->("Unknown |host| type");
            $receive_ng->("Unknown |host| type");
            return;
          }
          $dest_sent = 1;
          $self->{transport}->push_promise->then ($send_ok, sub {
            $send_ng->($last_error || $_[0]);
          });
        }
      } else {
        my $error = {failed => 1,
                     message => 'SOCKS5 server does not return a valid reply'};
        $error->{message} .= ": |@{[_e4d substr $data, 0, 100]}|";
        $error->{message} .= ' (EOF received)' if $_[0];
        $self->{transport}->abort (message => $error->{message});
        $last_error ||= $error;
        return;
      }
    } else {
      return;
    }

    if (length $data >= 2 + 5 or $_[0]) {
      if (length $data >= 2 + 5 and
          substr ($data, 2, 4) =~ /^\x05\x00\x00([\x01\x03\x04])/) {
        my $atyp = $1;
        my $length = $atyp eq "\x01" ? 4 : $atyp eq "\x04" ? 16 : 1 + ord substr ($data, 6, 1);
        if (length $data >= 2 + 4 + $length + 2) {
          substr ($data, 0, 2 + 4 + $length + 2) = '';
          undef $timer;
          $receive_ok->();
          $self->{started} = 1;
          $self->{cb}->($self, 'open');
          if (length $data) {
            $self->{cb}->($self, 'readdata', \$data);
          }
          return;
        } elsif (not $_[0]) {
          return;
        }
      }
      my $error = {failed => 1,
                   message => 'SOCKS5 server does not return a valid reply'};
      $error->{message} .= ": |@{[_e4d substr $data, 0, 100]}|";
      $error->{message} .= ' (EOF received)' if $_[0];
      $self->{transport}->abort (message => $error->{message});
      $last_error ||= $error;
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
      $self->{transport}->push_write (\"\x05\x01\x00");
    } elsif ($type eq 'close') {
      unless ($last_error) {
        $last_error = {failed => 1,
                       message => 'SOCKS5 server does not return a valid reply'};
      }
      $send_ng->($last_error);
      $receive_ng->($last_error);
      delete $self->{transport};
      delete $self->{cb};
      undef $timer;
      undef $self;
    }
  })->then (sub {
    return Promise->all ([$send_p, $receive_p]);
  });
} # start

sub read_closed ($) { return $_[0]->{transport}->read_closed }
sub write_closed ($) { return $_[0]->{transport}->write_closed }
sub write_to_be_closed ($) {
  return 1 unless defined $_[0]->{transport};
  return $_[0]->{transport}->write_to_be_closed;
} # write_to_be_closed

sub push_write ($$;$$) {
  croak "Bad state (not started)" unless $_[0]->{started};
  return shift->{transport}->push_write (@_);
} # push_write

sub push_promise ($) {
  croak "Bad state (not started)" unless $_[0]->{started};
  return shift->{transport}->push_promise (@_);
} # push_promise

sub push_shutdown ($) {
  croak "Bad state (not started)" unless $_[0]->{started};
  return shift->{transport}->push_shutdown (@_);
} # push_shutdown

sub abort ($;%) {
  return shift->{transport}->abort (@_) if defined $_[0]->{transport};
} # abort

sub DESTROY ($) {
  $_[0]->abort (message => "Aborted by DESTROY of $_[0]");

  local $@;
  eval { die };
  warn "$$: Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;

} # DESTROY

1;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
