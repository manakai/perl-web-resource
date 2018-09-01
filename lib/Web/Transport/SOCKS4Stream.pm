package Web::Transport::SOCKS4Stream;
use strict;
use warnings;
our $VERSION = '5.0';
use AnyEvent;
use Promise;
use Promised::Flow;
use Web::Transport::TypeError;
use Web::Transport::ProtocolError;
use ArrayBuffer;
use DataView;

push our @CARP_NOT, qw(
  Web::Transport::TypeError Web::Transport::ProtocolError
  Web::Transport::CustomStream
  Web::Transport::TCPStream
  Web::Transport::UnixStream
  Web::Transport::TLSStream
  Web::Transport::SOCKS4Stream
  Web::Transport::SOCKS5Stream
  Web::Transport::H1CONNECTStream
);

our $HandshakeTimeout ||= 30;

sub _tep ($) {
  return Promise->reject (Web::Transport::TypeError->new ($_[0]));
} # _tep

sub _pe ($) {
  return Web::Transport::ProtocolError->new ($_[0]);
} # _pe

sub create ($$) {
  my ($class, $args) = @_;

  return _tep "Bad |parent|"
      unless defined $args->{parent} and ref $args->{parent} eq 'HASH';
  return _tep "Bad |parent|"
      unless defined $args->{parent}->{class};
  return _tep "Bad |host|"
      unless defined $args->{host} and $args->{host}->is_ipv4;
  return _tep "Bad |port|" unless defined $args->{port};
  $args->{port} += 0;
  return _tep "Bad |port|" unless
      $args->{port} =~ /\A[0-9]+\z/ and $args->{port} < 2**16;

  my $info = {
    type => 'SOCKS4',
    layered_type => 'SOCKS4',
  };

  my $parent = {%{$args->{parent}}};
  $parent->{debug} = $args->{debug}
      if $args->{debug} and not defined $parent->{debug};
  my $signal = $parent->{signal} = $args->{signal}; # or undef
  return $parent->{class}->create ($parent)->then (sub {
    $info->{parent} = $_[0];
    $info->{layered_type} .= '/' . $info->{parent}->{layered_type};

    $info->{id} = $info->{parent}->{id} . 'S4';
    if ($args->{debug}) {
      warn "$info->{id}: $info->{type}: start as client (@{[$args->{host}->to_ascii]}:$args->{port})\n";
    }

    my $readable = delete $info->{parent}->{readable};
    my $writable = delete $info->{parent}->{writable};
    my $t_r = $readable->get_reader ('byob');
    my $t_w = $writable->get_writer;

    my $timer;
    my $onerror = sub {
      my $error = $_[0];
      $t_w->abort ($error) if defined $t_w;
      $t_r->cancel ($error)->catch (sub { }) if defined $t_r;
      undef $timer;
      undef $signal;
    }; # $onerror

    my $timeout = $HandshakeTimeout;
    $timer = AE::timer $timeout, 0, sub {
      $onerror->(_pe "SOCKS4 timeout ($timeout)");
    };

    if (defined $signal) {
      if ($signal->aborted) {
        my $error = $signal->manakai_error;
        $onerror->($error);
        die $error;
      } else {
        $signal->manakai_onabort (sub {
          $onerror->($signal->manakai_error);
        });
      }
    }

    my $port = $args->{port};
    my $addr = $args->{host}->packed_addr;
    $t_w->write
        (DataView->new (ArrayBuffer->new_from_scalarref (\("\x04\x01".(pack 'n', $port).$addr."\x00"))));

    my $bytes = '';
    my $dv = DataView->new (ArrayBuffer->new (8));
    return ((promised_until {
      return $t_r->read ($dv)->then (sub {
        return 'done' if $_[0]->{done};
        $dv = $_[0]->{value};
        $bytes .= $dv->manakai_to_string;
        $dv = DataView->new ($dv->buffer, $dv->byte_offset + $dv->byte_length);
        return 'done' if $dv->byte_length == 0;
        return not 'done';
      });
    })->then (sub {
      if (8 == length $bytes and substr ($bytes, 0, 2) eq "\x00\x5A") {
        undef $timer;
        undef $signal;

        $t_r->release_lock;
        $t_w->release_lock;
        $info->{readable} = $readable;
        $info->{writable} = $writable;
        $info->{closed} = delete $info->{parent}->{closed};

        return $info;
      } else {
        my $message = 'SOCKS4 server does not return a valid reply';
        if (length $bytes) {
          $message .= sprintf " (result code %d)", ord substr $bytes, 1, 1;
        } else {
          $message .= ' (empty)';
        }
        my $error = _pe $message;
        $onerror->($error);
        die $error;
      }
    }));
  });
} # create

1;

=head1 LICENSE

Copyright 2016-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
