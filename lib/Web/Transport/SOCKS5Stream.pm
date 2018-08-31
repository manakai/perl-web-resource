package Web::Transport::SOCKS5Stream;
use strict;
use warnings;
our $VERSION = '4.0';
use AnyEvent;
use Promise;
use Promised::Flow;
use Web::Encoding;
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

sub _te ($) {
  return Web::Transport::TypeError->new ($_[0]);
} # _te

sub _tep ($) {
  return Promise->reject (Web::Transport::TypeError->new ($_[0]));
} # _tep

sub _pe ($) {
  return Web::Transport::ProtocolError->new ($_[0]);
} # _pe

sub _e4d ($) {
  return $_[0] unless $_[0] =~ /[^\x20-\x5B\x5D-\x7E]/;
  my $x = $_[0];
  $x =~ s/([^\x20-\x5B\x5D-\x7E])/sprintf '\x%02X', ord $1/ge;
  return $x;
} # _e4d

sub create ($$) {
  my ($class, $args) = @_;

  return _tep "Bad |parent|"
      unless defined $args->{parent} and ref $args->{parent} eq 'HASH';
  return _tep "Bad |parent|" unless defined $args->{parent}->{class};
  return _tep "Bad |host|" unless defined $args->{host};
  return _tep "Bad |port|" unless defined $args->{port};
  $args->{port} += 0;
  return _tep "Bad |port|" unless
      $args->{port} =~ /\A[0-9]+\z/ and $args->{port} < 2**16;

  my $info = {
    type => 'SOCKS5',
    layered_type => 'SOCKS5',
  };

  my $parent = {%{$args->{parent}}};
  $parent->{debug} = $args->{debug}
      if $args->{debug} and not defined $parent->{debug};
  my $signal = $parent->{signal} = $args->{signal}; # or undef
  return $parent->{class}->create ($parent)->then (sub {
    $info->{parent} = $_[0];
    $info->{layered_type} .= '/' . $info->{parent}->{layered_type};

    $info->{id} = $info->{parent}->{id} . 'S5';
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
      $timer = $t_w = $t_r = $signal = undef;
    }; # $onerror

    my $timeout = $HandshakeTimeout;
    my $ontimer = sub {
      $onerror->(_pe "SOCKS5 timeout ($timeout)");
    };
    $timer = AE::timer $timeout, 0, $ontimer;

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

    $t_w->write
        (DataView->new (ArrayBuffer->new_from_scalarref (\"\x05\x01\x00")));

    my $read = sub {
      my $bytes = '';
      my $dv = DataView->new (ArrayBuffer->new (shift));
      my $read; $read = sub {
        return $t_r->read ($dv)->then (sub {
          return if $_[0]->{done};
          $dv = $_[0]->{value};
          $bytes .= $dv->manakai_to_string;
          $dv = DataView->new
              ($dv->buffer, $dv->byte_offset + $dv->byte_length);
          return if $dv->byte_length == 0;
          return $read->();
        });
      }; # $read
      return promised_cleanup { undef $read } $read->($bytes)->then (sub {
        return $bytes;
      });
    }; # $read

    return $read->(2)->then (sub {
      my $bytes = $_[0];
      if ($bytes eq "\x05\x00") {
        $timer = AE::timer $timeout, 0, $ontimer;
        my $port = $args->{port};
        my $host = $args->{host};
        if ($host->is_domain) {
          $host = encode_web_utf8 $host->stringify;
          $t_w->write
              (DataView->new (ArrayBuffer->new_from_scalarref (\("\x05\x01\x00\x03".(pack 'C', length $host).$host.(pack 'n', $port)))));
        } elsif ($host->is_ipv4) {
          $t_w->write
              (DataView->new (ArrayBuffer->new_from_scalarref (\("\x05\x01\x00\x01".$host->packed_addr.(pack 'n', $port)))));
        } elsif ($host->is_ipv6) {
          $t_w->write
              (DataView->new (ArrayBuffer->new_from_scalarref (\("\x05\x01\x00\x04".$host->packed_addr.(pack 'n', $port)))));
        } else { # never
          die _te "Unknown |host| type";
        }
      } else {
        die _pe "SOCKS5 server does not return a valid reply: |@{[_e4d $bytes]}|";
      }
      return $read->(4);
    })->then (sub {
      my $bytes = $_[0];
      if ($bytes =~ /^\x05\x00\x00([\x01\x03\x04])/) {
        my $atyp = $1;
        if ($atyp eq "\x03") {
          return $read->(1)->then (sub {
            my $length = 1 + ord $_[0];
            return $read->($length + 2);
          });
        } else {
          my $length = $atyp eq "\x01" ? 4 : 16;
          return $read->($length + 2);
        }
      } else {
        die _pe qq{SOCKS5 server does not return a valid reply: |@{[_e4d "\x05\x00$bytes"]}|};
      }
    })->then (sub {
      my $bytes = $_[0];
      undef $timer;
      undef $signal;

      $t_r->release_lock;
      $t_w->release_lock;
      $info->{readable} = $readable;
      $info->{writable} = $writable;
      $info->{closed} = delete $info->{parent}->{closed};
      
      return $info;
    }, sub {
      my $error = $_[0];
      $onerror->($error);
      die $error;
    });
  });
} # create

1;

=head1 LICENSE

Copyright 2016-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
