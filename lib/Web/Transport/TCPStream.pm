package Web::Transport::TCPStream;
use strict;
use warnings;
our $VERSION = '3.0';
use Carp;
use Errno qw(EAGAIN EWOULDBLOCK EINTR);
use Socket qw(IPPROTO_TCP TCP_NODELAY SOL_SOCKET SO_KEEPALIVE SO_OOBINLINE MSG_PEEK);
use AnyEvent::Socket qw(tcp_connect);
use AnyEvent::Util qw(WSAEWOULDBLOCK);
use AbortController;
use Promise;
use Streams::IOError;
use Streams::Filehandle;
use Web::Transport::Error;
use Web::Transport::TypeError;
use Web::Transport::ProtocolError;
use Web::Host;

push our @CARP_NOT, qw(
  Web::Transport::Error Web::Transport::TypeError Streams::IOError
  Web::Transport::ProtocolError
  Streams::Filehandle
);

sub _te ($) {
  return Web::Transport::TypeError->new ($_[0]);
} # _te

sub _tep ($) {
  return Promise->reject (Web::Transport::TypeError->new ($_[0]));
} # _tep

## Return whether the file handle is ready to be read, i.e. reading
## from it is likely to return some data, or not.  It does not perform
## any I/O.  It returns |0| if the file handle is not readable, or if
## it is not valid.  If the file handle has been closed by the peer
## (i.e. an EOF is readable), it can return a true value depending on
## the platform.
sub _is_readable ($) {
  my $fh = $_[0];
  return 0 unless defined $fh;
  my $fd = fileno $fh;
  return 0 unless defined $fd;
  my $rin = '';
  vec ($rin, $fd, 1) = 1;
  my $n = select ($rin, undef, undef, 0);
  return $n > 0;
} # _is_readable

## Return the state of the input side of the file handle, without
## consuming any data, as one of the following strings.
##
##  - |data|:  Some data is available to be read.
##  - |eof|:   The peer has closed the input side (EOF), with no data
##            remaining to be read.
##  - |empty|: No data and no EOF are available (i.e. the socket is
##            currently idle, as far as the input side is concerned).
##  - |error|: An error has occurred on the input side (such as a
##            TCP reset).
##  - |closed|: The file handle is not valid anymore.
##
## It does not perform any blocking I/O: it checks readability first
## and, when readable, performs a non-blocking |recv| with |MSG_PEEK|,
## which returns immediately for data, EOF and errors.  Note that
## |recv| uses the file handle's buffer to report the number of bytes
## that are pending: the bytes are placed in the buffer by |recv| and
## the value returned by |recv| is not a byte count.
sub _recv_peek_state ($) {
  my $fh = $_[0];
  return 'closed' unless defined $fh and defined (fileno $fh);
  return 'empty' unless _is_readable ($fh);
  my $buf = '';
  my $r = recv ($fh, $buf, 1, MSG_PEEK);
  if (not defined $r) {
    my $errno = 0 + $!;
    if ($errno == EAGAIN or $errno == EWOULDBLOCK or
        $errno == WSAEWOULDBLOCK or $errno == EINTR) {
      return 'empty';
    }
    return 'error';
  }
  return length ($buf) ? 'data' : 'eof';
} # _recv_peek_state

## Create a closure which returns whether data is pending on the file
## handle, i.e. whether reading it is likely to return some data, or
## not.  It returns a true value if and only if at least one byte is
## available to be read.  An EOF or an error does not make it return a
## true value (unlike checking whether the file handle is simply
## ready-to-read).  It captures only the file handle (not any other
## lexical variable in the scope where |create| is called), so that the
## closure does not keep other values alive on Perl versions whose
## anonymous subroutines capture the entire scope (such as Perl 5.14).
sub _make_pending_data_checker ($) {
  my $fh = $_[0];
  return sub {
    return _recv_peek_state ($fh) eq 'data';
  };
} # _make_pending_data_checker

## Create a closure which returns whether the input side of the file
## handle has been closed by the peer or has become unusable, or not.
## It returns a true value if the peer has sent EOF or an error (such
## as a TCP reset) has occurred, or if the file handle is not valid.
## It captures only the file handle, for the same reason as above.
sub _make_peer_closed_checker ($) {
  my $fh = $_[0];
  return sub {
    my $state = _recv_peek_state ($fh);
    return ($state eq 'eof' or $state eq 'error' or $state eq 'closed');
  };
} # _make_peer_closed_checker

sub create ($$) {
  my ($class, $args) = @_;

  return _tep "Bad |fh|" if $args->{server} and not defined $args->{fh};
  if ($class eq 'Web::Transport::UnixStream') {
    $args->{type} = 'Unix';
    if (not defined $args->{fh}) {
      $args->{addr} = 'unix/';
      return _tep "Bad |path|" unless defined $args->{path};
      $args->{port} = delete $args->{path};
    }
  } else {
    $args->{type} = 'TCP';
    return _tep "Bad |host|" unless defined $args->{host} and $args->{host}->is_ip;
    $args->{addr} = $args->{host}->text_addr;
    return _tep "Bad |port|" unless defined $args->{port};
    $args->{port} += 0;
    return _tep "Bad |port|" unless
        $args->{port} =~ /\A[0-9]+\z/ and $args->{port} < 2**16;
  }

  my $id = defined $args->{id} ? $args->{id} : (defined $args->{parent_id} ? $args->{parent_id} : $$) . '.' . ++$Web::Transport::NextID;
  my $info = {
    type => $args->{type},
    layered_type => $args->{type},
    id => $id,
    server => !!$args->{server},
  };
  if ($args->{type} eq 'TCP' and defined $args->{host}) {
    $info->{remote_host} = $args->{host};
    $info->{remote_port} = 0+$args->{port};
  }
  if ($args->{type} eq 'Unix' and defined $args->{path}) {
    $info->{path} = $args->{path};
  }

  if ($args->{debug}) {
    my $action = defined $info->{fh}
        ? $info->{server} ? 'attach as server' : 'attach as client'
        : 'connect';
    if (defined $info->{path}) {
      warn "$id: $info->{type}: $action ($info->{path})...\n"; # XXX $info->{path} can contain non-ASCII bytes
    } elsif (defined $info->{remote_host}) {
      warn "$id: $info->{type}: $action (remote: @{[$info->{remote_host}->to_ascii]}:$info->{remote_port})...\n";
    } else {
      warn "$id: $info->{type}: $action (filehandle)...\n";
    }
  }

  my $signal = $args->{signal};
  return Promise->new (sub {
    my ($ok, $ng) = @_;

    my $aborted = sub { };
    if (defined $signal) {
      if ($signal->aborted) {
        $ng->($signal->manakai_error);
        return;
      } else {
        $signal->manakai_onabort (sub {
          $aborted->($signal->manakai_error);
        });
      }
    }

    if (defined $args->{fh}) {
      $ok->($args->{fh});
      $signal->manakai_onabort (sub { }) if defined $signal;
      $ok = $ng = $aborted = $signal = sub { };
      return;
    }
    
    if ($args->{addr} eq '127.0.53.53') {
      $ng->(Web::Transport::ProtocolError->new ('ICANN_NAME_COLLISION'));
      $signal->manakai_onabort (sub { }) if defined $signal;
      $ok = $ng = $aborted = $signal = sub { };
      return;
    }

    my $con;
    $aborted = sub {
      $ng->($_[0]);
      $signal->manakai_onabort (sub { }) if defined $signal;
      $con = $ok = $ng = $aborted = $signal = sub { };
    };
    my $caller = [caller ((sub { Carp::short_error_loc })->() - 1)];
    $con = tcp_connect $args->{addr}, $args->{port}, sub {
      unless ($_[0]) {
        package TCPStream::_Dummy;
        my $file = $caller->[1];
        $file =~ s/[\x0D\x0A\x22]/_/g;
        my $error = eval sprintf q{
#line %d "%s"
          Streams::IOError->new ($!);
        }, $caller->[2], $file;
        $ng->($error);
        $signal->manakai_onabort (sub { }) if defined $signal;
        $con = $ok = $ng = $aborted = $signal = sub { };
        return;
      }

      $ok->($_[0]);
      $signal->manakai_onabort (sub { }) if defined $signal;
      $con = $ok = $ng = $aborted = $signal = sub { };
    };
  })->then (sub {
    my $fh = $_[0];

    if ($info->{type} eq 'TCP') {
      my ($p, $h) = AnyEvent::Socket::unpack_sockaddr getsockname $fh;
      $info->{local_host} = Web::Host->new_from_packed_addr ($h);
      $info->{local_port} = $p;
    }

    ## Applied to TCP only (not applied to Unix domain socket)
    setsockopt $fh, SOL_SOCKET, SO_OOBINLINE, 0;
    setsockopt $fh, IPPROTO_TCP, TCP_NODELAY, 1;
    setsockopt $fh, SOL_SOCKET, SO_KEEPALIVE, 1;
    # XXX KA options

    ($info->{readable}, $info->{writable}, $info->{closed})
        = Streams::Filehandle::fh_to_streams $fh, 1, 1;
    $info->{has_pending_data} = _make_pending_data_checker ($fh);
    $info->{peer_closed} = _make_peer_closed_checker ($fh);

    if ($args->{debug}) {
      if (defined $info->{local_host}) {
        warn "$id: $info->{type}: ready (local: @{[$info->{local_host}->to_ascii]}:$info->{local_port})\n";
      } else {
        warn "$id: $info->{type}: ready\n";
      }
      $info->{closed}->then (sub {
        warn "$id: $info->{type}: closed\n";
      });
    }

    return $info;
  })->catch (sub {
    my $error = Web::Transport::Error->wrap ($_[0]);

    if ($args->{debug}) {
      warn "$id: $info->{type}: failed ($error)\n";
    }

    die $error;
  });
} # create

## For tests only
package Web::Transport::TCPStream::Reset;
push our @ISA, qw(Web::Transport::Error);

$Web::DOM::Error::L1ObjectClass->{(__PACKAGE__)} = 1;

sub new ($) {
  return $_[0]->SUPER::new ('TCP reset requested');
} # new

sub name ($) {
  return 'AbortError';
} # name

1;

=head1 LICENSE

Copyright 2016-2026 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
