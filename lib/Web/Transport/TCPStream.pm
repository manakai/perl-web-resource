package Web::Transport::TCPStream;
use strict;
use warnings;
our $VERSION = '2.0';
use Errno qw(EAGAIN EWOULDBLOCK EINTR);
use Socket qw(IPPROTO_TCP TCP_NODELAY SOL_SOCKET SO_KEEPALIVE SO_OOBINLINE SO_LINGER);
use AnyEvent;
use AnyEvent::Util qw(WSAEWOULDBLOCK);
use AnyEvent::Socket qw(tcp_connect);
use Promise;
use Promised::Flow;
use Streams::IOError;
use Web::DOM::Error;
use Web::DOM::TypeError;
use DataView;
use Streams;
use Web::Host;

push our @CARP_NOT, qw(
  ReadableStream ReadableStreamBYOBRequest WritableStream
  Web::DOM::Error Web::DOM::TypeError Streams::IOError
);

sub _writing (&$$) {
  my ($code, $fh, $cancel) = @_;
  my $cancelled = 0;
  $$cancel = sub { $cancelled = 1 };
  my $try; $try = sub {
    return Promise->resolve if $cancelled or $code->();
    return Promise->new (sub {
      my $ok = $_[0];
      my $w; $w = AE::io $fh, 1, sub {
        undef $w;
        $$cancel = sub { $cancelled = 1 };
        $ok->();
      };
      $$cancel = sub {
        $cancelled = 1;
        undef $w;
        $$cancel = sub { };
        $ok->();
      };
    })->then ($try);
  };
  return promised_cleanup { undef $try } Promise->resolve->then ($try);
} # _writing

sub _te ($) {
  return Web::DOM::TypeError->new ($_[0]);
} # _te

sub _tep ($) {
  return Promise->reject (Web::DOM::TypeError->new ($_[0]));
} # _tep

sub create ($$) {
  my ($class, $args) = @_;

  return _tep "Bad |fh|" if $args->{server} and not defined $args->{fh};
  if ($class eq 'Unix') {
    $args->{type} = 'UNIX';
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

  # XXX
  #croak "Bad |id|" if defined $args->{id} and utf8::is_utf8 ($args->{id});
  #$args->{id} = (defined $args->{id} ? $args->{id} : (defined $args->{parent_id} ? $args->{parent_id} : $$) . '.' . ++$Web::Transport::NextID);

  my $fh;
  my $read_active = 1;
  my $rcancel = sub { };
  my $wc;
  my $wcancel;

  my $pull = sub {
    my ($rc, $req, $cancelref) = @_;
    return Promise->new (sub {
      my $ready = $_[0];
      my $failed = $_[1];
      my $w;
      $$cancelref = sub { $rc->error ($_[0]); undef $w; $failed->($_[0]) };
      $w = AE::io $fh, 0, sub {
        undef $w;
        $$cancelref = sub { $rc->error ($_[0]) };
        $ready->();
      };
    })->then (sub {
      my $bytes_read = eval { $req->manakai_respond_by_sysread ($fh) };
      if ($@) {
        my $error = Web::DOM::Error->wrap ($@); # XXX error location
        my $errno = $error->isa ('Streams::IOError') ? $error->errno : 0;
        if ($errno != EAGAIN && $errno != EINTR &&
            $errno != EWOULDBLOCK && $errno != WSAEWOULDBLOCK) {
          $rc->error ($error);
          $read_active = $rcancel = undef;
          if (defined $wc) {
            $wc->error ($error);
            $wcancel->() if defined $wcancel;
            $wc = $wcancel = undef;
          }
          undef $fh;
          return 0;
        }
        return 1;
      } # $@
      if (defined $bytes_read and $bytes_read <= 0) {
        $rc->close;
        $req->respond (0);
        $read_active = $rcancel = undef;
        undef $fh unless defined $wc;
        return 0;
      }
      return 1;
    }, sub {
      $read_active = $rcancel = undef;
      undef $fh unless defined $wc;
      return 0;
    });
  }; # $pull

  my $read_stream = ReadableStream->new ({
    type => 'bytes',
    auto_allocate_chunk_size => 1024*2,
    pull => sub {
      my $rc = $_[1];
      $rcancel = sub { $rc->error ($_[0]) };
      my $run; $run = sub {
        my $req = $rc->byob_request;
        return Promise->resolve unless defined $req;
        return $pull->($rc, $req, \$rcancel)->then (sub {
          return $run->() if $_[0];
        });
      };
      return $run->()->then (sub { undef $run });
    }, # pull
    cancel => sub {
      $read_active = $rcancel = undef;
      if (defined $wc) {
        my $reason = defined $_[1] ? $_[1] : "$class reader canceled";
        $wc->error ($reason);
        $wcancel->() if defined $wcancel;
        $wc = $wcancel = undef;
      }
      shutdown $fh, 2; # can result in EPIPE
      undef $fh;
    },
  });
  my $write_stream = WritableStream->new ({
    start => sub {
      $wc = $_[1];
    },
    write => sub {
      my $view = $_[1];
      return Promise->resolve->then (sub {
        die _te "The argument is not an ArrayBufferView"
            unless UNIVERSAL::isa ($view, 'ArrayBufferView'); # XXX location
        return if $view->byte_length == 0;
        return _writing {
          my $l = eval { $view->buffer->manakai_syswrite
                             ($fh, $view->byte_length, $view->byte_offset) };
          if ($@) {
            my $errno = UNIVERSAL::isa ($@, 'Streams::IOError') ? $@->errno : 0;
            if ($errno != EAGAIN && $errno != EINTR &&
                $errno != EWOULDBLOCK && $errno != WSAEWOULDBLOCK) {
              die $@;
            } else { # retry later
              return 0; # repeat
            }
          } else {
            $view = DataView->new
                ($view->buffer,
                 $view->byte_offset + $l, $view->byte_length - $l);
            return 1 if $view->byte_length == 0; # end
            return 0; # repeat
          }
        } $fh, \$wcancel;
      })->catch (sub {
        my $e = $_[0];
        $wc->error ($e);
        $wcancel->() if defined $wcancel;
        $wc = $wcancel = undef;
        if ($read_active) {
          $rcancel->($e);
          $read_active = $rcancel = undef;
        }
        undef $fh;
        die $e;
      });
    }, # write
    close => sub {
      shutdown $fh, 1; # can result in EPIPE
      $wcancel->() if defined $wcancel;
      $wc = $wcancel = undef;
      undef $fh unless $read_active;
      return undef;
    }, # close
    abort => sub {
      ## For tests only
      if (UNIVERSAL::isa ($_[1], __PACKAGE__ . '::Reset')) {
        setsockopt $fh, SOL_SOCKET, SO_LINGER, pack "II", 1, 0;
        $wcancel->() if defined $wcancel;
        $wc = $wcancel = undef;
        if ($read_active) {
          $rcancel->($_[1]);
          $read_active = $rcancel = undef;
        }
        undef $fh;
        return undef;
      }

      $wcancel->() if defined $wcancel;
      $wc = $wcancel = undef;
      if ($read_active) {
        my $reason = defined $_[1] ? $_[1] : "$class writer aborted";
        $rcancel->($reason);
        $read_active = $rcancel = undef;
      }
      shutdown $fh, 2; # can result in EPIPE
      undef $fh;
    }, # abort
  });

  return Promise->new (sub {
    my ($ok, $ng) = @_;
    if (defined $args->{fh}) {
      $ok->($args->{fh});
    } else {
      if ($args->{addr} eq '127.0.53.53') {
        return $ng->(_te 'ICANN_NAME_COLLISION');
      }
      tcp_connect $args->{addr}, $args->{port}, sub {
        # XXX exception's location becomes within AnyEvent::Socket...
        return $ng->(Streams::IOError->new ($!)) unless $_[0];
        $ok->($_[0]);
      };
    }
  })->then (sub {
    $fh = $_[0];

    my $info = {
      type => $args->{type},
      layered_type => $args->{type},
      #XXX id => $args->{id},
      is_server => !!$args->{server},
    };

    if ($info->{type} eq 'TCP') {
      my ($p, $h) = AnyEvent::Socket::unpack_sockaddr getsockname $fh;
      $info->{local_host} = Web::Host->new_from_packed_addr ($h);
      $info->{local_port} = $p;
      $info->{remote_host} = $args->{host};
      $info->{remote_port} = 0+$args->{port};
    }
    AnyEvent::Util::fh_nonblocking $fh, 1;

    ## Applied to TCP only (not applied to Unix domain socket)
    setsockopt $fh, SOL_SOCKET, SO_OOBINLINE, 0;
    setsockopt $fh, IPPROTO_TCP, TCP_NODELAY, 1;
    setsockopt $fh, SOL_SOCKET, SO_KEEPALIVE, 1;
    # XXX KA options

    $info->{read_stream} = $read_stream;
    $info->{write_stream} = $write_stream;
    return $info;
  })->catch (sub {
    my $error = Web::DOM::Error->wrap ($_[0]);
    if ($read_active) {
      $rcancel->($error);
      $read_active = $rcancel = undef;
    }
    if (defined $wc) {
      $wc->error ($error);
      $wcancel->() if defined $wcancel;
      $wc = $wcancel = undef;
    }
    undef $fh;
    die $error;
  });
} # create

## For tests only
package Web::Transport::TCPStream::Reset;
use Web::DOM::Exception;
push our @ISA, qw(Web::DOM::Exception);

$Web::DOM::Error::L1ObjectClass->{(__PACKAGE__)} = 1;

sub new ($) {
  return $_[0]->SUPER::new ('TCP reset requested', 'AbortError');
} # new

1;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
