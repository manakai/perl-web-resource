package Web::Transport::TCPStream;
use strict;
use warnings;
our $VERSION = '2.0';
use Carp;
use Errno qw(EAGAIN EWOULDBLOCK EINTR);
use Socket qw(IPPROTO_TCP TCP_NODELAY SOL_SOCKET SO_KEEPALIVE SO_OOBINLINE SO_LINGER);
use AnyEvent;
use AnyEvent::Util qw(WSAEWOULDBLOCK);
use AnyEvent::Socket qw(tcp_connect);
use Promise;
use Promised::Flow;
use Streams::IOError;
use Web::Transport::Error;
use Web::Transport::TypeError;
use Web::Transport::ProtocolError;
use DataView;
use Streams;
use Web::Host;

push our @CARP_NOT, qw(
  ArrayBuffer
  ReadableStream ReadableStreamBYOBRequest WritableStream
  Web::Transport::Error Web::Transport::TypeError Streams::IOError
  Web::Transport::ProtocolError
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
  return Web::Transport::TypeError->new ($_[0]);
} # _te

sub _tep ($) {
  return Promise->reject (Web::Transport::TypeError->new ($_[0]));
} # _tep

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

  my $fh;
  my ($r_fh_closed, $s_fh_closed) = promised_cv;
  my $read_active = 1;
  my $rcancel = sub { };
  my $wc;
  my $wcancel;

  my $pull = sub {
    my ($rc, $req, $rcancelref) = @_;
    return Promise->new (sub {
      my $ready = $_[0];
      my $failed = $_[1];
      return $failed->() unless defined $fh;

      my $w;
      $$rcancelref = sub {
        eval { $rc->error ($_[0]) } if $read_active;
        my $req = $rc->byob_request;
        $req->respond (0) if defined $req;

        undef $w;
        $failed->($_[0]);
      };
      $w = AE::io $fh, 0, sub {
        $$rcancelref = sub {
          eval { $rc->error ($_[0]) } if $read_active;
          my $req = $rc->byob_request;
          $req->respond (0) if defined $req;
        };

        undef $w;
        $ready->();
      };
    })->then (sub {
      my $bytes_read = eval { $req->manakai_respond_by_sysread ($fh) };
      if ($@) {
        my $error = Web::Transport::Error->wrap ($@);
        my $errno = $error->isa ('Streams::IOError') ? $error->errno : 0;
        if ($errno != EAGAIN && $errno != EINTR &&
            $errno != EWOULDBLOCK && $errno != WSAEWOULDBLOCK) {
          $rcancel->($error) if defined $rcancel;
          $read_active = $rcancel = undef;
          if (defined $wc) {
            $wc->error ($error);
            $wcancel->() if defined $wcancel;
            $wc = $wcancel = undef;
          }
          undef $fh;
          $s_fh_closed->();
          return 0;
        }
        return 1;
      } # $@
      if (defined $bytes_read and $bytes_read <= 0) {
        $rc->close;
        $req->respond (0);
        $read_active = undef;
        $rcancel->(undef);
        $rcancel = undef;
        unless (defined $wc) {
          undef $fh;
          $s_fh_closed->();
        }
        return 0;
      }
      return 1;
    }, sub {
      $read_active = $rcancel = undef;
      unless (defined $wc) {
        undef $fh;
        $s_fh_closed->();
      }
      return 0;
    });
  }; # $pull

  my $read_stream = ReadableStream->new ({
    type => 'bytes',
    auto_allocate_chunk_size => 1024*2,
    pull => sub {
      my $rc = $_[1];
      $rcancel = sub {
        eval { $rc->error ($_[0]) } if $read_active;
        my $req = $rc->byob_request;
        $req->respond (0) if defined $req;
      };
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
      my $reason = defined $_[1] ? $_[1] : "$class reader canceled";
      $rcancel->($reason) if defined $rcancel;
      $read_active = $rcancel = undef;
      if (defined $wc) {
        $wc->error ($reason);
        $wcancel->() if defined $wcancel;
        $wc = $wcancel = undef;
      }
      shutdown $fh, 2; # can result in EPIPE
      undef $fh;
      $s_fh_closed->();
    }, # cancel
  });
  my $write_stream = WritableStream->new ({
    start => sub {
      $wc = $_[1];
    },
    write => sub {
      my $view = $_[1];
      return Promise->resolve->then (sub {
        die _te "The argument is not an ArrayBufferView"
            unless UNIVERSAL::isa ($view, 'ArrayBufferView');
        return if $view->byte_length == 0;
        return _writing {
          return 1 unless defined $fh; # end
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
        if (defined $wc) {
          $wc->error ($e);
          $wcancel->() if defined $wcancel;
          $wc = $wcancel = undef;
        }
        if ($read_active) {
          $rcancel->($e);
          $read_active = $rcancel = undef;
        }
        undef $fh;
        $s_fh_closed->();
        die $e;
      });
    }, # write
    close => sub {
      shutdown $fh, 1; # can result in EPIPE
      $wcancel->() if defined $wcancel;
      $wc = $wcancel = undef;
      unless ($read_active) {
        undef $fh;
        $s_fh_closed->();
      }
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
        $s_fh_closed->();
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
      $s_fh_closed->();
    }, # abort
  });

  return Promise->new (sub {
    my ($ok, $ng) = @_;
    if (defined $args->{fh}) {
      $ok->($args->{fh});
    } else {
      if ($args->{addr} eq '127.0.53.53') {
        return $ng->(Web::Transport::ProtocolError->new ('ICANN_NAME_COLLISION'));
      }
      my $caller = [caller ((sub { Carp::short_error_loc })->() - 1)];
      tcp_connect $args->{addr}, $args->{port}, sub {
        unless ($_[0]) {
          package TCPStream::_Dummy;
          my $file = $caller->[1];
          $file =~ s/[\x0D\x0A\x22]/_/g;
          my $error = eval sprintf q{
#line %d "%s"
            Streams::IOError->new ($!);
          }, $caller->[2], $file;
          return $ng->($error);
        }
        $ok->($_[0]);
      };
    }
  })->then (sub {
    $fh = $_[0];

    if ($info->{type} eq 'TCP') {
      my ($p, $h) = AnyEvent::Socket::unpack_sockaddr getsockname $fh;
      $info->{local_host} = Web::Host->new_from_packed_addr ($h);
      $info->{local_port} = $p;
    }

    AnyEvent::Util::fh_nonblocking $fh, 1;

    ## Applied to TCP only (not applied to Unix domain socket)
    setsockopt $fh, SOL_SOCKET, SO_OOBINLINE, 0;
    setsockopt $fh, IPPROTO_TCP, TCP_NODELAY, 1;
    setsockopt $fh, SOL_SOCKET, SO_KEEPALIVE, 1;
    # XXX KA options

    $info->{readable} = $read_stream;
    $info->{writable} = $write_stream;
    $info->{closed} = $r_fh_closed;

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
    $s_fh_closed->();

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

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
