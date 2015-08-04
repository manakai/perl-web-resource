package HTTP;
use strict;
use warnings;
use Errno;
use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::Socket;
use Promise;

sub new_from_host_and_port ($$$) {
  return bless {host => $_[1], port => $_[2]}, $_[0];
} # new_from_host_and_port

sub _process_rbuf ($$) {
  my ($self, $handle) = @_;
  if ($self->{state} eq 'before response') {
    if ($handle->{rbuf} =~ s/^.{0,4}[Hh][Tt][Tt][Pp]//s) {
      $self->{state} = 'before response header';
    } elsif (8 <= length $handle->{rbuf}) {
      if ($self->{request}->{method} eq 'PUT') {
        $self->onevent->($self, $self->{request}, 'responseerror', {
          message => "HTTP/0.9 response to PUT request",
        });
        $self->{no_new_request} = 1;
        $self->{request_state} = 'sent';
        $self->_next;
        return;
      } else {
        $self->onevent->($self, $self->{request}, 'headers', $self->{response});
        $self->{state} = 'response body';
        delete $self->{unread_length};
      }
    }
  } elsif ($self->{state} eq 'before response header') {
    if (2**18-1 < length $handle->{rbuf}) {
      $self->onevent->($self, $self->{request}, 'responseerror', {
        message => "Header section too large",
      });
      $self->{no_new_request} = 1;
      $self->{request_state} = 'sent';
      $self->_next;
      return;
    } elsif ($handle->{rbuf} =~ s/^(.*?)\x0A\x0D?\x0A//s) {
      my $headers = [split /[\x0D\x0A]+/, $1, -1]; # XXX report CR
      my $start_line = shift @$headers;
      my $res = $self->{response};
      $res->{version} = '1.0';
      if ($start_line =~ s{\A/}{}) {
        if ($start_line =~ s{\A([0-9]+)}{}) {
          my $major = $1;
          $major = 0 if $major =~ /^0/;
          if ($start_line =~ s{\A\.}{}) {
            if ($start_line =~ s{\A([0-9]+)}{}) {
              my $n = 0+"$major.$1";
              $res->{version} = '1.1' if $n >= 1.1;
            }
          }
        }
        $start_line =~ s{\A\x20*}{}s;
        if ($start_line =~ s/\A0*?([0-9]+)//) {
          $res->{status} = 0+$1;
          $res->{status} = 2**31-1 if $res->{status} > 2**31-1;
          if ($start_line =~ s/\A\x20+//) {
            $res->{reason} = $start_line;
          } else {
            $res->{reason} = '';
          }
        }
      } elsif ($start_line =~ s{\A\x20+}{}) {
        if ($start_line =~ s/\A0*?([0-9]+)//) {
          $res->{status} = 0+$1;
          $res->{status} = 2**31-1 if $res->{status} > 2**31-1;
          if ($start_line =~ s/\A\x20//) {
            $res->{reason} = $start_line;
          } else {
            $res->{reason} = '';
          }
        }
      }

      my $last_header = undef;
      for (@$headers) {
        if (s/^[\x20\x09]+//) {
          if (defined $last_header) {
            $last_header->[1] .= ' ' . $_;
          }
        } elsif (s/\A([^:]+)://) {
          push @{$res->{headers}}, $last_header = [$1, $_];
        } else {
          $last_header = undef;
          # XXX report error
        }
      }
      my %length;
      my $has_broken_length = 0;
      for (@{$res->{headers}}) {
        $_->[0] =~ s/[\x09\x20]+\z//;
        $_->[1] =~ s/\A[\x09\x20]+//;
        $_->[1] =~ s/[\x09\x20]+\z//;
        $_->[2] = $_->[0];
        $_->[2] =~ tr/A-Z/a-z/; ## ASCII case-insensitive
        if ($_->[2] eq 'content-length') {
          for (split /[\x09\x20]*,[\x09\x20]*/, $_->[1]) {
            if (/\A[0-9]+\z/) {
              $length{$_}++;
            } else {
              $has_broken_length = 1;
            }
          }
        }
      }
      delete $self->{unread_length};
      if (($has_broken_length and keys %length) or 1 < keys %length) {
        $self->onevent->($self, $self->{request}, 'responseerror', {
          message => "Inconsistent content-length values",
        });
        $self->{no_new_request} = 1;
        $self->{request_state} = 'sent';
        $self->_next;
        return;
      } elsif (1 == keys %length) {
        my $length = each %length;
        $length =~ s/\A0+//;
        $length ||= 0;
        if ($length eq 0+$length) { # overflow check
          $self->{unread_length} = $res->{content_length} = 0+$length;
        } else {
          $self->onevent->($self, $self->{request}, 'responseerror', {
            message => "Inconsistent content-length values",
          });
          $self->{no_new_request} = 1;
          $self->{request_state} = 'sent';
          $self->_next;
          return;
        }
      }

      if (100 <= $res->{status} and $res->{status} <= 199) {
        if ($self->{request}->{method} eq 'CONNECT') {
          $self->onevent->($self, $self->{request}, 'responseerror', {
            message => "1xx response to CONNECT",
          });
          $self->{no_new_request} = 1;
          $self->{request_state} = 'sent';
          $self->_next;
          return;
        } else {
          push @{$res->{'1xxes'} ||= []}, {
            version => $res->{version},
            status => $res->{status},
            reason => $res->{reason},
            headers => $res->{headers},
          };
          $res->{version} = '0.9';
          $res->{status} = '200';
          $res->{reason} = 'OK';
          $res->{headers} = [];
          $self->{state} = 'before response';
        }
      } elsif ($res->{status} == 200 and
               $self->{request}->{method} eq 'CONNECT') {
        $self->onevent->($self, $self->{request}, 'headers', $res);
        $self->{no_new_request} = 1;
        $self->{state} = 'tunnel';
      } elsif ($res->{status} == 204 or
               $res->{status} == 205 or
               $res->{status} == 304 or
               $self->{request}->{method} eq 'HEAD') {
        $self->onevent->($self, $self->{request}, 'headers', $res);
        $self->{unread_length} = 0;
        $self->{state} = 'response body';
      } else {
        $self->onevent->($self, $self->{request}, 'headers', $res);
        $self->{state} = 'response body';
      }
    }
  }
  if ($self->{state} eq 'response body') {
    if (defined $self->{unread_length}) {
      if ($self->{unread_length} >= (my $len = length $handle->{rbuf})) {
        if ($len) {
          $self->onevent->($self, $self->{request}, 'data', $handle->{rbuf});
          $handle->{rbuf} = '';
          $self->{unread_length} -= $len;
        }
      } elsif ($self->{unread_length} > 0) {
        $self->onevent->($self, $self->{request}, 'data', substr $handle->{rbuf}, 0, $self->{unread_length});
        substr ($handle->{rbuf}, 0, $self->{unread_length}) = '';
        $self->{unread_length} = 0;
      }
      if ($self->{unread_length} <= 0) {
        $self->onevent->($self, $self->{request}, 'complete');

        my $connection = '';
        my $keep_alive = $self->{response}->{version} eq '1.1';
        for (@{$self->{response}->{headers} || []}) {
          if ($_->[2] eq 'connection') {
            $connection .= ',' . $_->[1];
          }
        }
        $connection =~ tr/A-Z/a-z/; ## ASCII case-insensitive
        for (split /[\x09\x20]*,[\x09\x20]*/, $connection) {
          if ($_ eq 'close') {
            $self->{no_new_request} = 1;
            last;
          } elsif ($_ eq 'keep-alive') {
            $keep_alive = 1;
          }
        }
        $self->{no_new_request} = 1 unless $keep_alive;

        $self->_next;
      }
    } else {
      $self->onevent->($self, $self->{request}, 'data', $handle->{rbuf})
          if length $handle->{rbuf};
      $handle->{rbuf} = '';
    }
  }
  if ($self->{state} eq 'tunnel') {
    $self->onevent->($self, $self->{request}, 'data', $handle->{rbuf})
        if length $handle->{rbuf};
    $handle->{rbuf} = '';
  }
  if ($self->{state} eq 'waiting' or $self->{state} eq 'sending') {
    $handle->{rbuf} = '';
  }
} # _process_rbuf

sub _process_rbuf_eof ($$;%) {
  my ($self, $handle, %args) = @_;
  if ($self->{state} eq 'before response') {
    if (length $handle->{rbuf}) {
      if ($self->{request}->{method} eq 'PUT') {
        $self->onevent->($self, $self->{request}, 'responseerror', {
          message => "HTTP/0.9 response to PUT request",
        });
      } else {
        $self->onevent->($self, $self->{request}, 'headers', $self->{response});
        $self->onevent->($self, $self->{request}, 'data', $handle->{rbuf});
        # XXX
        #abort => $args{abort},
        #errno => $args{errno},
        $self->onevent->($self, $self->{request}, 'complete');
      }
      $handle->{rbuf} = '';
    } else {
      $self->onevent->($self, $self->{request}, 'responseerror', {
        message => "Connection closed without response",
        errno => $args{errno},
      });
    }
  } elsif ($self->{state} eq 'response body') {
    if ($args{abort} or
        defined $self->{unread_length} and $self->{unread_length} > 0) {
      $self->{response}->{incomplete} = 1;
    }
    $self->onevent->($self, $self->{request}, 'complete');
        # XXX
        #abort => $args{abort},
        #errno => $args{errno},
  } elsif ($self->{state} eq 'tunnel') {
    $self->onevent->($self, $self->{request}, 'complete');
        # XXX
        #abort => $args{abort},
        #errno => $args{errno},
  } elsif ($self->{state} eq 'before response header') {
    $self->onevent->($self, $self->{request}, 'responseerror', {
      message => "Connection closed in response header",
      errno => $args{errno},
    });
  }

  $self->{no_new_request} = 1;
  $self->{request_state} = 'sent' if $args{abort};
  $self->_next;
} # _process_rbuf_eof

sub _next ($) {
  my $self = $_[0];
  return if $self->{state} eq 'stopped';

  if (not $self->{no_new_request} and $self->{request_state} eq 'sending') {
    $self->{state} = 'sending';
  } else {
    delete $self->{request};
    delete $self->{response};
    $self->{request_state} = 'initial';
    $self->{state} = $self->{no_new_request} ? 'stopped' : 'waiting';
    (delete $self->{request_done})->() if defined $self->{request_done};
    $self->{handle}->push_shutdown if $self->{no_new_request};
  }
} # _next

sub connect ($) {
  my $self = $_[0];
  return Promise->new (sub {
    my ($ok, $ng) = @_;
    tcp_connect $self->{host}, $self->{port}, sub {
      my $fh = shift or return $ng->($!);
      my $onclosed;
      my $closed = Promise->new (sub { $onclosed = $_[0] });
      $self->{handle} = AnyEvent::Handle->new
          (fh => $fh,
           oobinline => 0,
           on_read => sub {
             my ($handle) = @_;
             $self->_process_rbuf ($handle);
           },
           on_error => sub {
             my ($hdl, $fatal, $msg) = @_;
             if ($!{ECONNRESET}) {
               $self->onevent->($self, $self->{request}, 'reset')
                   if defined $self->{request};
               $self->{no_new_request} = 1;
               $self->{request_state} = 'sent';
               $self->_next;
             } else {
               $self->_process_rbuf ($hdl);
               $self->_process_rbuf_eof ($hdl, abort => 1, errno => $!);
             }
             $self->{handle}->destroy;
             delete $self->{handle};
             $onclosed->();
           },
           on_eof => sub {
             my ($hdl) = @_;
             $self->_process_rbuf ($hdl);
             $self->_process_rbuf_eof ($hdl);
             delete $self->{handle};
             $onclosed->();
           });
      $self->{state} = 'initial';
      $self->{request_state} = 'initial';
      $self->{closed} = $closed;
      $ok->();
    };
  });
} # connect

sub is_active ($) {
  return defined $_[0]->{state} && !$_[0]->{no_new_request};
} # is_active

sub send_request ($$) {
  my ($self, $req) = @_;
  my $method = $req->{method} // '';
  if (not defined $method or
      not length $method or
      $method =~ /[\x0D\x0A\x09\x20]/) {
    die "Bad |method|: |$method|";
  }
  my $url = $req->{target};
  if (not defined $url or
      not length $url or
      $url =~ /[\x0D\x0A]/ or
      $url =~ /\A[\x09\x20]/ or
      $url =~ /[\x09\x20]\z/) {
    die "Bad |url|: |$url|";
  }
  # XXX check body_ref vs Content-Length
  # XXX utf8 flag

  if (not defined $self->{state}) {
    return Promise->reject ("Connection has not been established");
  } elsif ($self->{no_new_request}) {
    return Promise->reject ("Connection is no longer in active");
  } elsif (not ($self->{state} eq 'initial' or $self->{state} eq 'waiting')) {
    return Promise->reject ("Connection is busy");
  }

  $self->{request} = $req;
  $self->{response} = {status => 200, reason => 'OK', version => '0.9',
                       headers => []};
  $self->{state} = 'before response';
  $self->{request_state} = 'sending';
  # XXX Connection: close
  my $req_done = Promise->new (sub { $self->{request_done} = $_[0] });
  AE::postpone {
    $self->{handle}->push_write ("$method $url HTTP/1.1\x0D\x0A\x0D\x0A");
    # XXX headers
    $self->{handle}->push_write (${$req->{body_ref}}) if defined $req->{body_ref};
    $self->{handle}->on_drain (sub {
      $self->{request_state} = 'sent';
      $self->onevent->($self, $req, 'requestsent');
      $self->_next if $self->{state} eq 'sending';
    });
  };
  return $req_done;
} # send_request

sub send_through_tunnel ($$) {
  my $self = $_[0];
  unless (defined $self->{state} and $self->{state} eq 'tunnel') {
    die "Tunnel is not open";
  }
  return unless length $_[1];
  $self->{handle}->push_write ($_[1]);
} # send_through_tunnel

sub close ($) {
  my $self = $_[0];
  if (not defined $self->{state}) {
    return Promise->reject ("Connection has not been established");
  }

  $self->{no_new_request} = 1;
  if ($self->{state} eq 'initial' or
      $self->{state} eq 'waiting' or
      $self->{state} eq 'tunnel') {
    $self->{handle}->push_shutdown;
  }

  return $self->{closed};
} # close

sub abort ($) {
  my $self = $_[0];
  if (not defined $self->{state}) {
    return Promise->reject ("Connection has not been established");
  }

  $self->{no_new_request} = 1;
  $self->{request_state} = 'sent';
  $self->_next;

  return $self->{closed};
} # abort

sub onevent ($;$) {
  if (@_ > 1) {
    $_[0]->{onevent} = $_[1];
  }
  return $_[0]->{onevent} ||= sub { };
} # onevent

sub DESTROY ($) {
  $_[0]->abort if defined $_[0]->{handle};
} # DESTROY

1;
