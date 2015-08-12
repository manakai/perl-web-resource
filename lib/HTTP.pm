package HTTP;
use strict;
use warnings;
use Errno;
use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::Socket;
use Promise;

my $DEBUG = $ENV{WEBUA_DEBUG};

sub new_from_host_and_port ($$$) {
  return bless {host => $_[1], port => $_[2]}, $_[0];
} # new_from_host_and_port

sub _process_rbuf ($$;%) {
  my ($self, $handle, %args) = @_;
  if ($self->{state} eq 'before response') {
    if ($handle->{rbuf} =~ s/^.{0,4}[Hh][Tt][Tt][Pp]//s) {
      $self->{state} = 'before response header';
      $self->{response_received} = 1;
    } elsif (8 <= length $handle->{rbuf}) {
      $self->{response_received} = 1;
      if ($self->{request}->{method} eq 'PUT') {
        $self->_ev ('responseerror', {
          message => "HTTP/0.9 response to PUT request",
        });
        $self->{no_new_request} = 1;
        $self->{request_state} = 'sent';
        $self->_next;
        return;
      } else {
        $self->_ev ('headers', $self->{response});
        $self->{state} = 'response body';
        delete $self->{unread_length};
      }
    }
  } elsif ($self->{state} eq 'before response header') {
    if (2**18-1 < length $handle->{rbuf}) {
      $self->_ev ('responseerror', {
        message => "Header section too large",
      });
      $self->{no_new_request} = 1;
      $self->{request_state} = 'sent';
      $self->_next;
      return;
    } elsif ($handle->{rbuf} =~ s/^(.*?)\x0A\x0D?\x0A//s or
             ($args{eof} and $handle->{rbuf} =~ s/\A(.*)\z//s and
              $self->{response}->{incomplete} = 1)) {
      my $headers = [split /[\x0D\x0A]+/, $1, -1];
      my $start_line = shift @$headers;
      $start_line = '' unless defined $start_line;
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
      my $te = '';
      for (@{$res->{headers}}) {
        $_->[0] =~ s/[\x09\x20]+\z//;
        $_->[1] =~ s/\A[\x09\x20]+//;
        $_->[1] =~ s/[\x09\x20]+\z//;
        $_->[2] = $_->[0];
        $_->[2] =~ tr/A-Z/a-z/; ## ASCII case-insensitive
        if ($_->[2] eq 'transfer-encoding') {
          $te .= ',' . $_->[1];
        } elsif ($_->[2] eq 'content-length') {
          for (split /[\x09\x20]*,[\x09\x20]*/, $_->[1]) {
            if (/\A[0-9]+\z/) {
              $length{$_}++;
            } else {
              $has_broken_length = 1;
            }
          }
        }
      }
      $te =~ tr/A-Z/a-z/; ## ASCII case-insensitive.
      my $chunked = !!grep { $_ eq 'chunked' } split /[\x09\x20]*,[\x09\x20]*/, $te;
      delete $self->{unread_length};
      if ($chunked and $self->{response}->{version} eq '1.1') {
        $has_broken_length = 0;
        %length = ();
      } else {
        $chunked = 0;
      }
      if (($has_broken_length and keys %length) or 1 < keys %length) {
        $self->_ev ('responseerror', {
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
          $self->_ev ('responseerror', {
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
          $self->_ev ('responseerror', {
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
        $self->_ev ('headers', $res);
        $self->{no_new_request} = 1;
        $self->{state} = 'tunnel';
      } elsif ($res->{status} == 204 or
               $res->{status} == 205 or
               $res->{status} == 304 or
               $self->{request}->{method} eq 'HEAD') {
        $self->_ev ('headers', $res);
        $self->{unread_length} = 0;
        $self->{state} = 'response body';
      } else {
        $self->_ev ('headers', $res);
        if ($chunked) {
          $self->{state} = 'before response chunk';
        } else {
          $self->{state} = 'response body';
        }
      }
    }
  }
  if ($self->{state} eq 'response body') {
    if (defined $self->{unread_length}) {
      if ($self->{unread_length} >= (my $len = length $handle->{rbuf})) {
        if ($len) {
          $self->_ev ('data', $handle->{rbuf});
          $handle->{rbuf} = '';
          $self->{unread_length} -= $len;
        }
      } elsif ($self->{unread_length} > 0) {
        $self->_ev ('data', substr $handle->{rbuf}, 0, $self->{unread_length});
        substr ($handle->{rbuf}, 0, $self->{unread_length}) = '';
        $self->{unread_length} = 0;
      }
      if ($self->{unread_length} <= 0) {
        $self->_ev ('complete');

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
      $self->_ev ('data', $handle->{rbuf})
          if length $handle->{rbuf};
      $handle->{rbuf} = '';
    }
  }
  if ($self->{state} eq 'before response chunk') {
    if ($handle->{rbuf} =~ /^[0-9A-Fa-f]/) {
      $self->{state} = 'response chunk size';
    } elsif (length $handle->{rbuf}) {
      $self->{response}->{incomplete} = 1;
      $self->{no_new_request} = 1;
      $self->{request_state} = 'sent';
      $self->_ev ('complete');
      $self->_next;
      return;
    }
  }
  if ($self->{state} eq 'response chunk size') {
    if ($handle->{rbuf} =~ s/^([0-9A-Fa-f]+)(?![0-9A-Fa-f])//) {
      my $h = $1;
      $h =~ tr/A-F/a-f/;
      $h =~ s/^0+//;
      $h ||= 0;
      my $n = hex $h;
      if (not $h eq sprintf '%x', $n) { # overflow
        $self->{response}->{incomplete} = 1;
        $self->{no_new_request} = 1;
        $self->{request_state} = 'sent';
        $self->_ev ('complete');
        $self->_next;
        return;
      }
      if ($n == 0) {
        $self->{state} = 'before response trailer';
      } else {
        $self->{unread_length} = $n;
        if ($handle->{rbuf} =~ s/^\x0A//) {
          $self->{state} = 'response chunk data';
        } else {
          $self->{state} = 'response chunk extension';
        }
      }
    }
  }
  if ($self->{state} eq 'response chunk extension') {
    $handle->{rbuf} =~ s/^[^\x0A]+//;
    if ($handle->{rbuf} =~ s/^\x0A//) {
      $self->{state} = 'response chunk data';
    }
  }
  if ($self->{state} eq 'response chunk data') {
    if ($self->{unread_length} > 0) {
      if ($self->{unread_length} >= (my $len = length $handle->{rbuf})) {
        $self->_ev ('data', $handle->{rbuf});
        $handle->{rbuf} = '';
        $self->{unread_length} -= $len;
      } else {
        $self->_ev ('data', substr $handle->{rbuf}, 0, $self->{unread_length});
        substr ($handle->{rbuf}, 0, $self->{unread_length}) = '';
        $self->{unread_length} = 0;
      }
    }
    if ($self->{unread_length} <= 0) {
      delete $self->{unread_length};
      if ($handle->{rbuf} =~ s/^\x0D?\x0A//) {
        $self->{state} = 'before response chunk';
      } elsif ($handle->{rbuf} =~ /^(?:\x0D[^\x0A]|[^\x0D\x0A])/) {
        $self->{response}->{incomplete} = 1;
        $self->{no_new_request} = 1;
        $self->{request_state} = 'sent';
        $self->_ev ('complete');
        $self->_next;
        return;
      }
    }
  }
  if ($self->{state} eq 'before response trailer') {
    if (2**18-1 < length $handle->{rbuf}) {
      $self->{no_new_request} = 1;
      $self->{request_state} = 'sent';
      $self->_ev ('complete');
      $self->_next;
      return;
    } elsif ($handle->{rbuf} =~ s/^(.*?)\x0A\x0D?\x0A//s) {
      $self->_ev ('complete');
      my $connection = '';
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
        }
      }
      $self->_next;
      return;
    }
  }
  if ($self->{state} eq 'tunnel') {
    $self->_ev ('data', $handle->{rbuf})
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
        $self->_ev ('responseerror', {
          message => "HTTP/0.9 response to PUT request",
        });
      } else {
        $self->_ev ('headers', $self->{response});
        $self->_ev ('data', $handle->{rbuf});
        # XXX
        #abort => $args{abort},
        #errno => $args{errno},
        $self->_ev ('complete');
      }
      $handle->{rbuf} = '';
    } else {
      $self->_ev ('responseerror', {
        message => "Connection closed without response",
        errno => $args{errno},
        can_retry => $self->{response_received},
      });
    }
  } elsif ($self->{state} eq 'response body') {
    if ($args{abort} or
        defined $self->{unread_length} and $self->{unread_length} > 0) {
      $self->{response}->{incomplete} = 1;
    }
    $self->_ev ('complete');
        # XXX
        #abort => $args{abort},
        #errno => $args{errno},
  } elsif ({
    'before response chunk' => 1,
    'response chunk size' => 1,
    'response chunk extension' => 1,
    'response chunk data' => 1,
  }->{$self->{state}}) {
    $self->{response}->{incomplete} = 1;
    $self->{request_state} = 'sent';
    $self->_ev ('complete');
  } elsif ($self->{state} eq 'before response trailer') {
    $self->{request_state} = 'sent';
    $self->_ev ('complete');
  } elsif ($self->{state} eq 'tunnel') {
    $self->_ev ('complete');
        # XXX
        #abort => $args{abort},
        #errno => $args{errno},
  } elsif ($self->{state} eq 'before response header') {
    $self->_ev ('responseerror', {
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
               $self->_ev ('reset')
                   if defined $self->{request};
               $self->{no_new_request} = 1;
               $self->{request_state} = 'sent';
               $self->_next;
             } else {
               $self->_process_rbuf ($hdl, eof => 1);
               $self->_process_rbuf_eof ($hdl, abort => 1, errno => $!);
             }
             $self->{handle}->destroy;
             delete $self->{handle};
             $onclosed->();
           },
           on_eof => sub {
             my ($hdl) = @_;
             $self->_process_rbuf ($hdl, eof => 1);
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
    die "Bad |target|: |$url|";
  }
  for (@{$req->{headers} or []}) {
    die "Bad header name |$_->[0]|"
        unless $_->[0] =~ /\A[!\x23-'*-+\x2D-.0-9A-Z\x5E-z|~]+\z/;
    die "Bad header value |$_->[1]|"
        unless $_->[1] =~ /\A[\x00-\x09\x0B\x0C\x0E-\xFF]*\z/;
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

  $req->{id} = int rand 1000000;
  if ($DEBUG) {
    warn "$req->{id}: ========== $$ @{[__PACKAGE__]}\n";
    warn "$req->{id}: @{[scalar gmtime]}\n";
  }

  $self->{request} = $req;
  $self->{response} = {status => 200, reason => 'OK', version => '0.9',
                       headers => []};
  $self->{state} = 'before response';
  $self->{request_state} = 'sending';
  # XXX Connection: close
  my $req_done = Promise->new (sub { $self->{request_done} = $_[0] });
  AE::postpone {
    my $handle = $self->{handle} or return;
    $handle->push_write ("$method $url HTTP/1.1\x0D\x0A");
    $handle->push_write (join '', map { "$_->[0]: $_->[1]\x0D\x0A" } @{$req->{headers} || []});
    $handle->push_write ("\x0D\x0A");
    if ($DEBUG) {
      warn "$req->{id}: S: $method $url HTTP/1.1\n";
      for (@{$req->{headers} || []}) {
        warn "$req->{id}: S: $_->[0]: $_->[1]\n";
      }
    }
    if (defined $req->{body_ref}) {
      $handle->push_write (${$req->{body_ref}});
      if ($DEBUG > 1) {
        warn "$req->{id}: S: \n";
        for (split /\x0D?\x0A/, ${$req->{body_ref}}, -1) {
          warn "$req->{id}: S: $_\n";
        }
      }
    }
    $handle->on_drain (sub {
      $self->{request_state} = 'sent';
      $self->_ev ('requestsent');
      $self->_next if $self->{state} eq 'sending';
      $_[0]->on_drain (undef);
    });
  };
  if ($DEBUG) {
    $req_done = $req_done->then (sub {
      warn "$req->{id}: ==========\n";
    });
  }
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

sub _ev ($$;$) {
  my $self = shift;
  my $req = $self->{request};
  if ($DEBUG) {
    warn "$req->{id}: $_[0] @{[scalar gmtime]}\n";
    if ($_[0] eq 'data' and $DEBUG > 1) {
      for (split /\x0D?\x0A/, $_[1], -1) {
        warn "$req->{id}: R: $_\n";
      }
    } elsif ($_[0] eq 'headers') {
      warn "$req->{id}: R: HTTP/$_[1]->{version} $_[1]->{status} $_[1]->{reason}\n";
      for (@{$_[1]->{headers}}) {
        warn "$req->{id}: R: $_->[0]: $_->[1]\n";
      }
      warn "$req->{id}: R: \n" if $DEBUG > 1;
    }
  }
  $self->onevent->($self, $req, @_);
} # _ev

sub DESTROY ($) {
  $_[0]->abort if defined $_[0]->{handle};
} # DESTROY

1;
