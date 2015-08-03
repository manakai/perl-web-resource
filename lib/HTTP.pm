package HTTP;
use strict;
use warnings;
use Errno;
use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::Socket;
use Promise;

sub new_from_host_and_port ($$$) {
  return bless {host => $_[1], port => $_[2],
                #state => 
                queue => [],
                next_response_id => 1}, $_[0];
} # new_from_host_and_port

sub _process_rbuf ($$) {
  my ($self, $handle) = @_;
  if ($self->{state} eq 'before response') {
    if ($handle->{rbuf} =~ s/^.{0,4}[Hh][Tt][Tt][Pp]//s) {
      $self->{state} = 'before response header';
    } elsif (8 <= length $handle->{rbuf}) {
      if ($self->{current_request}->{method} eq 'PUT') {
        $self->onevent->($self, $self->{current_request}, 'responseerror', {
          message => "HTTP/0.9 response to PUT request",
        });
        delete $self->{current_request};
        $self->{state} = 'stopped';
        $self->{no_new_request} = 1;
        $self->{handle}->push_shutdown;
        # XXX
        return;
      } else {
        $self->onevent->($self, $self->{current_request}, 'headers', $self->{current_response});
        $self->{state} = 'response body';
        delete $self->{unread_length};
      }
    }
  } elsif ($self->{state} eq 'before response header') {
    if (2**18-1 < length $handle->{rbuf}) {
      $self->onevent->($self, $self->{current_request}, 'responseerror', {
        message => "Header section too large",
      });
      delete $self->{current_request};
      $self->{state} = 'stopped';
      $self->{no_new_request} = 1;
      $self->{handle}->push_shutdown;
      # XXX
      return;
    } elsif ($handle->{rbuf} =~ s/^(.*?)\x0A\x0D?\x0A//s) {
      my $headers = [split /[\x0D\x0A]+/, $1, -1]; # XXX report CR
      my $start_line = shift @$headers;
      my $res = $self->{current_response};
      $res->{version} = '1.0';
      if ($start_line =~ s{\A/}{}) {
        if ($start_line =~ s{\A([0-9]+)}{}) {
          my $major = 0+$1;
          if ($start_line =~ s{\A\.}{}) {
            if ($start_line =~ s{\A([0-9]+)}{}) {
              my $minor = 0+$1;
              if ($major > 1 or ($major == 1 and $minor > 0)) {
                $res->{version} = '1.1';
              }
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
        $self->onevent->($self, $self->{current_request}, 'responseerror', {
          message => "Inconsistent content-length values",
        });
        delete $self->{current_request};
        $self->{state} = 'stopped';
        $self->{no_new_request} = 1;
        $self->{handle}->push_shutdown;
        # XXX
        return;
      } elsif (1 == keys %length) {
        my $length = each %length;
        $length =~ s/\A0+//;
        $length ||= 0;
        if ($length eq 0+$length) { # overflow check
          $self->{unread_length} = $res->{content_length} = 0+$length;
        } else {
          $self->onevent->($self, $self->{current_request}, 'responseerror', {
            message => "Inconsistent content-length values",
          });
          delete $self->{current_request};
          $self->{state} = 'stopped';
          $self->{no_new_request} = 1;
          $self->{handle}->push_shutdown;
          # XXX
          return;
        }
      }

      if (100 <= $res->{status} and $res->{status} <= 199) {
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
      } elsif ($res->{status} == 204 or
               $res->{status} == 205 or
               $res->{status} == 304 or
               $self->{current_request}->{method} eq 'HEAD') { # XXX or CONNECT
        $self->onevent->($self, $self->{current_request}, 'headers', $res);
        $self->onevent->($self, $self->{current_request}, 'complete');

        # XXX go to next
        delete $self->{current_request};
        $self->{state} = 'waiting';
        $self->{handle}->push_shutdown if $self->{no_new_request};
      } else {
        $self->onevent->($self, $self->{current_request}, 'headers', $res);
        $self->{state} = 'response body';
      }
    }
  }
  if ($self->{state} eq 'response body') {
    if (defined $self->{unread_length}) {
      if ($self->{unread_length} >= (my $len = length $handle->{rbuf})) {
        if ($len) {
          $self->onevent->($self, $self->{current_request}, 'data', $handle->{rbuf});
          $handle->{rbuf} = '';
          $self->{unread_length} -= $len;
        }
      } elsif ($self->{unread_length} > 0) {
        $self->onevent->($self, $self->{current_request}, 'data', substr $handle->{rbuf}, 0, $self->{unread_length});
        substr ($handle->{rbuf}, 0, $self->{unread_length}) = '';
        $self->{unread_length} = 0;
      }
      if ($self->{unread_length} <= 0) {
        $self->onevent->($self, $self->{current_request}, 'complete');

        # XXX switch state
        #delete $self->{current_request};

        delete $self->{current_request};
        $self->{state} = 'waiting';
        $self->{handle}->push_shutdown if $self->{no_new_request};
      }
    } else {
      $self->onevent->($self, $self->{current_request}, 'data', $handle->{rbuf})
          if length $handle->{rbuf};
      $handle->{rbuf} = '';
    }
  }
  if ($self->{state} eq 'waiting' or $self->{state} eq 'sending') {
    $handle->{rbuf} = '';
  }
} # _process_rbuf

sub _process_rbuf_eof ($$;%) {
  my ($self, $handle, %args) = @_;
  if ($self->{state} eq 'before response') {
    if (length $handle->{rbuf}) {
      if ($self->{current_request}->{method} eq 'PUT') {
        $self->onevent->($self, $self->{current_request}, 'responseerror', {
          message => "HTTP/0.9 response to PUT request",
        });
        delete $self->{current_request};
      } else {
        $self->onevent->($self, $self->{current_request}, 'headers', $self->{current_response});
        $self->onevent->($self, $self->{current_request}, 'data', $handle->{rbuf});
      }
      $handle->{rbuf} = '';
    } else {
      $self->onevent->($self, $self->{current_request}, 'responseerror', {
        message => "Connection closed without response",
      });
      delete $self->{current_request};
    }
  } elsif ($self->{state} eq 'response body') {
    if ($args{abort} or
        defined $self->{unread_length} and $self->{unread_length} > 0) {
      $self->{current_response}->{incomplete} = 1;
      $self->{onclose_error} = 'premature closure of the connection'; #XXX
    }
    $self->onevent->($self, $self->{current_request}, 'complete');
    delete $self->{current_request};
  } elsif ($self->{state} eq 'before response header') {
    $self->onevent->($self, $self->{current_request}, 'responseerror', {
      message => "Connection closed in response header",
    });
    delete $self->{current_request};
  }

  if (defined $self->{current_request}) {
    $self->onevent->($self, $self->{current_request}, 'complete');
    delete $self->{current_request};
  }

  unless ($self->{state} eq 'stopped') {
    $self->{state} = 'stopped';
    $self->{no_new_request} = 1;
    $self->{handle}->push_shutdown;

    # XXX
  }
} # _process_rbuf_eof

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
               if (defined $self->{current_request}) {
                 $self->onevent->($self, $self->{current_request}, 'reset');
               }
               delete $self->{current_request};
               unless ($self->{state} eq 'stopped') {
                 $self->{state} = 'stopped';
                 $self->{no_new_request} = 1;
                 #$self->{handle}->push_shutdown;
                 
                 # XXX
               }
             } else {
               $self->_process_rbuf ($hdl);
               $self->_process_rbuf_eof ($hdl, abort => 1);
             }
             $self->{handle}->destroy;
             delete $self->{handle};

             #XXX
             my $err = delete $self->{onclose_error};
             #AE::log error => $msg;
             #$self->onclose->($!{EPIPE} ? undef : $msg, $err); # XXX

             $onclosed->();
           },
           on_eof => sub {
             my ($hdl) = @_;
             $self->_process_rbuf ($hdl);
             $self->_process_rbuf_eof ($hdl);
             delete $self->{handle};

             # XXX
             my $err = delete $self->{onclose_error};
             #$self->onclose->(undef, $err); # XXX

             $onclosed->();
           });
      $self->{state} = 'initial';
      $self->{closed} = $closed;
      $ok->();
    };
  });
} # connect

sub can_send_request ($) {
  my $self = $_[0];
  if (not defined $self->{state}) {
    return 0;
  } elsif ($self->{no_new_request}) {
    return 0;
  } else {
    return 1;
  }
} # can_send_request

sub send_request ($$) {
  my ($self, $req) = @_;
  my $method = $req->{method} // '';
  if (not length $method or $method =~ /[\x0D\x0A\x09\x20]/) {
    die "Bad |method|: |$method|";
  }
  my $url = $req->{url};
  if (not defined $url or $url =~ /[\x0D\x0A]/ or
      $url =~ /\A[\x0D\x0A\x09\x20]/ or
      $url =~ /[\x0D\x0A\x09\x20]\z/) {
    die "Bad |url|: |$url|";
  }
  # XXX utf8 flag
  if (not defined $self->{state}) {
    die "Not connected";
  } elsif ($self->{no_new_request}) {
    $self->onevent->($self, $req, 'cancel');
    return;
  }
  push @{$self->{queue}}, {request => $req,
                           request_status => 'not',
                           response_status => 'not'};
  if ($self->{state} eq 'waiting' or $self->{state} eq 'initial') {
    if (@{$self->{queue}} == 1 or
        (@{$self->{queue}} > 1 and
         $self->{queue}->[-2]->{request_status} eq 'sent')) {
      my $queue_item = $self->{queue}->[-1];
      $queue_item->{request_status} = 'sending';
      $self->{current_request} = $req;
      $self->{current_response_id} = $self->{next_response_id}++;
      $self->{current_response} = {response_id => $self->{current_response_id},
                                   status => 200, reason => 'OK',
                                   version => '0.9',
                                   headers => []};
      $self->{state} = 'before response';

      AE::postpone {
        $self->{handle}->push_write ("$method $url HTTP/1.1\x0D\x0A\x0D\x0A");
        # XXX request body
        $queue_item->{request_status} = 'sent';
        $self->onevent->($self, $req, 'requestsent');
        if ($self->{state} eq 'sending') {
          # XXX goto next
            
        } else {
          # XXX pipelining
        }
      };
    }
  }
  return;
} # send_request

sub close ($) {
  my $self = $_[0];
  if (not defined $self->{state}) {
    return Promise->reject ("Not connected");
  } else {
    $self->{no_new_request} = 1;
    if ($self->{state} eq 'initial' or $self->{state} eq 'waiting') {
      $self->{handle}->push_shutdown;
    }
  }
  return $self->{closed};
} # close

sub onevent ($;$) {
  if (@_ > 1) {
    $_[0]->{onevent} = $_[1];
  }
  return $_[0]->{onevent} ||= sub { };
} # onevent

sub DESTROY ($) {
  $_[0]->close;
} # DESTROY

1;
