package HTTP;
use strict;
use warnings;
use Errno;
use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::Socket;
use Promise;

sub new_from_host_and_port ($$$) {
  return bless {host => $_[1], port => $_[2], state => 'waiting',
                next_response_id => 1}, $_[0];
} # new_from_host_and_port

sub _process_rbuf ($$) {
  my ($self, $handle) = @_;
  if ($self->{state} eq 'before response') {
    if ($handle->{rbuf} =~ s/^.{0,4}[Hh][Tt][Tt][Pp]//s) {
      ## HTTP/1.0 or HTTP/1.1
      $self->{state} = 'before response header';
    } elsif (8 <= length $handle->{rbuf}) {
      if ($self->{current_request}->{method} eq 'PUT') {
        $self->onresponsestart->({
          response_id => $self->{current_response_id},
          network_error => 1,
          error => "HTTP/0.9 response to PUT request",
        });
        $self->{handle}->push_shutdown;
        return;
      } else {
        $self->onresponsestart->($self->{current_response});
        $self->{state} = 'response body';
        delete $self->{unread_length};
      }
    }
  } elsif ($self->{state} eq 'before response header') {
    if (2**18-1 < length $handle->{rbuf}) {
      $self->onresponsestart->({
        response_id => $self->{current_response_id},
        network_error => 1,
        error => "Header too large",
      });
      $self->{handle}->push_shutdown;
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
        $self->onresponsestart->({
          response_id => $self->{current_response_id},
          network_error => 1,
          error => "Inconsistent content-length values",
        });
        $self->{handle}->push_shutdown;
        return;
      } elsif (1 == keys %length) {
        my $length = each %length;
        $length =~ s/\A0+//;
        $length ||= 0;
        if ($length eq 0+$length) { # overflow check
          $self->{unread_length} = $res->{content_length} = 0+$length;
        } else {
          $self->onresponsestart->({
            response_id => $self->{current_response_id},
            network_error => 1,
            error => "Inconsistent content-length values",
          });
          $self->{handle}->push_shutdown;
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
        $self->onresponsestart->($res);
        #XXX $self->onclose
        delete $self->{current_request};
        $self->{state} = 'waiting';
      } else {
        $self->onresponsestart->($res);
        $self->{state} = 'response body';
      }
    }
  }
  if ($self->{state} eq 'response body') {
    if (defined $self->{unread_length}) {
      if ($self->{unread_length} >= (my $len = length $handle->{rbuf})) {
        if ($len) {
          $self->ondata->($self->{current_response_id}, $handle->{rbuf});
          $handle->{rbuf} = '';
          $self->{unread_length} -= $len;
        }
      } elsif ($self->{unread_length} > 0) {
        $self->ondata->($self->{current_response_id}, substr $handle->{rbuf}, 0, $self->{unread_length});
        substr ($handle->{rbuf}, 0, $self->{unread_length}) = '';
        $self->{unread_length} = 0;
      }
      if ($self->{unread_length} <= 0) {
        # XXX switch state
        #delete $self->{current_request};
      }
    } else {
      $self->ondata->($self->{current_response_id}, $handle->{rbuf})
          if length $handle->{rbuf};
      $handle->{rbuf} = '';
    }
  }
} # _process_rbuf

sub _process_rbuf_eof ($$) {
  my ($self, $handle) = @_;
  if ($self->{state} eq 'before response') {
    if (length $handle->{rbuf}) {
      if ($self->{current_request}->{method} eq 'PUT') {
        $self->onresponsestart->({
          response_id => $self->{current_response_id},
          network_error => 1,
          error => "HTTP/0.9 response to PUT request",
        });
        $self->{handle}->push_shutdown;
        return;
      } else {
        $self->onresponsestart->($self->{current_response});
        $self->{state} = 'response body';
        delete $self->{unread_length};
        $self->ondata->($self->{current_response_id}, $handle->{rbuf});
        $handle->{rbuf} = '';
      }
    } else {
      $self->onresponsestart->({
        response_id => $self->{current_response_id},
        network_error => 1,
        error => "Connection closed",
      });
    }
  } elsif ($self->{state} eq 'response body') {
    if (defined $self->{unread_length} and
        $self->{unread_length} > 0) {
      $self->{onclose_error} = 'premature closure of the connection';
    }
  }
} # _process_rbuf_eof

sub connect ($) {
  my $self = $_[0];
  return Promise->new (sub {
    my ($ok, $ng) = @_;
    tcp_connect $self->{host}, $self->{port}, sub {
      my $fh = shift or return $ng->($!);
      $self->{handle} = AnyEvent::Handle->new
          (fh => $fh,
           oobinline => 0,
           on_read => sub {
             my ($handle) = @_;
             $self->_process_rbuf ($handle);
           },
           on_error => sub {
             my ($hdl, $fatal, $msg) = @_;
             $self->_process_rbuf ($hdl);
             $self->_process_rbuf_eof ($hdl);
             my $err = delete $self->{onclose_error};
             AE::log error => $msg;
             $self->{handle}->destroy;
             delete $self->{handle};
             $self->onclose->($!{EPIPE} ? undef : $msg, $err);
             delete $self->{current_request};
           },
           on_eof => sub {
             my ($hdl) = @_;
             $self->_process_rbuf ($hdl);
             $self->_process_rbuf_eof ($hdl);
             my $err = delete $self->{onclose_error};
             delete $self->{handle};
             $self->onclose->(undef, $err);
             delete $self->{current_request};
           });
      $ok->();
    };
  });
} # connect

sub send_request ($$) {
  my ($self, $req) = @_;
  unless (defined $self->{handle}) {
    return Promise->reject ("Not connected");
  }
  my $version = $req->{version} // '';
  if ($version eq '1.0') {
    unless ($self->{state} eq 'waiting') { # XXX pipelining
      return Promise->reject ("Can't use this connection: |$self->{state}|");
    }
    my $method = $req->{method} // '';
    if (not length $method or $method =~ /[\x0D\x0A\x09\x20]/) {
      return Promise->reject ("Bad |method|: |$method|");
    }
    my $url = $req->{url};
    if (not defined $url or $url =~ /[\x0D\x0A]/ or
        $url =~ /\A[\x0D\x0A\x09\x20]/ or
        $url =~ /[\x0D\x0A\x09\x20]\z/) {
      return Promise->reject ("Bad |url|: |$url|");
    }
    $self->{state} = 'before response';
    $self->{current_response_id} = $self->{next_response_id}++;
    $self->{current_response} = {response_id => $self->{current_response_id},
                                 status => 200, reason => 'OK',
                                 version => '0.9',
                                 headers => []};
    $self->{current_request} = $req;
    $self->{handle}->push_write ("$method $url HTTP/1.0\x0D\x0A\x0D\x0A");
    return Promise->resolve;
  } else {
    return Promise->reject ("Bad |version|: |$version|");
  }
} # send_request

sub onresponsestart ($;$) {
  if (@_ > 1) {
    $_[0]->{onresponsestart} = $_[1];
  }
  return $_[0]->{onresponsestart} ||= sub { };
} # onresponsestart

sub ondata ($;$) {
  if (@_ > 1) {
    $_[0]->{ondata} = $_[1];
  }
  return $_[0]->{ondata} ||= sub { };
} # ondata

sub onclose ($;$) {
  if (@_ > 1) {
    $_[0]->{onclose} = $_[1];
  }
  return $_[0]->{onclose} ||= sub { };
} # ondata

1;
