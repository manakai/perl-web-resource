use strict;
use warnings;
use AnyEvent::Socket;
use Promise;
use Web::Transport::TCPTransport;

my $host = 0;
my $port = 8522;

my $ReadTimeout = $ENV{SERVER_READ_TIMEOUT} || 60;

my $server = tcp_server $host, $port, sub {
  my ($fh, $client_host, $client_port) = @_;
  #warn "$client_host / $client_port";

  my $transport = Web::Transport::TCPTransport->new (fh => $fh);
  my $self = bless {transport => $transport,
                    rbuf => '', state => 'initial'}, 'Hoge';
  my $read_timer;
  my $onreadtimeout = sub {
    undef $read_timer;
    $transport->abort (message => "Read timeout ($ReadTimeout)");
  };
  my $p = $transport->start (sub {
    my ($transport, $type) = @_;
    if ($type eq 'readdata') {
      $read_timer = AE::timer $ReadTimeout, 0, $onreadtimeout;
      $self->_ondata ($_[2]);
    } elsif ($type eq 'readeof') {
      undef $read_timer;
      $self->_oneof ($_[2]);
    } elsif ($type eq 'writeeof') {
      $self->{write_closed} = 1;
    } elsif ($type eq 'close') {
      #warn "Closed";
      #warn scalar gmtime;
    }
  })->then (sub {
    #warn "Established";
    #warn scalar gmtime;
    $read_timer = AE::timer $ReadTimeout, 0, $onreadtimeout;
  });
};

AE::cv->recv;

package Hoge;

sub _ondata ($$) {
  my ($self, $inref) = @_;
  while (1) {
    if ($self->{state} eq 'initial') {
      $self->{rbuf} .= $$inref;
      if ($self->{rbuf} =~ s/^\x0D?\x0A// or
          2 <= length $self->{rbuf}) {
        $self->{state} = 'before request-line';
      } else {
        return;
      }
    } elsif ($self->{state} eq 'after request') {
      $self->{rbuf} .= $$inref;
      $self->{rbuf} =~ s/^[\x0D\x0A]+//;
      if ($self->{rbuf} =~ /^[^\x0D\x0A]/) {
        $self->{state} = 'before request-line';
      } else {
        return;
      }
    } elsif ($self->{state} eq 'before request-line') {
      $self->{rbuf} .= $$inref;
      if ($self->{rbuf} =~ s/\A([^\x0A]*)\x0A//) {
        my $line = $1;
        $line =~ s/\x0D\z//;
        my $method;
        my $version;
        if ($line =~ s{[\x09\x20]+(H[^\x09\x20]*)\z}{}) {
          $version = $1;
          if ($version =~ m{\AHTTP/1\.([0-9]+)\z}) {
            $version = $version =~ /[^0]/ ? 1.1 : 1.0;
          } elsif ($version =~ m{\AHTTP/0+1?\.}) {
            return $self->_fatal (0.9);
          } elsif ($version =~ m{\AHTTP/[0-9]+\.[0-9]+\z}) {
            $version = 1.1;
          } else {
            return $self->_fatal (0.9);
          }
        }
        if ($line =~ s{\A([^\x09\x20]+)[\x09\x20]+}{}) {
          $method = $1;
        }
        return $self->_fatal (0.9) unless defined $method;
        my $req = $self->{request} = {version => $version, method => $method,
                                      target => $line, headers => []};
        my $p1 = Promise->new (sub { $self->{request}->{req_done} = $_[0] });
        my $p2 = Promise->new (sub { $self->{request}->{res_done} = $_[0] });
        Promise->all ([$p1, $p2])->then (sub {
          $self->_done ($req);
        });
        if (not defined $version) {
          return $self->_fatal (0.9) unless $method eq 'GET';
          $self->{request}->{version} = 0.9;
          $self->{close_after_response} = 1;
          $self->onrequest ($self->{request});
        } else { # 1.0 / 1.1
          return $self->_fatal ($version) unless length $line;
          $self->{state} = 'before request header';
        }
      } else {
        return;
      }
      # XXX if rbuf is too long
  } elsif ($self->{state} eq 'before request header') {
    $self->{rbuf} .= $$inref;
    if ($self->{rbuf} =~ s/\A([^:\x20\x0A]+):([^\x0A]*)\x0A//) { # XXX \x09 \x0D
      my $name = $1;
      my $value = $2;
      $value =~ s/\A[\x09\x20]+//;
      $value =~ s/\x0D\z//;
      push @{$self->{request}->{headers}}, [$name, $value];
    } elsif ($self->{rbuf} =~ s/\A\x0D?\x0A//) {
      my @length;
      for (@{$self->{request}->{headers}}) {
        my $n = $_->[0];
        $n =~ tr/A-Z/a-z/; ## ASCII case-insensitive
        if ($n eq 'content-length') {
          push @length, $_->[1];
        }
      }
      # XXX if connection
      if ($self->{request}->{version} == 1.1) {
        
      } else { # 1.0
        $self->{close_after_response} = 1;
      }
      # XXX if transfer-encoding
      if (@length == 1 and $length[0] =~ /\A[0-9]+\z/) {
        my $l = 0+$length[0];
        $self->{request}->{body_length} = $l;
        $self->{unread_length} = $l;
        $self->onrequest ($self->{request});
        if ($l == 0) {
          $self->_request_done ($self->{request});
        } else {
          $self->{state} = 'request body';
        }
      } elsif (@length) {
        return $self->_fatal ($self->{request}->{version});
      } else {
        $self->onrequest ($self->{request});
        $self->_request_done ($self->{request});
      }

  # XXX length=0 tests
  # XXX wrapped

      } elsif ($self->{rbuf} =~ s/\A[^\x0A]*\x0A//) {
        return $self->_fatal ($self->{request}->{version});
      } else {
        return;
      }
  # XXX bad name
  # XXX spaces
  # XXX if rbuf is too long

    } elsif ($self->{state} eq 'request body') {
      if (length $self->{rbuf}) {
        $inref = \($self->{rbuf} . $$inref);
      }
      my $in_length = length $$inref;
      if ($self->{unread_length} == $in_length) {
        $self->ondata ($$inref);
        $self->onreof ({});
        $self->_request_done ($self->{request});
      } elsif ($self->{unread_length} < $in_length) {
        $self->{request}->{incomplete} = 1;
        $self->{close_after_response} = 1;
        $self->ondata (substr ($$inref, 0, $self->{unread_length}));
        $self->onreof ({});
        $self->_request_done ($self->{request});
      } else { # unread_length > $in_length
        $self->ondata ($$inref);
        $self->{unread_length} -= $in_length;
        return;
      }
    } else {
      die "Bad state |$self->{state}|";
    }
    $inref = \'';
  } # while
} # _ondata

sub _oneof ($$) {
  my ($self, $exit) = @_;
  $self->{close_after_response} = 1;
  if ($self->{state} eq 'initial' or
      $self->{state} eq 'before request-line') {
    return $self->_fatal (0.9);
  } elsif ($self->{state} eq 'before request header') {
    return $self->_fatal ($self->{request}->{version});
  } elsif ($self->{state} eq 'request body') {
    # $self->{unread_length} > 0
    $self->{request}->{incomplete} = 1;
    $self->onreof ($exit->{failed} ? $exit : {failed => 1, message => "Connection closed"});
    $self->_request_done ($self->{request});
  } elsif ($self->{state} eq 'after request') {
    return $self->_fatal (0.9) if length $self->{rbuf};
    $self->_response_done (undef);
  } else {
    die "Bad state |$self->{state}|";
  }
} # _oneof

sub _request_done ($$) {
  my ($self, $req) = @_;
  delete $self->{request};
  delete $self->{unread_length};
  $self->{state} = 'after request';
  if (defined $req and defined $req->{req_done}) {
    $req->{req_done}->();
  }
} # _request_done

sub _response_done ($$) {
  my ($self, $req) = @_;
  if (delete $self->{close_after_response}) {
    $self->{transport}->push_shutdown
        unless $self->{write_closed};
    $self->{write_closed} = 1;
  }
  if (defined $req and defined $req->{res_done}) {
    $req->{res_done}->();
  }
} # _response_done

sub _done ($$) {
  my ($self, $req) = @_;
  if (delete $self->{close_after_response}) {
    $self->{transport}->push_shutdown
        unless $self->{write_closed};
    $self->{write_closed} = 1;
  }
} # _done

sub _fatal ($$) {
  my ($self, $version) = @_;
  my $req = {version => $version, method => 'GET'}; # XXX HEAD fatal
  $self->_request_done ($req);
  unless ($self->{write_closed}) {
  my $res = q{<!DOCTYPE html><html>
<head><title>400 Bad Request</title></head>
<body>400 Bad Request</body>
</html>
};
    $self->{close_after_response} = 1;
    $self->send_response_headers
        ($req,
         {status => 400, status_text => 'Bad Request',
          headers => [
            ['Content-Type' => 'text/html; charset=utf-8'],
            ['Content-Length' => length $res],
            ['Connection' => 'close'],
          ]});
    $self->{transport}->push_write (\$res);
  }
  return $self->_response_done ($req);
} # _fatal

sub onrequest ($$) {
  my ($self, $request) = @_;
  if ($request->{target} =~ /[\x00]/) {
    return $self->_fatal ($request->{version});
  } elsif ($request->{target} =~ m{^/}) {
    #
  } elsif ($request->{target} =~ m{^[A-Za-z0-9.-]+://}) { # XXX
    #
  } else {
    return $self->_fatal ($request->{version});
  }

    if ($request->{target} eq '/end') {
      $self->send_response_headers
          ($request,
           {status => 200, status_text => 'OK', headers => []}); # XXX
      $self->{transport}->push_write (\qq{<html>200 Goodbye!\x0D\x0A\x0D\x0A</html>
});
      AE::postpone { exit };
    } elsif ($self->{write_closed}) {
      #
    } elsif ($request->{method} eq 'GET' or
             $request->{method} eq 'POST' or
             $request->{method} eq 'HEAD') {
      $self->send_response_headers
          ($request,
           {status => 404, status_text => 'Not Found', headers => []}); # XXX
      $self->{transport}->push_write (\qq{<html>...404 Not Found\x0D\x0A\x0D\x0A</html>
});
    } else {
      $self->send_response_headers
          ($request,
           {status => 405, status_text => 'Not Allowed', headers => []}); # XXX
      $self->{transport}->push_write (\qq{<html>...405 Not Allowed (@{[$request->{method}]})</html>
});
    }

  $self->_response_done ($request);
} # onrequest

sub ondata ($$) {
  warn "Server received [[$_[1]]]";
} # ondata

sub onreof ($$) {
  warn "End of request";
} # onreof

sub send_response_headers ($$$) {
  my ($self, $request, $response) = @_;
  # XXX validation
  unless ($request->{version} == 0.9) {
    my $res = sprintf qq{HTTP/1.1 %d %s\x0D\x0A},
        $response->{status},
        $response->{status_text};
    my @header;
    push @header, ['Server', 'Server/1'], ['Date', 'XXX'];
    for (@header, @{$response->{headers}}) {
      $res .= "$_->[0]: $_->[1]\x0D\x0A";
    }
    $res .= "\x0D\x0A";
    $self->{transport}->push_write (\$res);
  }
  # XXX
  if ($request->{method} eq 'HEAD' or
      ($request->{method} eq 'CONNECT' and
       200 <= $response->{status} and $response->{status} < 300) or
      $response->{status} == 304 or
      (100 <= $response->{status} and $response->{status} < 200)) {

  } else {
    
  }
} # send_response_headers

# XXX TRACE
# XXX space in target
