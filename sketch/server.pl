use strict;
use warnings;
use AnyEvent::Socket;
use Promise;
use Web::URL;
use Web::Transport::TCPTransport;

my $host = 0;
my $port = 8522;

my $ReadTimeout = $ENV{SERVER_READ_TIMEOUT} || 60;

my $cb = sub {
  my $self = $_[0];
  my $type = $_[1];
  if ($type eq 'open') {
    my $data = $_[2];
    warn "> Connection opened (Client: $data->{client_ip_addr}:$data->{client_port})\n";
  } elsif ($type eq 'close') {
    warn "> Connection closed\n";
  } else {
    warn "> $type\n";
  }
}; # $cb

my $server = tcp_server $host, $port, sub {
  my ($fh, $client_host, $client_port) = @_;

  my $transport = Web::Transport::TCPTransport->new (fh => $fh);
  my $self = bless {transport => $transport,
                    rbuf => '', state => 'initial',
                    cb => $cb}, 'Hoge';
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
      AE::postpone {
        $self->{cb}->($self, 'close');
      };
    }
  })->then (sub {
    #warn "Established";
    #warn scalar gmtime;
    $read_timer = AE::timer $ReadTimeout, 0, $onreadtimeout;
    AE::postpone {
      $self->{cb}->($self, 'open', {client_ip_addr => $client_host,
                                    client_port => $client_port});
    };
  });
};

AE::cv->recv;

package Hoge;

sub _ondata ($$) {
  my ($self, $inref) = @_;
  while (1) {
    #warn "[$self->{state}] |$self->{rbuf}|";
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
      if ($self->{rbuf} =~ s/\A([^\x0A]{0,8191})\x0A//) {
        my $line = $1;
        $line =~ s/\x0D\z//;
        return $self->_fatal (bless {
          transport => $self->{transport},
          version => 0.9, method => 'GET',
          write_closed_ref => \($self->{write_closed}),
        }, 'Hoge::Request') if $line =~ /[\x00\x0D]/;
        my $method;
        my $version;
        if ($line =~ s{\x20+(H[^\x20]*)\z}{}) {
          $version = $1;
          if ($version =~ m{\AHTTP/1\.([0-9]+)\z}) {
            $version = $1 =~ /[^0]/ ? 1.1 : 1.0;
          } elsif ($version =~ m{\AHTTP/0+1?\.}) {
            return $self->_fatal (bless {
              transport => $self->{transport},
              version => 0.9, method => 'GET',
              write_closed_ref => \($self->{write_closed}),
            }, 'Hoge::Request');
          } elsif ($version =~ m{\AHTTP/[0-9]+\.[0-9]+\z}) {
            $version = 1.1;
          } else {
            return $self->_fatal (bless {
              transport => $self->{transport},
              version => 0.9, method => 'GET',
              write_closed_ref => \($self->{write_closed}),
            }, 'Hoge::Request');
          }
        }
        if ($line =~ s{\A([^\x20]+)\x20+}{}) {
          $method = $1;
        }
        return $self->_fatal (bless {
          transport => $self->{transport},
          version => 0.9, method => 'GET',
          write_closed_ref => \($self->{write_closed}),
        }, 'Hoge::Request') unless defined $method;
        my $req = $self->{request} = bless {
          transport => $self->{transport},
          version => $version, method => $method,
          target => $line, headers => [],
          write_closed_ref => \($self->{write_closed}),
        }, 'Hoge::Request';
        my $p1 = Promise->new (sub { $self->{request}->{req_done} = $_[0] });
        my $p2 = Promise->new (sub { $self->{request}->{res_done} = $_[0] });
        Promise->all ([$p1, $p2])->then (sub {
          $self->_done ($req);
        });
        if (not defined $version) {
          $self->{request}->{version} = 0.9;
          $self->{request}->{close_after_response} = 1;
          $self->{request}->{method} = 'GET';
          return $self->_fatal ($self->{request}) unless $method eq 'GET';
          $self->onrequest ($self->{request});
        } else { # 1.0 / 1.1
          return $self->_fatal ($req) unless length $line;
          $self->{state} = 'before request header';
        }
      } elsif (8192 <= length $self->{rbuf}) {
        return $self->_414;
      } else {
        return;
      }
    } elsif ($self->{state} eq 'before request header') {
      $self->{rbuf} .= $$inref;
      if ($self->{rbuf} =~ s/\A([^\x0A]{0,8191})\x0A//) {
        my $line = $1;
        return $self->_fatal ($self->{request})
            if @{$self->{request}->{headers}} == 100;
        $line =~ s/\x0D\z//;
        return $self->_fatal ($self->{request})
            if $line =~ /[\x00\x0D]/;
        if ($line =~ s/\A([^\x09\x20:][^:]*):[\x09\x20]*//) {
          my $name = $1;
          push @{$self->{request}->{headers}}, [$name, $line];
        } elsif ($line =~ s/\A[\x09\x20]+// and @{$self->{request}->{headers}}) {
          if ((length $self->{request}->{headers}->[-1]->[0]) + 1 +
              (length $self->{request}->{headers}->[-1]->[1]) + 1 +
              (length $line) + 2 > 8192) {
            return $self->_fatal ($self->{request});
          } else {
            $self->{request}->{headers}->[-1]->[1] .= " " . $line;
          }
        } elsif ($line eq '') { # end of headers
          my @length;
          my @host;
          my @con;
          for (@{$self->{request}->{headers}}) {
            $_->[1] =~ s/[\x09\x20]+\z//;
            my $n = $_->[0];
            $n =~ tr/A-Z/a-z/; ## ASCII case-insensitive
            if ($n eq 'content-length') {
              push @length, $_->[1];
            } elsif ($n eq 'host') {
              push @host, $_->[1];
            } elsif ($n eq 'connection') {
              push @con, $_->[1];
            } elsif ($n eq 'transfer-encoding') {
              return $self->_411 ($self->{request});
            }
          }

          ## Host:
          if (@host == 1) {
            my $url = Web::URL->parse_string ("https://$host[0]/");
            if (not defined $url or
                not $url->path eq '/' or
                defined $url->query or
                defined $url->{fragment}) { # XXX
              return $self->_fatal ($self->{request});
            }
          } elsif (@host) { # multiple Host:
            return $self->_fatal ($self->{request});
          } else { # no Host:
            if ($self->{request}->{version} == 1.1) {
              return $self->_fatal ($self->{request});
            }
          }

          ## Connection:
          my $con = join ',', '', @con, '';
          $con =~ tr/A-Z/a-z/; ## ASCII case-insensitive.
          if ($con =~ /,[\x09\x0A\x0D\x20]*close[\x09\x0A\x0D\x20]*,/) {
            $self->{request}->{close_after_response} = 1;
          } elsif ($self->{request}->{version} == 1.0) {
            unless ($con =~ /,[\x09\x0A\x0D\x20]*keep-alive[\x09\x0A\x0D\x20]*,/) {
              $self->{request}->{close_after_response} = 1;
            }
          }

          ## Content-Length:
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
            return $self->_fatal ($self->{request});
          } else {
            $self->onrequest ($self->{request});
            $self->_request_done ($self->{request});
          }
        } else {
          return $self->_fatal ($self->{request});
        }
      } elsif (8192 <= length $self->{rbuf}) {
        return $self->_fatal ($self->{request});
      } else {
        return;
      }
    } elsif ($self->{state} eq 'request body') {
      if (length $self->{rbuf}) {
        $inref = \($self->{rbuf} . $$inref);
        $self->{rbuf} = '';
      }
      my $in_length = length $$inref;
      if ($self->{unread_length} == $in_length) {
        $self->ondata ($$inref);
        $self->onreof ({});
        $self->_request_done ($self->{request});
      } elsif ($self->{unread_length} < $in_length) {
        $self->{request}->{incomplete} = 1;
        $self->{request}->{close_after_response} = 1;
        $self->ondata (substr ($$inref, 0, $self->{unread_length}));
        $self->onreof ({});
        $self->_request_done ($self->{request});
      } else { # unread_length > $in_length
        $self->ondata ($$inref);
        $self->{unread_length} -= $in_length;
        return;
      }
    } elsif ($self->{state} eq 'end') {
      return;
    } else {
      die "Bad state |$self->{state}|";
    }
    $inref = \'';
  } # while
} # _ondata

sub _oneof ($$) {
  my ($self, $exit) = @_;
  if ($self->{state} eq 'initial' or
      $self->{state} eq 'before request-line') {
    return $self->_fatal (bless {
      transport => $self->{transport}, version => 0.9, method => 'GET',
      write_closed_ref => \($self->{write_closed}),
    }, 'Hoge::Request');
  } elsif ($self->{state} eq 'before request header') {
    $self->{request}->{close_after_response} = 1;
    return $self->_fatal ($self->{request});
  } elsif ($self->{state} eq 'request body') {
    # $self->{unread_length} > 0
    $self->{request}->{close_after_response} = 1;
    $self->{request}->{incomplete} = 1;
    $self->onreof ($exit->{failed} ? $exit : {failed => 1, message => "Connection closed"});
    $self->_request_done ($self->{request});
  } elsif ($self->{state} eq 'after request') {
    return $self->_fatal (bless {
      transport => $self->{transport},
      version => 0.9, method => 'GET',
      close_after_response => 1,
      write_closed_ref => \($self->{write_closed}),
    }) if length $self->{rbuf};
    $self->_response_done (undef);
  } elsif ($self->{state} eq 'end') {
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
  if (not defined $req or
      delete $req->{close_after_response}) {
    $self->{transport}->push_shutdown
        unless $self->{write_closed};
    $self->{write_closed} = 1;
    $self->{state} = 'end';
  }
  if (defined $req and defined $req->{res_done}) {
    $req->{res_done}->();
  }
} # _response_done

sub _done ($$) {
  my ($self, $req) = @_;
  if (delete $req->{close_after_response}) {
    $self->{transport}->push_shutdown
        unless $self->{write_closed};
    $self->{write_closed} = 1;
    $self->{state} = 'end';
  }
} # _done

sub _send_error ($$$$) {
  my ($self, $req, $status, $status_text) = @_;
  my $res = qq{<!DOCTYPE html><html>
<head><title>$status $status_text</title></head>
<body>$status $status_text};
  #$res .= Carp::longmess;
  $res .= qq{</body></html>\x0A};
  $req->send_response_headers
      ({status => $status, status_text => $status_text,
        headers => [
          ['Content-Type' => 'text/html; charset=utf-8'],
          ['Content-Length' => length $res],
        ]}, close => 1);
  $self->{transport}->push_write (\$res)
      unless $req->{method} eq 'HEAD';
} # _send_error

sub _fatal ($$) {
  my ($self, $req) = @_;
  $self->_request_done ($req);
  $self->{state} = 'end';
  $self->{rbuf} = '';
  $self->_send_error ($req, 400, 'Bad Request') unless $self->{write_closed};
  return $self->_response_done ($req);
} # _fatal

sub _411 ($$) {
  my ($self, $req) = @_;
  $self->_request_done ($req);
  $self->_send_error ($req, 411, 'Length Required')
      unless $self->{write_closed};
  return $self->_response_done ($req);
} # _411

sub _414 ($) {
  my ($self) = @_;
  my $req = bless {
    version => 1.1, method => 'GET', transport => $self->{transport},
  }, 'Hoge::Request';
  $self->_request_done ($req);
  $self->_send_error ($req, 414, 'Request-URI Too Large')
      unless $self->{write_closed};
  return $self->_response_done ($req);
} # _414

sub onrequest ($$) {
  my ($self, $req) = @_;
  if ($req->{target} =~ m{^/}) {
    #
  } elsif ($req->{target} =~ m{^[A-Za-z][A-Za-z0-9.+-]+://}) {
    #
  } else {
    return $self->_fatal ($req);
  }

    if ($req->{target} eq '/end') {
      $req->send_response_headers
          ({status => 200, status_text => 'OK', headers => []}); # XXX
      $self->{transport}->push_write (\qq{<html>200 Goodbye!\x0D\x0A\x0D\x0A</html>
});
      AE::postpone { exit };
    } elsif ($self->{write_closed}) {
      #
    } elsif ($req->{method} eq 'GET' or
             $req->{method} eq 'POST') {
      $req->send_response_headers
          ({status => 404, status_text => 'Not Found', headers => []}, close => 0); # XXX
      $self->{transport}->push_write (\qq{<html>...404 Not Found\x0D\x0A\x0D\x0A</html>
});
    } elsif ($req->{method} eq 'HEAD') {
      $req->send_response_headers
          ({status => 404, status_text => 'Not Found', headers => []}); # XXX
    } else {
      $req->send_response_headers
          ({status => 405, status_text => 'Not Allowed', headers => []}); # XXX
      $self->{transport}->push_write (\qq{<html>...405 Not Allowed (@{[$req->{method}]})</html>
});
    }

  $self->_response_done ($req);
} # onrequest

sub ondata ($$) {
  warn "Server received [[$_[1]]]";
} # ondata

sub onreof ($$) {
  warn "End of request";
} # onreof

sub DESTROY ($) {
  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

package Hoge::Request;

sub send_response_headers ($$$;%) {
  my ($req, $response, %args) = @_;
  # XXX validation
  if ($req->{version} == 0.9) {
    $req->{close_after_response} = 1;
  } else {
    my $res = sprintf qq{HTTP/1.1 %d %s\x0D\x0A},
        $response->{status},
        $response->{status_text};
    my @header;
    push @header, ['Server', 'Server/1'], ['Date', 'XXX'];
    if ($args{close} or $req->{close_after_response}) {
      push @header, ['Connection', 'close'];
      $req->{close_after_response} = 1;
    } elsif ($req->{version} == 1.0) {
      push @header, ['Connection', 'keep-alive'];
    }
    for (@header, @{$response->{headers}}) {
      $res .= "$_->[0]: $_->[1]\x0D\x0A";
    }
    $res .= "\x0D\x0A";
    $req->{transport}->push_write (\$res);
  }
  # XXX
  if ($req->{method} eq 'HEAD' or
      ($req->{method} eq 'CONNECT' and
       200 <= $response->{status} and $response->{status} < 300) or
      $response->{status} == 304 or
      (100 <= $response->{status} and $response->{status} < 200)) {

  } else {
    
  }
} # send_response_headers

sub DESTROY ($) {
  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

# XXX CONNECT
# XXX WS
