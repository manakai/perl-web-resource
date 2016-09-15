package Web::Transport::HTTPServerConnection;
use strict;
use warnings;
our $VERSION = '1.0';
use AnyEvent;
use Promise;
use Web::URL;
use Web::Transport::TCPTransport;

our $ReadTimeout ||= 60;

sub new_from_fh_and_host_and_port_and_cb ($$$$$) {
  my ($class, $fh, $client_host, $client_port, $cb) = @_;

  my $transport = Web::Transport::TCPTransport->new (fh => $fh);
  my $self = bless {transport => $transport,
                    rbuf => '', state => 'initial',
                    cb => $cb}, $class;
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
        delete $self->{cb};
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
} # new_from_...

sub _new_req ($) {
  my $self = $_[0];
  my $req = $self->{request} = bless {
    connection => $self, headers => [],
    # method target version
  }, __PACKAGE__ . '::Request';
  my $p1 = Promise->new (sub { $req->{req_done} = $_[0] });
  my $p2 = Promise->new (sub { $req->{res_done} = $_[0] });
  Promise->all ([$p1, $p2])->then (sub {
    $self->_done ($req, $_[0]->[0] || $_[0]->[1] || {});
  });
  return $req;
} # _new_req

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
        my $req = $self->_new_req;
        $line =~ s/\x0D\z//;
        if ($line =~ /[\x00\x0D]/) {
          $req->{version} = 0.9;
          $req->{method} = 'GET';
          return $self->_fatal ($req);
        }
        if ($line =~ s{\x20+(H[^\x20]*)\z}{}) {
          my $version = $1;
          if ($version =~ m{\AHTTP/1\.([0-9]+)\z}) {
            $req->{version} = $1 =~ /[^0]/ ? 1.1 : 1.0;
          } elsif ($version =~ m{\AHTTP/0+1?\.}) {
            $req->{version} = 0.9;
            $req->{method} = 'GET';
            return $self->_fatal ($req);
          } elsif ($version =~ m{\AHTTP/[0-9]+\.[0-9]+\z}) {
            $req->{version} = 1.1;
          } else {
            $req->{version} = 0.9;
            $req->{method} = 'GET';
            return $self->_fatal ($req);
          }
        } else { # no version
          $req->{version} = 0.9;
        }
        if ($line =~ s{\A([^\x20]+)\x20+}{}) {
          $req->{method} = $1;
        } else { # no method
          $req->{method} = 'GET';
          return $self->_fatal ($req);
        }
        $req->{target} = $line;
        if ($req->{version} == 0.9) {
          # XXX if $line is empty
          $req->{close_after_response} = 1;
          unless ($req->{method} eq 'GET') {
            $req->{method} = 'GET';
            return $self->_fatal ($req);
          }
          AE::postpone { $self->{cb}->($self, 'requestheaders', $req) };
        } else { # 1.0 / 1.1
          return $self->_fatal ($req) unless length $line;
          $self->{state} = 'before request header';
        }
      } elsif (8192 <= length $self->{rbuf}) {
        my $req = $self->_new_req;
        $req->{version} = 0.9;
        $req->{method} = 'GET';
        return $self->_414 ($req);
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
          my $req = $self->{request};
          my @length;
          my @host;
          my @con;
          for (@{$req->{headers}}) {
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
              return $self->_411 ($req);
            }
          } # headers

          ## Host:
          if (@host == 1) {
            my $url = Web::URL->parse_string ("https://$host[0]/");
            if (not defined $url or
                not $url->path eq '/' or
                defined $url->query or
                defined $url->{fragment}) { # XXX
              return $self->_fatal ($req);
            }
          } elsif (@host) { # multiple Host:
            return $self->_fatal ($req);
          } else { # no Host:
            if ($self->{request}->{version} == 1.1) {
              return $self->_fatal ($req);
            }
          }

          ## Connection:
          my $con = join ',', '', @con, '';
          $con =~ tr/A-Z/a-z/; ## ASCII case-insensitive.
          if ($con =~ /,[\x09\x20]*close[\x09\x20]*,/) {
            $req->{close_after_response} = 1;
          } elsif ($req->{version} == 1.0) {
            unless ($con =~ /,[\x09\x20]*keep-alive[\x09\x20]*,/) {
              $req->{close_after_response} = 1;
            }
          }

          ## Content-Length:
          if (@length == 1 and $length[0] =~ /\A[0-9]+\z/) {
            my $l = 0+$length[0];
            $req->{body_length} = $l;
            $self->{unread_length} = $l;
            AE::postpone {
              $self->{cb}->($self, 'requestheaders', $req);
              $self->{cb}->($self, 'datastart');
            };
            if ($l == 0) {
              AE::postpone { $self->{cb}->($self, 'dataend') };
              $self->_request_done ($req);
            } else {
              $self->{state} = 'request body';
            }
          } elsif (@length) {
            return $self->_fatal ($req);
          } else {
            AE::postpone { $self->{cb}->($self, 'requestheaders', $req) };
            $self->_request_done ($req);
          }
        } else { # broken line
          return $self->_fatal ($self->{request});
        }
      } elsif (8192 <= length $self->{rbuf}) {
        return $self->_fatal ($self->{request});
      } else {
        return;
      }
    } elsif ($self->{state} eq 'request body') {
      my $ref = $inref;
      if (length $self->{rbuf}) {
        $ref = \($self->{rbuf} . $$inref); # string copy!
        $self->{rbuf} = '';
      }
      my $in_length = length $$ref;
      if (not $in_length) {
        return;
      } elsif ($self->{unread_length} == $in_length) {
        AE::postpone {
          $self->{cb}->($self, 'data', $$ref);
          $self->{cb}->($self, 'dataend');
        };
        $self->_request_done ($self->{request});
      } elsif ($self->{unread_length} < $in_length) { # has redundant data
        $self->{request}->{incomplete} = 1;
        $self->{request}->{close_after_response} = 1;
        AE::postpone {
          $self->{cb}->($self, 'data', substr ($$ref, 0, $self->{unread_length}));
          $self->{cb}->($self, 'dataend');
        };
        $self->_request_done ($self->{request});
        return;
      } else { # unread_length > $in_length
        AE::postpone {
          $self->{cb}->($self, 'data', $$ref);
        };
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
    my $req = $self->_new_req;
    $req->{version} = 0.9;
    $req->{method} = 'GET';
    return $self->_fatal ($req);
  } elsif ($self->{state} eq 'before request header') {
    $self->{request}->{close_after_response} = 1;
    return $self->_fatal ($self->{request});
  } elsif ($self->{state} eq 'request body') {
    # $self->{unread_length} > 0
    $self->{request}->{close_after_response} = 1;
    $self->{request}->{incomplete} = 1;
    AE::postpone {
      $self->{cb}->($self, 'dataend');
    };
    $self->_request_done ($self->{request}, $exit->{failed} ? $exit : {failed => 1, message => "Connection closed"});
  } elsif ($self->{state} eq 'after request') {
    if (length $self->{rbuf}) {
      my $req = $self->_new_req;
      $req->{version} = 0.9;
      $req->{method} = 'GET';
      return $self->_fatal ($req);
    }

    $self->{transport}->push_shutdown
        unless $self->{write_closed};
    $self->{write_closed} = 1;
    $self->{state} = 'end';
  } elsif ($self->{state} eq 'end') {
    $self->{transport}->push_shutdown
        unless $self->{write_closed};
    $self->{write_closed} = 1;
  } else {
    die "Bad state |$self->{state}|";
  }
} # _oneof

sub _request_done ($$;$) {
  my ($self, $req, $exit) = @_;
  delete $self->{request};
  delete $self->{unread_length};
  if ($req->{close_after_response}) {
    $self->{state} = 'end';
  } else {
    $self->{state} = 'after request';
  }
  if (defined $req->{req_done}) {
    $req->{req_done}->($exit);
  }
} # _request_done

sub _done ($$$) {
  my ($self, $req, $exit) = @_;
  if (delete $req->{close_after_response}) {
    $self->{transport}->push_shutdown
        unless $self->{write_closed};
    $self->{write_closed} = 1;
    $self->{state} = 'end';
  }
  AE::postpone {
    $self->{cb}->($self, 'complete', $exit);
  };
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
  $req->_response_done;
} # _fatal

sub _411 ($$) {
  my ($self, $req) = @_;
  $self->_request_done ($req);
  $self->_send_error ($req, 411, 'Length Required')
      unless $self->{write_closed};
  $req->_response_done;
} # _411

sub _414 ($$) {
  my ($self, $req) = @_;
  $req->{version} = 1.1;
  $req->{method} = 'GET';
  $self->_request_done ($req);
  $self->_send_error ($req, 414, 'Request-URI Too Large')
      unless $self->{write_closed};
  $req->_response_done;
} # _414

sub DESTROY ($) {
  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

package Web::Transport::HTTPServerConnection::Request;
use Carp qw(croak);

sub send_response_headers ($$$;%) {
  my ($req, $response, %args) = @_;
  # XXX validation
  $req->{close_after_response} = 1 if $args{close} or $req->{version} == 0.9;
  my $done = 0;
  if ($req->{method} eq 'HEAD' or
      ($req->{method} eq 'CONNECT' and
       200 <= $response->{status} and $response->{status} < 300) or
      $response->{status} == 304 or
      (100 <= $response->{status} and $response->{status} < 200)) {
    ## No response body by definition
    $done = 1;
  } else {
    if (defined $args{content_length}) {
      ## If body length is specified
      $req->{write_mode} = 'raw';
      $req->{write_length} = 0+$args{content_length};
      $done = 1 if $req->{write_length} <= 0;

    ## Otherwise, if chunked encoding can be used
#XXX
    } else {
      ## Otherwise, end of the response is the termination of the connection
      $req->{close_after_response} = 1;
      $req->{write_mode} = 'raw';
    }
  }

  ## Response-line and response headers
  if ($req->{version} != 0.9) {
    my $res = sprintf qq{HTTP/1.1 %d %s\x0D\x0A},
        $response->{status},
        $response->{status_text};
    my @header;
    push @header, ['Server', 'Server/1'], ['Date', 'XXX'];
    if ($req->{close_after_response}) {
      push @header, ['Connection', 'close'];
    } elsif ($req->{version} == 1.0) {
      push @header, ['Connection', 'keep-alive'];
    }
    if (defined $req->{write_length}) {
      push @header, ['Content-Length', $req->{write_length}];
    }
    for (@header, @{$response->{headers}}) {
      $res .= "$_->[0]: $_->[1]\x0D\x0A";
    }
    $res .= "\x0D\x0A";
    $req->{connection}->{transport}->push_write (\$res);
  }

  $req->_response_done if $done;
} # send_response_headers

sub send_response_data ($$) {
  my ($req, $ref) = @_;
  # XXX error if utf8
  if (defined $req->{write_mode} and $req->{write_mode} eq 'raw') {
    if (defined $req->{write_length}) {
      if ($req->{write_length} >= length $$ref) {
        $req->{write_length} -= length $$ref;
      } else {
        croak sprintf "Data too long (given %d bytes whereas only %d bytes allowed)",
            length $$ref, $req->{write_length};
      }
    }
    $req->{connection}->{transport}->push_write ($ref);
    if (defined $req->{write_length} and $req->{write_length} <= 0) {
      $req->_response_done;
    }
  } else {
    croak "Not writable for now";
  }
} # send_response_data

# XXX close API

sub _response_done ($;$) {
  my ($req, $exit) = @_;
  if (defined $req->{connection}) {
    if (defined $req->{write_length} and
        $req->{write_length} > 0) {
      $req->{close_after_response} = 1;
    }
    if (delete $req->{close_after_response}) {
      $req->{connection}->{transport}->push_shutdown
          unless $req->{connection}->{write_closed};
      $req->{connection}->{write_closed} = 1;
      $req->{connection}->{state} = 'end';
    }
    if (defined $req->{res_done}) {
      (delete $req->{res_done})->($exit);
    }
    delete $req->{connection};
    delete $req->{write_mode};
    delete $req->{write_length};
  }
} # _response_done

sub DESTROY ($) {
  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

# XXX CONNECT
# XXX WS
# XXX leaking
# XXX reset
# XXX sketch/server.pl

1;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
