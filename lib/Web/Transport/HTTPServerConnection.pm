package Web::Transport::HTTPServerConnection;
use strict;
use warnings;
our $VERSION = '1.0';
use AnyEvent;
use Promise;
use Web::URL;
use Web::Transport::TCPTransport;

use constant DEBUG => $ENV{WEBSERVER_DEBUG} || 0;
our $ReadTimeout ||= 60;

sub new_from_fh_and_host_and_port_and_cb ($$$$$) {
  my ($class, $fh, $client_host, $client_port, $cb) = @_;

  my $transport = Web::Transport::TCPTransport->new (fh => $fh);
  my $self = bless {transport => $transport, id => $transport->id, req_id => 0,
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
    is_server => 1, DEBUG => DEBUG,
    connection => $self, headers => [],
    id => $self->{id} . '.' . ++$self->{req_id},
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
          my %headers;
          for (@{$req->{headers}}) {
            $_->[1] =~ s/[\x09\x20]+\z//;
            my $n = $_->[0];
            $n =~ tr/A-Z/a-z/; ## ASCII case-insensitive
            $_->[2] = $n;
            push @{$headers{$n} ||= []}, $_->[1];
          } # headers

          # XXX check request-target

          ## Host:
          if (@{$headers{host} or []} == 1) {
            my $url = Web::URL->parse_string ("https://$headers{host}->[0]/");
            if (not defined $url or
                not $url->path eq '/' or
                defined $url->query or
                defined $url->{fragment}) { # XXX
              return $self->_fatal ($req);
            }
          } elsif (@{$headers{host} or []}) { # multiple Host:
            return $self->_fatal ($req);
          } else { # no Host:
            if ($self->{request}->{version} == 1.1) {
              return $self->_fatal ($req);
            }
          }
          # XXX Host: == request_url->hostport

          ## Connection:
          my $con = join ',', '', @{$headers{connection} or []}, '';
          $con =~ tr/A-Z/a-z/; ## ASCII case-insensitive.
          if ($con =~ /,[\x09\x20]*close[\x09\x20]*,/) {
            $req->{close_after_response} = 1;
          } elsif ($req->{version} == 1.0) {
            unless ($con =~ /,[\x09\x20]*keep-alive[\x09\x20]*,/) {
              $req->{close_after_response} = 1;
            }
          }

          ## Upgrade: websocket
          if (@{$headers{upgrade} or []} == 1) {
            WS_OK: {
              my $status = 400;
              WS_CHECK: {
                last WS_CHECK unless $req->{method} eq 'GET';
                last WS_CHECK unless $req->{version} == 1.1;
                # XXX request-url->scheme eq 'http' or 'https'
                my $upgrade = $headers{upgrade}->[0];
                $upgrade =~ tr/A-Z/a-z/; ## ASCII case-insensitive;
                last WS_CHECK unless $upgrade eq 'websocket';
                last WS_CHECK unless $con =~ /,[\x09\x20]*upgrade[\x09\x20]*,/;

                last WS_CHECK unless @{$headers{'sec-websocket-key'} or []} == 1;
                $req->{ws_key} = $headers{'sec-websocket-key'}->[0];
                ## 16 bytes (unencoded) = 3*5+1 = 4*5+4 (encoded)
                last WS_CHECK unless $req->{ws_key} =~ m{\A[A-Za-z0-9+/]{22}==\z};

                last WS_CHECK unless @{$headers{'sec-websocket-version'} or []} == 1;
                my $ver = $headers{'sec-websocket-version'}->[0];
                unless ($ver eq '13') {
                  $status = 426;
                  last WS_CHECK;
                }

                $self->{ws_protos} = [grep { length $_ } split /[\x09\x20]*,[\x09\x20]*/, join ',', '', @{$headers{'sec-websocket-protocol'} or []}, ''];

                # XXX
                #my $exts = [grep { length $_ } split /[\x09\x20]*,[\x09\x20]*/, join ',', '', @{$headers{'sec-websocket-extensions'} or []}, ''];

                last WS_OK;
              } # WS_CHECK

              if ($status == 426) {
                return $self->_426 ($req);
              } else {
                return $self->_fatal ($req);
              }
            } # WS_OK
          } elsif (@{$headers{upgrade} or []}) {
            return $self->_fatal ($req);
          }

          ## Transfer-Encoding:
          if (@{$headers{'transfer-encoding'} or []}) {
            return $self->_411 ($req);
          }

          ## Content-Length:
          if (@{$headers{'content-length'} or []} == 1 and
              $headers{'content-length'}->[0] =~ /\A[0-9]+\z/) {
            my $l = 0+$headers{'content-length'}->[0];
            if ($req->{method} eq 'CONNECT') {
              AE::postpone {
                $self->{cb}->($self, 'requestheaders', $req);
                $self->{cb}->($self, 'datastart');
              };
              $self->{state} = 'request body';
            } elsif ($l == 0) {
              AE::postpone {
                $self->{cb}->($self, 'requestheaders', $req);
                $self->{cb}->($self, 'datastart');
                $self->{cb}->($self, 'dataend');
              };
              if (defined $req->{ws_key}) {
                $self->{state} = 'ws handshaking';
                $self->{request}->{close_after_response} = 1;
              } else {
                $self->_request_done ($req);
              }
            } else {
              AE::postpone {
                $self->{cb}->($self, 'requestheaders', $req);
                $self->{cb}->($self, 'datastart');
              };
              $req->{body_length} = $l;
              $self->{unread_length} = $l;
              $self->{state} = 'request body';
            }
          } elsif (@{$headers{'content-length'} or []}) {
            return $self->_fatal ($req);
          } else {
            if ($req->{method} eq 'CONNECT') {
              AE::postpone {
                $self->{cb}->($self, 'requestheaders', $req);
                $self->{cb}->($self, 'datastart');
              };
              $self->{state} = 'request body';
            } elsif (defined $req->{ws_key}) {
              AE::postpone { $self->{cb}->($self, 'requestheaders', $req) };
              $self->{state} = 'ws handshaking';
              $self->{request}->{close_after_response} = 1;
            } else {
              AE::postpone { $self->{cb}->($self, 'requestheaders', $req) };
              $self->_request_done ($req);
            }
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

      if (not defined $self->{unread_length}) { # CONNECT data
        AE::postpone {
          $self->{cb}->($self, 'data', $self->{request}, $$ref);
        };
        return;
      }

      my $in_length = length $$ref;
      if (not $in_length) {
        return;
      } elsif ($self->{unread_length} == $in_length) {
        AE::postpone {
          $self->{cb}->($self, 'data', $self->{request}, $$ref);
          $self->{cb}->($self, 'dataend');
        };
        if (defined $self->{request}->{ws_key}) {
          $self->{state} = 'ws handshaking';
          $self->{request}->{close_after_response} = 1;
        } else {
          $self->_request_done ($self->{request});
        }
      } elsif ($self->{unread_length} < $in_length) { # has redundant data
        $self->{request}->{incomplete} = 1;
        $self->{request}->{close_after_response} = 1;
        AE::postpone {
          $self->{cb}->($self, 'data', $self->{request}, substr ($$ref, 0, $self->{unread_length}));
          $self->{cb}->($self, 'dataend');
        };
        if (defined $self->{request}->{ws_key}) {
          $self->{state} = 'ws handshaking';
          $self->{request}->{close_after_response} = 1;
        } else {
          $self->_request_done ($self->{request});
        }
        return;
      } else { # unread_length > $in_length
        AE::postpone {
          $self->{cb}->($self, 'data', $self->{request}, $$ref);
        };
        $self->{unread_length} -= $in_length;
        return;
      }
    } elsif ($self->{state} eq 'ws') {
      return $self->{request}->_ws_received ($inref);
    } elsif ($self->{state} eq 'ws handshaking') {
      return unless length $$inref;
      return $self->_fatal ($self->{request});
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
    $self->{request}->{close_after_response} = 1;
    if (defined $self->{unread_length}) {
      # $self->{unread_length} > 0
      $self->{request}->{incomplete} = 1;
      $exit = {failed => 1, message => 'Connection closed'}
          unless $exit->{failed};
    }
    AE::postpone { $self->{cb}->($self, 'dataend') };
    $self->_request_done ($self->{request}, $exit);
  } elsif ($self->{state} eq 'ws') {
    $self->{request}->{exit} = $exit; # XXX
    return $self->{request}->_ws_received_eof (\'');
  } elsif ($self->{state} eq 'ws handshaking') {
    return $self->_fatal ($self->{request});
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
    $self->{cb}->($self, 'complete', $exit)

if $self->{cb}  # XXX
;
  };
} # _done

sub _send_error ($$$$;$) {
  my ($self, $req, $status, $status_text, $headers) = @_;
  my $res = qq{<!DOCTYPE html><html>
<head><title>$status $status_text</title></head>
<body>$status $status_text};
  #$res .= Carp::longmess;
  $res .= qq{</body></html>\x0A};
  $req->send_response_headers
      ({status => $status, status_text => $status_text,
        headers => [
          @{$headers or []},
          ['Content-Type' => 'text/html; charset=utf-8'],
        ]}, close => 1, content_length => length $res);
  $req->send_response_data (\$res) unless $req->{method} eq 'HEAD';
} # _send_error

sub _fatal ($$) {
  my ($self, $req) = @_;
  $self->_request_done ($req);
  $self->{state} = 'end';
  $self->{rbuf} = '';
  $self->_send_error ($req, 400, 'Bad Request') unless $self->{write_closed};
  $req->close_response;
} # _fatal

sub _411 ($$) {
  my ($self, $req) = @_;
  $self->_request_done ($req);
  $self->_send_error ($req, 411, 'Length Required')
      unless $self->{write_closed};
  $req->close_response;
} # _411

sub _414 ($$) {
  my ($self, $req) = @_;
  $req->{version} = 1.1;
  $req->{method} = 'GET';
  $self->_request_done ($req);
  $self->_send_error ($req, 414, 'Request-URI Too Large')
      unless $self->{write_closed};
  $req->close_response;
} # _414

sub _426 ($$) {
  my ($self, $req) = @_;
  $self->_request_done ($req);
  $self->_send_error ($req, 426, 'Upgrade Required', [
    ['Upgrade', 'websocket'],
    ['Sec-WebSocket-Version', '13'],
  ]) unless $self->{write_closed};
  $req->close_response;
} # _426

sub DESTROY ($) {
  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

package Web::Transport::HTTPServerConnection::Request;
use Web::Transport::HTTPStream;
push our @ISA, qw(Web::Transport::HTTPStream);
use Carp qw(carp croak);
use Digest::SHA qw(sha1);
use MIME::Base64 qw(encode_base64);

sub send_response_headers ($$$;%) {
  my ($req, $response, %args) = @_;
  # XXX validation
  $req->{close_after_response} = 1 if $args{close} or $req->{version} == 0.9;
  my $done = 0;
  my $connect = 0;
  my $ws = 0;
  if ($req->{method} eq 'HEAD' or
      $response->{status} == 304) {
    ## No response body by definition
    if (defined $args{content_length}) {
      $req->{to_be_sent_length} = 0+$args{content_length};
    }
    $done = 1;
  } elsif ($req->{method} eq 'CONNECT' and
           200 <= $response->{status} and $response->{status} < 300) {
    ## No response body by definition but switched to the tunnel mode
    croak "|content_length| not allowed" if defined $args{content_length};
    $req->{write_mode} = 'raw';
    $connect = 1;
  } elsif (100 <= $response->{status} and $response->{status} < 200) {
    ## No response body by definition
    croak "|content_length| not allowed" if defined $args{content_length};
    if (defined $req->{ws_key} and $response->{status} == 101) {
      $ws = 1;
      $req->{write_mode} = 'ws';
      $req->{ws_state} = 'OPEN';
      $req->{connection}->{state} = 'ws';
      $req->{state} = 'before ws frame';
    } else {
      croak "1xx response not supported";
    }
  } else {
    if (defined $args{content_length}) {
      ## If body length is specified
      $req->{write_mode} = 'raw';
      $req->{to_be_sent_length} = 0+$args{content_length};
      $done = 1 if $req->{to_be_sent_length} <= 0;
    } elsif ($req->{version} == 1.1) {
      ## Otherwise, if chunked encoding can be used
      $req->{write_mode} = 'chunked';
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
    if ($ws) {
      push @header,
          ['Upgrade', 'websocket'],
          ['Connection', 'Upgrade'],
          ['Sec-WebSocket-Accept', encode_base64 sha1 ($req->{ws_key} . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'), ''];
      # XXX Sec-WebSocket-Protocol
      # XXX Sec-WebSocket-Extensions
    } else {
      if ($req->{close_after_response} and not $connect) {
        push @header, ['Connection', 'close'];
      } elsif ($req->{version} == 1.0) {
        push @header, ['Connection', 'keep-alive'];
      }
      if (defined $req->{write_mode} and $req->{write_mode} eq 'chunked') {
        push @header, ['Transfer-Encoding', 'chunked'];
      }
      if (defined $req->{to_be_sent_length}) {
        push @header, ['Content-Length', $req->{to_be_sent_length}];
      }
    }
    for (@header, @{$response->{headers}}) {
      $res .= "$_->[0]: $_->[1]\x0D\x0A";
    }
    $res .= "\x0D\x0A";
    $req->{connection}->{transport}->push_write (\$res);
  }

  if ($done) {
    delete $req->{to_be_sent_length};
    $req->close_response;
  }
} # send_response_headers

sub send_response_data ($$) {
  my ($req, $ref) = @_;
  croak "Data is utf8-flagged" if utf8::is_utf8 $$ref;
  my $wm = $req->{write_mode} || '';
  if ($wm eq 'chunked') {
    if (length $$ref) {
      $req->{connection}->{transport}->push_write (\sprintf "%X\x0D\x0A", length $$ref);
      $req->{connection}->{transport}->push_write ($ref);
      $req->{connection}->{transport}->push_write (\"\x0A");
    }
  } elsif ($wm eq 'raw' or $wm eq 'ws') {
    croak "Not writable for now"
        if $wm eq 'ws' and
            (not $req->{ws_state} eq 'OPEN' or
             not defined $req->{to_be_sent_length} or
             $req->{to_be_sent_length} <= 0);
    if (defined $req->{to_be_sent_length}) {
      if ($req->{to_be_sent_length} >= length $$ref) {
        $req->{to_be_sent_length} -= length $$ref;
      } else {
        croak sprintf "Data too long (given %d bytes whereas only %d bytes allowed)",
            length $$ref, $req->{to_be_sent_length};
      }
    }
    $req->{connection}->{transport}->push_write ($ref);
    if ($wm eq 'raw' and
        defined $req->{to_be_sent_length} and $req->{to_be_sent_length} <= 0) {
      $req->close_response;
    }
  } else {
    croak "Not writable for now";
  }
} # send_response_data

# XXX rename as close?
sub close_response ($;%) {
  my ($req, %args) = @_;
  return unless defined $req->{connection};
  if (defined $req->{to_be_sent_length} and $req->{to_be_sent_length} > 0) {
    carp sprintf "Truncated end of sent data (%d more bytes expected)",
        $req->{to_be_sent_length};
    $req->{close_after_response} = 1;
    $req->_next;
  } else {
    $req->{close_after_response} = 1 if $req->{method} eq 'CONNECT';
    if (defined $req->{write_mode} and $req->{write_mode} eq 'chunked') {
      # XXX trailer headers
      $req->{connection}->{transport}->push_write (\"0\x0D\x0A\x0D\x0A");
      $req->_next;
    } elsif (defined $req->{write_mode} and $req->{write_mode} eq 'ws') {
      $req->close (%args);
    } else {
      $req->_next;
    }
  }
} # close_response

sub _next ($) {
  my $req = $_[0];
  if (delete $req->{close_after_response}) {
    $req->{connection}->{transport}->push_shutdown
        unless $req->{connection}->{write_closed};
    $req->{connection}->{write_closed} = 1;
  }
  if (defined $req->{res_done}) {
    (delete $req->{res_done})->({});
  }
  delete $req->{connection};
  delete $req->{write_mode};
  delete $req->{to_be_sent_length};
} # _next

BEGIN {
  *_e4d = \&Web::Transport::HTTPStream::_e4d;
  *_e4d_t = \&Web::Transport::HTTPStream::_e4d_t;
}

sub _ev ($$;$$) {
  my $self = shift;
  my $req = $self; #XXX
  if ($self->{DEBUG}) {
    warn "$req->{id}: $_[0] @{[scalar gmtime]}\n";
    if ($_[0] eq 'data' and $self->{DEBUG} > 1) {
      for (split /\x0D?\x0A/, $_[1], -1) {
        warn "$req->{id}: R: @{[_e4d $_]}\n";
      }
    } elsif ($_[0] eq 'text' and $self->{DEBUG} > 1) {
      for (split /\x0D?\x0A/, $_[1], -1) {
        warn "$req->{id}: R: @{[_e4d_t $_]}\n";
      }
    } elsif ($_[0] eq 'headers') {
      if ($_[1]->{version} eq '0.9') {
        warn "$req->{id}: R: HTTP/0.9\n";
      } else {
        warn "$req->{id}: R: HTTP/$_[1]->{version} $_[1]->{status} $_[1]->{reason}\n";
        for (@{$_[1]->{headers}}) {
          warn "$req->{id}: R: @{[_e4d $_->[0]]}: @{[_e4d $_->[1]]}\n";
        }
      }
      warn "$req->{id}: + WS established\n" if $self->{DEBUG} and $_[2];
    } elsif ($_[0] eq 'complete') {
      my $err = join ' ',
          $_[1]->{reset} ? 'reset' : (),
          $self->{response}->{incomplete} ? 'incomplete' : (),
          $_[1]->{failed} ? 'failed' : (),
          $_[1]->{cleanly} ? 'cleanly' : (),
          $_[1]->{can_retry} ? 'retryable' : (),
          defined $_[1]->{errno} ? 'errno=' . $_[1]->{errno} : (),
          defined $_[1]->{message} ? 'message=' . $_[1]->{message} : (),
          defined $_[1]->{status} ? 'status=' . $_[1]->{status} : (),
          defined $_[1]->{reason} ? 'reason=' . $_[1]->{reason} : ();
      warn "$req->{id}: + @{[_e4d $err]}\n" if length $err;
    } elsif ($_[0] eq 'ping') {
      if ($_[2]) {
        warn "$req->{id}: R: pong data=@{[_e4d $_[1]]}\n";
      } else {
        warn "$req->{id}: R: data=@{[_e4d $_[1]]}\n";
      }
    }
  }
  if ($_[0] eq 'complete') {
    #XXX (delete $self->{request_done})->();
  }
  # XXX
  my $type = shift @_;
  $self->{connection}->{cb}->($self, $type, $req, @_)
      if defined $self->{connection};
} # _ev

sub DESTROY ($) {
  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

# XXX leaking
# XXX reset
# XXX sketch/server.pl

1;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
