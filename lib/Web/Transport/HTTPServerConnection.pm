package Web::Transport::HTTPServerConnection;
use strict;
use warnings;
our $VERSION = '1.0';
use Web::Transport::HTTPConnection;
push our @ISA, qw(Web::Transport::HTTPConnection);
use AnyEvent;
use Promise;
use Promised::Flow;
use Web::Host;
use Web::URL;

use constant DEBUG => $ENV{WEBSERVER_DEBUG} || 0;
our $ReadTimeout ||= 60;

BEGIN {
  *_e4d = \&Web::Transport::HTTPConnection::Stream::_e4d;
  *_e4d_t = \&Web::Transport::HTTPConnection::Stream::_e4d_t;
}

sub new ($%) {
  my ($class, %args) = @_;
  my $self = bless {DEBUG => DEBUG, is_server => 1,
                    id => $args{transport}->id, req_id => 0,
                    transport => $args{transport},
                    rbuf => '', state => 'initial',
                    con_cb => $args{cb}}, $class;
  my $closed;
  my $close_p = Promise->new (sub { $closed = $_[0] });
  $self->{closed} = promised_cleanup {
    delete $self->{timer};
  } $args{transport}->start (sub {
    my ($transport, $type) = @_;
    if ($type eq 'readdata') {
      if ($self->{disable_timer}) {
        delete $self->{timer};
      } else {
        $self->{timer} = AE::timer $ReadTimeout, 0, sub { $self->_timeout };
      }
      $self->_ondata ($_[2]);
    } elsif ($type eq 'readeof') {
      my $data = $_[2];
      if (DEBUG) {
        my $id = $transport->id;
        if (defined $data->{message}) {
          warn "$id: R: EOF (@{[_e4d_t $data->{message}]})\n";
        } else {
          warn "$id: R: EOF\n";
        }
      }
      delete $self->{timer};
      $self->{write_closed} = 1;
      $self->_oneof ($data);
    } elsif ($type eq 'writeeof') {
      if (DEBUG) {
        my $data = $_[2];
        my $id = $transport->id;
        if (defined $data->{message}) {
          warn "$id: S: EOF (@{[_e4d_t $data->{message}]})\n";
        } else {
          warn "$id: S: EOF\n";
        }
      }
      $self->{write_closed} = 1;
    } elsif ($type eq 'close') {
      $closed->();
    }
  })->then (sub {
    $self->{timer} = AE::timer $ReadTimeout, 0, sub { $self->_timeout };
    $self->{info} = {};
    $self->_con_ev ('openconnection', {});
    return $close_p;
  }, sub {
    my $error = $_[0];
    if (ref $error eq 'HASH' and $error->{failed}) {
      $self->{info} = {};
      $self->_con_ev ('openconnection', $error);
      $self->{exit} = $error->{exit};
    } else {
      die $error;
    }
  })->then (sub {
    $self->_con_ev ('closeconnection', $self->{exit} || {});
  });
  return $self;
} # new

sub server_header ($;$) {
  if (@_ > 1) {
    $_[0]->{server_header} = $_[1];
  }
  return defined $_[0]->{server_header} ? $_[0]->{server_header} : 'Server';
} # server_header

sub _url_scheme ($) {
  my $self = $_[0];
  my $transport = $self->{transport};
  if ($transport->type eq 'TLS') {
    return 'https';
  } else { # TCP or UNIXDomainSocket
    return 'http';
  }
} # _url_scheme

sub _url_hostport ($) {
  my $self = $_[0];
  my $transport = $self->{transport};
  if ($transport->type eq 'TLS') {
    $transport = $transport->{transport};
  }
  if ($transport->type eq 'TCP') {
    return $transport->info->{local_host}->to_ascii . ':' . $transport->{info}->{local_port};
  } else { # UNIXDomainSocket
    return '0.0.0.0';
  }
} # _url_hostport

sub _new_stream ($) {
  my $self = $_[0];
  my $req = $self->{stream} = bless {
    is_server => 1, DEBUG => DEBUG,
    connection => $self,
    id => $self->{id} . '.' . ++$self->{req_id},
    request => {
      headers => [],
      # method target_url version
    },
    # cb target
  }, __PACKAGE__ . '::Stream';
  $req->{cb} = $self->_con_ev ('startstream', $req);
  return $req;
} # _new_stream

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
        my $stream = $self->_new_stream;
        $line =~ s/\x0D\z//;
        if ($line =~ /[\x00\x0D]/) {
          $stream->{request}->{version} = 0.9;
          $stream->{request}->{method} = 'GET';
          return $stream->_fatal;
        }
        if ($line =~ s{\x20+(H[^\x20]*)\z}{}) {
          my $version = $1;
          if ($version =~ m{\AHTTP/1\.([0-9]+)\z}) {
            $stream->{request}->{version} = $1 =~ /[^0]/ ? 1.1 : 1.0;
          } elsif ($version =~ m{\AHTTP/0+1?\.}) {
            $stream->{request}->{version} = 0.9;
            $stream->{request}->{method} = 'GET';
            return $stream->_fatal;
          } elsif ($version =~ m{\AHTTP/[0-9]+\.[0-9]+\z}) {
            $stream->{request}->{version} = 1.1;
          } else {
            $stream->{request}->{version} = 0.9;
            $stream->{request}->{method} = 'GET';
            return $stream->_fatal;
          }
          if ($line =~ s{\A([^\x20]+)\x20+}{}) {
            $stream->{request}->{method} = $1;
          } else { # no method
            $stream->{request}->{method} = 'GET';
            return $stream->_fatal;
          }
        } else { # no version
          $stream->{request}->{version} = 0.9;
          $stream->{request}->{method} = 'GET';
          unless ($line =~ s{\AGET\x20+}{}) {
            return $stream->_fatal;
          }
        }
        $stream->{target} = $line;
        if ($stream->{target} =~ m{\A/}) {
          if ($stream->{request}->{method} eq 'CONNECT') {
            return $stream->_fatal;
          } else {
            #
          }
        } elsif ($stream->{target} =~ m{^[A-Za-z][A-Za-z0-9.+-]+://}) {
          if ($stream->{request}->{method} eq 'CONNECT') {
            return $stream->_fatal;
          } else {
            #
          }
        } else {
          if ($stream->{request}->{method} eq 'OPTIONS' and
              $stream->{target} eq '*') {
            #
          } elsif ($stream->{request}->{method} eq 'CONNECT' and
                   length $stream->{target}) {
            #
          } else {
            return $stream->_fatal;
          }
        }
        if ($stream->{request}->{version} == 0.9) {
          $self->_request_headers or return;
        } else { # 1.0 / 1.1
          return $stream->_fatal unless length $line;
          $self->{state} = 'before request header';
        }
      } elsif (8192 <= length $self->{rbuf}) {
        my $stream = $self->_new_stream;
        $stream->{request}->{method} = 'GET';
        $stream->{request}->{version} = 1.1;
        $stream->_receive_done;
        $stream->_send_error (414, 'Request-URI Too Large')
            unless $self->{write_closed};
        $stream->close_response;
        return;
      } else {
        return;
      }
    } elsif ($self->{state} eq 'before request header') {
      my $stream = $self->{stream};
      $self->{rbuf} .= $$inref;
      if ($self->{rbuf} =~ s/\A([^\x0A]{0,8191})\x0A//) {
        my $line = $1;
        return $stream->_fatal
            if @{$stream->{request}->{headers}} == 100;
        $line =~ s/\x0D\z//;
        return $stream->_fatal
            if $line =~ /[\x00\x0D]/;
        if ($line =~ s/\A([^\x09\x20:][^:]*):[\x09\x20]*//) {
          my $name = $1;
          push @{$stream->{request}->{headers}}, [$name, $line];
        } elsif ($line =~ s/\A[\x09\x20]+// and
                 @{$stream->{request}->{headers}}) {
          if ((length $stream->{request}->{headers}->[-1]->[0]) + 1 +
              (length $stream->{request}->{headers}->[-1]->[1]) + 1 +
              (length $line) + 2 > 8192) {
            return $stream->_fatal;
          } else {
            $stream->{request}->{headers}->[-1]->[1] .= " " . $line;
          }
        } elsif ($line eq '') { # end of headers
          $self->_request_headers or return;
        } else { # broken line
          return $stream->_fatal;
        }
      } elsif (8192 <= length $self->{rbuf}) {
        return $stream->_fatal;
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
        $self->{stream}->_ev ('data', $$ref);
        return;
      }

      my $in_length = length $$ref;
      if (not $in_length) {
        return;
      } elsif ($self->{unread_length} == $in_length) {
        if (defined $self->{stream}->{ws_key}) {
          $self->{state} = 'ws handshaking';
          $self->{stream}->{close_after_response} = 1;
        }
        $self->{stream}->_ev ('data', $$ref);
        $self->{stream}->_ev ('dataend');
        unless (defined $self->{stream}->{ws_key}) {
          $self->{stream}->_receive_done;
        }
      } elsif ($self->{unread_length} < $in_length) { # has redundant data
        $self->{stream}->{incomplete} = 1;
        $self->{stream}->{close_after_response} = 1;
        if (defined $self->{stream}->{ws_key}) {
          $self->{state} = 'ws handshaking';
        }
        $self->{stream}->_ev ('data', substr ($$ref, 0, $self->{unread_length}));
        $self->{stream}->_ev ('dataend');
        unless (defined $self->{stream}->{ws_key}) {
          $self->{stream}->_receive_done;
        }
        return;
      } else { # unread_length > $in_length
        $self->{unread_length} -= $in_length;
        $self->{stream}->_ev ('data', $$ref);
        return;
      }
    } elsif ($self->{state} eq 'before ws frame' or
             $self->{state} eq 'ws data' or
             $self->{state} eq 'ws terminating') {
      return $self->_ws_received ($inref);
    } elsif ($self->{state} eq 'ws handshaking') {
      return unless length $$inref;
      return $self->{stream}->_fatal;
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
    if ($self->{write_closed}) {
      delete $self->{timer};
      $self->{state} = 'end';
      return;
    } else {
      my $stream = $self->_new_stream;
      $stream->{request}->{version} = 0.9;
      $stream->{request}->{method} = 'GET';
      return $stream->_fatal;
    }
  } elsif ($self->{state} eq 'before request header') {
    $self->{stream}->{close_after_response} = 1;
    return $self->{stream}->_fatal;
  } elsif ($self->{state} eq 'request body') {
    $self->{stream}->{close_after_response} = 1;
    if (defined $self->{unread_length}) {
      # $self->{unread_length} > 0
      $self->{stream}->{incomplete} = 1;
      $exit = {failed => 1, message => 'Connection closed'}
          unless $exit->{failed};
    }
    $self->{stream}->_ev ('dataend');
    $self->{exit} = $exit;
    $self->{stream}->_receive_done ($exit);
  } elsif ($self->{state} eq 'before ws frame' or
           $self->{state} eq 'ws data' or
           $self->{state} eq 'ws terminating') {
    $self->{exit} = $exit;
    return $self->_ws_received_eof (\'');
  } elsif ($self->{state} eq 'ws handshaking') {
    return $self->{stream}->_fatal;
  } elsif ($self->{state} eq 'after request') {
    if (length $self->{rbuf}) {
      my $stream = $self->_new_stream;
      $stream->{request}->{version} = 0.9;
      $stream->{request}->{method} = 'GET';
      return $stream->_fatal;
    } else {
      $self->{transport}->push_shutdown unless $self->{write_closed};
      $self->{write_closed} = 1;
      $self->{state} = 'end';
    }
  } elsif ($self->{state} eq 'end') {
    $self->{transport}->push_shutdown unless $self->{write_closed};
    $self->{write_closed} = 1;
  } else {
    die "Bad state |$self->{state}|";
  }
} # _oneof

sub _request_headers ($) {
  my $self = $_[0];
  my $stream = $self->{stream};

  my %headers;
  for (@{$stream->{request}->{headers}}) {
    $_->[1] =~ s/[\x09\x20]+\z//;
    my $n = $_->[0];
    $n =~ tr/A-Z/a-z/; ## ASCII case-insensitive
    $_->[2] = $n;
    push @{$headers{$n} ||= []}, $_->[1];
  } # headers

  ## Host:
  my $host;
  if (@{$headers{host} or []} == 1) {
    $host = $headers{host}->[0];
    $host =~ s/([\x80-\xFF])/sprintf '%%%02X', ord $1/ge;
  } elsif (@{$headers{host} or []}) { # multiple Host:
    $stream->_fatal;
    return 0;
  } else { # no Host:
    if ($stream->{request}->{version} == 1.1) {
      $stream->_fatal;
      return 0;
    }
  }

  ## Request-target and Host:
  my $target_url;
  my $host_url;
  if ($stream->{request}->{method} eq 'CONNECT') {
    if (defined $host) {
      $host_url = Web::URL->parse_string ("http://$host/");
      if (not defined $host_url or
          not $host_url->path eq '/' or
          defined $host_url->query or
          defined $host_url->{fragment}) { # XXX
        $stream->_fatal;
        return 0;
      }
    }

    my $target = delete $stream->{target};
    $target =~ s/([\x80-\xFF])/sprintf '%%%02X', ord $1/ge;
    $target_url = Web::URL->parse_string ("http://$target/");
    if (not defined $target_url or
        not $target_url->path eq '/' or
        defined $target_url->query or
        defined $target_url->{fragment}) { # XXX
      $stream->_fatal;
      return 0;
    }
  } elsif ($stream->{target} eq '*') {
    if (defined $host) {
      my $scheme = $stream->{connection}->_url_scheme;
      $host_url = Web::URL->parse_string ("$scheme://$host/");
      if (not defined $host_url or
          not $host_url->path eq '/' or
          defined $host_url->query or
          defined $host_url->{fragment}) { # XXX
        $stream->_fatal;
        return 0;
      }
      $target_url = $host_url;
      delete $stream->{target};
    } else {
      $stream->_fatal;
      return 0;
    }
  } elsif ($stream->{target} =~ m{\A/}) {
    if (defined $host) {
      my $scheme = $stream->{connection}->_url_scheme;
      $host_url = Web::URL->parse_string ("$scheme://$host/");
      if (not defined $host_url or
          not $host_url->path eq '/' or
          defined $host_url->query or
          defined $host_url->{fragment}) { # XXX
        $stream->_fatal;
        return 0;
      }
    }

    my $target = delete $stream->{target};
    $target =~ s/([\x80-\xFF])/sprintf '%%%02X', ord $1/ge;
    if (defined $host_url) {
      $target_url = Web::URL->parse_string ($host_url->get_origin->to_ascii . $target);
    } else {
      my $scheme = $stream->{connection}->_url_scheme;
      my $hostport = $stream->{connection}->_url_hostport;
      $target_url = Web::URL->parse_string ("$scheme://$hostport" . $target);
    }
    if (not defined $target_url or
        not defined $target_url->host) {
      $stream->_fatal;
      return 0;
    }
  } else { # absolute URL
    my $target = delete $stream->{target};
    $target =~ s/([\x80-\xFF])/sprintf '%%%02X', ord $1/ge;
    $target_url = Web::URL->parse_string ($target);
    if (not defined $target_url or
        not defined $target_url->host) {
      $stream->_fatal;
      return 0;
    }

    if (defined $host) {
      my $scheme = $target_url->scheme;
      $host_url = Web::URL->parse_string ("$scheme://$host/");
      if (not defined $host_url or
          not $host_url->path eq '/' or
          defined $host_url->query or
          defined $host_url->{fragment}) { # XXX
        $stream->_fatal;
        return 0;
      }
    }
  }
  if (defined $host_url and defined $target_url) {
    unless ($host_url->host->equals ($target_url->host)) {
      $stream->_fatal;
      return 0;
    }
    my $host_port = $host_url->port;
    my $target_port = $target_url->port;
    if (defined $host_port and
        defined $target_port and
        $host_port eq $target_port) {
      #
    } elsif (not defined $host_port and not defined $target_port) {
      #
    } else {
      $stream->_fatal;
      return 0;
    }
  }
  # XXX SNI host
  $stream->{request}->{target_url} = $target_url;

  ## Connection:
  my $con = join ',', '', @{$headers{connection} or []}, '';
  $con =~ tr/A-Z/a-z/; ## ASCII case-insensitive.
  if ($con =~ /,[\x09\x20]*close[\x09\x20]*,/) {
    $stream->{close_after_response} = 1;
  } elsif ($stream->{request}->{version} != 1.1) {
    unless ($con =~ /,[\x09\x20]*keep-alive[\x09\x20]*,/) {
      $stream->{close_after_response} = 1;
    }
  }

  ## Upgrade: websocket
  if (@{$headers{upgrade} or []} == 1) {
    WS_OK: {
      my $status = 400;
      WS_CHECK: {
        last WS_CHECK unless $stream->{request}->{method} eq 'GET';
        last WS_CHECK unless $stream->{request}->{version} == 1.1;
        # XXX request-url->scheme eq 'http' or 'https'
        my $upgrade = $headers{upgrade}->[0];
        $upgrade =~ tr/A-Z/a-z/; ## ASCII case-insensitive;
        last WS_CHECK unless $upgrade eq 'websocket';
        last WS_CHECK unless $con =~ /,[\x09\x20]*upgrade[\x09\x20]*,/;

        last WS_CHECK unless @{$headers{'sec-websocket-key'} or []} == 1;
        $stream->{ws_key} = $headers{'sec-websocket-key'}->[0];
        ## 16 bytes (unencoded) = 3*5+1 = 4*5+4 (encoded)
        last WS_CHECK unless $stream->{ws_key} =~ m{\A[A-Za-z0-9+/]{22}==\z};

        last WS_CHECK unless @{$headers{'sec-websocket-version'} or []} == 1;
        my $ver = $headers{'sec-websocket-version'}->[0];
        unless ($ver eq '13') {
          $status = 426;
          last WS_CHECK;
        }

        # XXX
        $stream->{ws_protos} = [grep { length $_ } split /[\x09\x20]*,[\x09\x20]*/, join ',', '', @{$headers{'sec-websocket-protocol'} or []}, ''];

        # XXX
        #my $exts = [grep { length $_ } split /[\x09\x20]*,[\x09\x20]*/, join ',', '', @{$headers{'sec-websocket-extensions'} or []}, ''];

        last WS_OK;
      } # WS_CHECK

      if ($status == 426) {
        $stream->_receive_done;
        $stream->_send_error (426, 'Upgrade Required', [
          ['Upgrade', 'websocket'],
          ['Sec-WebSocket-Version', '13'],
        ]) unless $self->{write_closed};
        $stream->close_response;
      } else {
        $stream->_fatal;
      }
      return 0;
    } # WS_OK
  } elsif (@{$headers{upgrade} or []}) {
    $stream->_fatal;
    return 0;
  }

  ## Transfer-Encoding:
  if (@{$headers{'transfer-encoding'} or []}) {
    $stream->_receive_done;
    $stream->_send_error (411, 'Length Required') unless $self->{write_closed};
    $stream->close_response;
    return 0;
  }

  $self->{state} = 'request body' if $stream->{request}->{method} eq 'CONNECT';

  ## Content-Length:
  my $l = 0;
  if (@{$headers{'content-length'} or []} == 1 and
      $headers{'content-length'}->[0] =~ /\A[0-9]+\z/) {
    $l = 0+$headers{'content-length'}->[0]
        unless $stream->{request}->{method} eq 'CONNECT';
  } elsif (@{$headers{'content-length'} or []}) { # multiple headers or broken
    $stream->_fatal;
    return 0;
  }
  if ($l == 0) {
    if (defined $stream->{ws_key}) {
      $self->{state} = 'ws handshaking';
      $self->{stream}->{close_after_response} = 1;
    }
  } else {
    $stream->{body_length} = $l;
    $self->{unread_length} = $l;
    $self->{state} = 'request body';
  }
  $stream->_ev ('headers', $stream->{request});
  $stream->_ev ('datastart');
  if ($l == 0 and not $stream->{request}->{method} eq 'CONNECT') {
    $stream->_ev ('dataend');
    unless (defined $stream->{ws_key}) {
      $stream->_receive_done;
    }
  }

  return 1;
} # _request_headers

sub _timeout ($) {
  my $self = $_[0];
  delete $self->{timer};
  $self->{transport}->abort (message => "Read timeout ($ReadTimeout)");
} # _timeout

sub closed ($) {
  return $_[0]->{closed};
} # closed

sub abort ($) {
  my ($self, %args) = @_;
  $self->{transport}->abort (%args);
  $self->{write_closed} = 1;
  if (defined $self->{stream}) {
    $self->{stream}->_send_done;
  }
  return $self->{closed};
} # abort

package Web::Transport::HTTPServerConnection::Stream;
push our @ISA, qw(Web::Transport::HTTPConnection::Stream);
use Carp qw(carp croak);
use Digest::SHA qw(sha1);
use MIME::Base64 qw(encode_base64);
use Web::Encoding;
use Web::DateTime;
use Web::DateTime::Clock;

BEGIN {
  *_e4d = \&Web::Transport::HTTPConnection::Stream::_e4d;
  *_e4d_t = \&Web::Transport::HTTPConnection::Stream::_e4d_t;
}

sub send_response_headers ($$$;%) {
  my ($stream, $response, %args) = @_;
  croak "|send_response_headers| is invoked twice"
      if defined $stream->{write_mode};

  my $con = $stream->{connection};
  my $close = $args{close} ||
              $stream->{close_after_response} ||
              $stream->{request}->{version} == 0.9;
  my $done = 0;
  my $connect = 0;
  my $ws = 0;
  my $to_be_sent = undef;
  my $write_mode = 'sent';
  if ($stream->{request}->{method} eq 'HEAD' or
      $response->{status} == 304) {
    ## No response body by definition
    $to_be_sent = 0+$args{content_length} if defined $args{content_length};
    $done = 1;
  } elsif ($stream->{request}->{method} eq 'CONNECT' and
           200 <= $response->{status} and $response->{status} < 300) {
    ## No response body by definition but switched to the tunnel mode
    croak "|content_length| not allowed" if defined $args{content_length};
    $write_mode = 'raw';
    $connect = 1;
  } elsif (100 <= $response->{status} and $response->{status} < 200) {
    ## No response body by definition
    croak "|content_length| not allowed" if defined $args{content_length};
    if (defined $stream->{ws_key} and $response->{status} == 101) {
      $ws = 1;
      $write_mode = 'ws';
    } else {
      croak "1xx response not supported";
    }
  } else {
    if (defined $args{content_length}) {
      ## If body length is specified
      $write_mode = 'raw';
      $to_be_sent = 0+$args{content_length};
      $done = 1 if $to_be_sent <= 0;
    } elsif ($stream->{request}->{version} == 1.1) {
      ## Otherwise, if chunked encoding can be used
      $write_mode = 'chunked';
    } else {
      ## Otherwise, end of the response is the termination of the connection
      $close = 1;
      $write_mode = 'raw';
    }
  }

  my @header;
  push @header, ['Server', encode_web_utf8 $con->server_header];

  my $dt = Web::DateTime->new_from_unix_time
      (Web::DateTime::Clock->realtime_clock->());
  push @header, ['Date', $dt->to_http_date_string];

  if ($ws) {
    $con->{ws_state} = 'OPEN';
    $con->{state} = 'before ws frame';
    push @header,
        ['Upgrade', 'websocket'],
        ['Connection', 'Upgrade'],
        ['Sec-WebSocket-Accept', encode_base64 sha1 ($stream->{ws_key} . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'), ''];
      # XXX Sec-WebSocket-Protocol
      # XXX Sec-WebSocket-Extensions
  } else {
    if ($close and not $connect) {
      push @header, ['Connection', 'close'];
    } elsif ($stream->{request}->{version} == 1.0) {
      push @header, ['Connection', 'keep-alive'];
    }
    if ($write_mode eq 'chunked') {
      push @header, ['Transfer-Encoding', 'chunked'];
    }
    if (defined $to_be_sent) {
      push @header, ['Content-Length', $to_be_sent];
    }
  }

  push @header, @{$response->{headers} or []};

  croak "Bad status text |@{[_e4d $response->{status_text}]}|"
      if $response->{status_text} =~ /[\x0D\x0A]/;
  croak "Status text is utf8-flagged"
      if utf8::is_utf8 $response->{status_text};

  for (@header) {
    croak "Bad header name |@{[_e4d $_->[0]]}|"
        unless $_->[0] =~ /\A[!\x23-'*-+\x2D-.0-9A-Z\x5E-z|~]+\z/;
    croak "Bad header value |$_->[0]: @{[_e4d $_->[1]]}|"
        unless $_->[1] =~ /\A[\x00-\x09\x0B\x0C\x0E-\xFF]*\z/;
    croak "Header name |$_->[0]| is utf8-flagged" if utf8::is_utf8 $_->[0];
    croak "Header value of |$_->[0]| is utf8-flagged" if utf8::is_utf8 $_->[1];
  }

  if ($stream->{request}->{version} != 0.9) {
    my $res = sprintf qq{HTTP/1.1 %d %s\x0D\x0A},
        $response->{status},
        $response->{status_text};
    for (@header) {
      $res .= "$_->[0]: $_->[1]\x0D\x0A";
    }
    $res .= "\x0D\x0A";
    if ($stream->{DEBUG}) {
      warn "$stream->{id}: Sending response headers... @{[scalar gmtime]}\n";
      for (split /\x0A/, $res) {
        warn "$stream->{id}: S: @{[_e4d $_]}\n";
      }
    }
    $con->{transport}->push_write (\$res);
  } else {
    if ($stream->{DEBUG}) {
      warn "$stream->{id}: Response headers skipped (HTTP/0.9) @{[scalar gmtime]}\n";
    }
  }

  $stream->{close_after_response} = 1 if $close;
  $stream->{write_mode} = $write_mode;
  if ($done) {
    delete $stream->{to_be_sent_length};
    $stream->close_response;
  } else {
    $stream->{to_be_sent_length} = $to_be_sent if defined $to_be_sent;
  }
} # send_response_headers

sub send_response_data ($$) {
  my ($req, $ref) = @_;
  croak "Data is utf8-flagged" if utf8::is_utf8 $$ref;
  my $wm = $req->{write_mode} || '';
  if ($req->{DEBUG} > 1) {
    for (split /\x0A/, $$ref, -1) {
      warn "$req->{id}: S: @{[_e4d $_]}\n";
    }
  }
  my $transport = $req->{connection}->{transport};
  if ($wm eq 'chunked') {
    if (length $$ref) {
      $transport->push_write (\sprintf "%X\x0D\x0A", length $$ref);
      $transport->push_write ($ref);
      $transport->push_write (\"\x0D\x0A");
    }
  } elsif ($wm eq 'raw' or $wm eq 'ws') {
    croak "Not writable for now"
        if $wm eq 'ws' and
            (not $req->{connection}->{ws_state} eq 'OPEN' or
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
    $transport->push_write ($ref);
    if ($wm eq 'raw' and
        defined $req->{to_be_sent_length} and $req->{to_be_sent_length} <= 0) {
      $req->close_response;
    }
  } else {
    croak "Not writable for now";
  }
} # send_response_data

sub close_response ($;%) {
  my ($stream, %args) = @_;
  return unless defined $stream->{connection};
  if (not defined $stream->{write_mode}) {
    $stream->abort (message => 'Closed without response');
  } elsif (defined $stream->{to_be_sent_length} and
           $stream->{to_be_sent_length} > 0) {
    carp sprintf "Truncated end of sent data (%d more bytes expected)",
        $stream->{to_be_sent_length};
    $stream->{close_after_response} = 1;
    $stream->_send_done;
  } else {
    $stream->{close_after_response} = 1
        if $stream->{request}->{method} eq 'CONNECT';
    if ($stream->{write_mode} eq 'chunked') {
      # XXX trailer headers
      my $transport = $stream->{connection}->{transport};
      $transport->push_write (\"0\x0D\x0A\x0D\x0A");
      $stream->_send_done;
    } elsif (defined $stream->{write_mode} and $stream->{write_mode} eq 'ws') {
      $stream->close (%args);
    } else {
      $stream->_send_done;
    }
  }
} # close_response

sub abort ($;%) {
  my $stream = shift;
  return $stream->{connection}->abort (@_);
} # abort

sub _send_error ($$$;$) {
  my ($stream, $status, $status_text, $headers) = @_;
  my $res = qq{<!DOCTYPE html><html>
<head><title>$status $status_text</title></head>
<body>$status $status_text};
  #$res .= Carp::longmess;
  $res .= qq{</body></html>\x0A};
  $stream->send_response_headers
      ({status => $status, status_text => $status_text,
        headers => [
          @{$headers or []},
          ['Content-Type' => 'text/html; charset=utf-8'],
        ]}, close => 1, content_length => length $res);
  $stream->send_response_data (\$res)
      unless $stream->{request}->{method} eq 'HEAD';
} # _send_error

sub _fatal ($) {
  my ($req) = @_;
  my $con = $req->{connection};
  $req->_receive_done;
  $con->{state} = 'end';
  $con->{rbuf} = '';
  $req->_send_error (400, 'Bad Request') unless $con->{write_closed};
  $req->close_response;
} # _fatal

sub _send_done ($) {
  my $stream = $_[0];
  if (delete $stream->{close_after_response}) {
    my $transport = $stream->{connection}->{transport};
    $transport->push_shutdown if not $stream->{connection}->{write_closed};
    $stream->{connection}->{write_closed} = 1;
  }
  $stream->{write_mode} = 'sent';
  delete $stream->{to_be_sent_length};
  $stream->{send_done} = 1;
  if ($stream->{receive_done}) {
    $stream->_both_done;
  }
} # _send_done

sub _receive_done ($) {
  my $stream = $_[0];
  my $con = $stream->{connection};
  delete $con->{timer};
  $con->{disable_timer} = 1;
  delete $con->{stream};
  delete $con->{unread_length};
  delete $con->{ws_timer};
  if ($stream->{close_after_response}) {
    $con->{state} = 'end';
  } else {
    $con->{state} = 'after request';
  }
  $stream->{receive_done} = 1;
  if ($stream->{send_done}) {
    $stream->_both_done;
  }
} # _receive_done

sub _both_done ($) {
  my $stream = $_[0];
  my $con = $stream->{connection};
  return unless defined $con;

  if (delete $stream->{close_after_response}) {
    $con->{transport}->push_shutdown unless $con->{write_closed};
    $con->{write_closed} = 1;
    $con->{state} = 'end';
  }
  delete $con->{disable_timer};
  $stream->_ev ('complete', $con->{exit} || {});
  $con->_con_ev ('endstream', $stream);

  $con->{timer} = AE::timer $ReadTimeout, 0, sub { $con->_timeout };
  delete $stream->{connection};
} # _both_done

sub DESTROY ($) {
  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

# XXX server-side API
# XXX TLS configurations

1;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
