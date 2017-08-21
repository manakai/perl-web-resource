package Web::Transport::HTTPStream;
use strict;
use warnings;
no warnings 'utf8';
use warnings FATAL => 'recursion';
our $VERSION = '1.0';
use AnyEvent;
use Web::Encoding;
use Encode qw(decode); # XXX
use ArrayBuffer;
use TypedArray;
use Promised::Flow;
use Streams;
use Web::Transport::Error;
use Web::Transport::TypeError;
use Web::Transport::ProtocolError;

push our @CARP_NOT, qw(
  Web::Transport::HTTPStream::Stream
  Web::Transport::TCPStream
  Web::Transport::UnixStream
  Web::Transport::TLSStream
  Web::Transport::SOCKS4Stream
  Web::Transport::SOCKS5Stream
  Web::Transport::H1CONNECTStream
);

## This module is not public.  It should not be used by external
## applications and modules.

sub _e4d ($) {
  return $_[0] unless $_[0] =~ /[^\x20-\x5B\x5D-\x7E]/;
  my $x = $_[0];
  $x =~ s/([^\x20-\x5B\x5D-\x7E])/sprintf '\x%02X', ord $1/ge;
  return $x;
} # _e4d

sub _e4d_t ($) {
  return encode_web_utf8 $_[0] unless $_[0] =~ /[^\x20-\x5B\x5D-\x7E]/;
  my $x = $_[0];
  $x =~ s{([^\x20-\x5B\x5D-\x7E])}{
    my $c = ord $1;
    if ($c < 0x10000) {
      sprintf '\u%04X', $c;
    } else {
      sprintf '\U%08X', $c;
    }
  }ge;
  return encode_web_utf8 $x;
} # _e4d_t

sub _pcap () {
  my ($x, $y);
  my $p = Promise->new (sub { ($x, $y) = @_ });
  return [$p, $x, $y];
} # _pcap

sub _pe ($) {
  return Web::Transport::ProtocolError::HTTPParseError->_new_fatal ($_[0]);
} # _pe

sub _pw ($) {
  return Web::Transport::ProtocolError::HTTPParseError->_new_non_fatal ($_[0]);
} # _pw

## This class, with its two subclasses, represents an HTTP connection.

## Create and return a new HTTP connection.
##
## The argument is a hash reference with following key/value pairs:
##
##   parent: A hash reference defining the underlying transport.  If
##   it represents new transport, a new connection is initiated as
##   soon as possible.
##
##   server: Whether it is a server or not.
##
##   server_header: The value of the |Server:| header for the
##   responses.  If it is not defined, the value |Server| is used.  It
##   must be a character string.  It is encoded in UTF-8.
##
##   debug: The debug level for the connection.  The value can be |2|
##   (very verbose), |1| (verbose), or |0| (normal; default).  If the
##   value is not defined but there is the |WEBUA_DEBUG| (for client)
##   or |WEBSERVER_DEBUG| (for server) environment variable set when
##   the constructor is invoked, that value is used.
sub new ($$) {
  my $args = $_[1];
  my $con = bless {
    next_stream_id => 1,
    temp_buffer => '',
  }, ($args->{server} ? __PACKAGE__ . '::ServerConnection' : __PACKAGE__ . '::ClientConnection');
  if ($args->{server}) {
    $con->{is_server} = 1;
    $con->{rbuf} = '';

    $con->{server_header} = encode_web_utf8
        (defined $args->{server_header} ? $args->{server_header} : 'Server');
  }
  if (defined $args->{debug}) {
    $con->{DEBUG} = $args->{debug};
  } else {
    $con->{DEBUG} = $con->{is_server} ? $ENV{WEBSERVER_DEBUG} || 0 : $ENV{WEBUA_DEBUG} || 0;
  }

  $con->{ready} = _pcap;
  $con->{closed} = _pcap;

  my $parent = $args->{parent};
  if ($con->{DEBUG}) {
    $parent = {%$parent};
    $parent->{debug} = $con->{DEBUG} unless defined $parent->{debug};
  }

  $con->{streams} = ReadableStream->new ({
    start => sub {
      $con->{streams_controller} = $_[1];
    }, # start
    pull => sub {
      return $con->_read;
    }, # pull
    cancel => sub {
      my $error = Web::Transport::Error->wrap ($_[1]);
      delete $con->{streams_controller};
      return $con->abort ($error);
    }, # cancel
  }); # streams
  $con->{streams_done} = sub {
    $con->{streams_controller}->close if defined $con->{streams_controller};
    delete $con->{streams_controller};
    $con->{streams_done} = sub { };
  }; # streams_done

  $parent->{class}->create ($parent)->then (sub {
    my $info = $_[0];

    $con->{id} = $info->{id} . 'h1';
    $con->{info} = {
      type => 'H1',
      layered_type => 'H1/' . $info->{layered_type},
      id => $con->{id},
      parent => $info,
    };
    if ($con->{DEBUG}) {
      my $action = $con->{is_server} ? 'start as server' : 'start as client';
      warn "$con->{id}: H1: $action over $info->{layered_type} @{[scalar gmtime]}\n";
      warn "$con->{id}: H1: DEBUG mode |$con->{DEBUG}|\n" unless $con->{DEBUG} eq '1';
    }

    $con->{reader} = (delete $info->{readable})->get_reader ('byob');
    $con->{writer} = (delete $info->{writable})->get_writer;
    $con->{state} = 'initial';

    if ($con->{is_server}) {
      my $tinfo = $info;
      if ($info->{type} eq 'TLS') {
        $con->{url_scheme} = 'https';
        $tinfo = $tinfo->{parent};
      } else { # TCP or Unix
        $con->{url_scheme} = 'http';
      }
      if ($tinfo->{type} eq 'TCP') {
        $con->{url_hostport} = $tinfo->{local_host}->to_ascii . ':' . $tinfo->{local_port};
      } else { # Unix
        $con->{url_hostport} = '0.0.0.0';
      }

      $con->{timer} = AE::timer $Web::Transport::HTTPStream::ServerConnection::ReadTimeout, 0, sub { $con->_timeout };
      $con->_read;
    } else { # client
      $con->{response_received} = 1;
      #$con->_read;
    }

    my $p1 = $con->{is_server} ? $con->{reader}->closed->then (sub {
      delete $con->{reader};

      if ($con->{DEBUG}) {
        warn "$con->{id}: R: EOF\n";
      }

      $con->_oneof (undef);
      delete $con->{timer};
      return undef;
    }, sub {
      my $error = Web::Transport::Error->wrap ($_[0]);
      delete $con->{reader};

      if ($con->{DEBUG}) {
        warn "$con->{id}: R: EOF (@{[_e4d_t $error]})\n";
      }

      $con->_oneof ($_[0]);
      delete $con->{timer};
      return undef;
    }) : $con->{reader}->closed->then (sub {
      delete $con->{reader};

      if ($con->{DEBUG}) {
        warn "$con->{id}: R: EOF\n";
      }

      $con->_process_rbuf (undef);
      $con->_process_rbuf_eof (undef);
      return undef;
    }, sub {
      my $error = Web::Transport::Error->wrap ($_[0]);
      delete $con->{reader};

      if ($con->{DEBUG}) {
        warn "$con->{id}: R: EOF (@{[_e4d $error]})\n";
      }

      if (Web::Transport::ProtocolError->is_reset ($error)) {
        return $con->_connection_error ($error);
      } else {
        $con->_process_rbuf (undef);
        $con->_process_rbuf_eof ($error);
        return;
      }
    }); # reader closed

    my $p2 = $con->{writer}->closed->then (sub {
      if ($con->{DEBUG}) {
        warn "$con->{id}: S: EOF\n";
      }
    }, sub {
      delete $con->{writer};
      if ($con->{DEBUG}) {
        my $error = Web::Transport::Error->wrap ($_[0]);
        warn "$con->{id}: S: EOF (@{[_e4d $error]})\n";
      }
    }); # writer closed

    if ($con->{DEBUG}) {
      $con->{closed}->[0]->then (sub {
        warn "$con->{id}: H1: closed @{[scalar gmtime]}\n";
      });
    }

    (delete $con->{ready}->[1])->(undef), delete $con->{ready}->[2];
    return Promise->all ([$p1, $p2, delete $info->{closed}])->then (sub {
      $con->{streams_done}->();
      (delete $con->{closed}->[1])->(undef), delete $con->{closed}->[2];
    });
  })->catch (sub {
    my $error = Web::Transport::Error->wrap ($_[0]);

    if ($con->{DEBUG} and defined $con->{id}) {
      warn "$con->{id}: H1: failed @{[scalar gmtime]}\n";
    }

    (delete $con->{writer})->abort ($error) if defined $con->{writer};
    (delete $con->{reader})->cancel ($error)->catch (sub { })
        if defined $con->{reader};

    (delete $con->{ready}->[2])->($error), delete $con->{ready}->[1]
        if defined $con->{ready}->[1];
    $con->{streams_done}->();
    (delete $con->{closed}->[1])->(undef), delete $con->{closed}->[2];
  });

  return $con;
} # new

## Client:
##   $con->send_request->then (sub {
##     $_[0]->{stream}
##     $_[0]->{body}
##   })
##   $stream->headers_received->then (sub {
##     $_[0]->{version}
##     $_[0]->{status}
##     $_[0]->{status_text}
##     $_[0]->{headers}
##     $_[0]->{body}
##     $_[0]->{incomplete}
##     $_[0]->{messages}
##     $_[0]->{closing}
##     $_[0]->{reading}
##     $_[0]->{writing}
##   })
## Server:
##   $con->streams->read->then (sub { $stream = $_[0]->{value} })
##   $stream->headers_received->then (sub {
##     $_[0]->{version}
##     $_[0]->{method}
##     $_[0]->{target_url}
##     $_[0]->{headers}
##     $_[0]->{body}
##     $_[0]->{messages}
##     $_[0]->{closing}
##   })
##   $stream->send_response->then (sub {
##     $_[0]->{body}
##     $_[0]->{reading}
##     $_[0]->{writing}
##   })
##
## An HTTP connection is in the WS mode if it is a client and it has
## sent a WebSocket request, or it is a server and it has received a
## WebSocket request.
##
## An HTTP connection is in the tunnel mode if it is a client, it has
## sent a request whose method is |CONNECT|, and it has received a
## |200| response, or if it is a server, it has received a request
## whose method is |CONNECT|, and it has sent a |2/xx/| response.
##
## Methods |send_request|, |send_response|, and |headers_received|
## returns a promise which is fulfilled with a hash reference.  The
## hash reference contains following key/value pairs, which are
## defined only where applicable:
##
##   stream - If the method is |send_request|, the HTTP stream
##   initiated by the request.
##
##   version - If the method is the server's |headers_received|,
##   request's HTTP version.  If the method is the client's
##   |headers_received|, the response's HTTP version.  The value is
##   one of |0.9|, |1.0|, or |1.1|.
##
##   method - If the method is the server's |headers_received|, the
##   request's method.
##
##   target - If the method is the server's |headers_received|, the
##   request's target URL.  The value is a |Web::URL| object.
##
##   status - If the method is the client's |headers_received|, the
##   response's status.
##
##   status_text - If the method is the client's |headers_received|,
##   the response's status text.
##
##   headers - If the method is the server's |headers_received|, the
##   request's headers.  If the method is the client's
##   |headers_received|, the response's headers.  It is an array
##   reference of zero or more array references of (header name,
##   header value, lowercased header name).
##
##   body - If the method is |send_request|, the writable stream for
##   the request body.  If the method is |send_response|, the writable
##   stream for the response body.  These writable streams accept
##   |ArrayBufferView|s.  If the |content_length| option was specified
##   to the |send_request| or |send_response| method, the total byte
##   length must be equal to the |content_length| option value.  If
##   the method is client's |headers_received|, the readable byte
##   stream for the response body.  If the method is server's
##   |headers_received|, the readable byte stream for the request
##   body.  If the HTTP connection is in the WS mode, in the tunnel
##   mode, the method is |send_request| and the request's method is
##   |CONNECT|, or the method is server's |headers_received| and the
##   request's method is |CONNECT|, however, not defined.  If these
##   readable streams are canceled, or these writable streams are
##   aborted, the relevant HTTP stream is aborted.
##
##   messages - If the method is |headers_received| and the HTTP
##   connection is in the WS mode, a readable stream of zero or more
##   received WebSocket messages.  If the readable stream is canceled,
##   the HTTP stream is aborted.  A WebSocket messages is represented
##   by a hash reference with following key/value pairs, which are
##   only defined where applicable:
##
##     body - If it is a binary message, a readable byte stream of the
##     data of the message.  If the readable stream is canceled, the
##     HTTP stream is aborted.
##
##     text_body - If it is a text message, a readable stream of zero
##     or more scalar references to texts (possibly utf8-flagged Perl
##     strings of characters), whose concatenation in order is the
##     data of the message.  If the readable stream is canceled, the
##     HTTP stream is aborted.
##
##   closing - If the method is |headers_received| and the HTTP
##   connection is in the WS mode, a promise which is to be fulfilled
##   when the |closing| event should be fired on a WebSocket client
##   object (or equivalent).  It is rejected if a WebSocket request is
##   responded by a non-WebSocket response or if the WebSocket session
##   is abnormally terminated.
##
##   readable - If the method is |send_response| or the method is the
##   client's |headers_received|, a readable byte stream of the tunnel
##   data received.  If the readable stream is canceled, the HTTP
##   stream is aborted.
##
##   writable - If the method is |send_response| or the method is the
##   client's |headers_received|, a writable stream of the tunnel data
##   sent.  It accepts |ArrayBufferView|s.  If the writable stream is
##   aborted, the HTTP stream is aborted.
##
## The server's |headers_received| method is the |headers_received| of
## an HTTP stream obtained from the |streams| readable stream of a
## server HTTP connection.
##
## The client's |headers_received| method is the |headers_received| of
## an HTTP stream obtained from the |stream| key of the hash reference
## of the returned promise of the |send_request| method.

# XXX replace croak

sub MAX_BYTES () { 2**31-1 }

## Returns the "info" hash reference of the HTTP connection, which
## contains the metadata on the HTTP connection, if the HTTP
## connection is ready (or |undef| otherwise).  The hash reference
## contains following key/value pairs:
##
##   id - The short string identifying the HTTP connection, provided
##   for debugging.
##
##   parent - The "info" hash reference of the underlying transport of
##   the HTTP connection.
sub info ($) {
  return $_[0]->{info}; # or undef
} # info

## Return the |ready| promise of the HTTP connection, which is
## fulfilled with |undef| when the HTTP connection becomes ready.  An
## HTTP connection becomes ready once an underlying transport has been
## established.  It is rejected instead if the transport cannot be
## successfully initiated.
sub ready ($) {
  return $_[0]->{ready}->[0];
} # ready

## Returns a readable stream of zero or more HTTP streams.  If the
## HTTP connection is client, this is an empty stream.  If the HTTP
## connection is server, a new HTTP stream is created and appended to
## the readable stream whenever it receives a request.  If the
## readable stream is canceled, the HTTP stream is aborted.
sub streams ($) {
  return $_[0]->{streams};
} # streams

sub _ws_received ($) {
  my ($self, $ref) = @_;
  my $stream = $self->{stream};
  my $ws_failed;
  WS: {
    if ($self->{state} eq 'before ws frame') {
      my $read_bytes = sub ($) {
        my $want = $_[0] - length $self->{temp_buffer};
        return 1 if $want <= 0;

        my $avail = length ($$ref) - pos ($$ref);
        return 0 unless $avail >= $want;

        $self->{temp_buffer} .= substr $$ref, pos $$ref, $want;
        pos ($$ref) += $want;
        return 1;
      }; # $read_bytes

      my $length = 2;
      $read_bytes->(2) or last WS;
      my $b1 = ord substr $self->{temp_buffer}, 0, 1;
      my $b2 = ord substr $self->{temp_buffer}, 1, 1;
      my $fin = $b1 & 0b10000000;
      my $opcode = $b1 & 0b1111;
      my $mask = $b2 & 0b10000000;
      $self->{unread_length} = $b2 & 0b01111111;
      if ($self->{unread_length} == 126) {
        if ($opcode >= 8) {
          $ws_failed = '';
          last WS;
        }
        $length = 4;
        $read_bytes->(4) or last WS;
        $self->{unread_length} = unpack 'n', substr $self->{temp_buffer}, 2, 2;
        if ($self->{unread_length} < 126) {
          $ws_failed = '';
          last WS;
        }
      } elsif ($self->{unread_length} == 127) {
        if ($opcode >= 8) {
          $ws_failed = '';
          last WS;
        }
        $length = 10;
        $read_bytes->(10) or last WS;
        $self->{unread_length} = unpack 'Q>', substr $self->{temp_buffer}, 2, 8;
        if ($self->{unread_length} > MAX_BYTES) { # spec limit=2**63
          $ws_failed = '';
          last WS;
        }
        if ($self->{unread_length} < 2**16) {
          $ws_failed = '';
          last WS;
        }
      }
      if ($mask) {
        $read_bytes->($length + 4) or last WS;
        $self->{ws_decode_mask_key} = substr $self->{temp_buffer}, $length, 4;
        $length += 4;
        $self->{ws_read_length} = 0;
        unless ($self->{is_server}) {
          $ws_failed = 'Masked frame from server';
          last WS;
        }
      } else {
        delete $self->{ws_decode_mask_key};
        if ($self->{is_server}) {
          $ws_failed = 'WebSocket Protocol Error';
          last WS;
        }
      }
      $stream->_ws_debug ('R', '',
                        FIN => !!$fin,
                        RSV1 => !!($b1 & 0b01000000),
                        RSV2 => !!($b1 & 0b00100000),
                        RSV3 => !!($b1 & 0b00010000),
                        opcode => $opcode,
                        mask => $self->{ws_decode_mask_key},
                        length => $self->{unread_length}) if $self->{DEBUG};
      if (not $fin and ($opcode == 8 or $opcode == 9 or $opcode == 10)) {
        $ws_failed = '';
        last WS;
      }
      if ($b1 & 0b01110000) {
        $ws_failed = 'Invalid reserved bit';
        last WS;
      }
      if ((3 <= $opcode and $opcode <= 7) or
          (11 <= $opcode and $opcode <= 15)) {
        $ws_failed = 'Unknown opcode';
        last WS;
      }
      if ($opcode == 0) {
        if (not defined $self->{ws_data_frame}) {
          $ws_failed = 'Unexpected continuation';
          last WS;
        }
        $self->{ws_frame} = $self->{ws_data_frame};
      } elsif ($opcode == 1 or $opcode == 2) {
        if (defined $self->{ws_data_frame}) {
          $ws_failed = 'Previous data frame unfinished';
          last WS;
        }
        $self->{ws_data_frame} = $self->{ws_frame} = [$opcode, []];
      } else {
        $self->{ws_frame} = [$opcode, []];
      }
      $self->{ws_frame}->[2] = 1 if $fin;
      $self->{state} = 'ws data';
    }
    if ($self->{state} eq 'ws data') {
      if ($self->{unread_length} > 0) {
        my $length = length ($$ref) - pos ($$ref);
        $length = $self->{unread_length} if $self->{unread_length} < $length;
        push @{$self->{ws_frame}->[1]}, substr $$ref, pos $$ref, $length; # XXX string copy!
        if (defined $self->{ws_decode_mask_key}) {
          for (0..($length-1)) {
            substr ($self->{ws_frame}->[1]->[-1], $_, 1)
                = substr ($self->{ws_frame}->[1]->[-1], $_, 1)
                ^ substr ($self->{ws_decode_mask_key}, ($self->{ws_read_length} + $_) % 4, 1);
          }
        }
        $self->{ws_read_length} += $length;
        pos ($$ref) += $length;
        $self->{unread_length} -= $length;
      }
      if ($self->{unread_length} <= 0) {
        if ($self->{ws_frame}->[0] == 8) { # close
          my $data = join '', @{$self->{ws_frame}->[1]}; # XXX string copy!
          if (1 == length $data) {
            $ws_failed = '-';
            last WS;
          }
          my $status;
          my $reason;
          if (length $data) {
            $status = unpack 'n', substr $data, 0, 2;
            if ($status == 1005 or $status == 1006) {
              $ws_failed = '-';
              last WS;
            }
            my $buffer = substr $data, 2;
            $reason = eval { decode 'utf-8', $buffer, Encode::FB_CROAK }; # XXX Encoding Standard
            if (length $buffer) {
              $ws_failed = 'Invalid UTF-8 in Close frame';
              last WS;
            }
          }
          if ($self->{DEBUG} and $self->{unread_length} > 1) {
            warn sprintf "%s: R: status=%d %s\n",
                $stream->{id},
                unpack ('n', $status), _e4d $reason;
          }
          unless ($self->{ws_state} eq 'CLOSING') {
            $self->{ws_state} = 'CLOSING';
            (delete $stream->{closing}->[1])->(undef), delete $stream->{closing}->[2];
            warn "$stream->{id}: closing @{[scalar gmtime]}\n" if $self->{DEBUG};
            my $mask = '';
            my $masked = 0;
            unless ($self->{is_server}) {
              $masked = 0b10000000;
              $mask = pack 'CCCC', rand 256, rand 256, rand 256, rand 256;
              for (0..((length $data)-1)) {
                substr ($data, $_, 1) = substr ($data, $_, 1) ^ substr ($mask, $_ % 4, 1);
              }
            }
            my $frame_info = [defined $reason ? $reason : '',
                              FIN => 1, opcode => 8, mask => $mask,
                              length => length $data, status => $status];
            my $frame = DataView->new (ArrayBuffer->new_from_scalarref (\(pack ('CC', 0b10000000 | 8, $masked | length $data) . $mask . $data)));
            if (defined $self->{cancel_current_writable_stream}) {
              push @{$self->{ws_pendings}}, [8, $frame, $frame_info];
            } else {
              $stream->_ws_debug ('S', @$frame_info) if $self->{DEBUG};
              $self->{writer}->write ($frame);
              $self->_send_done (close => 1);
            }
          } # not CLOSING
          $self->{state} = 'ws terminating';
          if (length ($$ref) - pos ($$ref)) { # ws terminating state
            $self->{exit} = Web::Transport::ProtocolError::WebSocketClose->new
                (1006, '', _pe 'Invalid byte after WebSocket Close frame');
            $$ref = '';
          } else {
            $self->{exit} = Web::Transport::ProtocolError::WebSocketClose->new
                (defined $status ? $status : 1005,
                 defined $reason ? $reason : '',
                 undef); # closed cleanly
          }
          if ($self->{is_server}) {
            $self->_receive_done;
          } else {
            $self->{ws_timer} = AE::timer 1, 0, sub { # XXX spec
              if ($self->{DEBUG}) {
                warn "$stream->{id}: WS timeout (1)\n";
              }
              $self->_receive_done;
            };
          }
          return;
        } elsif ($self->{ws_frame}->[0] <= 2) { # 0, 1, 2
          if ($self->{ws_frame}->[2]) { # FIN
            my $is_text = $self->{ws_frame}->[0] == 1;
            my $rc;
            my $rs = ReadableStream->new ({
              type => ($is_text ? undef : 'bytes'),
              start => sub { $rc = $_[1] },
              pull => sub {
                return $self->_read;
              }, # pull
              cancel => sub {
                undef $rc;
                return $self->abort (Web::Transport::Error->wrap ($_[1]));
              }, # cancel
            });

            if ($is_text) {
              my $buffer = join '', @{$self->{ws_frame}->[1]}; # XXX string copy!
              $self->{ws_frame}->[1] = [eval { decode 'utf-8', $buffer, Encode::FB_CROAK }]; # XXX Encoding Standard # XXX streaming decoder
              if (length $buffer) {
                $rc->error;
                $ws_failed = 'Invalid UTF-8 in text frame';
                last WS;
              }
              for (@{$self->{ws_frame}->[1]}) {
                $stream->_receive_text (\$_) if $self->{DEBUG};
                $rc->enqueue (\$_);
              }
            } else { # binary
              for (@{$self->{ws_frame}->[1]}) {
                my $dv = DataView->new (ArrayBuffer->new_from_scalarref (\$_));
                $stream->_receive_body ($dv, 1) if $self->{DEBUG};
                $rc->enqueue ($dv);
              }
            }
            $stream->{messages_controller}->enqueue ({
              ($is_text ? 'text_body' : 'body') => $rs,
            });
            $rc->close;
            unless ($is_text) {
              my $req = $rc->byob_request;
              $req->respond (0) if defined $req;
            }
            delete $self->{ws_data_frame};
          }
        } elsif ($self->{ws_frame}->[0] == 9) {
          my $data = join '', @{$self->{ws_frame}->[1]};
          my $mask = '';
          my $masked = 0;
          unless ($self->{is_server}) {
            $masked = 0b10000000;
            $mask = pack 'CCCC', rand 256, rand 256, rand 256, rand 256;
          }
          my $frame_info = [$data, FIN => 1, opcode => 10, mask => $mask,
                            length => length $data];
          unless ($self->{is_server}) {
            for (0..((length $data)-1)) {
              substr ($data, $_, 1) = substr ($data, $_, 1) ^ substr ($mask, $_ % 4, 1);
            }
          }
          my $frame = DataView->new (ArrayBuffer->new_from_scalarref (\(pack ('CC', 0b10000000 | 10, $masked | length $data) . $mask . $data)));
          if (defined $self->{cancel_current_writable_stream}) {
            push @{$self->{ws_pendings}}, [9, $frame, $frame_info];
          } else {
            $stream->_ws_debug ('S', @$frame_info) if $self->{DEBUG};
            $self->{writer}->write ($frame);
          }
          if ($self->{DEBUG}) {
            warn "$stream->{id}: R: data=@{[_e4d join '', @{$self->{ws_frame}->[1]}]}\n";
          }
        } elsif ($self->{ws_frame}->[0] == 10) {
          if ($self->{DEBUG}) {
            warn "$stream->{id}: R: pong data=@{[_e4d join '', @{$self->{ws_frame}->[1]}]}\n";
          }
        } # frame type
        delete $self->{ws_frame};
        delete $self->{ws_decode_mask_key};
        $self->{state} = 'before ws frame';
        $self->{temp_buffer} = '';
        redo WS;
      }
    }
  } # WS
  if (defined $ws_failed) {
    $self->{ws_state} = 'CLOSING';
    $ws_failed = 'WebSocket Protocol Error' unless length $ws_failed;
    $ws_failed = '' if $ws_failed eq '-';
    my $exit = Web::Transport::ProtocolError::WebSocketClose->new
        (1002, $ws_failed, _pe $ws_failed);
    my $data = pack 'n', 1002;
    $data .= $ws_failed;
    my $mask = '';
    my $masked = 0;
    unless ($self->{is_server}) {
      $masked = 0b10000000;
      $mask = pack 'CCCC', rand 256, rand 256, rand 256, rand 256;
      for (0..((length $data)-1)) {
        substr ($data, $_, 1) = substr ($data, $_, 1) ^ substr ($mask, $_ % 4, 1);
      }
    }
    # length $data must be < 126
    $stream->_ws_debug ('S', $ws_failed, FIN => 1, opcode => 8,
                        mask => $mask, length => length $data,
                        status => 1002) if $self->{DEBUG};
    $self->{writer}->write
        (DataView->new (ArrayBuffer->new_from_scalarref (\(pack ('CC', 0b10000000 | 8, $masked | length $data) . $mask . $data))));
    $self->{state} = 'ws terminating';
    return $self->_connection_error ($exit);
  }
  if ($self->{state} eq 'ws terminating') {
    if ((length $$ref) - (pos $$ref)) {
      $self->{exit} = Web::Transport::ProtocolError::WebSocketClose->new
          (1006, '', _pe 'Invalid byte after WebSocket Close frame')
              if not Web::Transport::ProtocolError->is_error ($self->{exit});
      $ref = \'';
    }
  }
  if ((length $$ref) - (pos $$ref)) { # before ws frame
    $self->{temp_buffer} .= substr $$ref, pos $$ref;
    $ref = \'';
  }
} # _ws_received

# XXX can_create_stream is_active && (if h1: no current request)

## Send a request.  The argument must be a hash reference of following
## key/value pairs:
##
##   method - The request method.  It must be a non-empty byte string
##   of canonicalized (as specified in Fetch Standard) method name.
##
##   target - The request target.  It must be a byte string.
##
##   length - The byte length of the request body, if any.
##
##   ws - Whether the request is part of the WebSocket handshake or
##   not.
##
##   ws_protocols - An array reference of zero or more byte strings
##   representing WebSocket subprotocol names, if |ws| is true.
##
## This method must be invoked while the HTTP connection is ready, is
## not to be closed, and is not sending another request.  It returns a
## promise which is to be fulfilled with a hash reference that might
## contain a writable stream of the request body, as described
## earlier.
sub send_request ($$;%) {
  my $con = shift;
  my $req = shift;
  return Promise->reject (Web::Transport::TypeError->new ("Request is not allowed"))
      if $con->{is_server};

  my $stream = bless {
    connection => $con,
  },'Web::Transport::HTTPStream::Stream';
  return $stream->_send_request ($req, @_);
} # send_request

## Return the |closed| promise of the HTTP connection, which is
## fulfilled with |undef| when the HTTP connection has been closed or
## aborted.  This is fulfilled rather than rejected even when the HTTP
## connection is abnormally closed.
sub closed ($) {
  return $_[0]->{closed}->[0];
} # closed

## Stop the HTTP connection accepting new requests and close the
## connection AFTER any ongoing stream has been completed.  If the
## HTTP connection is not ready yet, a rejected promise is returned.
## Otherwise, it returns the |closed| promise.
sub close_after_current_stream ($) {
  my $con = $_[0];
  return Promise->reject (Web::Transport::TypeError->new ("Connection is not ready"))
      unless defined $con->{state};

  $con->{to_be_closed} = 1;
  if ($con->{state} eq 'initial' or
      $con->{state} eq 'before request-line' or # XXXspec
      $con->{state} eq 'waiting') {
    $con->{exit} = _pw 'Close by |close_after_current_stream|';
    $con->_send_done (close => 1);
    $con->_read;
  }

  return $con->{closed}->[0];
} # close_after_current_stream

## Return whether the HTTP connection is ready and accepting new
## requests or not.
sub is_active ($) {
  return defined $_[0]->{state} && !$_[0]->{to_be_closed};
} # is_active

## Abort the HTTP connection.  It must be invoked after the HTTP
## connection becomes ready.  The first argument, if specified,
## represents the reason of the abort, which might be used to reject
## various relevant promises and in various debug outputs.  The second
## and later arguments are key/value pairs of named arguments.  If the
## |graceful| argument has a true value, the HTTP connection is
## aborted after any queued write operation has been completed.
## Otherwise, the connection is aborted as soon as possible.  It
## should be an exception object, though any value is allowed.  It
## returns the |closed| promise of the HTTP connection.
sub abort ($;$%) {
  my ($con, $reason, %args) = @_;
  if (not defined $con->{state}) {
    # XXX abort any connection handshake and invalidate $con
    return Promise->reject (Web::Transport::TypeError->new ("Connection has not been established"));
  }

  my $error = Web::Transport::Error->wrap ($reason);
  $con->{exit} = $error;

  (($args{graceful} && defined $con->{writer}) ? $con->{writer}->write (DataView->new (ArrayBuffer->new (0))) : Promise->resolve)->then (sub {
    (delete $con->{writer})->abort ($error) if defined $con->{writer};
    $con->_send_done (close => 1);

    (delete $con->{reader})->cancel ($error)->catch (sub { })
        if defined $con->{reader};
  });

  return $con->{closed}->[0];
} # abort

sub _connection_error ($$;$$$) {
  my $con = $_[0];
  $con->{exit} = $_[1];

  if ($con->{state} eq 'ws terminating') {
    $con->_send_done (close => 1);
    $con->_receive_done;
    return;
  }

  if ($con->{is_server}) {
    if (not defined $con or defined $con->{write_mode}) {
      ## A response is being sent or has been sent.
      $con->_send_done (close => 1);
      $con->_receive_done;
      return;
    }

    my $status = $_[2] || 400;
    my $reason = $_[3] || 'Bad Request';
    my $headers = $_[4] || [];

    my $stream = $con->{stream};
    my $with_body = not ($stream->{request}->{method} eq 'HEAD');
    my $res = qq{<!DOCTYPE html><html>
<head><title>$status $reason</title></head>
<body>$status $reason</body></html>\x0A};
    my $p = $stream->send_response (
      {
        status => $status, status_text => $reason,
        headers => [
          @{$headers or []},
          ['Content-Type' => 'text/html; charset=utf-8'],
        ],
        close => 1,
        length => ($with_body ? length $res : undef),
      },
    )->then (sub {
      my $w = $_[0]->{body}->get_writer;
      $w->write (DataView->new (ArrayBuffer->new_from_scalarref (\$res)))
          if $with_body;
      return $w->close;
    });

    $con->_receive_done;
    return $p;
  } else {
    $con->_send_done (close => 1);
    $con->_receive_done;
    return;
  }
} # _connection_error

sub _send_done ($;%) {
  my ($con, %args) = @_;

  if ($args{close}) {
    $con->{to_be_closed} = 1;
    $con->{writer}->close if defined $con->{writer};
    delete $con->{writer};
  }

  if (defined $con->{cancel_current_writable_stream}) {
    $con->{cancel_current_writable_stream}->(undef);
  }
  $con->{write_mode} = 'sent';

  $con->{send_done} = 1;
  $con->_both_done if $con->{receive_done};
} # _send_done

sub _receive_done ($;%) {
  my ($con, %args) = @_;
  my $stream = $con->{stream};

  return if $con->{state} eq 'stopped';

  if (defined $stream->{messages_controller}) {
    $stream->{messages_controller}->close;
    delete $stream->{messages_controller};
  }

  delete $con->{unread_length}; # XXX spec
  delete $con->{timer};
  $con->{disable_timer} = 1; # XXX spec
  delete $con->{ws_timer};
  if (defined $con->{write_mode} and not $con->{write_mode} eq 'sent') {
    $con->{state} = 'sending';
  } elsif ($con->{state} eq 'before request header') { # XXX spec
    $con->{state} = 'sending';
  }
  $con->{receive_done} = 1;
  $con->_both_done if $con->{send_done};
} # _receive_done

sub _both_done ($) {
  my $con = $_[0];
  my $stream = $con->{stream};

  my $error = $con->{exit};
  $error = _pw 'HTTP stream closed' unless defined $error;

  if (defined $stream) {
    (delete $stream->{headers_received}->[2])->($error), delete $stream->{headers_received}->[1]
        if defined $stream->{headers_received}->[1];

    (delete $stream->{closing}->[2])->($error), delete $stream->{closing}->[1]
        if defined $stream->{closing}->[1];

    # XXXspec
    (delete $stream->{body_controller})->error ($error)
        if defined $stream->{body_controller};

    (delete $stream->{closed}->[1])->($error), delete $stream->{closed}->[2]
        if defined $stream->{closed}->[1];

    if ($con->{DEBUG}) {
      if (defined $con->{response} and $con->{response}->{incomplete}) {
        warn "$con->{id}: incomplete message\n";
      }
      warn "$con->{id}: endstream $stream->{id} @{[scalar gmtime]}\n";
      warn "$con->{id}: ========== @{[ref $con]}\n";
    }
  } # $stream

  if ($con->{is_server}) {

  delete $stream->{connection};
  delete $con->{stream};
  delete $con->{send_done};
  delete $con->{receive_done};
  delete $con->{write_mode};
  delete $con->{exit};

  delete $con->{disable_timer};
  if ($con->{to_be_closed}) {
    my ($r_written, $s_written) = promised_cv;
    if (defined $con->{writer}) {
      my $writer = $con->{writer};
      &promised_cleanup ($s_written, $writer->close);
      $con->{timer} = AE::timer 1, 0, sub {
        $writer->abort (_pe "HTTP completion timer (1)");
        $s_written->();
      };
      delete $con->{writer};
    } else {
      delete $con->{timer};
      $s_written->();
    }
    $r_written->then (sub {
      if (defined $con->{reader}) { # XXX spec
        $con->closed->then (sub { delete $con->{timer} });
        $con->{timer} = AE::timer 1, 0, sub {
          return unless defined $con->{reader};
          $con->{reader}->cancel ($error);
          delete $con->{reader};
        };
      }
    });
    $con->{state} = 'stopped';
  } else { # not to be closed
    $con->{timer} = AE::timer $Web::Transport::HTTPStream::ServerConnection::ReadTimeout, 0, sub { $con->_timeout };

    if ($con->{rbuf} =~ /[^\x0D\x0A]/) {
      $con->{state} = 'before request-line';
      $con->_ondata (undef);
    } else {
      $con->{state} = 'waiting';
    }
  }

  return;
  }

  delete $con->{stream};
  delete $con->{send_done};
  delete $con->{receive_done};
  delete $con->{response};
  delete $con->{write_mode};
  delete $con->{exit};

  if ($con->{to_be_closed}) {
    my ($r_written, $s_written) = promised_cv;
    if (defined $con->{writer}) {
      my $writer = $con->{writer};
      &promised_cleanup ($s_written, $writer->close);
      $con->{timer} = AE::timer 1, 0, sub {
        $writer->abort (_pe "HTTP completion timer (1)");
        $s_written->();
      };
      delete $con->{writer};
    } else {
      $s_written->();
    }
    $r_written->then (sub {
      if (defined $con->{reader}) { # XXX spec
        $con->closed->then (sub { delete $con->{timer} });
        $con->{timer} = AE::timer 1, 0, sub {
          return unless defined $con->{reader};
          $con->{reader}->cancel ($error);
          delete $con->{reader};
        };
      }
    });
    $con->{state} = 'stopped';
  } else {
    $con->{state} = 'waiting';
    $con->{response_received} = 0;
  }
} # _both_done

sub DESTROY ($) {
  local $@;
  eval { die };
  warn "$$: Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

# End of Web::Transport::HTTPStream

package Web::Transport::HTTPStream::ClientConnection;
push our @ISA, qw(Web::Transport::HTTPStream);
use Carp qw(croak);
use MIME::Base64 qw(encode_base64);
use Digest::SHA qw(sha1);
use AnyEvent;
use Promise;
use Promised::Flow;

BEGIN {
  *_e4d = \&Web::Transport::HTTPStream::_e4d;
  *_e4d_t = \&Web::Transport::HTTPStream::_e4d_t;
  *MAX_BYTES = \&Web::Transport::HTTPStream::MAX_BYTES;
  *_pe = \&Web::Transport::HTTPStream::_pe;
  *_pw = \&Web::Transport::HTTPStream::_pw;
}

my $BytesDataStates = {
  'response body' => 1,
  'response chunk data' => 1,
  'tunnel' => 1,
  # XXX request body
  # XXX ws data
};

sub _read ($) {
  my ($self) = @_;
  return unless defined $self->{reader};
  return if $self->{read_running};
  $self->{read_running} = 1;
  my $stream = $self->{stream};

  if ($BytesDataStates->{$self->{state}} and
      defined $stream->{body_controller}) {
    my $req = $stream->{body_controller}->byob_request;
    unless (defined $req) {
      delete $self->{read_running};
      return;
    }
    my $expected_size = $req->view->byte_length;
    if (defined $self->{unread_length} and $self->{unread_length} < $expected_size) {
      $expected_size = $self->{unread_length};
    }
    if ($expected_size > 0) {
      my $view = DataView->new
          ($req->view->buffer, $req->view->byte_offset, $expected_size);
      return $self->{reader}->read ($view)->then (sub {
        delete $self->{read_running};
        return if $_[0]->{done};

        my $length = $_[0]->{value}->byte_length;
        $stream->_receive_body ($_[0]->{value}, 1) if $self->{DEBUG};
        $req->manakai_respond_with_new_view ($_[0]->{value});

        if (defined $self->{unread_length}) {
          $self->{unread_length} -= $length;
          if ($self->{unread_length} <= 0) {
            $self->_process_rbuf ('');
          }
        }

        return $self->_read;
      }, sub {
        delete $self->{read_running};
        # $_[0] will be reported by $self->{reader}->closed->catch
      });
    } # $expected_size
  } # byob

  my $view = DataView->new (ArrayBuffer->new (1024*2));
  $view->buffer->manakai_label ('HTTP-client reading');
  return $self->{reader}->read ($view)->then (sub {
    delete $self->{read_running};
    return if $_[0]->{done};

    $self->_process_rbuf ($_[0]->{value});
    return $self->_read;
  }, sub {
    delete $self->{read_running};
    # $_[0] will be reported by $self->{reader}->closed->catch
  });
} # _read

sub _process_rbuf ($$) {
  my ($self, $view) = @_;
  my $ref = \'';
  my $offset = pos ($$ref) = 0;
  if (defined $view and ref $view) {
    $offset = $view->byte_offset;
    my $length = $view->byte_length;
    $ref = $view->buffer->manakai_transfer_to_scalarref;
    substr ($$ref, $offset + $length) = '';
    pos ($$ref) = $offset;
  }
  my $stream = $self->{stream};

  HEADER: {
    if ($self->{state} eq 'before response') {
      my $head = $self->{temp_buffer} . substr $$ref, pos ($$ref), 9;
      if ($head =~ /^.{0,4}[Hh][Tt][Tt][Pp]/s) {
        pos ($$ref) += $+[0] - length $self->{temp_buffer};
        $self->{response_received} = 1;
        $self->{temp_buffer} = '';
        $self->{state} = 'before response header';
      } elsif (8 <= length $head) {
        $self->{response_received} = 1;
        if ($stream->{request_method} eq 'PUT' or
            $stream->{request_method} eq 'CONNECT') {
          return $self->_connection_error (_pe "HTTP/0.9 response");
        } else {
          $stream->_headers_received;
          $stream->_receive_body
              (DataView->new (ArrayBuffer->new_from_scalarref (\($self->{temp_buffer}))));
          $self->{state} = 'response body';
          delete $self->{unread_length};
        }
      } else {
        $self->{temp_buffer} .= substr $$ref, pos $$ref;
        return;
      }
    }
    if ($self->{state} eq 'before response header') {
      if (not defined $view) { # EOF
        $self->{response}->{incomplete} = 1;
        #
      } else {
        if ($self->{temp_buffer} =~ /\x0A\x0D\z/ and
            $$ref =~ /\A\x0A/gcs) {
          $self->{temp_buffer} =~ s/\x0A\x0D\z//;
          #
        } elsif ($self->{temp_buffer} =~ /\x0A\z/ and
                 $$ref =~ /\A\x0D\x0A/gcs) {
          $self->{temp_buffer} =~ s/\x0A\z//;
          #
        } elsif ($self->{temp_buffer} =~ /\x0A\z/ and
                 $$ref =~ /\A\x0A/gcs) {
          $self->{temp_buffer} =~ s/\x0A\z//;
          #
        } elsif ($self->{temp_buffer} =~ /\x0A\z/ and
                 $$ref =~ /\A\x0D\z/gcs) {
          $self->{temp_buffer} .= "\x0D";
          return;
        } elsif ($$ref =~ /\G(.*?)\x0A\x0D?\x0A/gcs) {
          if (2**18-1 < (length $self->{temp_buffer}) + (length $1)) {
            return $self->_connection_error (_pe "Header section too large");
          }
          $self->{temp_buffer} .= $1;
          #
        } else {
          if (2**18-1 + 2 < (length $self->{temp_buffer}) + (length $$ref) - (pos $$ref)) {
            return $self->_connection_error (_pe "Header section too large");
          }
          $self->{temp_buffer} .= substr $$ref, pos $$ref;
          return;
        }
      }

      my $headers = [split /[\x0D\x0A]+/, $self->{temp_buffer}, -1];
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
            $res->{status_text} = $start_line;
          } else {
            $res->{status_text} = '';
          }
        }
      } elsif ($start_line =~ s{\A\x20+}{}) {
        if ($start_line =~ s/\A0*?([0-9]+)//) {
          $res->{status} = 0+$1;
          $res->{status} = 2**31-1 if $res->{status} > 2**31-1;
          if ($start_line =~ s/\A\x20//) {
            $res->{status_text} = $start_line;
          } else {
            $res->{status_text} = '';
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
        return $self->_connection_error
            (_pe "Inconsistent content-length values");
      } elsif (1 == keys %length) {
        my $length = each %length;
        $length =~ s/\A0+//;
        $length ||= 0;
        if ($length eq 0+$length) { # overflow check
          $self->{unread_length} = $res->{content_length} = 0+$length;
        } else {
          return $self->_connection_error
              (_pe "Inconsistent content-length values");
        }
      }

      if ($res->{status} == 200 and $stream->{request_method} eq 'CONNECT') {
        $stream->_headers_received (is_tunnel => 1);
        $self->{to_be_closed} = 1;
        $self->{state} = 'tunnel';
        delete $self->{unread_length};
      } elsif (defined $self->{ws_state} and
               $self->{ws_state} eq 'CONNECTING' and
               $res->{status} == 101) {
        my $failed = 0;
        {
          my $ug = '';
          my $con = '';
          my $accept = '';
          my $proto;
          my $exts = '';
          for (@{$res->{headers}}) {
            if ($_->[2] eq 'upgrade') {
              $ug .= ',' . $_->[1];
            } elsif ($_->[2] eq 'connection') {
              $con .= ',' . $_->[1];
            } elsif ($_->[2] eq 'sec-websocket-accept') {
              $accept .= ',' if not defined $accept;
              $accept .= $_->[1];
            } elsif ($_->[2] eq 'sec-websocket-protocol') {
              $proto .= ',' if defined $proto;
              $proto .= $_->[1];
            } elsif ($_->[2] eq 'sec-websocket-extensions') {
              $exts .= ',' . $_->[2];
            }
          }
          $ug =~ tr/A-Z/a-z/;
          do { $failed = 1; last } unless
              grep { $_ eq 'websocket' } map {
                s/\A[\x09\x0A\x0D\x20]+//; s/[\x09\x0A\x0D\x20]+\z//; $_;
              } split /,/, $ug;
          $con =~ tr/A-Z/a-z/;
          do { $failed = 1; last } unless
              grep { $_ eq 'upgrade' } map {
                s/\A[\x09\x0A\x0D\x20]+//; s/[\x09\x0A\x0D\x20]+\z//; $_;
              } split /,/, $con;
          do { $failed = 1; last } unless
              $accept eq encode_base64 sha1 ($self->{ws_key} . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'), '';
          if (defined $proto) {
            do { $failed = 1; last }
                if not grep { $_ eq $proto } @{$self->{ws_protos}};
          } else {
            do { $failed = 1; last } if @{$self->{ws_protos}};
          }
          do { $failed = 1; last }
              if grep { length $_ } split /,/, $exts;
        }
        if ($failed) {
          $stream->_headers_received;
          $stream->_receive_bytes_done;
          return $self->_connection_error
              (Web::Transport::ProtocolError::WebSocketClose->new (1006, '', _pe 'Bad WebSocket handshake'));
        } else {
          $self->{ws_state} = 'OPEN';
          $stream->_headers_received (is_ws => 1);
          $stream->_receive_bytes_done;
          $self->{to_be_closed} = 1;
          $self->{state} = 'before ws frame';
          $self->{temp_buffer} = '';
        }
      } elsif (100 <= $res->{status} and $res->{status} <= 199) {
        if ($stream->{request_method} eq 'CONNECT' or
            (defined $self->{ws_state} and
             $self->{ws_state} eq 'CONNECTING')) {
          return $self->_connection_error
              (_pe "1xx response to CONNECT or WS");
        } else {
          #push @{$res->{'1xxes'} ||= []}, {
          #  version => $res->{version},
          #  status => $res->{status},
          #  status_text => $res->{status_text},
          #  headers => $res->{headers},
          #};
          $res->{version} = '0.9';
          $res->{status} = 200;
          $res->{status_text} = 'OK';
          $res->{headers} = [];
          $self->{state} = 'before response';
          $self->{temp_buffer} = '';
          redo HEADER;
        }
      } elsif ($res->{status} == 204 or
               $res->{status} == 205 or
               $res->{status} == 304 or
               $stream->{request_method} eq 'HEAD') {
        $stream->_headers_received;
        $self->{unread_length} = 0;
        $self->{state} = 'response body';
      } else {
        $stream->_headers_received;
        if ($chunked) {
          $self->{state} = 'before response chunk';
        } else {
          $self->{state} = 'response body';
        }
      }
    } # before response header
  } # HEADER

  if ($self->{state} eq 'response body') {
    if (defined $self->{unread_length}) {
      my $len = (length $$ref) - (pos $$ref);
      if ($self->{unread_length} >= $len) {
        if ($len) {
          $stream->_receive_body
              (DataView->new (ArrayBuffer->new_from_scalarref (\substr $$ref, pos $$ref)));
          $ref = \'';
          $self->{unread_length} -= $len;
        }
      } elsif ($self->{unread_length} > 0) {
        $stream->_receive_body
            (DataView->new (ArrayBuffer->new_from_scalarref (\substr $$ref, (pos $$ref), $self->{unread_length})));
        pos ($$ref) += $self->{unread_length};
        $self->{unread_length} = 0;
      }
      if ($self->{unread_length} <= 0) {
        $self->{stream}->_receive_bytes_done;

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
            $self->{to_be_closed} = 1;
            last;
          } elsif ($_ eq 'keep-alive') {
            $keep_alive = 1;
          }
        }
        $self->{to_be_closed} = 1 unless $keep_alive;

        $self->_receive_done;
      }
    } else {
      $stream->_receive_body
          (DataView->new (ArrayBuffer->new_from_scalarref (\substr $$ref, pos $$ref)))
          if (length $$ref) - (pos $$ref);
      $ref = \'';
    }
  }

  CHUNK: {
    if ($self->{state} eq 'before response chunk') {
      if ($$ref =~ /\G([0-9A-Fa-f]+)/gc) {
        $self->{temp_buffer} = $1;
        $self->{state} = 'response chunk size';
      } elsif ((length $$ref) - (pos $$ref)) {
        $self->{response}->{incomplete} = 1;
        $self->{stream}->_receive_bytes_done;
        return $self->_connection_error (_pw 'Invalid chunk size');
      }
    }
    if ($self->{state} eq 'response chunk size') {
      if ($$ref =~ /\G([0-9A-Fa-f]+)/gc) {
        # XXX better overflow handling
        $self->{temp_buffer} .= $1;
      }

      if ((pos $$ref) < (length $$ref)) {
        $self->{temp_buffer} =~ tr/A-F/a-f/;
        $self->{temp_buffer} =~ s/^0+//;
        $self->{temp_buffer} ||= 0;
        my $n = hex $self->{temp_buffer}; # XXX overflow warning
        unless ($self->{temp_buffer} eq sprintf '%x', $n) { # overflow
          $self->{response}->{incomplete} = 1;
          $self->{stream}->_receive_bytes_done;
          return $self->_connection_error (_pw 'Chunk size overflow');
        }
        if ($n == 0) {
          $self->{stream}->_receive_bytes_done;
          $self->{state} = 'before response trailer';
          $self->{temp_buffer} = 0;
        } else {
          $self->{unread_length} = $n;
          if ($$ref =~ /\G\x0A/gc) {
            $self->{state} = 'response chunk data';
          } else {
            $self->{state} = 'response chunk extension';
          }
        }
      }
    } # response chunk size
    if ($self->{state} eq 'response chunk extension') {
      $$ref =~ /\G[^\x0A]+/gc;
      if ($$ref =~ /\G\x0A/gc) {
        $self->{state} = 'response chunk data';
      }
    }
    if ($self->{state} eq 'response chunk data') {
      if ($self->{unread_length} > 0) {
        my $len = (length $$ref) - (pos $$ref);
        if ($len <= 0) {
          #
        } elsif ($self->{unread_length} >= $len) {
          $stream->_receive_body
              (DataView->new (ArrayBuffer->new_from_scalarref (\substr $$ref, pos $$ref)));
          $ref = \'';
          $self->{unread_length} -= $len;
        } else {
          $stream->_receive_body
              (DataView->new (ArrayBuffer->new_from_scalarref (\substr $$ref, (pos $$ref), $self->{unread_length})));
          (pos $$ref) += $self->{unread_length};
          $self->{unread_length} = 0;
        }
      }
      if ($self->{unread_length} <= 0) {
        if ($$ref =~ /\G\x0D?\x0A/gc) {
          delete $self->{unread_length};
          $self->{state} = 'before response chunk';
          redo CHUNK;
        } elsif ($$ref =~ /\G\x0D/gc) {
          $self->{state} = 'after response chunk CR';
        } elsif ((length $$ref) - (pos $$ref)) {
          delete $self->{unread_length};
          $self->{response}->{incomplete} = 1;
          $self->{stream}->_receive_bytes_done;
          return $self->_connection_error (_pw 'No CRLF after chunk');
        }
      }
    }
    if ($self->{state} eq 'after response chunk CR') {
      if ($$ref =~ /\G\x0A/gc) {
        delete $self->{unread_length};
        $self->{state} = 'before response chunk';
        redo CHUNK;
      } elsif ((length $$ref) - (pos $$ref)) {
        delete $self->{unread_length};
        $self->{response}->{incomplete} = 1;
        $self->{stream}->_receive_bytes_done;
        return $self->_connection_error (_pw 'No CRLF after chunk');
      }
    }
  } # CHUNK
  if ($self->{state} eq 'before response trailer') {
    if ($$ref =~ /\G(.*?)\x0A\x0D?\x0A/gcs) {
      if (2**18-1 < $self->{temp_buffer} + (length $1)) {
        return $self->_connection_error (_pw 'Header section too large');
      }
      $self->{temp_buffer} += length $1;
      #
    } else {
      if (2**18-1 < $self->{temp_buffer} + (length $$ref) - (pos $$ref)) {
        return $self->_connection_error (_pw 'Header section too large');
      }
      $self->{temp_buffer} += (length $$ref) - (pos $$ref);
      return;
    }

    my $connection = '';
    for (@{$self->{response}->{headers} || []}) {
      if ($_->[2] eq 'connection') {
        $connection .= ',' . $_->[1];
      }
    }
    $connection =~ tr/A-Z/a-z/; ## ASCII case-insensitive
    for (split /[\x09\x20]*,[\x09\x20]*/, $connection) {
      if ($_ eq 'close') {
        $self->{to_be_closed} = 1;
        last;
      }
    }
    $self->_receive_done;
    return;
  } # before response trailer
  if ($self->{state} eq 'before ws frame' or
      $self->{state} eq 'ws data' or
      $self->{state} eq 'ws terminating') {
    return $self->_ws_received ($ref);
  }
  if ($self->{state} eq 'tunnel') {
    $stream->_receive_body
        (DataView->new (ArrayBuffer->new_from_scalarref (\substr $$ref, pos $$ref)))
        if (length $$ref) - (pos $$ref);
    $ref = \'';
  }
  #if ($self->{state} eq 'waiting' or
  #    $self->{state} eq 'sending' or
  #    $self->{state} eq 'stopped') {
  #  #
  #}
} # _process_rbuf

sub _process_rbuf_eof ($$) {
  my ($self, $error) = @_;
  my $stream = $self->{stream};
  
  if ($self->{state} eq 'before response') {
    if (length $self->{temp_buffer}) {
      if ($stream->{request_method} eq 'PUT' or
          $stream->{request_method} eq 'CONNECT') {
        return $self->_connection_error
            (defined $error ? $error : _pe "HTTP/0.9 response");
      } else {
        $stream->_headers_received;
        $stream->_receive_body
            (DataView->new (ArrayBuffer->new_from_scalarref (\($self->{temp_buffer}))));
        $self->{response}->{incomplete} = 1 if defined $error;
        $stream->_receive_bytes_done;
        return $self->_connection_error (_pw 'Connection truncated') # XXX associate $error
            if defined $error;

        $self->{to_be_closed} = 1;
        $self->_receive_done;
        return;
      }
    } else { # empty
      return $self->_connection_error ($error) if defined $error;
      return $self->_connection_error
          (Web::Transport::ProtocolError::HTTPParseError->_new_retry ("Connection closed without response", !$self->{response_received}));
    }
  } elsif ($self->{state} eq 'response body') {
    if (defined $self->{unread_length}) {
      if ($self->{unread_length} > 0) {
        $self->{response}->{incomplete} = 1;
        $self->{stream}->_receive_bytes_done;
        if ($self->{response}->{version} eq '1.1') {
          return $self->_connection_error
              (defined $error ? $error : _pe 'Connection truncated');
        } else {
          return $self->_connection_error (_pw 'Connection truncated'); # XXX associate $error
        }
      } else { # all data read
        $self->{stream}->_receive_bytes_done;
        return $self->_connection_error (_pw 'Connection truncated') # XXX associate $error
            if defined $error;

        $self->{to_be_closed} = 1;
        $self->_receive_done;
        return;
      }
    } else {
      $self->{response}->{incomplete} = 1 if defined $error;
      $self->{stream}->_receive_bytes_done;
      return $self->_connection_error (_pw 'Connection truncated') # XXX associate $error
          if defined $error;

      $self->{to_be_closed} = 1;
      $self->_receive_done;
      return;
    }
  } elsif ({
    'before response chunk' => 1,
    'response chunk size' => 1,
    'response chunk extension' => 1,
    'response chunk data' => 1,
    'after response chunk CR' => 1, # XXX need tests
  }->{$self->{state}}) {
    $self->{response}->{incomplete} = 1;
    $self->{stream}->_receive_bytes_done;
    return $self->_connection_error (_pw 'Connection truncated within chunk'); # XXX associate $error
  } elsif ($self->{state} eq 'before response trailer') {
    return $self->_connection_error
        (_pw 'Connection truncated within trailer'); # XXX associate $error
  } elsif ($self->{state} eq 'tunnel') {
    $self->{stream}->_receive_bytes_done;
    return $self->_connection_error ($error) if defined $error;
    $self->{to_be_closed} = 1;
    $self->_receive_done;
    return;
  } elsif ($self->{state} eq 'before response header') {
    return $self->_connection_error
        (defined $error ? $error : _pe 'Connection truncated');
  } elsif ($self->{state} eq 'before ws frame' or
           $self->{state} eq 'ws data') {
    $self->{ws_state} = 'CLOSING';
    $self->{state} = 'ws terminating';
    return $self->_connection_error
        (Web::Transport::ProtocolError::WebSocketClose->new (1006, '', defined $error ? $error : _pe 'Connection truncated'));
  } elsif ($self->{state} eq 'ws terminating') {
    $self->{exit} = Web::Transport::ProtocolError::WebSocketClose->new
        (1006, '', $error)
            if defined $error and
               not Web::Transport::ProtocolError->is_error ($self->{exit});
    $self->_send_done (close => 1);
    $self->_receive_done;
    return;
  } elsif ($self->{state} eq 'sending') {
    return $self->_connection_error ($error) if defined $error;
    return $self->_receive_done;
  } elsif ($self->{state} eq 'stopped') {
    #
  } else {
    # initial
    # waiting
    return $self->_connection_error ($error) if defined $error;
    return $self->_connection_error (_pw 'Connection closed');
  }
} # _process_rbuf_eof

# End of ::ClientConnection

package Web::Transport::HTTPStream::ServerConnection;
push our @ISA, qw(Web::Transport::HTTPStream);
use AnyEvent;
use Promise;
use Promised::Flow;
use Web::Host;
use Web::URL;
use Web::Encoding;

our $ReadTimeout ||= 60;

BEGIN {
  *_e4d = \&Web::Transport::HTTPStream::_e4d;
  *_e4d_t = \&Web::Transport::HTTPStream::_e4d_t;
  *MAX_BYTES = \&Web::Transport::HTTPStream::MAX_BYTES;
  *_pcap = \&Web::Transport::HTTPStream::_pcap;
  *_pe = \&Web::Transport::HTTPStream::_pe;
}

sub _url_scheme ($) {
  return $_[0]->{url_scheme};
} # _url_scheme

sub _url_hostport ($) {
  return $_[0]->{url_hostport};
} # _url_hostport

sub _new_stream ($) {
  my $con = $_[0];

  my $stream = $con->{stream} = bless {
    is_server => 1,
    connection => $con,
    id => $con->{id} . '.' . $con->{next_stream_id}++,
    request => {
      headers => [],
      # method target_url version
    },
    # target
  }, 'Web::Transport::HTTPStream::Stream';

  if ($con->{DEBUG}) {
    warn "$con->{id}: ========== @{[ref $con]}\n";
    warn "$con->{id}: startstream $stream->{id} @{[scalar gmtime]}\n";
  }

  $stream->{headers_received} = _pcap;
  $stream->{closed} = _pcap;

  $con->{streams_controller}->enqueue ($stream);

  return $stream;
} # _new_stream

sub _read ($) {
  my $self = $_[0];
  return unless defined $self->{reader};
  my $read; $read = sub {
    return $self->{reader}->read (DataView->new (ArrayBuffer->new (1024*2)))->then (sub {
      return if $_[0]->{done};

      if ($self->{disable_timer}) {
        delete $self->{timer};
      } else {
        $self->{timer} = AE::timer $ReadTimeout, 0, sub { $self->_timeout };
      }
      $self->_ondata ($_[0]->{value});

      return $read->();
    });
  }; # $read;
  return $read->()->catch (sub {
    $self->abort ($_[0]);
    return undef;
  })->then (sub { undef $read });
} # _read

sub _ondata ($$) {
  my ($con, $in) = @_;
  my $stream = $con->{stream}; # or undef
  my $inref = defined $in ? \($in->manakai_to_string) : \'';
  while (1) {
    #warn "[$con->{state}] |$con->{rbuf}|";
    if ($con->{state} eq 'initial') {
      $con->{rbuf} .= $$inref;
      if ($con->{rbuf} =~ s/^\x0D?\x0A// or 2 <= length $con->{rbuf}) {
        $con->{state} = 'before request-line';
      } else {
        return;
      }
    } elsif ($con->{state} eq 'before request-line') {
      $con->{rbuf} .= $$inref;
      if ($con->{rbuf} =~ s/\A([^\x0A]{0,8191})\x0A//) {
        my $line = $1;
        $con->_new_stream;
        $stream = $con->{stream};
        $line =~ s/\x0D\z//;
        if ($line =~ /[\x00\x0D]/) {
          $stream->{request}->{version} = '0.9';
          $stream->{request}->{method} = 'GET';
          return $con->_connection_error (_pe 'Invalid byte in headers');
        }
        if ($line =~ s{\x20+(H[^\x20]*)\z}{}) {
          my $version = $1;
          if ($version =~ m{\AHTTP/1\.([0-9]+)\z}) {
            $stream->{request}->{version} = $1 =~ /[^0]/ ? '1.1' : '1.0';
          } elsif ($version =~ m{\AHTTP/0+1?\.}) {
            $stream->{request}->{version} = '0.9';
            $stream->{request}->{method} = 'GET';
            return $con->_connection_error (_pe 'Unknown HTTP version');
          } elsif ($version =~ m{\AHTTP/[0-9]+\.[0-9]+\z}) {
            $stream->{request}->{version} = 1.1;
          } else {
            $stream->{request}->{version} = '0.9';
            $stream->{request}->{method} = 'GET';
            return $con->_connection_error (_pe 'Unknown HTTP version');
          }
          if ($line =~ s{\A([^\x20]+)\x20+}{}) {
            $stream->{request}->{method} = $1;
          } else { # no method
            $stream->{request}->{method} = 'GET';
            return $con->_connection_error (_pe 'No request method');
          }
        } else { # no version
          $stream->{request}->{version} = '0.9';
          $stream->{request}->{method} = 'GET';
          unless ($line =~ s{\AGET\x20+}{}) {
            return $con->_connection_error (_pe 'Bad request method');
          }
        }
        $stream->{target} = $line;
        if ($stream->{target} =~ m{\A/}) {
          if ($stream->{request}->{method} eq 'CONNECT') {
            return $con->_connection_error (_pe 'Bad request-target host');
          } else {
            #
          }
        } elsif ($stream->{target} =~ m{^[A-Za-z][A-Za-z0-9.+-]+://}) {
          if ($stream->{request}->{method} eq 'CONNECT') {
            return $con->_connection_error (_pe 'Bad request-target host');
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
            return $con->_connection_error (_pe 'Bad request-target');
          }
        }
        if ($stream->{request}->{version} eq '0.9') {
          $con->_request_headers or return;
        } else { # 1.0 / 1.1
          return $con->_connection_error (_pe 'Bad request-target')
              unless length $line;
          $con->{state} = 'before request header';
        }
      } elsif (8192 <= length $con->{rbuf}) {
        $con->_new_stream;
        $stream = $con->{stream};
        $stream->{request}->{method} = 'GET';
        $stream->{request}->{version} = 1.1;
        return $con->_connection_error
            (_pe ('Bad target URL'), 414, 'Request-URI Too Large', []);
      } else {
        return;
      }
    } elsif ($con->{state} eq 'before request header') {
      $con->{rbuf} .= $$inref;
      if ($con->{rbuf} =~ s/\A([^\x0A]{0,8191})\x0A//) {
        my $line = $1;
        return $con->_connection_error (_pe 'Too many headers')
            if @{$stream->{request}->{headers}} == 100;
        $line =~ s/\x0D\z//;
        return $con->_connection_error (_pe 'Invalid byte in headers')
            if $line =~ /[\x00\x0D]/;
        if ($line =~ s/\A([^\x09\x20:][^:]*):[\x09\x20]*//) {
          my $name = $1;
          push @{$stream->{request}->{headers}}, [$name, $line];
        } elsif ($line =~ s/\A[\x09\x20]+// and
                 @{$stream->{request}->{headers}}) {
          if ((length $stream->{request}->{headers}->[-1]->[0]) + 1 +
              (length $stream->{request}->{headers}->[-1]->[1]) + 1 +
              (length $line) + 2 > 8192) {
            return $con->_connection_error (_pe 'Headers too large');
          } else {
            $stream->{request}->{headers}->[-1]->[1] .= " " . $line;
          }
        } elsif ($line eq '') { # end of headers
          $con->_request_headers or return;
          $stream = $con->{stream};
        } else { # broken line
          return $con->_connection_error (_pe 'Invalid header line');
        }
      } elsif (8192 <= length $con->{rbuf}) {
        return $con->_connection_error (_pe 'Headers too large');
      } else {
        return;
      }
    } elsif ($con->{state} eq 'request body') {
      my $ref = $inref;
      if (length $con->{rbuf}) {
        $ref = \($con->{rbuf} . $$inref); # string copy!
        $con->{rbuf} = '';
      }

      if (not defined $con->{unread_length}) {
        $stream->_receive_body
            (DataView->new (ArrayBuffer->new_from_scalarref ($ref)))
                if length $$ref;
        return;
      }

      my $in_length = length $$ref;
      if (not $in_length) {
        return;
      } elsif ($con->{unread_length} == $in_length) {
        if (defined $stream->{ws_key}) {
          $con->{state} = 'ws handshaking';
          $con->{to_be_closed} = 1;
        }
        $stream->_receive_body
            (DataView->new (ArrayBuffer->new_from_scalarref ($ref)));
        $stream->_receive_bytes_done;
        unless (defined $stream->{ws_key}) {
          $con->_receive_done;
        }
      } elsif ($con->{unread_length} < $in_length) { # has redundant data
        $stream->{incomplete} = 1;
        $con->{to_be_closed} = 1;
        if (defined $stream->{ws_key}) {
          $con->{state} = 'ws handshaking';
        }
        $stream->_receive_body
            (DataView->new (ArrayBuffer->new_from_scalarref ($ref), 0, $con->{unread_length}));
        $stream->_receive_bytes_done;
        unless (defined $stream->{ws_key}) {
          $con->_receive_done;
        }
        return;
      } else { # unread_length > $in_length
        $con->{unread_length} -= $in_length;
        $stream->_receive_body
            (DataView->new (ArrayBuffer->new_from_scalarref ($ref)));
        return;
      }
    } elsif ($con->{state} eq 'before ws frame' or
             $con->{state} eq 'ws data' or
             $con->{state} eq 'ws terminating') {
      my $ref = $inref;
      if (length $con->{rbuf}) {
        $ref = \($con->{rbuf} . $$inref); # XXX string copy!
        $con->{rbuf} = '';
      }
      pos ($$ref) = 0;
      return $con->_ws_received ($ref);
    } elsif ($con->{state} eq 'ws handshaking') {
      return unless length $$inref;
      return $con->_connection_error
          (_pe 'Invalid byte during WebSocket handshake');
    } elsif ($con->{state} eq 'sending') {
      $con->{rbuf} .= $$inref;
      $con->{rbuf} =~ s/^[\x0D\x0A]+//;
      return;
    } elsif ($con->{state} eq 'waiting') {
      $con->{rbuf} .= $$inref;
      $con->{rbuf} =~ s/^[\x0D\x0A]+//;
      if (defined $con->{writer} and $con->{rbuf} =~ /^[^\x0D\x0A]/) {
        $con->{state} = 'before request-line';
      } else {
        return;
      }
    } elsif ($con->{state} eq 'stopped') {
      return;
    } else {
      die "Bad state |$con->{state}|";
    }
    $inref = \'';
  } # while
} # _ondata

sub _oneof ($$) {
  my ($con, $error) = @_;
  if ($con->{state} eq 'before request header') {
    $con->{to_be_closed} = 1;
    $error = _pe 'Connection truncated' unless defined $error;
    return $con->_connection_error ($error);
  } elsif ($con->{state} eq 'request body') {
    $con->{to_be_closed} = 1;
    if (defined $con->{unread_length}) {
      # $con->{unread_length} > 0
      $con->{stream}->{incomplete} = 1;
      $error = _pe 'Connection truncated' unless defined $error;
    }
    $con->{stream}->_receive_bytes_done;
    $con->{exit} = $error; # or undef
    $con->_receive_done;
  } elsif ($con->{state} eq 'before ws frame' or
           $con->{state} eq 'ws data') {
    $con->{ws_state} = 'CLOSING';
    $con->{state} = 'ws terminating';
    $error = _pe 'Connection truncated' unless defined $error;
    return $con->_connection_error
        (Web::Transport::ProtocolError::WebSocketClose->new (1006, '', $error));
  } elsif ($con->{state} eq 'ws terminating') {
    $con->{exit} = Web::Transport::ProtocolError::WebSocketClose->new
        (1006, '', $error) if defined $error;
    $con->_send_done (close => 1);
    $con->_receive_done;
    return;
  } elsif ($con->{state} eq 'ws handshaking') {
    $error = _pe 'Connection truncated' unless defined $error;
    return $con->_connection_error ($error);
  } elsif ($con->{state} eq 'sending') {
    return $con->_connection_error ($error) if defined $error;
    return $con->_receive_done;
  } elsif ($con->{state} eq 'stopped') {
    #
  } else {
    # $con->{state} eq 'initial'
    # $con->{state} eq 'before request-line'
    # $con->{state} eq 'waiting'
    if (defined $error or not $con->{state} eq 'waiting') {
      if (defined $con->{writer}) {
        my $stream = $con->_new_stream;
        $stream->{request}->{version} = '0.9';
        $stream->{request}->{method} = 'GET';
      }
      $error = _pe 'Connection truncated' unless defined $error;
      return $con->_connection_error ($error);
    }
    $con->_send_done (close => 1);
    return $con->_receive_done;
  }
} # _oneof

sub _request_headers ($) {
  my $con = $_[0];
  my $stream = $con->{stream};

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
    $con->_connection_error (_pe "Bad |Host:|");
    return 0;
  } else { # no Host:
    if ($stream->{request}->{version} == 1.1) {
      $con->_connection_error (_pe "Bad |Host:|");
      return 0;
    }
  }

  ## Request-target and Host:
  my $target_url;
  my $host_host;
  my $host_port;
  if ($stream->{request}->{method} eq 'CONNECT') {
    if (defined $host) {
      ($host_host, $host_port) = Web::Host->parse_hostport_string ($host);
      unless (defined $host_host) {
        $con->_connection_error (_pe 'Bad |Host:|');
        return 0;
      }
    }

    my $target = delete $stream->{target};
    $target =~ s/([\x80-\xFF])/sprintf '%%%02X', ord $1/ge;
    my ($target_host, $target_port) = Web::Host->parse_hostport_string ($target);
    unless (defined $target_host) {
      $con->_connection_error (_pe 'Bad |Host:|');
      return 0;
    }
    $target_url = Web::URL->parse_string ("http://$target/");
  } elsif ($stream->{target} eq '*') {
    if (defined $host) {
      ($host_host, $host_port) = Web::Host->parse_hostport_string ($host);
      unless (defined $host_host) {
        $con->_connection_error (_pe 'Bad |Host:|');
        return 0;
      }
      my $scheme = $con->_url_scheme;
      $target_url = Web::URL->parse_string ("$scheme://$host/");
      delete $stream->{target};
    } else {
      $con->_connection_error (_pe 'Bad |Host:|');
      return 0;
    }
  } elsif ($stream->{target} =~ m{\A/}) {
    if (defined $host) {
      ($host_host, $host_port) = Web::Host->parse_hostport_string ($host);
      unless (defined $host_host) {
        $con->_connection_error (_pe 'Bad |Host:|');
        return 0;
      }
    }

    my $scheme = $con->_url_scheme;
    my $target = delete $stream->{target};
    $target =~ s/([\x80-\xFF])/sprintf '%%%02X', ord $1/ge;
    if (defined $host_host) {
      $target_url = Web::URL->parse_string ("$scheme://$host$target");
    } else {
      my $hostport = $con->_url_hostport;
      $target_url = Web::URL->parse_string ("$scheme://$hostport$target");
    }
    if (not defined $target_url or not defined $target_url->host) {
      $con->_connection_error (_pe 'Bad request-target URL');
      return 0;
    }
  } else { # absolute URL
    my $target = delete $stream->{target};
    $target =~ s/([\x80-\xFF])/sprintf '%%%02X', ord $1/ge;
    $target_url = Web::URL->parse_string ($target);
    if (not defined $target_url or not defined $target_url->host) {
      $con->_connection_error (_pe 'Bad request-target URL');
      return 0;
    }

    if (defined $host) {
      ($host_host, $host_port) = Web::Host->parse_hostport_string ($host);
      unless (defined $host_host) {
        $con->_connection_error (_pe 'Bad |Host:|');
        return 0;
      }
    }
  }
  if (defined $host_host and defined $target_url) {
    unless ($host_host->equals ($target_url->host)) {
      $con->_connection_error (_pe 'Bad |Host:|');
      return 0;
    }
    my $target_port = $target_url->port;
    $host_port = Web::URL->parse_string ($target_url->scheme . '://' . $host)->port;
    if (defined $host_port and defined $target_port and
        $host_port eq $target_port) {
      #
    } elsif (not defined $host_port and not defined $target_port) {
      #
    } else {
      $con->_connection_error (_pe 'Bad |Host:|');
      return 0;
    }
  }
  # XXX SNI host
  $stream->{request}->{target_url} = $target_url;

  ## Connection:
  my $conn = join ',', '', @{$headers{connection} or []}, '';
  $conn =~ tr/A-Z/a-z/; ## ASCII case-insensitive.
  if ($conn =~ /,[\x09\x20]*close[\x09\x20]*,/) {
    $con->{to_be_closed} = 1;
  } elsif ($stream->{request}->{version} != 1.1) {
    unless ($conn =~ /,[\x09\x20]*keep-alive[\x09\x20]*,/) {
      $con->{to_be_closed} = 1;
    }
  }

  ## Upgrade: websocket
  my $is_ws;
  if (@{$headers{upgrade} or []} == 1) {
    WS_OK: {
      my $status = 400;
      WS_CHECK: {
        last WS_CHECK unless $stream->{request}->{method} eq 'GET';
        last WS_CHECK unless $stream->{request}->{version} == 1.1;
        last WS_CHECK unless $stream->{request}->{target_url}->is_http_s;
        my $upgrade = $headers{upgrade}->[0];
        $upgrade =~ tr/A-Z/a-z/; ## ASCII case-insensitive;
        last WS_CHECK unless $upgrade eq 'websocket';
        last WS_CHECK unless $conn =~ /,[\x09\x20]*upgrade[\x09\x20]*,/;

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

        $is_ws = 1;
        last WS_OK;
      } # WS_CHECK

      if ($status == 426) {
        $con->_connection_error ((_pe 'Bad WebSocket version'), 426, 'Upgrade Required', [
          ['Upgrade', 'websocket'],
          ['Sec-WebSocket-Version', '13'],
        ]);
      } else {
        $con->_connection_error (_pe 'WebSocket handshake error');
      }
      return 0;
    } # WS_OK
  } elsif (@{$headers{upgrade} or []}) {
    $con->_connection_error (_pe 'Bad |Upgrade:|');
    return 0;
  }

  ## Transfer-Encoding:
  if (@{$headers{'transfer-encoding'} or []}) {
    $con->_connection_error
        (_pe ('|Transfer-Encoding:| in request'), 411, 'Length Required', []);
    return 0;
  }

  ## Content-Length:
  my $l = 0;
  if (@{$headers{'content-length'} or []} == 1 and
      $headers{'content-length'}->[0] =~ /\A[0-9]+\z/) {
    $l = 0+$headers{'content-length'}->[0]
        unless $stream->{request}->{method} eq 'CONNECT';
  } elsif (@{$headers{'content-length'} or []}) { # multiple headers or broken
    $con->_connection_error (_pe 'Bad |Content-Length:|');
    return 0;
  }
  $stream->{request}->{body_length} = $l;

  if (defined $stream->{ws_key}) {
    unless ($l == 0) {
      $con->_connection_error (_pe 'Bad |Content-Length:|');
      return 0;
    }
    $stream->_headers_received (is_ws => 1, is_request => 1);
    $con->{state} = 'ws handshaking';
    $con->{to_be_closed} = 1;
    delete $con->{timer};
    $con->{disable_timer} = 1;
  } elsif ($stream->{request}->{method} eq 'CONNECT') {
    $stream->_headers_received (is_tunnel => 1, is_request => 1);
    $con->{state} = 'request body';
    $con->{to_be_closed} = 1;
    delete $con->{timer};
    $con->{disable_timer} = 1;
  } elsif ($l == 0) {
    $stream->_headers_received (is_request => 1);
    $stream->_receive_bytes_done;
    $con->_receive_done;
  } else {
    $stream->_headers_received (is_request => 1);
    $con->{unread_length} = $l;
    $con->{state} = 'request body';
  }

  return 1;
} # _request_headers

sub _timeout ($) {
  my $self = $_[0];
  delete $self->{timer};
  return $self->abort
      (Web::Transport::TypeError->new ("Read timeout ($ReadTimeout)"));
} # _timeout

# End of ::ServerConnection

package Web::Transport::HTTPStream::Stream;
use Carp qw(croak);
use MIME::Base64 qw(encode_base64);
use Digest::SHA qw(sha1);
use Web::Encoding;
use ArrayBuffer;
use DataView;
use AnyEvent;
use Promise;
use Promised::Flow;
use Web::DateTime;
use Web::DateTime::Clock;

push our @CARP_NOT, qw(
  Web::Transport::TypeError
  Web::Transport::ProtocolError::HTTPParseError
  Web::Transport::ProtocolError::WebSocketClose
  Web::Transport::HTTPStream::ClientConnection
  Web::Transport::HTTPStream::ServerConnection
  WritableStream WritableStreamDefaultWriter
);

## This class represents an HTTP stream, which is an interchange of a
## request and response pair.

BEGIN {
  *_e4d = \&Web::Transport::HTTPStream::_e4d;
  *_e4d_t = \&Web::Transport::HTTPStream::_e4d_t;
  *MAX_BYTES = \&Web::Transport::HTTPStream::MAX_BYTES;
  *_pcap = \&Web::Transport::HTTPStream::_pcap;
}

sub _open_sending_stream ($$;%) {
  my ($stream, $slot_length, %args) = @_;
  my $con = $stream->{connection};
  my $canceled = 0;

  my $ws = ($con->{write_mode} eq 'ws' || $con->{write_mode} eq 'before tunnel data') ? undef : WritableStream->new ({
    start => sub {
      my $wc = $_[1];
      $con->{cancel_current_writable_stream} = sub {
        $wc->error ($_[0]) if defined $_[0];
        $canceled = 1;
        delete $con->{cancel_current_writable_stream};
      };
    }, # start
    write => sub {
      my $chunk = $_[1];
      # XXX error location
      return Promise->resolve->then (sub {
        die Web::Transport::TypeError->new ("The argument is not an ArrayBufferView")
            unless UNIVERSAL::isa ($chunk, 'ArrayBufferView');

      my $wm = $con->{write_mode} || '';
      if ($wm eq 'chunked') {
        my $byte_length = $chunk->byte_length; # can throw
        die Web::Transport::TypeError->new
            (sprintf "Byte length %d is greater than expected length 0",
                 $byte_length) if $canceled;
        return unless $byte_length;

        my $dv = UNIVERSAL::isa ($chunk, 'DataView')
            ? $chunk : DataView->new ($chunk->buffer, $chunk->byte_offset, $byte_length); # or throw
        if ($con->{DEBUG} > 1) {
          for (split /\x0A/, $dv->manakai_to_string, -1) {
            warn "$stream->{id}: S: @{[_e4d $_]}\n";
          }
        }

        ## Note that some clients fail to parse chunks if there are
        ## TCP segment boundaries within a chunk (which is smaller
        ## than MSS).
        return $con->{writer}->write
            (DataView->new (ArrayBuffer->new_from_scalarref
                (\sprintf "%X\x0D\x0A%s\x0D\x0A", $byte_length, $dv->manakai_to_string))); # XXX string copy!

        } else { # raw
          my $byte_length = $chunk->byte_length; # can throw
          die Web::Transport::TypeError->new
              (sprintf "Byte length %d is greater than expected length %d",
                   $byte_length, ($canceled ? 0 : $slot_length || 0))
                  if $canceled or
                     (defined $slot_length and $slot_length < $byte_length);
          return unless $byte_length;

          if ($con->{DEBUG}) {
            my $dv = UNIVERSAL::isa ($chunk, 'DataView')
                ? $chunk : DataView->new ($chunk->buffer, $chunk->byte_offset, $byte_length); # or throw
            if ($con->{DEBUG} > 1 or $byte_length <= 40) {
              for (split /\x0A/, $dv->manakai_to_string, -1) {
                warn "$stream->{id}: S: @{[_e4d $_]}\n";
              }
            } else {
              warn "$stream->{id}: S: @{[_e4d substr $_, 0, 40]}... (@{[length $_]})\n"
                  for $dv->manakai_to_string;
            }
          } # DEBUG

          my $sent;
          my $mask = $con->{ws_encode_mask_key};
          if (defined $mask) {
            my @data;
            $chunk = DataView->new ($chunk->buffer, $chunk->byte_offset, $byte_length); # or throw
            my $ref = \($chunk->manakai_to_string);
            my $o = $con->{ws_sent_length};
            for (0..($byte_length-1)) {
              push @data, substr ($$ref, $_, 1) ^ substr ($mask, ($o+$_) % 4, 1);
            }
            $sent = $con->{writer}->write
                (DataView->new (ArrayBuffer->new_from_scalarref (\join '', @data)));
          } else {
            $sent = $con->{writer}->write ($chunk);
          }

          if (defined $slot_length) {
            $slot_length -= $byte_length;
            $con->{ws_sent_length} += $byte_length if defined $con->{ws_pendings};
            if ($slot_length <= 0) {
              delete $con->{cancel_current_writable_stream};
              $canceled = 1;
              if (defined $con->{ws_pendings}) {
                $con->{write_mode} = 'ws';
                delete $con->{ws_pendings};
                for (@{$con->{ws_pendings}}) {
                  $stream->_ws_debug ('S', @{$_->[2]}) if $con->{DEBUG};
                  $con->{writer}->write ($_->[1]);
                  if ($_->[0] == 8) { # close
                    $con->_send_done;
                  }
                }
              } else {
                $con->_send_done;
              }
            }
          }
          return $sent;
        }
      })->catch (sub {
        my $error = Web::Transport::Error->wrap ($_[0]);
        $con->{cancel_current_writable_stream}->($error)
            if defined $con->{cancel_current_writable_stream};
        $con->abort ($error);
        die $error;
      });
    }, # write
    close => sub {
      return if $canceled;
      if (defined $slot_length) {
        if ($slot_length > 0) {
          my $error = Web::Transport::TypeError->new
              (sprintf "Closed before bytes (n = %d) are sent", $slot_length);
          $con->{cancel_current_writable_stream}->($error)
              if defined $con->{cancel_current_writable_stream};
          $con->abort ($error);
          die $error;
        }
      }

      delete $con->{cancel_current_writable_stream};
      $canceled = 1;
      if ($con->{write_mode} eq 'chunked') {
        # XXX trailer headers
        my $p = $con->{writer}->write
            (DataView->new (ArrayBuffer->new_from_scalarref (\"0\x0D\x0A\x0D\x0A")));
        $con->_send_done;
        return $p;
      } elsif (not defined $slot_length) {
        $con->_send_done (close => 1);
        return;
      }
    }, # close
    abort => sub {
      my $error = Web::Transport::Error->wrap ($_[1]);
      $con->{cancel_current_writable_stream}->($error)
          if defined $con->{cancel_current_writable_stream};
      return $con->abort ($error);
    }, # abort
  }); # $ws

  if (defined $slot_length and $slot_length <= 0) {
    delete $con->{cancel_current_writable_stream};
    $canceled = 1;
    if (defined $con->{ws_pendings}) {
      $con->{write_mode} = 'ws';
      delete $con->{ws_pendings};
    } elsif ($con->{write_mode} eq 'chunked') {
      # XXX trailer headers
      $con->{writer}->write
          (DataView->new (ArrayBuffer->new_from_scalarref (\"0\x0D\x0A\x0D\x0A")));
      $con->_send_done;
    } else {
      $con->_send_done;
    }
  }

  return ($ws);
} # _open_sending_stream

## Return the |headers_received| promise of the HTTP stream, which is
## fulfilled when a header section has been received.  It is rejected
## if there is an error before receiving the headers.
sub headers_received ($) {
  return $_[0]->{headers_received}->[0];
} # headers_received

sub _headers_received ($;%) {
  my ($stream, %args) = @_;
  my $con = $stream->{connection};
  my $return = $args{is_request} ? $stream->{request} : $stream->{response};
  if ($args{is_ws}) {
    my $read_message_stream = ReadableStream->new ({
      start => sub {
        $stream->{messages_controller} = $_[1];
      },
      pull => sub {
        return $stream->{connection}->_read;
      },
      cancel => sub {
        delete $stream->{messages_controller};
        return $con->abort (Web::Transport::Error->wrap ($_[1]));
      }, # cancel
    });
    $return->{messages} = $read_message_stream;
    $stream->{closing} = _pcap;
    $return->{closing} = $stream->{closing}->[0];
  } else { # not is_ws
    my $read_stream = ReadableStream->new ({
      type => 'bytes',
      auto_allocate_chunk_size => 1024*2,
      start => sub {
        $stream->{body_controller} = $_[1];
        return undef;
      },
      pull => sub {
        return $stream->{connection}->_read;
      },
      cancel => sub {
        delete $stream->{body_controller};
        return $con->abort (Web::Transport::Error->wrap ($_[1]));
      },
    });
    if (defined $con->{write_mode} and
        $con->{write_mode} eq 'before tunnel data') {
      if ($args{is_tunnel}) {
        $con->{write_mode} = 'raw';
        my ($ws) = $stream->_open_sending_stream (undef);
        $return->{writable} = $ws;
        $return->{readable} = $read_stream;
      } else {
        $con->_send_done;
        $return->{body} = $read_stream;
      }
    } else {
      if ($args{is_tunnel}) {
        $stream->{tunnel_readable} = $read_stream;
      } else {
        $return->{body} = $read_stream;
      }
    }
  } # not is_ws
  (delete $stream->{headers_received}->[1])->($return), delete $stream->{headers_received}->[2];

  if ($con->{DEBUG}) {
    if ($args{is_request}) {
      my $url = $return->{target_url}->stringify;
      warn "$stream->{id}: R: $return->{method} $url HTTP/$return->{version}\n";
    } else { # response
      if ($return->{version} eq '0.9') {
        warn "$stream->{id}: R: HTTP/0.9\n";
      } else {
        warn "$stream->{id}: R: HTTP/$return->{version} $return->{status} $return->{status_text}\n";
      }
    }
    for (@{$return->{headers}}) {
      warn "$stream->{id}: R: @{[_e4d $_->[0]]}: @{[_e4d $_->[1]]}\n";
    }
    warn "$stream->{id}: WS established\n" if $args{is_ws};
    warn "$stream->{id}: R: \n";
  } # DEBUG
} # _headers_received

sub _receive_body ($$;$) {
  my ($stream, $dv, $dump_only) = @_;

  my $con = $stream->{connection};
  if ($con->{DEBUG}) {
    if ($con->{DEBUG} > 1 or $dv->byte_length <= 40) { # or throw
      for (split /\x0D?\x0A/, $dv->manakai_to_string, -1) {
        warn "$stream->{id}: R: @{[_e4d $_]}\n";
      }
    } else {
      warn "$stream->{id}: R: @{[_e4d substr $dv->manakai_to_string, 0, 40]}... (@{[$dv->byte_length]})\n";
    }
  }

  $stream->{body_controller}->enqueue ($dv) unless $dump_only; # or throw
} # _receive_body

sub _receive_text ($$) {
  my ($stream, $tref) = @_;
  my $con = $stream->{connection};
  if ($con->{DEBUG} > 1 or length $$tref <= 40) {
    for (split /\x0D?\x0A/, $$tref, -1) {
      warn "$stream->{id}: R: @{[_e4d_t $$tref]}\n";
    }
  } else {
    warn "$stream->{id}: R: @{[_e4d_t substr $$tref, 0, 40]}... (@{[length $$tref]})\n";
  }
} # _receive_text

sub _receive_bytes_done ($) {
  my $stream = $_[0];
  if (defined (my $rc = delete $stream->{body_controller})) {
    $rc->close;
    my $req = $rc->byob_request;
    $req->manakai_respond_with_new_view
        (DataView->new (ArrayBuffer->new (0))) if defined $req;
  }
  return undef;
} # _receive_bytes_done

sub _send_request ($$) {
  my ($stream, $req) = @_;

  # XXX input validation
  my $method = defined $req->{method} ? $req->{method} : '';
  if (not length $method or $method =~ /[\x0D\x0A\x09\x20]/) {
    croak "Bad |method|: |$method|";
  }
  my $url = $req->{target};
  if (not defined $url or
      not length $url or
      $url =~ /[\x0D\x0A]/ or
      $url =~ /\A[\x09\x20]/ or
      $url =~ /[\x09\x20]\z/) {
    croak "Bad |target|: |$url|";
  }
  for (@{$req->{headers} or []}) {
    croak "Bad header name |@{[_e4d $_->[0]]}|"
        unless $_->[0] =~ /\A[!\x23-'*-+\x2D-.0-9A-Z\x5E-z|~]+\z/;
    croak "Bad header value |@{[_e4d $_->[1]]}|"
        unless $_->[1] =~ /\A[\x00-\x09\x0B\x0C\x0E-\xFF]*\z/;
  }

  my $cl = $req->{length};
  if ($method eq 'CONNECT') {
    return Promise->reject
        (Web::Transport::TypeError->new ("Bad byte length $cl")) if defined $cl;
  } else {
    $cl = 0+($cl || 0);
    return Promise->reject
        (Web::Transport::TypeError->new ("Bad byte length $cl"))
            unless $cl =~ /\A[0-9]+\z/;
    if ($cl > 0 or $method eq 'POST' or $method eq 'PUT') {
      push @{$req->{headers} ||= []}, ['Content-Length', $cl];
    }
  }

  # XXX croak if WS protocols is bad
  # XXX utf8 flag
  # XXX header size

  my $con = $stream->{connection};
  if (not defined $con->{state}) {
    return Promise->reject
        (Web::Transport::TypeError->new ("Connection is not ready"));
  } elsif ($con->{to_be_closed}) {
    return Promise->reject (Web::Transport::TypeError->new ("Connection is closed"));
  } elsif (not ($con->{state} eq 'initial' or $con->{state} eq 'waiting')) {
    return Promise->reject (Web::Transport::TypeError->new ("Connection is busy"));
  }

  $stream->{id} = $con->{id} . '.' . $con->{next_stream_id}++;
  if ($con->{DEBUG}) {
    warn "$con->{id}: ========== @{[ref $con]}\n";
    warn "$con->{id}: startstream $stream->{id} @{[scalar gmtime]}\n";
  }

  $stream->{headers_received} = _pcap;
  $stream->{closed} = _pcap;

  $con->{stream} = $stream;
  $stream->{request_method} = $method;
  my $res = $stream->{response} = $con->{response} = {
    status => 200, status_text => 'OK', version => '0.9',
    headers => [],
  };
  $con->{state} = 'before response';
  $con->{temp_buffer} = '';
  # XXX Connection: close
  if ($req->{ws}) {
    $con->{ws_state} = 'CONNECTING';
    $con->{ws_key} = encode_base64 join ('', map { pack 'C', rand 256 } 1..16), '';
    push @{$req->{headers} ||= []},
        ['Sec-WebSocket-Key', $con->{ws_key}],
        ['Sec-WebSocket-Version', '13'];
    $con->{ws_protos} = $req->{ws_protocols} || [];
    if (@{$con->{ws_protos}}) {
      push @{$req->{headers}},
          ['Sec-WebSocket-Protocol', join ',', @{$con->{ws_protos}}];
    }
    # XXX extension
  }
  my $header = join '',
      "$method $url HTTP/1.1\x0D\x0A",
      (map { "$_->[0]: $_->[1]\x0D\x0A" } @{$req->{headers} || []}),
      "\x0D\x0A";
  if ($con->{DEBUG}) {
    for (split /\x0A/, $header) {
      warn "$stream->{id}: S: @{[_e4d $_]}\n";
    }
  }
  my $sent = $con->{writer}->write
      (DataView->new (ArrayBuffer->new_from_scalarref (\$header)));
  $con->{write_mode} = $req->{ws} ? 'ws' : $method eq 'CONNECT' ? 'before tunnel data' : 'raw';
  my ($ws) = $stream->_open_sending_stream ($cl);
  $con->_read;
  return $sent->then (sub {
    return {stream => $stream, body => $ws};
  }); ## could be rejected when connection aborted
} # _send_request

## Send a WebSocket message.  The first argument must be the byte
## length of the message's data.  The second argument must be a
## boolean value of whether it is a binary message (true) or text
## message (false).  This method must be invoked while the WebSocket
## state of the HTTP connection is OPEN and there is no sending
## WebSocket message.  The method returns a promise, which is to be
## fulfilled with a hash reference with a key/value pair: |body|,
## whose value is a writable stream of the message's data.  It accepts
## |ArrayBufferView|s.  The total byte length must be equal to the
## byte length.  If the writable stream is aborted, the HTTP stream is
## aborted.
sub send_ws_message ($$$) {
  my ($self, $length, $is_binary) = @_;
  croak "Data too large" if MAX_BYTES < $length; # spec limit 2**63

  my $con = $self->{connection};
  return Promise->reject (Web::Transport::TypeError->new ("Stream is busy"))
      if not (defined $con->{ws_state} and $con->{ws_state} eq 'OPEN') or
         defined $con->{cancel_current_writable_stream};

  my $mask = '';
  my $masked = 0;
  unless ($self->{is_server}) {
    $masked = 0b10000000;
    $con->{ws_encode_mask_key} = $mask = pack 'CCCC', rand 256, rand 256, rand 256, rand 256;
  } else {
    delete $con->{ws_encode_mask_key};
  }

  $con->{ws_sent_length} = 0;

  my $length0 = $length;
  my $len = '';
  if ($length >= 2**16) {
    $length0 = 0x7F;
    $len = pack 'n', $length;
  } elsif ($length >= 0x7E) {
    $length0 = 0x7E;
    $len = pack 'Q>', $length;
  }
  $self->_ws_debug ('S', $_[2], FIN => 1, opcode => 2, mask => $mask,
                    length => $length) if $self->{DEBUG};
  $con->{writer}->write
      (DataView->new (ArrayBuffer->new_from_scalarref (\(pack ('CC', 0b10000000 | ($is_binary ? 2 : 1), $masked | $length0) . $len . $mask))));
  $con->{write_mode} = 'raw';
  $con->{ws_pendings} = [];
  my ($ws) = $con->{stream}->_open_sending_stream ($length);

  return Promise->resolve ({body => $ws});
} # send_ws_message

sub send_ping ($;%) {
  my ($self, %args) = @_;
  $args{data} = '' unless defined $args{data};
  croak "Data is utf8-flagged" if utf8::is_utf8 $args{data};
  croak "Data too large" if 0x7D < length $args{data}; # spec limit 2**63

  my $con = $self->{connection};
  return Promise->reject (Web::Transport::TypeError->new ("Stream is busy"))
      if not (defined $con->{ws_state} and $con->{ws_state} eq 'OPEN') or
         defined $con->{cancel_current_writable_stream};

  my $mask = '';
  my $masked = 0;
  unless ($self->{is_server}) {
    $masked = 0b10000000;
    $mask = pack 'CCCC', rand 256, rand 256, rand 256, rand 256;
  }
  my $opcode = $args{pong} ? 10 : 9;
  $self->_ws_debug ('S', $args{data}, FIN => 1, opcode => $opcode,
                    mask => $mask, length => length $args{data})
      if $self->{DEBUG};
  unless ($self->{is_server}) {
    for (0..((length $args{data})-1)) {
      substr ($args{data}, $_, 1) = substr ($args{data}, $_, 1) ^ substr ($mask, $_ % 4, 1);
    }
  }
  $con->{writer}->write
      (DataView->new (ArrayBuffer->new_from_scalarref (\(pack ('CC', 0b10000000 | $opcode, $masked | length $args{data}) . $mask . $args{data}))));
  return undef;
  # XXX return promise waiting pong?
} # send_ping

## Send a WebSocket Close frame over the HTTP stream, if applicable.
## This method must be invoked while the WebSocket state of the HTTP
## connection is OPEN or CLOSING (i.e. after |headers_received|
## promise has been fulfilled) and there is no sending WebSocket
## message.  Then it returns the |closed| promise of the HTTP stream.
sub send_ws_close ($;$$) {
  my ($stream, $status, $reason) = @_;

  my $con = $stream->{connection};
  return Promise->reject (Web::Transport::TypeError->new ("Stream is busy"))
      if not defined $con->{ws_state} or
         not ($con->{ws_state} eq 'OPEN' or $con->{ws_state} eq 'CLOSING') or
         defined $con->{cancel_current_writable_stream};
  return $stream->{closed}->[0] if $con->{ws_state} eq 'CLOSING';

  if (defined $status and $status > 0xFFFF) {
    return Promise->reject ("Bad status"); # XXXerror
  }
  if (defined $reason) {
    return Promise->reject ("Status text is utf8-flagged") # XXXerror
        if utf8::is_utf8 $reason;
    return Promise->reject ("Status text is too long") # XXXerror
        if 0x7D < length $reason;
  }

  my $masked = 0;
  my $mask = '';
  unless ($con->{is_server}) {
    $masked = 0b10000000;
    $mask = pack 'CCCC', rand 256, rand 256, rand 256, rand 256;
  }
  my $data = '';
  my $frame_info = $con->{DEBUG} ? [$reason, FIN => 1, opcode => 8, mask => $mask, length => length $data, status => $status] : undef;
  if (defined $status) {
    $data = pack 'n', $status;
    $data .= $reason if defined $reason;
    unless ($con->{is_server}) {
      for (0..((length $data)-1)) {
        substr ($data, $_, 1) = substr ($data, $_, 1) ^ substr ($mask, $_ % 4, 1);
      }
    }
  }
  my $frame = pack ('CC', 0b10000000 | 8, $masked | length $data) . $mask . $data;
  $stream->_ws_debug ('S', @$frame_info) if $con->{DEBUG};
  $con->{writer}->write (DataView->new (ArrayBuffer->new_from_scalarref (\$frame)));
  $con->{ws_state} = 'CLOSING';
  $con->{ws_timer} = AE::timer 20, 0, sub {
    if ($con->{DEBUG}) {
      warn "$stream->{id}: WS timeout (20)\n";
    }
    # XXXerror
    # XXX set exit ?
    $con->_receive_done;
  };
  (delete $stream->{closing}->[1])->(undef), delete $stream->{closing}->[2];
  warn "$stream->{id}: closing @{[scalar gmtime]}\n" if $con->{DEBUG};
  $con->_send_done;

  return $stream->{closed}->[0];
} # send_ws_close

sub _ws_debug ($$$%) {
  my $stream = $_[0];
  my $side = $_[1];
  my %args = @_[3..$#_];
  my $con = $stream->{connection};

  warn sprintf "$stream->{id}: %s: WS %s L=%d\n",
      $side,
      (join ' ',
          $args{opcode},
          ({
            0 => '(continue)',
            1 => '(text)',
            2 => '(binary)',
            8 => '(close)',
            9 => '(ping)',
            10 => '(pong)',
          }->{$args{opcode}} || ()),
          ($args{FIN} ? 'F' : ()),
          ($args{RSV1} ? 'R1' : ()),
          ($args{RSV2} ? 'R2' : ()),
          ($args{RSV3} ? 'R3' : ()),
          (defined $args{mask} && length $args{mask}
               ? sprintf 'mask=%02X%02X%02X%02X',
                                     unpack 'CCCC', $args{mask} : ())),
      $args{length};
  if ($args{opcode} == 8 and defined $args{status}) {
    warn "$stream->{id}: S: status=$args{status} |@{[_e4d (defined $_[2] ? $_[2] : '')]}|\n";
  } elsif (length $_[2]) {
    if ($con->{DEBUG} > 1 or length $_[2] <= 40) {
      warn "$stream->{id}: S: @{[_e4d $_[2]]}\n";
    } else {
      warn "$stream->{id}: S: @{[_e4d substr $_[2], 0, 40]}... (@{[length $_[2]]})\n";
    }
  }
} # _ws_debug

## Send a response.  The argument must be a hash reference with
## following key/value pairs:
##
##   status - The status code of the response.  It must be an integer
##   in the range [100, 999].
##
##   status_text - The reason phrase of the response.  It must be a
##   byte string with no 0x0D or 0x0A byte.  It can be the empty
##   string.
##
##   headers - The headers of the response.  It must be an array
##   reference of zero or more array references representing a pair of
##   header name and value, which are byte strings with no 0x0D or
##   0x0A byte.  The header names cannot be the empty string and
##   cannot contain some kinds of bytes.
##
##   length - The byte length of the response body, if any.
##
##   close - Whether the HTTP connection should be closed after
##   sending this response.
##
##   forwarding - Whether this response is received from the upstream
##   and is to be forwarded to the downstream or not.  If this option
##   is true, this method does not generate some headers.
##
## This method must be invoked while the HTTP connection is waiting
## for an HTTP response.  It returns a promise which is to be
## fulfilled with a hash reference that might contain a writable
## stream of the response body, as described earlier.
sub send_response ($$$) {
  my ($stream, $response) = @_;
  my $con = $stream->{connection};

  return Promise->reject (Web::Transport::TypeError->new ("Response is not allowed"))
      if not defined $con or defined $con->{write_mode} or not $con->{is_server};

  return Promise->reject (Web::Transport::TypeError->new ("Bad |status|"))
      unless defined $response->{status} and
             99 < $response->{status} and
             $response->{status} < 1000;

  my $close = $response->{close} ||
              $con->{to_be_closed} ||
              $stream->{request}->{version} eq '0.9';
  my $connect = 0;
  my $is_ws = 0;
  my @header;
  my $to_be_sent = undef;
  my $write_mode = 'sent';
  if ($stream->{request}->{method} eq 'HEAD' or
      $response->{status} == 204 or
      $response->{status} == 304) {
    ## No response body by definition
    return Promise->reject
        (Web::Transport::TypeError->new ("Bad byte length $response->{length}"))
            if defined $response->{length};
    $to_be_sent = 0;
  } elsif ($stream->{request}->{method} eq 'CONNECT' and
           200 <= $response->{status} and $response->{status} < 300) {
    ## No response body by definition but switched to the tunnel mode
    croak "|length| not allowed" if defined $response->{length};
    $write_mode = 'raw';
    $connect = 1;
    $close = 1;
  } elsif (100 <= $response->{status} and $response->{status} < 200) {
    ## No response body by definition
    croak "|length| not allowed" if defined $response->{length};
    if (defined $stream->{ws_key} and $response->{status} == 101) {
      $is_ws = 1;
      $write_mode = 'ws';
    } else {
      return Promise->reject
          (Web::Transport::TypeError->new ("1xx response not supported"));
    }
  } else {
    if (defined $response->{length}) {
      ## If body length is specified
      $write_mode = 'raw';
      $to_be_sent = 0+$response->{length};
      push @header, ['Content-Length', $to_be_sent];
    } elsif ($stream->{request}->{version} == 1.1) {
      ## Otherwise, if chunked encoding can be used
      $write_mode = 'chunked';
    } else {
      ## Otherwise, end of the response is the termination of the connection
      $close = 1;
      $write_mode = 'raw';
    }
    $close = 1 if $stream->{request}->{method} eq 'CONNECT';
  }

  push @header, @{$response->{headers} or []};

  croak "Bad status text |@{[_e4d $response->{status_text}]}|"
      if $response->{status_text} =~ /[\x0D\x0A]/;
  croak "Status text is utf8-flagged"
      if utf8::is_utf8 $response->{status_text};

  my $has_header = {};
  for (@header) {
    croak "Bad header name |@{[_e4d $_->[0]]}|"
        unless $_->[0] =~ /\A[!\x23-'*-+\x2D-.0-9A-Z\x5E-z|~]+\z/;
    croak "Bad header value |$_->[0]: @{[_e4d $_->[1]]}|"
        unless $_->[1] =~ /\A[\x00-\x09\x0B\x0C\x0E-\xFF]*\z/;
    croak "Header name |$_->[0]| is utf8-flagged" if utf8::is_utf8 $_->[0];
    croak "Header value of |$_->[0]| is utf8-flagged" if utf8::is_utf8 $_->[1];
    my $name = $_->[0];
    $name =~ tr/A-Z/a-z/; ## ASCII case-insensitive
    $has_header->{$name} = 1;
  }

  unshift @header, ['Server', $con->{server_header}]
      unless $response->{forwarding};

  unless ($has_header->{date}) {
    my $dt = Web::DateTime->new_from_unix_time
        (Web::DateTime::Clock->realtime_clock->()); # XXX
    unshift @header, ['Date', $dt->to_http_date_string];
  }

  if ($is_ws) {
    push @header,
        ['Upgrade', 'websocket'],
        ['Connection', 'Upgrade'],
        ['Sec-WebSocket-Accept', encode_base64 sha1 ($stream->{ws_key} . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'), ''];
      # XXX Sec-WebSocket-Protocol
      # XXX Sec-WebSocket-Extensions
  } else {
    if ($close and not $connect) {
      push @header, ['Connection', 'close'];
    } elsif ($stream->{request}->{version} eq '1.0') {
      push @header, ['Connection', 'keep-alive'];
    }
    if ($write_mode eq 'chunked') {
      push @header, ['Transfer-Encoding', 'chunked'];
    }
  }

  if ($is_ws) {
    $con->{ws_state} = 'OPEN';
    $con->{state} = 'before ws frame';
    $con->{temp_buffer} = '';
  } elsif ($con->{state} eq 'ws handshaking') {
    $con->_receive_done;
  }

  if ($stream->{request}->{version} ne '0.9') {
    my $res = sprintf qq{HTTP/1.1 %d %s\x0D\x0A},
        $response->{status},
        $response->{status_text};
    for (@header) {
      $res .= "$_->[0]: $_->[1]\x0D\x0A";
    }
    $res .= "\x0D\x0A";
    if ($con->{DEBUG}) {
      for (split /\x0A/, $res) {
        warn "$stream->{id}: S: @{[_e4d $_]}\n";
      }
    }

    $con->{writer}->write
        (DataView->new (ArrayBuffer->new_from_scalarref (\$res)));
  } else {
    if ($con->{DEBUG}) {
      warn "$stream->{id}: Response headers skipped (HTTP/0.9)\n";
    }
  }

  $con->{to_be_closed} = 1 if $close;
  $con->{write_mode} = $write_mode;
  my ($ws) = $stream->_open_sending_stream ($to_be_sent);

  if ($connect and defined $stream->{tunnel_readable}) {
    return Promise->resolve ({readable => delete $stream->{tunnel_readable},
                              writable => $ws});
  } else {
    delete $stream->{tunnel_readable};
    return Promise->resolve ({body => $ws});
  }
} # send_response

## Return the |closed| promise of the HTTP stream, which is to be
## fulfilled when both sending and receiving a pair of request
## response have been completed or aborted.  This is fulfilled rather
## than rejected even when the HTTP stream is abnormally closed.
sub closed ($) {
  return $_[0]->{closed}->[0];
} # closed

## Abort the HTTP stream.  It effectively abort the underlying HTTP
## connection.  The method accepts arguments; see connection's |abort|
## method.  It returns the HTTP stream's |closed| promise.
sub abort ($;$%) {
  my $stream = shift;
  $stream->{connection}->abort (@_) if defined $stream->{connection};
  return $stream->{closed}->[0];
} # abort

sub DESTROY ($) {
  local $@;
  eval { die };
  warn "$$: Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

# End of ::Stream

1;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
