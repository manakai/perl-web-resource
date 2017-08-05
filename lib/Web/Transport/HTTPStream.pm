package Web::Transport::HTTPStream;
use strict;
use warnings;
our $VERSION = '1.0';
use Web::Encoding;

## This module is not public.  It should not be used by external
## applications and modules.

## Client:
##   $con->send_request->then (sub {
##     $_[0]->{stream}
##     $_[0]->{body}
##   })
##   $stream->headers_received->then (sub {
##     $_[0]->{body}
##     $_[0]->{messages}
##   })
## Server:
##   $con->received_streams->read->then (sub { $stream = $_[0]->{value} })
##   $stream->headers_received->then (sub {
##     $_[0]->{body}
##     $_[0]->{messages}
##   })
##   $stream->send_response->then (sub {
##     $_[0]->{body}
##   })
##
## If the connection is NOT in the WebSocket mode,
## |headers_received|'s |body| is a ReadableStream.  It is a readable
## byte stream containing received body's byte sequence.  If the
## readable stream is canceled, the underlying HTTP stream (or the
## entire HTTP connection in HTTP/1) is aborted.  If the connection is
## in the WebSocket mode, |headers_received|'s |body| is not defined.
##
## If the connection is in the WebSocket mode, |headers_received|'s
## |messages| is a ReadableStream.  If the readable stream is
## canceled, the underlying HTTP stream (in fact the entire HTTP
## connection) is aborted.  If the connection is NOT in the WebSocket
## mode, |headers_received|'s |messages| is not defined.
##
## The |messages| stream is a readable stream of zero or more
## WebSocket messages.  A WebSocket messages is represented by a hash
## reference with following key/value pairs:
##
##   $_->{body}       If it is a binary message, the data of the message,
##                    as a readable byte stream.  Otherwise, not defined.
##   $_->{text_body}  If it is a text message, the data of the message,
##                    as a readable stream of zero or more scalar
##                    references to texts.  The concatenation of the
##                    texts in order is the data of the message.  Otherwise,
##                    not defined.
##
## If the readable stream is canceled, the underlying HTTP stream (in
## fact the entire HTTP connection) is aborted.

# XXX httpserver tests
# XXX replace {exit} by exception objects
# XXX restore debug features & id
# XXX XXX cleanup
# XXX _connection_error for client
# XXX abort

sub new ($$) {
  return Web::Transport::HTTPStream::ClientConnection->new ($_[1]); # XXX
} # new

sub new_XXXserver ($$) {
  return Web::Transport::HTTPStream::ServerConnection->new ($_[1]); # XXX
} # new_XXXserver

sub MAX_BYTES () { 2**31-1 }

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

package Web::Transport::HTTPStream::Connection;
use AnyEvent;
use Web::Encoding;
use Encode qw(decode); # XXX

push our @CARP_NOT, qw(Web::Transport::HTTPStream::Stream);

BEGIN {
  *_e4d = \&Web::Transport::HTTPStream::_e4d;
  *_e4d_t = \&Web::Transport::HTTPStream::_e4d_t;
  *MAX_BYTES = \&Web::Transport::HTTPStream::MAX_BYTES;
}

sub _ws_received ($) {
  my ($self, $ref) = @_;
  my $stream = $self->{stream};
  my $ws_failed;
  WS: {

warn "XXX $self->{state}";

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
            my $id = 'XXX';
            warn sprintf "$id: R: status=%d %s\n",
                unpack ('n', $status), _e4d $reason;
          }
          unless ($self->{ws_state} eq 'CLOSING') {
            $self->{ws_state} = 'CLOSING';
            #$self->_ev ('closing');  #XXX
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
              $self->_send_done;
            }
          }
          $self->{state} = 'ws terminating';
          $self->{exit} = {status => defined $status ? $status : 1005,
                           reason => defined $reason ? $reason : '',
                           ws => 1, cleanly => 1};
          if (length ($$ref) - pos ($$ref)) { # ws terminating state
            if (not $self->{exit}->{failed}) {
              $self->{exit}->{failed} = 1;
              $self->{exit}->{ws} = 1;
              $self->{exit}->{status} = 1006;
              $self->{exit}->{reason} = '';
              delete $self->{exit}->{cleanly};
            }
            $$ref = '';
          }
          if ($self->{is_server}) {
            $self->_receive_done;
          } else {
            $self->{ws_timer} = AE::timer 1, 0, sub { # XXX spec
              if ($self->{DEBUG}) {
                my $id = defined $self->{request} ? $self->{request}->{id} : $self->{id};
                warn "$id: WS timeout (1)\n";
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
                return $self->abort (message => $_[1]);
              }, # cancel
            });

            if ($is_text) {
              my $buffer = join '', @{$self->{ws_frame}->[1]}; # XXX string copy!
              $self->{ws_frame}->[1] = [eval { decode 'utf-8', $buffer, Encode::FB_CROAK }]; # XXX Encoding Standard # XXX streaming decoder
              if (length $buffer) {
                $ws_failed = 'Invalid UTF-8 in text frame';
                last WS;
              }
              for (@{$self->{ws_frame}->[1]}) {
                $rc->enqueue (\$_);
              }
            } else { # binary
              for (@{$self->{ws_frame}->[1]}) {
                $rc->enqueue
                    (DataView->new (ArrayBuffer->new_from_scalarref (\$_)));
              }
            }
            $stream->{messages_controller}->enqueue ({
              ($is_text ? 'text_body' : 'body') => $rs,
            });
            $rc->close;
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
          #$stream->_ev ('ping', (join '', @{$self->{ws_frame}->[1]}), 0);
        } elsif ($self->{ws_frame}->[0] == 10) {
          #$stream->_ev ('ping', (join '', @{$self->{ws_frame}->[1]}), 1);
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
    my $exit = {ws => 1, failed => 1, status => 1002, reason => $ws_failed};
    my $data = pack 'n', $exit->{status};
    $data .= $exit->{reason};
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
    $stream->_ws_debug ('S', $exit->{reason}, FIN => 1, opcode => 8,
                        mask => $mask, length => length $data,
                        status => $exit->{status}) if $self->{DEBUG};
    $self->{writer}->write
        (DataView->new (ArrayBuffer->new_from_scalarref (\(pack ('CC', 0b10000000 | 8, $masked | length $data) . $mask . $data))));
    $self->{state} = 'ws terminating';
    return $self->_connection_error ($exit);
  }
  if ($self->{state} eq 'ws terminating') {
    if ((length $$ref) - (pos $$ref)) {
      if (not $self->{exit}->{failed}) {
        $self->{exit}->{failed} = 1;
        $self->{exit}->{ws} = 1;
        $self->{exit}->{status} = 1006;
        $self->{exit}->{reason} = '';
        delete $self->{exit}->{cleanly};
      }
      $ref = \'';
    }
  }
  if ((length $$ref) - (pos $$ref)) { # before ws frame
    $self->{temp_buffer} .= substr $$ref, pos $$ref;
    $ref = \'';
  }
} # _ws_received

sub _ws_received_eof ($;%) {
  my ($self, $ref, %args) = @_;

  if ($self->{state} eq 'before ws frame' or
      $self->{state} eq 'ws data') {
    $self->{ws_state} = 'CLOSING';
    my $reason = '';
    $reason = $self->{exit}->{message}
        if defined $self->{exit} and
           defined $self->{exit}->{message} and
           $self->{is_server};
    $self->{exit} = {ws => 1, failed => 1, status => 1006, reason => $reason};
  } elsif ($self->{state} eq 'ws terminating') {
    $self->{ws_state} = 'CLOSING';
    if ($args{abort} and not $self->{exit}->{failed}) {
      $self->{exit}->{failed} = 1;
      $self->{exit}->{ws} = 1;
      $self->{exit}->{status} = 1006;
      $self->{exit}->{reason} = '';
    }
  }
  $self->{to_be_closed} = 1;
  $self->{write_mode} = 'sent';

  $self->_receive_done;
} # _ws_received_eof

# XXX
sub _debug_handshake_done ($$) {
  my ($self, $exit) = @_;
  no warnings 'uninitialized';
  my $id = $self->{id};

  my @transport = (); # XXX$self->{transport});
  while (@transport) {
    if (defined $transport[-1]->{transport}) {
      push @transport, $transport[-1]->{transport};
    } elsif (defined $transport[-1]->{http}) {
      push @transport, $transport[-1]->{http};
    } else {
      last;
    }
  }

  warn "$id: DEBUG mode |$self->{DEBUG}|\n" unless $self->{DEBUG} eq '1';
  for my $transport (reverse @transport) {
    warn "$id: + @{[$transport->id]} @{[$transport->type]}\n";
    my $info = $transport->info;

    if (defined $info->{remote_host}) {
      my $host = $info->{remote_host}->to_ascii;
      warn "$id:   + Remote: $host:$info->{remote_port}\n";
    }
    if (defined $info->{local_host}) {
      my $host = $info->{local_host}->to_ascii;
      if (defined $info->{is_server}) {
        warn "$id:   + Local: $host:$info->{local_port} " . ($info->{is_server} ? 'Server' : 'Client') . "\n";
      } else {
        warn "$id:   + Local: $host:$info->{local_port}\n";
      }
    } elsif (defined $info->{is_server}) {
      warn "$id:   + " . ($info->{is_server} ? 'Server' : 'Client') . "\n";
    }

    if (defined $info->{openssl_version}) {
      warn "$id:   + OpenSSL: $info->{openssl_version}->[0]\n";
      if ($self->{DEBUG} > 1) {
        warn "$id:   +          $info->{openssl_version}->[1]\n";
        warn "$id:   +          $info->{openssl_version}->[2]\n";
        warn "$id:   +          $info->{openssl_version}->[3]\n";
      }
    }
    if ($self->{DEBUG} > 1) {
      if (defined $info->{net_ssleay_version}) {
        warn "$id:   + Net::SSLeay: $info->{net_ssleay_version} $info->{net_ssleay_path}\n";
      }
    }

    if (defined $info->{tls_protocol}) {
      my $ver = $info->{tls_protocol} == 0x0301 ? '1.0' :
                $info->{tls_protocol} == 0x0302 ? '1.1' :
                $info->{tls_protocol} == 0x0303 ? '1.2' :
                $info->{tls_protocol} == 0x0304 ? '1.3' :
                sprintf '0x%04X', $info->{tls_protocol};
      warn "$id:   + TLS version: $ver\n";
    }
    if (defined $info->{tls_cipher}) {
      warn "$id:   + Cipher suite: $info->{tls_cipher} ($info->{tls_cipher_usekeysize})\n";
    }
    warn "$id:   + Resumed session\n" if $info->{tls_session_resumed};
    my $i = 0;
    for (@{$info->{tls_cert_chain} or []}) {
      if (defined $_) {
        warn "$id:   + #$i: @{[$_->debug_info]}\n";
      } else {
        warn "$id:   + #$i: ?\n";
      }
      $i++;
    }
    if (defined (my $result = $info->{stapling_result})) {
      if ($result->{failed}) {
        warn "$id:   + OCSP stapling: NG - $result->{message}\n";
      } else {
        warn "$id:   + OCSP stapling: OK\n";
      }
      if (defined (my $res = $result->{response})) {
        warn "$id:   +   Status=$res->{response_status} Produced=$res->{produced}\n";
        for my $r (values %{$res->{responses} or {}}) {
          warn "$id:   +   - Status=$r->{cert_status} Revocation=$r->{revocation_time} ThisUpdate=$r->{this_update} NextUpdate=$r->{next_update}\n";
        }
      }
    } elsif (defined $info->{tls_protocol}) {
      warn "$id:   + OCSP stapling: N/A\n";
    }
  } # $transport

  if ($exit->{failed}) {
    warn "$id: + Failure ($exit->{message})\n";
  }
} # _debug_handshake_done

# XXX can_create_stream is_active && (if h1: no current request)

sub send_request ($$;%) {
  my $con = shift;
  my $req = shift;
  return Promise->reject (Web::DOM::TypeError->new ("Request is not allowed"))
      if $con->{is_server};

  my $stream = bless {
    connection => $con,
  },'Web::Transport::HTTPStream::Stream';
  return $stream->_send_request ($req, @_);
} # send_request

## Stop accepting new requests and close the connection AFTER any
## ongoing processing has been completed.
sub close_after_current_stream ($) {
  my $con = $_[0];

  if (not defined $con->{state}) {
    return Promise->reject ("Connection has not been established");
  }

  # XXX
  if ($con->{is_server}) {
    if (defined $con->{stream}) {
      $con->{to_be_closed} = 1;
    } else {
      if (defined $con->{writer}) {
        my $w = $con->{writer};
        # XXX
        $w->write (DataView->new (ArrayBuffer->new))->then (sub {
          my $error = 'Close by |close_after_current_stream|'; # XXX
          $w->abort ($error);
          $con->{reader}->cancel ($error)->catch (sub { });
        });
        delete $con->{writer};
      }
      $con->{state} = 'end';
    }
    return $con->{closed};
  }

  $con->{to_be_closed} = 1;
  if ($con->{state} eq 'initial' or
      $con->{state} eq 'waiting') {
    $con->{writer}->close; # can fail
    delete $con->{writer};
    $con->_read;
  }

  return $con->{closed};
} # close_after_current_stream

# XXX server tests
sub is_active ($) {
  return defined $_[0]->{state} && !$_[0]->{to_be_closed};
} # is_active

sub abort ($;%) {
  my ($self, %args) = @_;
  if (not defined $self->{state}) {
    return Promise->reject ("Connection has not been established");
  }
  my $error = Web::DOM::Error->wrap ($args{message});

  if ($self->{is_server}) {

  if (defined $self->{writer}) {
    $self->{writer}->abort ($error);
    $self->_send_done ($error);
    delete $self->{writer};
  }

} else {

  $self->{to_be_closed} = 1;
  $self->{write_mode} = 'sent';
  delete $self->{to_be_sent_length};
  $self->{writer}->abort ($error)
      if defined $self->{writer};

}

  if (defined $self->{reader}) {
    unless ($self->{is_server}) { # XXX
      $self->{reader}->cancel ($error)->catch (sub { });
    }
  }

  return $self->{closed};
} # abort

# XXX tests
sub closed ($) {
  return $_[0]->{closed};
} # closed

sub _connection_error ($$) {
  my $con = $_[0];
  my $error;
  if (defined $_[1]) {
    if (ref $_[1]) {
      $error = $_[1];
    } else {
      $error = {failed => 1, message => $_[1]};
    }
  } else {
    $error = {failed => 1, message => 'Parse error'}; # XXX
  }

  $con->{exit} = $error if defined $error;
  $con->{to_be_closed} = 1;

  if ($con->{state} eq 'ws terminating') {
    $con->_send_done;
    $con->_receive_done;
    return;
  }

  if ($con->{is_server}) {
    $con->_receive_done;
    $con->{state} = 'end';
    $con->{rbuf} = '';

    if (defined $con->{write_mode}) {
      ## A response is being sent or has been sent.
      return $con->abort; # XXX {$status $status_text}
    }

    my $status = 400;
    my $reason = 'Bad Request';
    my $headers = [];
    if (ref $error eq 'HASH' and $error->{failed} and
        defined $error->{status} and not $error->{ws}) {
      $status = $error->{status};
      $reason = $error->{reason};
      $headers = $error->{headers} || [];
    }

    my $stream = $con->{stream};
    my $res = qq{<!DOCTYPE html><html>
<head><title>$status $reason</title></head>
<body>$status $reason</body></html>\x0A};
    return $stream->send_response
        ({status => $status, status_text => $reason,
          headers => [
            @{$headers or []},
            ['Content-Type' => 'text/html; charset=utf-8'],
          ]}, close => 1, content_length => length $res)->then (sub { # XXX if head
      my $w = $_[0]->{body}->get_writer;
      $w->write (DataView->new (ArrayBuffer->new_from_scalarref (\$res)))
          unless $stream->{request}->{method} eq 'HEAD';
      return $w->close;
    });
  } else {
    $con->_send_done;
    $con->_receive_done;
  }
} # _connection_error

sub _send_done ($;$) {
  my ($con, $error) = @_;
  my $stream = $con->{stream};

  if ($con->{is_server}) {

  if (defined $error and not defined $con->{exit}) {
    $con->{exit} = $error;
  }

  if ($con->{to_be_closed}) {
    $con->{writer}->close if defined $con->{writer};
    delete $con->{writer};
  }
  $con->{write_mode} = 'sent';
  delete $con->{to_be_sent_length};
  $stream->{send_done} = 1;
  if (defined $con->{cancel_current_writable_stream}) {
    $con->{cancel_current_writable_stream}->(undef);
  }
  if ($stream->{receive_done}) {
    $con->_both_done;
  }

  return;
  }

  $con->{write_mode} = 'sent';

  if (defined $con->{cancel_current_writable_stream}) {
    $con->{cancel_current_writable_stream}->(undef);
  }

  # XXX
  if ($con->{to_be_closed}) {
    $con->{writer}->close if defined $con->{writer};
    delete $con->{writer};
  }

  $con->_both_done if $con->{state} eq 'sending';
} # _send_done


sub _receive_done ($) {
  my $con = $_[0];
  my $stream = $con->{stream};

  my $exit = $con->{exit} || {};

  if ($con->{is_server}) {

  delete $con->{timer};
  $con->{disable_timer} = 1;
  delete $con->{unread_length};
  delete $con->{ws_timer};
  delete $con->{write_mode};

  if (defined $stream->{messages_controller}) {
    $stream->{messages_controller}->close;
    delete $stream->{messages_controller};
  }

  if ($con->{to_be_closed} or
      not defined $con->{writer}) { # _send_done already called with to_be_closed
    $con->{state} = 'end';
  } else {
    $con->{state} = 'after request';
  }
  $stream->{receive_done} = 1;
  if ($stream->{send_done}) {
    $con->_both_done;
  }

  return;
  }

  return if $con->{state} eq 'stopped';

  if (defined $stream->{messages_controller}) {
    $stream->{messages_controller}->close;
    delete $stream->{messages_controller};
  }

  delete $con->{timer};
  delete $con->{ws_timer};
  if (defined $con->{write_mode} and
      $con->{write_mode} eq 'raw') {
    $con->{state} = 'sending';
  } else {
    $con->_both_done;
  }
} # _receive_done


sub _both_done ($) {
  my $con = $_[0];
  my $stream = $con->{stream};

  if ($con->{is_server}) {

  delete $con->{stream};
  my $error = $con->{exit} || {};
  if (Web::DOM::Error->is_error ($error)) { # XXX
    $stream->{closed_reject}->($error);
  } elsif (eval { $error->{failed} }) { # XXX
    $stream->{closed_reject}->($error);
  } else {
    $stream->{closed_resolve}->();
  }
  if (defined $stream->{headers_received} and
      defined $stream->{headers_received}->[1]) {
    $stream->{headers_received}->[1]->(Promise->reject ($error)); # XXX
  }
  delete $stream->{closed_resolve};
  delete $stream->{closed_reject};
  if ($con->{DEBUG}) { #XXX
    warn "$con->{id}: endstream $stream->{id} @{[scalar gmtime]}\n";
    warn "$con->{id}: ========== @{[ref $con]}\n";
  }
  delete $con->{disable_timer};
  $con->{timer} = AE::timer $Web::Transport::HTTPStream::ServerConnection::ReadTimeout, 0, sub { $con->_timeout };
  delete $stream->{connection};

  return;
  }

  # XXX
  if ($con->{to_be_closed} and defined $con->{reader}) {
    $con->{reader}->cancel ($con->{exit});
    delete $con->{reader};
  }

  if (defined $con->{request} and $con->{write_mode} eq 'sent') {
    if ($con->{exit}->{failed}) {
      $con->{response}->{stream_reject}->($con->{exit});

      if (defined $stream->{headers_received} and
          defined $stream->{headers_received}->[1]) {
        (delete $stream->{headers_received}->[1])->(Promise->reject ($con->{exit})); # XXX
      }

      if (defined (my $rc = delete $stream->{body_controller})) {
        $rc->error ($con->{exit});
      }
    } else {
      $con->{response}->{stream_resolve}->($con->{exit});
    }
    #$con->_ev ('complete', $con->{exit}); # XXX
  }
  delete $con->{stream};
  delete $con->{request};
  delete $con->{response};
  delete $con->{write_mode};
  delete $con->{to_be_sent_length};
  if ($con->{to_be_closed}) {
    if (defined $con->{writer}) {
      # XXX
      my $writer = $con->{writer};
      $writer->close->catch (sub { }); # can fail
      $con->{timer} = AE::timer 1, 0, sub {
        $writer->abort ("HTTP completion timer (1)"); # XXX and reader?
      };
      delete $con->{writer};
    }
    $con->{state} = 'stopped';
  } else {
    $con->{state} = 'waiting';
    $con->{response_received} = 0;
  }
} # _both_done

sub _terminate ($) {
  my $self = $_[0];
  delete $self->{reader};
  delete $self->{writer};
  delete $self->{timer};
} # _terminate

sub DESTROY ($) {
  $_[0]->abort if $_[0]->{is_server} and defined $_[0]->{transport}; # XXX

  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

# End of ::Connection

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
  Web::DOM::TypeError
  Web::Transport::HTTPStream::ClientConnection
  Web::Transport::HTTPStream::ServerConnection
  WritableStream WritableStreamDefaultWriter
);

BEGIN {
  *_e4d = \&Web::Transport::HTTPStream::_e4d;
  *_e4d_t = \&Web::Transport::HTTPStream::_e4d_t;
  *MAX_BYTES = \&Web::Transport::HTTPStream::MAX_BYTES;
}

sub _open_sending_stream ($;%) {
  my ($stream, %args) = @_;
  my $con = $stream->{connection};
  my $canceled = 0;

  if ($args{XXX_ws_message}) {
  my $ws = WritableStream->new ({
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
          die Web::DOM::TypeError->new ("The argument is not an ArrayBufferView")
              unless UNIVERSAL::isa ($chunk, 'ArrayBufferView');

          my $byte_length = $chunk->byte_length; # or throw
          die Web::DOM::TypeError->new
              (sprintf "Byte length %d is greater than expected length %d",
                   $byte_length, ($canceled ? 0 : $con->{to_be_sent_length} || 0))
                  if $canceled or
                     (defined $con->{to_be_sent_length} and
                      $con->{to_be_sent_length} < $byte_length);
          return unless $byte_length;

        if ($con->{DEBUG}) {
          if ($con->{DEBUG} > 1 or $byte_length <= 40) {
            for (split /\x0A/, 'XXX', -1) {
              warn "$con->{request}->{id}: S: @{[_e4d $_]}\n";
            }
          } else {
            warn "$con->{request}->{id}: S: @{[_e4d substr $_, 0, 40]}... (@{[length $_]})\n";
          }
        }

          my $mask = $con->{ws_encode_mask_key};
          if (defined $mask) {
            my @data;
            $chunk = DataView->new ($chunk->buffer, $chunk->byte_offset, $byte_length); # or throw
            my $ref = \($chunk->manakai_to_string);
            my $o = $con->{ws_sent_length};
            for (0..($byte_length-1)) {
              push @data, substr ($$ref, $_, 1) ^ substr ($mask, ($o+$_) % 4, 1);
            }
              $con->{writer}->write
                  (DataView->new (ArrayBuffer->new_from_scalarref (\join '', @data)));
            } else {
              $con->{writer}->write ($chunk);
            }

            $con->{ws_sent_length} += $byte_length;
            $con->{to_be_sent_length} -= $byte_length;
          if ($con->{to_be_sent_length} <= 0) {
            delete $con->{cancel_current_writable_stream};
            $canceled = 1;
            delete $con->{ws_message_stream_controller};

            for (@{$con->{ws_pendings}}) {
              $stream->_ws_debug ('S', @{$_->[2]}) if $con->{DEBUG};
              $con->{writer}->write ($_->[1]);
              if ($_->[0] == 8) { # close
                $con->_send_done;
              }
            }
          }
        })->catch (sub {
          $con->abort (message => $_[0]);
          $con->{cancel_current_writable_stream}->($_[0])
              if defined $con->{cancel_current_writable_stream};
          die $_[0];
        });
      }, # write
      close => sub {
      if ($con->{to_be_sent_length} > 0) {
        my $error = Web::DOM::TypeError->new
            (sprintf "Closed before bytes (n = %d) are sent", $con->{to_be_sent_length});
        $con->abort (message => $error);
        $con->{cancel_current_writable_stream}->($error)
            if defined $con->{cancel_current_writable_stream};
        delete $con->{ws_message_stream_controller};
        die $error;
      }

      }, # close
      abort => sub {
        delete $con->{ws_message_stream_controller};
        $con->{cancel_current_writable_stream}->($_[1])
            if defined $con->{cancel_current_writable_stream};
      # XXX

      },
    }); # $ws

    $con->{ws_pendings} = [];
    # XXX
    if ($con->{to_be_sent_length} <= 0) {
      $con->{cancel_current_writable_stream}->();
      delete $con->{ws_message_stream_controller};
    }

  return ($ws);
  }

# XXX busy check by cancel_current_writable_stream
  if ($args{XXX_response}) {
    my $ws = $args{is_ws} ? undef : WritableStream->new ({
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
        die Web::DOM::TypeError->new ("The argument is not an ArrayBufferView")
            unless UNIVERSAL::isa ($chunk, 'ArrayBufferView');

      my $wm = $con->{write_mode} || '';
      if ($wm eq 'chunked') {
        my $byte_length = $chunk->byte_length; # can throw
        die Web::DOM::TypeError->new
            (sprintf "Byte length %d is greater than expected length 0",
                 $byte_length) if $canceled;
        return unless $byte_length;

        my $dv = UNIVERSAL::isa ($chunk, 'DataView')
            ? $chunk : DataView->new ($chunk->buffer, $chunk->byte_offset, $byte_length); # or throw
        if ($stream->{DEBUG} > 1) {
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
          die Web::DOM::TypeError->new
              (sprintf "Byte length %d is greater than expected length %d",
                   $byte_length, ($canceled ? 0 : $con->{to_be_sent_length} || 0))
                  if $canceled or
                     (defined $con->{to_be_sent_length} and
                      $con->{to_be_sent_length} < $byte_length);
          return unless $byte_length;

          if ($stream->{DEBUG} > 1) {
            my $dv = UNIVERSAL::isa ($chunk, 'DataView')
                ? $chunk : DataView->new ($chunk->buffer, $chunk->byte_offset, $byte_length); # or throw
            for (split /\x0A/, $dv->manakai_to_string, -1) {
              warn "$stream->{id}: S: @{[_e4d $_]}\n";
            }
          }

          my $sent = $con->{writer}->write ($chunk);
          if (defined $con->{to_be_sent_length}) {
            $con->{to_be_sent_length} -= $byte_length;
            if (defined $con->{to_be_sent_length} and
                $con->{to_be_sent_length} <= 0) {
              delete $con->{cancel_current_writable_stream};
              $canceled = 1;
              return $sent->then (sub {
                $con->_send_done;
              });
            }
          }
          return $sent;
        }
      })->catch (sub {
        $con->{cancel_current_writable_stream}->($_[0])
            if defined $con->{cancel_current_writable_stream};
        $stream->abort (message => $_[0]); # XXX
        die $_[0];
      });
    }, # write
    close => sub {
      if (defined $con->{to_be_sent_length}) {
        if ($con->{to_be_sent_length} > 0) {
          my $error = Web::DOM::TypeError->new
              (sprintf "Closed before bytes (n = %d) are sent",
                   $con->{to_be_sent_length});
          $con->{cancel_current_writable_stream}->($error)
              if defined $con->{cancel_current_writable_stream};
          $con->abort (message => $error); # XXX
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
      } elsif (not defined $con->{to_be_sent_length}) {
        $con->_send_done;
        return;
      }
    }, # close
    abort => sub {
      $con->{cancel_current_writable_stream}->($_[1])
          if defined $con->{cancel_current_writable_stream};
      return $con->abort (message => $_[1]); # XXX
    },
  });

# XXX length:0 then ws->close
    $con->{to_be_closed} = 1
        if $stream->{request}->{method} eq 'CONNECT';
  if (defined $con->{to_be_sent_length} and
      $con->{to_be_sent_length} <= 0) {
    delete $con->{cancel_current_writable_stream};
    $canceled = 1;
    if ($con->{write_mode} eq 'chunked') {
      # XXX trailer headers
      $con->{writer}->write
          (DataView->new (ArrayBuffer->new_from_scalarref (\"0\x0D\x0A\x0D\x0A")));
      $con->_send_done;
    } else {
      $con->_send_done;
    }
  }
    return ($ws);
  }

  my $ws = $args{is_ws} ? undef : WritableStream->new ({
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
      return Promise->resolve->then (sub {
        die Web::DOM::TypeError->new ("The argument is not an ArrayBufferView")
            unless UNIVERSAL::isa ($chunk, 'ArrayBufferView'); # XXX location

        my $byte_length = $chunk->byte_length;
        die Web::DOM::TypeError->new
              (sprintf "Byte length %d is greater than expected length %d",
                   $byte_length, ($canceled ? 0 : $con->{to_be_sent_length} || 0))
                  if $canceled or
                     (defined $con->{to_be_sent_length} and
                      $con->{to_be_sent_length} < $byte_length);
        return unless $byte_length;

        if ($con->{DEBUG}) {
          if ($con->{DEBUG} > 1 or $byte_length <= 40) {
            for (split /\x0A/, 'XXX', -1) {
              warn "$con->{request}->{id}: S: @{[_e4d $_]}\n";
            }
          } else {
            warn "$con->{request}->{id}: S: @{[_e4d substr $_, 0, 40]}... (@{[length $_]})\n";
          }
        }

        my $sent = $con->{writer}->write ($chunk);
        if (defined $con->{to_be_sent_length}) {
          $con->{to_be_sent_length} -= $byte_length;
          if ($con->{to_be_sent_length} <= 0) {
            delete $con->{cancel_current_writable_stream};
            $canceled = 1;
            return $sent->then (sub {
              $con->_send_done;
            });
          }
        }
        return $sent;
      })->catch (sub {
        $con->{cancel_current_writable_stream}->($_[0])
            if defined $con->{cancel_current_writable_stream};
        $con->abort (message => $_[0]); # XXX
        die $_[0];
      });
    }, # write
    close => sub {
      if (defined $con->{to_be_sent_length}) {
        if ($con->{to_be_sent_length} > 0) {
          my $error = Web::DOM::TypeError->new
              (sprintf "Closed before bytes (n = %d) are sent",
                   $con->{to_be_sent_length});
          $con->{cancel_current_writable_stream}->($error)
              if defined $con->{cancel_current_writable_stream};
          $con->abort (message => $error); # XXX
          die $error;
        }
      } else {
        $con->_send_done;
        return;
      }
    }, # close
    abort => sub {
      $con->{cancel_current_writable_stream}->($_[1])
          if defined $con->{cancel_current_writable_stream};
      return $con->abort (message => $_[1]); # XXX
    }, # abort
  });

  return ($ws);
} # _open_sending_stream

sub headers_received ($) {
  return $_[0]->{headers_received}->[0];
} # headers_received

sub _headers_received ($;%) {
  my ($stream, %args) = @_;
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
        my $con = $stream->{connection};
        return $con->abort (message => $_[1]);
      }, # cancel
    });
    $return->{messages} = $read_message_stream;
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
        my $con = $stream->{connection};
        return $con->abort (message => $_[1]);
      },
    });
    $return->{body} = $read_stream;
  } # not is_ws
  (delete $stream->{headers_received}->[1])->($return);
} # _headers_received

sub _receive_bytes_done ($) {
  my $stream = $_[0];
  if (defined (my $rc = delete $stream->{body_controller})) {
    $rc->close;
    while (defined (my $req = $rc->byob_request)) {
      $req->manakai_respond_with_new_view
          (DataView->new (ArrayBuffer->new (0)));
    }
  }
  return undef;
} # _receive_bytes_done

sub _send_request ($$;%) {
  my ($stream, $req, %args) = @_;

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

  if ($method eq 'CONNECT') {
    return Promise->reject
        (Web::DOM::TypeError->new ("Bad byte length $args{content_length}"))
            if defined $args{content_length};
  } else {
    $args{content_length} = 0+($args{content_length} || 0);
    return Promise->reject
        (Web::DOM::TypeError->new ("Bad byte length $args{content_length}"))
            unless $args{content_length} =~ /\A[0-9]+\z/;
    if ($args{content_length} > 0 or
        $method eq 'POST' or $method eq 'PUT') {
      push @{$req->{headers} ||= []},
          ['Content-Length', $args{content_length}];
    }
  }

  # XXX croak if WS protocols is bad
  # XXX utf8 flag
  # XXX header size

  my $con = $stream->{connection};
  if (not defined $con->{state}) {
    return Promise->reject
        (Web::DOM::TypeError->new ("Connection is not ready"));
  } elsif ($con->{to_be_closed}) {
    return Promise->reject (Web::DOM::TypeError->new ("Connection is closed"));
  } elsif (not ($con->{state} eq 'initial' or $con->{state} eq 'waiting')) {
    return Promise->reject (Web::DOM::TypeError->new ("Connection is busy"));
  }

  # XXX
  $req->{id} = $con->{id} . '.' . ++$con->{req_id};
  if ($con->{DEBUG}) { # XXX
    warn "$con->{id}: ========== @{[ref $con]}\n";
    warn "$con->{id}: startstream $req->{id} @{[scalar gmtime]}\n";
  }

  $stream->{headers_received} = [promised_cv];
  my ($resolve_stream, $reject_stream);
  my $stream_closed = Promise->new
      (sub { ($resolve_stream, $reject_stream) = @_ });
  $stream_closed->catch (sub { # XXX
    (delete $stream->{headers_received}->[1])->(Promise->reject ($_[0]))
        if defined $stream->{headers_received} and
           defined $stream->{headers_received}->[1];
  });
  if ($con->{DEBUG}) { # XXX
    promised_cleanup {
      warn "$con->{id}: endstream $req->{id} @{[scalar gmtime]}\n";
      warn "$con->{id}: ========== @{[ref $con]}\n";
    } $stream_closed;
  }

  $con->{stream} = $stream;
  $con->{to_be_sent_length} = $args{content_length};
  $con->{request} = $req;
  my $res = $con->{response} = {
    status => 200, reason => 'OK', version => '0.9',
    headers => [],
    stream_resolve => $resolve_stream, # XXX
    stream_reject => $reject_stream, # XXX
  };
  $con->{state} = 'before response';
  $con->{temp_buffer} = '';
  # XXX Connection: close
  if ($args{ws}) {
    $con->{ws_state} = 'CONNECTING';
    $con->{ws_key} = encode_base64 join ('', map { pack 'C', rand 256 } 1..16), '';
    push @{$req->{headers} ||= []},
        ['Sec-WebSocket-Key', $con->{ws_key}],
        ['Sec-WebSocket-Version', '13'];
    $con->{ws_protos} = $args{ws_protocols} || [];
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
      warn "$req->{id}: S: @{[_e4d $_]}\n";
    }
  }
    $stream->{response} =  $res; # XXX
  my $sent = $con->{writer}->write
      (DataView->new (ArrayBuffer->new_from_scalarref (\$header)));
  $con->{write_mode} = 'raw';
  if (defined $con->{to_be_sent_length} and $con->{to_be_sent_length} <= 0) {
    $sent = $sent->then (sub {
      $con->_send_done;
    });
  }
  my ($ws) = $stream->_open_sending_stream (is_ws => $args{ws});
  $con->_read;
  return $sent->then (sub {
    return {stream => $stream, body => $ws, closed => $stream_closed};
  }); ## could be rejected when connection aborted
} # _send_request

sub send_ws_message ($$$) {
  my ($self, $length, $is_binary) = @_;
  croak "Data too large" if MAX_BYTES < $length; # spec limit 2**63

  my $con = $self->{connection};
  return Promise->reject (Web::DOM::TypeError->new ("Stream is busy"))
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
  $con->{to_be_sent_length} = $length;

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
                    length => $length) if $self->{DEBUG}; # XXX
  $con->{writer}->write
      (DataView->new (ArrayBuffer->new_from_scalarref (\(pack ('CC', 0b10000000 | ($is_binary ? 2 : 1), $masked | $length0) . $len . $mask))));
  my ($ws) = $con->{stream}->_open_sending_stream (XXX_ws_message => 1);

  return Promise->resolve ({stream => $ws});
} # send_ws_message

sub send_ping ($;%) {
  my ($self, %args) = @_;
  $args{data} = '' unless defined $args{data};
  croak "Data is utf8-flagged" if utf8::is_utf8 $args{data};
  croak "Data too large" if 0x7D < length $args{data}; # spec limit 2**63

  my $con = $self->{connection};
  return Promise->reject (Web::DOM::TypeError->new ("Stream is busy"))
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

sub send_ws_close ($;$$) {
  my ($stream, $status, $reason) = @_;

  my $con = $stream->{connection};
  return Promise->reject (Web::DOM::TypeError->new ("Stream is busy"))
      if not (defined $con->{ws_state} and $con->{ws_state} eq 'OPEN') or
         defined $con->{cancel_current_writable_stream};

  if (defined $status and $status > 0xFFFF) {
    return Promise->reject ("Bad status");
  }
  if (defined $reason) {
    return Promise->reject ("Reason is utf8-flagged")
        if utf8::is_utf8 $reason;
    return Promise->reject ("Reason is too long")
        if 0x7D < length $reason;
  }

# XXX CONNECTING test
  if (defined $con->{ws_state} and
      ($con->{ws_state} eq 'OPEN' or
       $con->{ws_state} eq 'CONNECTING')) {
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
    my $frame = pack ('CC', 0b10000000 | 8, $masked | length $data) .
        $mask . $data;
    if ($con->{ws_state} eq 'CONNECTING') {
      $con->{pending_frame} = $frame;
      $con->{pending_frame_info} = $frame_info if $con->{DEBUG};
    } else {
      $stream->_ws_debug ('S', @$frame_info) if $con->{DEBUG};
      $con->{writer}->write (DataView->new (ArrayBuffer->new_from_scalarref (\$frame)));
      $con->{ws_state} = 'CLOSING';
      $con->{ws_timer} = AE::timer 20, 0, sub {
        if ($con->{DEBUG}) {
          my $id = $con->{is_server} ? $con->{id} : $con->{request}->{id};
          warn "$id: WS timeout (20)\n";
        }
        # XXX set exit ?
        $con->_receive_done;
      };
      #$con->_ev ('closing'); # XXX
      $con->_send_done;
    }

    return $stream->{closed};
  }

  die "XXX bad state";
} # send_ws_close

sub _ws_debug ($$$%) {
  my $self = $_[0];
  my $side = $_[1];
  my %args = @_[3..$#_];

  my $id = $self->{is_server} ? $self->{id} : $self->{request}->{id};
  warn sprintf "$id: %s: WS %s L=%d\n",
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
    warn "$id: S: status=$args{status} |@{[_e4d (defined $_[2] ? $_[2] : '')]}|\n";
  } elsif (length $_[2]) {
    if ($self->{DEBUG} > 1 or length $_[2] <= 40) {
      warn "$id: S: @{[_e4d $_[2]]}\n";
    } else {
      warn "$id: S: @{[_e4d substr $_[2], 0, 40]}... (@{[length $_[2]]})\n";
    }
  }
} # _ws_debug

#XXX
sub _ev ($$;$$) {
  my $self = shift;
  my $type = shift;
  my $req = $self->{is_server} ? $self : $self->{request};
  if ($self->{DEBUG}) {
    warn "$req->{id}: $type @{[scalar gmtime]}\n";
    if ($type eq 'data' and $self->{DEBUG}) {
      if ($self->{DEBUG} > 1 or length $_[0] <= 40) {
        for (split /\x0D?\x0A/, $_[0], -1) {
          warn "$req->{id}: R: @{[_e4d $_]}\n";
        }
      } else {
        warn "$req->{id}: R: @{[_e4d substr $_[0], 0, 40]}... (@{[length $_[0]]})\n";
      }
    } elsif ($type eq 'text' and $self->{DEBUG}) {
      if ($self->{DEBUG} > 1 or length $_[0] <= 40) {
        for (split /\x0D?\x0A/, $_[0], -1) {
          warn "$req->{id}: R: @{[_e4d_t $_]}\n";
        }
      } else {
        warn "$req->{id}: R: @{[_e4d_t substr $_[0], 0, 40]}... (@{[length $_[0]]})\n";
      }
    } elsif ($type eq 'headers') {
      my $obj = $_[0];
      if (defined $obj->{status}) { # response
        if ($obj->{version} eq '0.9') {
          warn "$req->{id}: R: HTTP/0.9\n";
        } else {
          warn "$req->{id}: R: HTTP/$obj->{version} $obj->{status} $obj->{reason}\n";
        }
      } else { # request
        my $url = $obj->{target_url}->stringify;
        warn "$req->{id}: R: $obj->{method} $url HTTP/$obj->{version}\n";
      }
      for (@{$obj->{headers}}) {
        warn "$req->{id}: R: @{[_e4d $_->[0]]}: @{[_e4d $_->[1]]}\n";
      }
      warn "$req->{id}: + WS established\n" if $_[1];
    } elsif ($type eq 'complete') {
      my $err = join ' ',
          $_[0]->{reset} ? 'reset' : (),
          $self->{response}->{incomplete} ? 'incomplete' : (),
          $_[0]->{failed} ? 'failed' : (),
          $_[0]->{cleanly} ? 'cleanly' : (),
          $_[0]->{can_retry} ? 'retryable' : (),
          defined $_[0]->{errno} ? 'errno=' . $_[0]->{errno} : (),
          defined $_[0]->{message} ? 'message=' . $_[0]->{message} : (),
          defined $_[0]->{status} ? 'status=' . $_[0]->{status} : (),
          defined $_[0]->{reason} ? 'reason=' . $_[0]->{reason} : ();
      warn "$req->{id}: + @{[_e4d_t $err]}\n" if length $err;
    } elsif ($type eq 'ping') {
      if ($_[1]) {
        warn "$req->{id}: R: pong data=@{[_e4d $_[0]]}\n";
      } else {
        warn "$req->{id}: R: data=@{[_e4d $_[0]]}\n";
      }
    }
  }
  #$self->{cb}->($self, $type, @_);
  if ($type eq 'complete') {
    $self->{is_completed} = 1;
    delete $self->{cb};
  }
} # _ev

sub send_response ($$$;%) {
  my ($stream, $response, %args) = @_;
  my $con = $stream->{connection};

  return Promise->reject (Web::DOM::TypeError->new ("Response is not allowed"))
      if not defined $con or defined $con->{write_mode} or not $con->{is_server};

  my $close = $args{close} ||
              $con->{to_be_closed} ||
              $stream->{request}->{version} == 0.9;
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
        (Web::DOM::TypeError->new ("Bad byte length $args{content_length}"))
            if defined $args{content_length};
    $to_be_sent = 0;
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
      $is_ws = 1;
      $write_mode = 'ws';
    } else {
      return Promise->reject
          (Web::DOM::TypeError->new ("1xx response not supported"));
    }
  } else {
    if (defined $args{content_length}) {
      ## If body length is specified
      $write_mode = 'raw';
      $to_be_sent = 0+$args{content_length};
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

  unless ($args{proxying}) {
    push @header, ['Server', encode_web_utf8 (defined $con ? $con->server_header : '')];

    my $dt = Web::DateTime->new_from_unix_time
        (Web::DateTime::Clock->realtime_clock->()); # XXX
    push @header, ['Date', $dt->to_http_date_string];
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
    } elsif ($stream->{request}->{version} == 1.0) {
      push @header, ['Connection', 'keep-alive'];
    }
    if ($write_mode eq 'chunked') {
      push @header, ['Transfer-Encoding', 'chunked'];
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

  if ($is_ws) {
    $con->{ws_state} = 'OPEN';
    $con->{state} = 'before ws frame';
    $con->{temp_buffer} = '';
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

    $con->{writer}->write (DataView->new (ArrayBuffer->new_from_scalarref (\$res)));
  } else {
    if ($stream->{DEBUG}) {
      warn "$stream->{id}: Response headers skipped (HTTP/0.9) @{[scalar gmtime]}\n";
    }
  }

  $con->{to_be_closed} = 1 if $close;
  $con->{write_mode} = $write_mode;
  $con->{to_be_sent_length} = $to_be_sent; # or undef
  my ($ws) = $stream->_open_sending_stream (is_ws => $is_ws, XXX_response => 1);

  return Promise->resolve ({body => $ws});
} # send_response

# XXX tests
sub abort ($;%) {
  my $stream = shift;
  $stream->{connection}->abort (@_) if defined $stream->{connection};
} # abort

sub closed ($) {
  return $_[0]->{closed};
} # closed

sub DESTROY ($) {
  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

# End of ::Stream

package Web::Transport::HTTPStream::ClientConnection;
push our @ISA, qw(Web::Transport::HTTPStream::Connection);
use Carp qw(croak);
use Errno;
use MIME::Base64 qw(encode_base64);
use Digest::SHA qw(sha1);
use Errno qw(ECONNRESET);
use Web::DOM::Error;
use Web::DOM::TypeError;
use AnyEvent;
use AnyEvent::Socket;
use Promise;
use Promised::Flow;
use ArrayBuffer;
use TypedArray;
use Streams;

push our @CARP_NOT, qw(Web::DOM::Error);

use constant DEBUG => $ENV{WEBUA_DEBUG} || 0;

BEGIN {
  *_e4d = \&Web::Transport::HTTPStream::_e4d;
  *_e4d_t = \&Web::Transport::HTTPStream::_e4d_t;
  *MAX_BYTES = \&Web::Transport::HTTPStream::MAX_BYTES;
}

sub new ($$) {
  my $self = bless {id => '',
                    req_id => 0,
                    temp_buffer => '',
                    DEBUG => DEBUG}, shift;
  $self->{args} = $_[0];
  $self->{DEBUG} = delete $self->{args}->{debug} if defined $self->{args}->{debug};
  return $self;
} # new_from_cb

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
      my $view = TypedArray::Uint8Array->new
          ($req->view->buffer, $req->view->byte_offset, $expected_size);
      return $self->{reader}->read ($view)->then (sub {
        delete $self->{read_running};
        return if $_[0]->{done};

        my $length = $_[0]->{value}->byte_length;
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
        if ($self->{request}->{method} eq 'PUT' or
            $self->{request}->{method} eq 'CONNECT') {
          return $self->_connection_error ("HTTP/0.9 response to non-GET request");
        } else {
          $stream->_headers_received;
          $stream->{body_controller}->enqueue
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
            return $self->_connection_error ("Header section too large");
          }
          $self->{temp_buffer} .= $1;
          #
        } else {
          if (2**18-1 + 2 < (length $self->{temp_buffer}) + (length $$ref) - (pos $$ref)) {
            return $self->_connection_error ("Header section too large");
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
        return $self->_connection_error ("Inconsistent content-length values");
      } elsif (1 == keys %length) {
        my $length = each %length;
        $length =~ s/\A0+//;
        $length ||= 0;
        if ($length eq 0+$length) { # overflow check
          $self->{unread_length} = $res->{content_length} = 0+$length;
        } else {
          return $self->_connection_error ("Inconsistent content-length values");
        }
      }

      if ($res->{status} == 200 and
          $self->{request}->{method} eq 'CONNECT') {
        $stream->_headers_received;
        $self->{to_be_closed} = 1;
        $self->{state} = 'tunnel';
        delete $self->{to_be_sent_length};
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
          return $self->_connection_error ({ws => 1, failed => 1, status => 1006, reason => ''});
        } else {
          $self->{ws_state} = 'OPEN';
          $stream->_headers_received (is_ws => 1);
          $stream->_receive_bytes_done;
          $self->{to_be_closed} = 1;
          $self->{state} = 'before ws frame';
          $self->{temp_buffer} = '';
          if (defined $self->{pending_frame}) {
            $self->{ws_state} = 'CLOSING';
            $self->{writer}->write
                (DataView->new (ArrayBuffer->new_from_scalarref (\($self->{pending_frame}))));
            $stream->_ws_debug ('S', @{$self->{pending_frame_info}}) if $self->{DEBUG};
            $self->{ws_timer} = AE::timer 20, 0, sub {
              warn "$self->{request}->{id}: WS timeout (20)\n" if $self->{DEBUG};
              $self->_receive_done;
            };
            $self->_send_done;
          }
        }
      } elsif (100 <= $res->{status} and $res->{status} <= 199) {
        if ($self->{request}->{method} eq 'CONNECT' or
            (defined $self->{ws_state} and
             $self->{ws_state} eq 'CONNECTING')) {
          return $self->_connection_error ("1xx response to CONNECT or WS");
        } else {
          #push @{$res->{'1xxes'} ||= []}, {
          #  version => $res->{version},
          #  status => $res->{status},
          #  reason => $res->{reason},
          #  headers => $res->{headers},
          #};
          $res->{version} = '0.9';
          $res->{status} = 200;
          $res->{reason} = 'OK';
          $res->{headers} = [];
          $self->{state} = 'before response';
          $self->{temp_buffer} = '';
          redo HEADER;
        }
      } elsif ($res->{status} == 204 or
               $res->{status} == 205 or
               $res->{status} == 304 or
               $self->{request}->{method} eq 'HEAD') {
        $self->{stream}->_headers_received;
        $self->{unread_length} = 0;
        $self->{state} = 'response body';
      } else {
        $self->{stream}->_headers_received;
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
          $stream->{body_controller}->enqueue
              (DataView->new (ArrayBuffer->new_from_scalarref (\substr $$ref, pos $$ref)));
          $ref = \'';
          $self->{unread_length} -= $len;
        }
      } elsif ($self->{unread_length} > 0) {
        $stream->{body_controller}->enqueue
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

        $self->{exit} = {};
        $self->_receive_done;
      }
    } else {
      $stream->{body_controller}->enqueue (DataView->new (ArrayBuffer->new_from_scalarref (\substr $$ref, pos $$ref)))
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
        return $self->_connection_error ({
          failed => 0,
          message => 'Invalid chunk size',
        });
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
          return $self->_connection_error ({
            failed => 0,
            message => 'Chunk size overflow',
          });
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
          $stream->{body_controller}->enqueue (DataView->new (ArrayBuffer->new_from_scalarref (\substr $$ref, pos $$ref)));
          $ref = \'';
          $self->{unread_length} -= $len;
        } else {
          $stream->{body_controller}->enqueue (DataView->new (ArrayBuffer->new_from_scalarref (\substr $$ref, (pos $$ref), $self->{unread_length})));
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
          return $self->_connection_error ({
            failed => 0,
            message => 'No CRLF after chunk',
          });
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
        return $self->_connection_error ({
          failed => 0,
          message => 'No CRLF after chunk',
        });
      }
    }
  } # CHUNK
  if ($self->{state} eq 'before response trailer') {
    if ($$ref =~ /\G(.*?)\x0A\x0D?\x0A/gcs) {
      if (2**18-1 < $self->{temp_buffer} + (length $1)) {
        return $self->_connection_error ({
          failed => 0,
          message => 'Header section too large',
        });
      }
      $self->{temp_buffer} += length $1;
      #
    } else {
      if (2**18-1 < $self->{temp_buffer} + (length $$ref) - (pos $$ref)) {
        return $self->_connection_error ({
          failed => 0,
          message => 'Header section too large',
        });
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
    $self->{exit} = {};
    $self->_receive_done;
    return;
  } # before response trailer
  if ($self->{state} eq 'before ws frame' or
      $self->{state} eq 'ws data' or
      $self->{state} eq 'ws terminating') {
    return $self->_ws_received ($ref);
  }
  if ($self->{state} eq 'tunnel') {
    $stream->{body_controller}->enqueue (DataView->new (ArrayBuffer->new_from_scalarref (\substr $$ref, pos $$ref)))
        if (length $$ref) - (pos $$ref);
    $ref = \'';
  }
  #if ($self->{state} eq 'waiting' or
  #    $self->{state} eq 'sending' or
  #    $self->{state} eq 'stopped') {
  #  #
  #}
} # _process_rbuf

sub _process_rbuf_eof ($;%) {
  my ($self, %args) = @_;
  my $stream = $self->{stream};
  # XXX %args

  if ($self->{state} eq 'before response') {
    if (length $self->{temp_buffer}) {
      if ($self->{request}->{method} eq 'PUT' or
          $self->{request}->{method} eq 'CONNECT') {
        return $self->_connection_error ("HTTP/0.9 response to non-GET request");
      } else {
        $stream->_headers_received;
        $stream->{body_controller}->enqueue (DataView->new (ArrayBuffer->new_from_scalarref (\($self->{temp_buffer}))));
        $self->{response}->{incomplete} = 1 if $args{abort};
        $stream->_receive_bytes_done;
        return $self->_connection_error ({
          failed => 0,
          message => 'Connection truncated',
        }) if $args{abort};

        $self->{exit} = {};
        $self->{to_be_closed} = 1;
        $self->_receive_done;
        return;
      }
    } else { # empty
      return $self->_connection_error ({
        failed => 1,
        message => $args{error_message} || "Connection closed without response",
        errno => $args{errno}, # XXX
        can_retry => !$args{abort} && !$self->{response_received},
      });
    }
  } elsif ($self->{state} eq 'response body') {
    if (defined $self->{unread_length}) {
      if ($self->{unread_length} > 0) {
        $self->{response}->{incomplete} = 1;
        $self->{stream}->_receive_bytes_done;
        return $self->_connection_error ({
          failed => ($self->{response}->{version} eq '1.1'),
          message => $args{error_message} || "Connection truncated", # XXX
          errno => $args{errno}, # XXX
        });
      } else { # all data read
        $self->{stream}->_receive_bytes_done;
        return $self->_connection_error ({
          failed => 0,
          message => 'Connection truncated',
        }) if $args{abort};

        $self->{exit} = {};
        $self->{to_be_closed} = 1;
        $self->_receive_done;
        return;
      }
    } else {
      $self->{response}->{incomplete} = 1 if $args{abort};
      $self->{stream}->_receive_bytes_done;
      return $self->_connection_error ({
        failed => 0,
        message => 'Connection truncated',
      }) if $args{abort};

      $self->{exit} = {};
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
    return $self->_connection_error ({
      failed => 0,
      message => 'Connection truncated within chunk',
    });
  } elsif ($self->{state} eq 'before response trailer') {
    return $self->_connection_error ({
      failed => 0,
      message => 'Connection truncated within trailer',
    });
  } elsif ($self->{state} eq 'tunnel') {
    $self->{stream}->_receive_bytes_done;
    return $self->_connection_error ("Connection truncated")
        if $args{abort};
    $self->{exit} = {};
    $self->{to_be_closed} = 1;
    $self->_receive_done;
    return;
  } elsif ($self->{state} eq 'before response header') {
    return $self->_connection_error ({
      failed => 1,
      message => $args{error_message} || "Connection closed within response headers",
      errno => $args{errno},
    });
  } elsif ($self->{state} eq 'before ws frame' or
           $self->{state} eq 'ws data' or
           $self->{state} eq 'ws terminating') {
    return $self->_ws_received_eof (\($self->{temp_buffer}), %args);
  } else {
    # initial
    # waiting
    # sending
    # stopped
    return $self->_connection_error ({
      failed => $args{abort},
      message => 'Connection closed',
    });
  }
} # _process_rbuf_eof

# XXX merge with new?
sub connect ($) {
  my ($self) = @_;
  croak "Bad state" if not defined $self->{args};
  my $args = delete $self->{args};
  $self->{state} = 'initial';
  $self->{response_received} = 1;

  my $onclosed;
  my $closed = Promise->new (sub { $onclosed = $_[0] });
  $self->{closed} = $closed->then (sub {
    $self->_terminate;
    return undef;
  });

  if ($self->{DEBUG}) {
    #XXX
    #my $id = $self->{id};
    #warn "$id: Connect (@{[$self->{transport}->layered_type]})... @{[scalar gmtime]}\n";
  }

  return $args->{parent}->{class}->create ($args->{parent})->then (sub {
    my $info = $_[0];

    $self->{info} = {}; # XXX
    if ($self->{DEBUG}) { # XXX
      warn "$self->{id}: openconnection @{[scalar gmtime]}\n";
      $self->_debug_handshake_done ({});
    }

    $self->{reader} = $info->{read_stream}->get_reader ('byob');
    $self->{writer} = $info->{write_stream}->get_writer;
    #$self->_read;

    my $p1 = $self->{reader}->closed->then (sub { # XXX
        delete $self->{reader};
        if ($self->{DEBUG}) {
          my $id = $self->{id};
          warn "$id: R: EOF\n";
        }

        $self->_process_rbuf (undef);
        $self->_process_rbuf_eof;
        return undef;
      }, sub {
        delete $self->{reader};
        my $data = {failed => 1, message => $_[0]}; # XXX
        my $error = Web::DOM::Error->wrap ($_[0]);

        if ($self->{DEBUG}) {
          my $id = $self->{id};
          warn "$id: R: EOF ($data->{message})\n";
        }

        if (UNIVERSAL::isa ($error, 'Streams::IOError') and
            $error->errno == ECONNRESET) {
          return $self->_connection_error ({failed => 1, reset => 1});
        } else {
          $self->_process_rbuf (undef);
          $self->_process_rbuf_eof
              (abort => $data->{failed},
               errno => $data->{errno},
               error_message => $data->{message});
          return;
        }
      });

    my $p2 = $self->{writer}->closed->then (sub { # XXX
        if ($self->{DEBUG}) {
          my $id = $self->{id};
          warn "$id: S: EOF\n";
        }
      }, sub {
        if ($self->{DEBUG}) {
          my $data = $_[0];
          my $id = $self->{id};
          if (ref $data eq 'HASH' and defined $data->{message}) { # XXX
            warn "$id: S: EOF ($data->{message})\n";
          } else {
            warn "$id: S: EOF\n";
          }
        }
      });

    Promise->all ([$p1, $p2, #$info->{closed} XXX
    ])->then (sub {
      $onclosed->();
    });

    return undef;
  })->catch (sub {
    my $error = $_[0];
    unless (ref $error eq 'HASH' and $error->{failed}) {
      $error = {failed => 1, message => ''.$error};
    }
    $self->{info} = {};
    if ($self->{DEBUG}) { # XXX
      warn "$self->{id}: openconnection @{[scalar gmtime]}\n";
      $self->_debug_handshake_done ($error);
    }
    $self->{writer}->abort ('XXX 1') if defined $self->{writer}; # XXX and reader?
    $onclosed->();
    die $error;
  });
} # connect

# End of ::ClientConnection

package Web::Transport::HTTPStream::ServerConnection;
push our @ISA, qw(Web::Transport::HTTPStream::Connection);
use AnyEvent;
use Promise;
use Promised::Flow;
use Web::Host;
use Web::URL;

use constant DEBUG => $ENV{WEBSERVER_DEBUG} || 0;
our $ReadTimeout ||= 60;

BEGIN {
  *_e4d = \&Web::Transport::HTTPStream::_e4d;
  *_e4d_t = \&Web::Transport::HTTPStream::_e4d_t;
  *MAX_BYTES = \&Web::Transport::HTTPStream::MAX_BYTES;
}

# XXX
sub new ($$) {
  my ($class, $args) = @_;
  my $self = bless {DEBUG => DEBUG, is_server => 1,
                    id => rand,
                    #XXX id => $args{transport}->id, req_id => 0,
                    #XXX transport => $args{transport},
                    rbuf => '', state => 'initial'}, $class;
  $self->{DEBUG} = $args->{debug} if defined $args->{debug};

  $self->{received_streams} = ReadableStream->new ({
    start => sub {
      $self->{stream_controller} = $_[1];
    },
    pull => sub {
      return $self->_read;
    },
    cancel => sub {
      # XXX abort
      
    },
  }); # received_streams

  $self->{closed} = $args->{parent}->{class}->create ($args->{parent})->then (sub {
    my $info = $_[0];

    my $tinfo = $info;
    if ($info->{type} eq 'TLS') {
      $self->{url_scheme} = 'https';
      $tinfo = $tinfo->{parent};
    } else { # TCP or Unix
      $self->{url_scheme} = 'http';
    }
    if ($tinfo->{type} eq 'TCP') {
      $self->{url_hostport} = $tinfo->{local_host}->to_ascii . ':' . $tinfo->{local_port};
    } else { # Unix
      $self->{url_hostport} = '0.0.0.0';
    }

    $self->{timer} = AE::timer $ReadTimeout, 0, sub { $self->_timeout };
    $self->{info} = {};
    if ($self->{DEBUG}) { # XXX
      warn "$self->{id}: openconnection @{[scalar gmtime]}\n";
      $self->_debug_handshake_done ({});
    }

    $self->{reader} = $info->{read_stream}->get_reader ('byob');
    $self->{writer} = $info->{write_stream}->get_writer;

    $self->_read;

    my $p1 = $self->{reader}->closed->then (sub {
      delete $self->{reader};
      if ($self->{DEBUG}) {
        my $id = ''; # XXX $transport->id;
        warn "$id: R: EOF\n";
      }
      delete $self->{timer};
      $self->_oneof (undef);
      return undef;
    }, sub {
      delete $self->{reader};
      if ($self->{DEBUG}) {
        my $id = ''; # XXX $transport->id;
        warn "$id: R: EOF (@{[_e4d_t $_[0]]})\n";
      }
      delete $self->{timer};
      $self->{exit} = {failed => 1, message => $_[0]}; # XXX
      $self->_oneof ($_[0]);
      return undef;
    });

    my $p2 = $self->{writer}->closed->then (sub {
      delete $self->{writer};
      if ($self->{DEBUG}) {
        my $id = ''; # XXX $transport->id;
        warn "$id: S: EOF\n";
      }
      return undef;
    }, sub {
      delete $self->{writer};
      if ($self->{DEBUG}) {
        my $id = ''; # XXX $transport->id;
        warn "$id: S: EOF (@{[_e4d_t $_[0]]})\n";
      }
      return undef;
    }); # underlying writer closed

    return Promise->all ([$p1, $p2, $info->{closed}])->then (sub {
      my $p;
      # XXX
      $p = $self->{stream_controller}->close
          if defined $self->{stream_controller};
      delete $self->{stream_controller};
      $self->_terminate;
      return undef;
    });
  })->catch (sub {
    my $error = Web::DOM::Error->wrap ($_[0]);
    $self->{info} = {};
    if ($self->{DEBUG}) { # XXX
      warn "$self->{id}: openconnection @{[scalar gmtime]}\n";
      $self->_debug_handshake_done ($error);
    }

    $self->{exit} = $error; # XXX$error->{exit};
    my $p;
    $p = $self->{stream_controller}->close
        if defined $self->{stream_controller};
    $self->_terminate;
    return Promise->resolve ($p)->then (sub {
      die $error;
    });
  });
  return $self;
} # new

sub id ($) { # XXX
  return $_[0]->{id};
} # id

# XXX constructor
sub server_header ($;$) {
  if (@_ > 1) {
    $_[0]->{server_header} = $_[1];
  }
  return defined $_[0]->{server_header} ? $_[0]->{server_header} : 'Server';
} # server_header

sub _url_scheme ($) {
  return $_[0]->{url_scheme};
} # _url_scheme

sub _url_hostport ($) {
  return $_[0]->{url_hostport};
} # _url_hostport

sub _new_stream ($) {
  my $con = $_[0];
  my $req = $con->{stream} = bless {
    is_server => 1, DEBUG => $con->{DEBUG},
    connection => $con,
    id => $con->{id} . '.' . ++$con->{req_id},
    request => {
      headers => [],
      # method target_url version
    },
    # cb target
  }, 'Web::Transport::HTTPStream::Stream';

  if ($con->{DEBUG}) { # XXX
    warn "$con->{id}: ========== @{[ref $con]}\n";
    warn "$con->{id}: startstream $req->{id} @{[scalar gmtime]}\n";
  }

  my ($resolve_stream, $reject_stream);
  $req->{headers_received} = [promised_cv];

  $req->{closed} = Promise->new (sub {
    $req->{closed_resolve} = $_[0];
    $req->{closed_reject} = $_[1];
  }); # XXX

  $con->{stream_controller}->enqueue ({stream => $req, closed => $req->{closed}});

  return $req;
} # _new_stream

sub _read ($) {
  my $self = $_[0];
  return unless defined $self->{reader};
  my $read; $read = sub {
    return $self->{reader}->read (DataView->new (ArrayBuffer->new (1024*3)))->then (sub {
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
    $self->abort (message => $_[0]);
    return undef;
  })->then (sub { undef $read });
} # _read

sub _ondata ($$) {
  my ($self, $in) = @_;
  my $stream = $self->{stream};
  my $inref = \($in->manakai_to_string);
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
        $self->_new_stream;
        $stream = $self->{stream};
        $line =~ s/\x0D\z//;
        if ($line =~ /[\x00\x0D]/) {
          $stream->{request}->{version} = 0.9;
          $stream->{request}->{method} = 'GET';
          return $self->_connection_error;
        }
        if ($line =~ s{\x20+(H[^\x20]*)\z}{}) {
          my $version = $1;
          if ($version =~ m{\AHTTP/1\.([0-9]+)\z}) {
            $stream->{request}->{version} = $1 =~ /[^0]/ ? 1.1 : 1.0;
          } elsif ($version =~ m{\AHTTP/0+1?\.}) {
            $stream->{request}->{version} = 0.9;
            $stream->{request}->{method} = 'GET';
            return $self->_connection_error;
          } elsif ($version =~ m{\AHTTP/[0-9]+\.[0-9]+\z}) {
            $stream->{request}->{version} = 1.1;
          } else {
            $stream->{request}->{version} = 0.9;
            $stream->{request}->{method} = 'GET';
            return $self->_connection_error;
          }
          if ($line =~ s{\A([^\x20]+)\x20+}{}) {
            $stream->{request}->{method} = $1;
          } else { # no method
            $stream->{request}->{method} = 'GET';
            return $self->_connection_error;
          }
        } else { # no version
          $stream->{request}->{version} = 0.9;
          $stream->{request}->{method} = 'GET';
          unless ($line =~ s{\AGET\x20+}{}) {
            return $self->_connection_error;
          }
        }
        $stream->{target} = $line;
        if ($stream->{target} =~ m{\A/}) {
          if ($stream->{request}->{method} eq 'CONNECT') {
            return $self->_connection_error;
          } else {
            #
          }
        } elsif ($stream->{target} =~ m{^[A-Za-z][A-Za-z0-9.+-]+://}) {
          if ($stream->{request}->{method} eq 'CONNECT') {
            return $self->_connection_error;
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
            return $self->_connection_error;
          }
        }
        if ($stream->{request}->{version} == 0.9) {
          $self->_request_headers or return;
        } else { # 1.0 / 1.1
          return $self->_connection_error unless length $line;
          $self->{state} = 'before request header';
        }
      } elsif (8192 <= length $self->{rbuf}) {
        $self->_new_stream;
        $stream = $self->{stream};
        $stream->{request}->{method} = 'GET';
        $stream->{request}->{version} = 1.1;
        return $self->_connection_error ({
          failed => 1,
          status => 414,
          reason => 'Request-URI Too Large',
        });
      } else {
        return;
      }
    } elsif ($self->{state} eq 'before request header') {
      $self->{rbuf} .= $$inref;
      if ($self->{rbuf} =~ s/\A([^\x0A]{0,8191})\x0A//) {
        my $line = $1;
        return $self->_connection_error
            if @{$stream->{request}->{headers}} == 100;
        $line =~ s/\x0D\z//;
        return $self->_connection_error
            if $line =~ /[\x00\x0D]/;
        if ($line =~ s/\A([^\x09\x20:][^:]*):[\x09\x20]*//) {
          my $name = $1;
          push @{$stream->{request}->{headers}}, [$name, $line];
        } elsif ($line =~ s/\A[\x09\x20]+// and
                 @{$stream->{request}->{headers}}) {
          if ((length $stream->{request}->{headers}->[-1]->[0]) + 1 +
              (length $stream->{request}->{headers}->[-1]->[1]) + 1 +
              (length $line) + 2 > 8192) {
            return $self->_connection_error;
          } else {
            $stream->{request}->{headers}->[-1]->[1] .= " " . $line;
          }
        } elsif ($line eq '') { # end of headers
          $self->_request_headers or return;
          $stream = $self->{stream};
        } else { # broken line
          return $self->_connection_error;
        }
      } elsif (8192 <= length $self->{rbuf}) {
        return $self->_connection_error;
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
        $stream->{body_controller}->enqueue
            (DataView->new (ArrayBuffer->new_from_scalarref ($ref)));
        return;
      }

      my $in_length = length $$ref;
      if (not $in_length) {
        return;
      } elsif ($self->{unread_length} == $in_length) {
        if (defined $stream->{ws_key}) {
          $self->{state} = 'ws handshaking';
          $self->{to_be_closed} = 1;
        }
        $stream->{body_controller}->enqueue
            (DataView->new (ArrayBuffer->new_from_scalarref ($ref)));
        $stream->_receive_bytes_done;
        unless (defined $stream->{ws_key}) {
          $self->_receive_done;
        }
      } elsif ($self->{unread_length} < $in_length) { # has redundant data
        $stream->{incomplete} = 1;
        $self->{to_be_closed} = 1;
        if (defined $stream->{ws_key}) {
          $self->{state} = 'ws handshaking';
        }
        $stream->{body_controller}->enqueue
            (DataView->new (ArrayBuffer->new_from_scalarref ($ref), 0, $self->{unread_length}));
        $stream->_receive_bytes_done;
        unless (defined $stream->{ws_key}) {
          $self->_receive_done;
        }
        return;
      } else { # unread_length > $in_length
        $self->{unread_length} -= $in_length;
        $stream->{body_controller}->enqueue
            (DataView->new (ArrayBuffer->new_from_scalarref ($ref)));
        return;
      }
    } elsif ($self->{state} eq 'before ws frame' or
             $self->{state} eq 'ws data' or
             $self->{state} eq 'ws terminating') {
      my $ref = $inref;
      if (length $self->{rbuf}) {
        $ref = \($self->{rbuf} . $$inref); # string copy!
        $self->{rbuf} = '';
      }
      pos ($$ref) = 0;
      return $self->_ws_received ($ref);
    } elsif ($self->{state} eq 'ws handshaking') {
      return unless length $$inref;
      return $self->_connection_error;
    } elsif ($self->{state} eq 'end') {
      return;
    } else {
      die "Bad state |$self->{state}|";
    }
    $inref = \'';
  } # while
} # _ondata

sub _oneof ($$) {
  my ($self, $error) = @_;
  delete $self->{writer} if defined $error; # XXX
  if ($self->{state} eq 'initial' or
      $self->{state} eq 'before request-line') {
    if (not defined $self->{writer}) {
      delete $self->{timer};
      $self->{state} = 'end';
      return;
    } else {
      my $stream = $self->_new_stream;
      $stream->{request}->{version} = 0.9;
      $stream->{request}->{method} = 'GET';
      return $self->_connection_error ($error);
    }
  } elsif ($self->{state} eq 'before request header') {
    $self->{to_be_closed} = 1;
    return $self->_connection_error ($error);
  } elsif ($self->{state} eq 'request body') {
    $self->{to_be_closed} = 1;
    if (defined $self->{unread_length}) {
      # $self->{unread_length} > 0
      $self->{stream}->{incomplete} = 1;
      $error = {failed => 1, message => 'Connection closed'} # XXX
          unless defined $error;
    }
    $self->{stream}->_receive_bytes_done;
    $self->{exit} = $error;
    $self->_receive_done;
  } elsif ($self->{state} eq 'before ws frame' or
           $self->{state} eq 'ws data' or
           $self->{state} eq 'ws terminating') {
    $self->{exit} = {failed => 1, message => $error}; # XXX
    return $self->_ws_received_eof (\'');
  } elsif ($self->{state} eq 'ws handshaking') {
    return $self->_connection_error ($error);
  } elsif ($self->{state} eq 'after request') {
    if (length $self->{rbuf}) { # XXX
      my $stream = $self->_new_stream;
      $stream->{request}->{version} = 0.9;
      $stream->{request}->{method} = 'GET';
      return $self->_connection_error ($error);
    } elsif (defined $self->{stream}) {
      return $self->_connection_error ($error);
    } else {
      # XXX
      $self->{writer}->close if defined $self->{writer};
      delete $self->{writer};
      $self->{state} = 'end';
    }
  } elsif ($self->{state} eq 'end') {
    # XXX
    $self->{writer}->close if defined $self->{writer};
    delete $self->{writer};
  } else {
    die "Bad state |$self->{state}|";
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
    $con->_connection_error;
    return 0;
  } else { # no Host:
    if ($stream->{request}->{version} == 1.1) {
      $con->_connection_error;
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
        $con->_connection_error;
        return 0;
      }
    }

    my $target = delete $stream->{target};
    $target =~ s/([\x80-\xFF])/sprintf '%%%02X', ord $1/ge;
    my ($target_host, $target_port) = Web::Host->parse_hostport_string ($target);
    unless (defined $target_host) {
      $con->_connection_error;
      return 0;
    }
    $target_url = Web::URL->parse_string ("http://$target/");
  } elsif ($stream->{target} eq '*') {
    if (defined $host) {
      ($host_host, $host_port) = Web::Host->parse_hostport_string ($host);
      unless (defined $host_host) {
        $con->_connection_error;
        return 0;
      }
      my $scheme = $con->_url_scheme;
      $target_url = Web::URL->parse_string ("$scheme://$host/");
      delete $stream->{target};
    } else {
      $con->_connection_error;
      return 0;
    }
  } elsif ($stream->{target} =~ m{\A/}) {
    if (defined $host) {
      ($host_host, $host_port) = Web::Host->parse_hostport_string ($host);
      unless (defined $host_host) {
        $con->_connection_error;
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
      $con->_connection_error;
      return 0;
    }
  } else { # absolute URL
    my $target = delete $stream->{target};
    $target =~ s/([\x80-\xFF])/sprintf '%%%02X', ord $1/ge;
    $target_url = Web::URL->parse_string ($target);
    if (not defined $target_url or not defined $target_url->host) {
      $con->_connection_error;
      return 0;
    }

    if (defined $host) {
      ($host_host, $host_port) = Web::Host->parse_hostport_string ($host);
      unless (defined $host_host) {
        $con->_connection_error;
        return 0;
      }
    }
  }
  if (defined $host_host and defined $target_url) {
    unless ($host_host->equals ($target_url->host)) {
      $con->_connection_error;
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
      $con->_connection_error;
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
        $con->_connection_error ({
          failed => 1,
          status => 426,
          reason => 'Upgrade Required',
          headers => [
            ['Upgrade', 'websocket'],
            ['Sec-WebSocket-Version', '13'],
          ],
         });
      } else {
        $con->_connection_error;
      }
      return 0;
    } # WS_OK
  } elsif (@{$headers{upgrade} or []}) {
    $con->_connection_error;
    return 0;
  }

  ## Transfer-Encoding:
  if (@{$headers{'transfer-encoding'} or []}) {
    $con->_connection_error ({
      failed => 1,
      status => 411,
      reason => 'Length Required',
    });
    return 0;
  }

  $con->{state} = 'request body' if $stream->{request}->{method} eq 'CONNECT';

  ## Content-Length:
  my $l = 0;
  if (@{$headers{'content-length'} or []} == 1 and
      $headers{'content-length'}->[0] =~ /\A[0-9]+\z/) {
    $l = 0+$headers{'content-length'}->[0]
        unless $stream->{request}->{method} eq 'CONNECT';
  } elsif (@{$headers{'content-length'} or []}) { # multiple headers or broken
    $con->_connection_error;
    return 0;
  }
  $stream->{request}->{body_length} = $l;

  if (defined $stream->{ws_key}) {
    unless ($l == 0) {
      $con->_connection_error;
      return 0;
    }
    $stream->_headers_received (is_ws => 1, is_request => 1);
    $con->{state} = 'ws handshaking';
    $con->{to_be_closed} = 1;
    # XXX disable timer
  } elsif ($stream->{request}->{method} eq 'CONNECT') {
    $stream->_headers_received (is_request => 1);
    delete $con->{timer};
    $con->{disable_timer} = 1;
  } elsif ($l == 0) {
    $stream->_headers_received (is_request => 1);
    $stream->_receive_bytes_done;
    unless (defined $stream->{ws_key}) {
      $con->_receive_done;
    }
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
  my $error = Web::DOM::TypeError->new ("Read timeout ($ReadTimeout)");
  return $self->abort (message => $error);
} # _timeout

sub received_streams ($) {
  return $_[0]->{received_streams};
} # received_streams

# End of ::ServerConnection

1;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
