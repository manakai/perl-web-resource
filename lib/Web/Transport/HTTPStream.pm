package Web::Transport::HTTPStream;
use strict;
use warnings;
our $VERSION = '1.0';
use Web::Encoding;

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

BEGIN {
  *_e4d = \&Web::Transport::HTTPStream::_e4d;
  *_e4d_t = \&Web::Transport::HTTPStream::_e4d_t;
  *MAX_BYTES = \&Web::Transport::HTTPStream::MAX_BYTES;
}

sub info ($) { return $_[0]->{info} } # or undef

sub _ws_received ($;%) {
  my ($self, $ref, %args) = @_;
  my $stream = $self->{is_server} ? $self->{stream} : $self;
  my $ws_failed;
  WS: {
    if ($self->{state} eq 'before ws frame') {
      my $rlength = length $$ref;
      last WS if $rlength < 2;

      my $b1 = ord substr $$ref, 0, 1;
      my $b2 = ord substr $$ref, 1, 1;
      my $fin = $b1 & 0b10000000;
      my $opcode = $b1 & 0b1111;
      my $mask = $b2 & 0b10000000;
      $self->{unread_length} = $b2 & 0b01111111;
      if ($self->{unread_length} == 126) {
        if ($opcode >= 8) {
          $ws_failed = '';
          last WS;
        }
        last WS unless $rlength >= 4;
        $self->{unread_length} = unpack 'n', substr $$ref, 2, 2;
        pos ($$ref) = 4;
        if ($self->{unread_length} < 126) {
          $ws_failed = '';
          last WS;
        }
      } elsif ($self->{unread_length} == 127) {
        if ($opcode >= 8) {
          $ws_failed = '';
          last WS;
        }
        last WS unless $rlength >= 10;
        $self->{unread_length} = unpack 'Q>', substr $$ref, 2, 8;
        pos ($$ref) = 10;
        if ($self->{unread_length} > MAX_BYTES) { # spec limit=2**63
          $ws_failed = '';
          last WS;
        }
        if ($self->{unread_length} < 2**16) {
          $ws_failed = '';
          last WS;
        }
      } else {
        pos ($$ref) = 2;
      }
      if ($mask) {
        last WS unless $rlength >= pos ($$ref) + 4;
        $self->{ws_decode_mask_key} = substr $$ref, pos ($$ref), 4;
        $self->{ws_read_length} = 0;
        pos ($$ref) += 4;
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
      substr ($$ref, 0, pos $$ref) = '';
      $self->{state} = 'ws data';
    }
    if ($self->{state} eq 'ws data') {
      if ($self->{unread_length} > 0 and
          length ($$ref) >= $self->{unread_length}) {
        if (defined $self->{ws_decode_mask_key}) {
          push @{$self->{ws_frame}->[1]}, substr $$ref, 0, $self->{unread_length};
          for (0..((length $self->{ws_frame}->[1]->[-1])-1)) {
            substr ($self->{ws_frame}->[1]->[-1], $_, 1) = substr ($self->{ws_frame}->[1]->[-1], $_, 1) ^ substr ($self->{ws_decode_mask_key}, ($self->{ws_read_length} + $_) % 4, 1);
          }
          $self->{ws_read_length} += length $self->{ws_frame}->[1];
        } else {
          push @{$self->{ws_frame}->[1]}, substr $$ref, 0, $self->{unread_length};
        }
        #if ($self->{DEBUG} > 1 or
        #    ($self->{DEBUG} and $self->{ws_frame}->[0] >= 8)) {
        if ($self->{DEBUG} and $self->{ws_frame}->[0] == 8) {
          my $id = defined $self->{request} ? $self->{request}->{id} : $self->{id};
          if ($self->{ws_frame}->[0] == 8 and
              $self->{unread_length} > 1) {
            warn sprintf "$id: R: status=%d %s\n",
                unpack ('n', substr $$ref, 0, 2),
                _e4d substr ($$ref, 2, $self->{unread_length});
          } else {
            warn sprintf "$id: R: %s\n",
                _e4d substr ($$ref, 0, $self->{unread_length});
          }
        }
        substr ($$ref, 0, $self->{unread_length}) = '';
        $self->{unread_length} = 0;
      }
      if ($self->{unread_length} <= 0) {
        if ($self->{ws_frame}->[0] == 8) {
          my $data = join '', @{$self->{ws_frame}->[1]};
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
          unless ($self->{ws_state} eq 'CLOSING') {
            $self->{ws_state} = 'CLOSING';
            $stream->_ev ('closing');
            my $mask = '';
            my $masked = 0;
            unless ($self->{is_server}) {
              $masked = 0b10000000;
              $mask = pack 'CCCC', rand 256, rand 256, rand 256, rand 256;
              for (0..((length $data)-1)) {
                substr ($data, $_, 1) = substr ($data, $_, 1) ^ substr ($mask, $_ % 4, 1);
              }
            }
            $stream->_ws_debug ('S', defined $reason ? $reason : '',
                              FIN => 1, opcode => 8, mask => $mask,
                              length => length $data, status => $status)
                if $self->{DEBUG};
            $stream->{writer}->write
                (DataView->new (ArrayBuffer->new_from_scalarref (\(pack ('CC', 0b10000000 | 8, $masked | length $data) .
                   $mask . $data))));
          }
          $self->{state} = 'ws terminating';
          $self->{exit} = {status => defined $status ? $status : 1005,
                           reason => defined $reason ? $reason : '',
                           ws => 1, cleanly => 1};
          $stream->_send_done;
          if ($self->{is_server}) {
            $stream->_receive_done;
          } else {
            $self->{ws_timer} = AE::timer 1, 0, sub { # XXX spec
              if ($self->{DEBUG}) {
                my $id = defined $self->{request} ? $self->{request}->{id} : $self->{id};
                warn "$id: WS timeout (1)\n";
              }
              delete $self->{ws_timer};
              $stream->_receive_done;
            };
          }
          return;
        } elsif ($self->{ws_frame}->[0] <= 2) { # 0, 1, 2
          if ($self->{ws_frame}->[2]) { # FIN
            if ($self->{ws_frame}->[0] == 1) { # text
              my $buffer = join '', @{$self->{ws_frame}->[1]};
              $self->{ws_frame}->[1] = [eval { decode 'utf-8', $buffer, Encode::FB_CROAK }]; # XXX Encoding Standard # XXX streaming decoder
              if (length $buffer) {
                $ws_failed = 'Invalid UTF-8 in text frame';
                last WS;
              }
              $stream->_ev ('textstart', {});
              for (@{$self->{ws_frame}->[1]}) {
                $stream->_ev ('text', $_);
              }
              $stream->_ev ('textend');
            } else { # binary
              $stream->_ev ('datastart', {});
              for (@{$self->{ws_frame}->[1]}) {
                $stream->_ev ('data', $_);
              }
              $stream->_ev ('dataend');
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
          $stream->_ws_debug ('S', $data, FIN => 1, opcode => 10, mask => $mask,
                            length => length $data) if $self->{DEBUG};
          unless ($self->{is_server}) {
            for (0..((length $data)-1)) {
              substr ($data, $_, 1) = substr ($data, $_, 1) ^ substr ($mask, $_ % 4, 1);
            }
          }
          $stream->{writer}->write
              (DataView->new (ArrayBuffer->new_from_scalarref (\(pack ('CC', 0b10000000 | 10, $masked | length $data) .
                 $mask . $data))));
          $stream->_ev ('ping', (join '', @{$self->{ws_frame}->[1]}), 0);
        } elsif ($self->{ws_frame}->[0] == 10) {
          $stream->_ev ('ping', (join '', @{$self->{ws_frame}->[1]}), 1);
        } # frame type
        delete $self->{ws_frame};
        delete $self->{ws_decode_mask_key};
        $self->{state} = 'before ws frame';
        redo WS;
      }
    }
  } # WS
  if (defined $ws_failed) {
    $self->{ws_state} = 'CLOSING';
    $ws_failed = 'WebSocket Protocol Error' unless length $ws_failed;
    $ws_failed = '' if $ws_failed eq '-';
    $self->{exit} = {ws => 1, failed => 1, status => 1002, reason => $ws_failed};
    my $data = pack 'n', $self->{exit}->{status};
    $data .= $self->{exit}->{reason};
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
    $stream->_ws_debug ('S', $self->{exit}->{reason}, FIN => 1, opcode => 8,
                      mask => $mask, length => length $data,
                      status => $self->{exit}->{status}) if $self->{DEBUG};
    $stream->{writer}->write
        (DataView->new (ArrayBuffer->new_from_scalarref (\(pack ('CC', 0b10000000 | 8, $masked | length $data) .
           $mask . $data))));
    $self->{state} = 'ws terminating';
    $self->{no_new_request} = 1;
    $stream->_send_done;
    $stream->_receive_done;
    return;
  }
  if ($self->{state} eq 'ws terminating') {
    if (length $$ref) {
      if (not $self->{exit}->{failed}) {
        $self->{exit}->{failed} = 1;
        $self->{exit}->{ws} = 1;
        $self->{exit}->{status} = 1006;
        $self->{exit}->{reason} = '';
        delete $self->{exit}->{cleanly};
      }
      $$ref = '';
    }
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
  $self->{no_new_request} = 1;
  $self->{request_state} = 'sent';
  my $stream = $self->{is_server} ? $self->{stream} : $self;
  $stream->_receive_done;
} # _ws_received_eof

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

package Web::Transport::HTTPStream::Stream;
use Carp qw(croak);
use AnyEvent;
use Promise;
use Web::Encoding;
use ArrayBuffer;
use DataView;

BEGIN {
  *_e4d = \&Web::Transport::HTTPStream::_e4d;
  *_e4d_t = \&Web::Transport::HTTPStream::_e4d_t;
  *MAX_BYTES = \&Web::Transport::HTTPStream::MAX_BYTES;
}

sub _end_of_headers ($) {
  my $self = $_[0];
  my $read_stream = ReadableStream->new ({
    type => 'bytes',
    auto_allocate_chunk_size => 1024*2,
    start => sub {
      $self->{receive_controller} = $_[1];
      return undef;
    },
    pull => sub {
      return $self->_read;
    },
    cancel => sub {
      delete $self->{receive_controller};
      return $self->abort (message => defined $_[1] ? $_[1] : 'HTTP reader cancelled');
    },
  });
  $self->{receiving}->{body} = $read_stream;
  (delete $self->{receiving}->{end_of_headers})->();
} # _end_of_headers

sub _receive_bytes_done ($) {
  my $self = $_[0];
  my $rc = delete $self->{receive_controller};
  return undef unless defined $rc;
  $rc->close;
  my $req = $rc->byob_request;
  if (defined $req) {
    $req->manakai_respond_with_new_view (DataView->new (ArrayBuffer->new));
  }
  return undef;
} # _receive_bytes_done

sub send_text_header ($$) {
  my ($self, $length) = @_;
  croak "Data is utf8-flagged" if utf8::is_utf8 $_[2];
  croak "Data too large" if MAX_BYTES < $length; # spec limit 2**63
  my $con = $self->{is_server} ? $self->{connection} : $self;
  croak "Bad state"
      if not (defined $con->{ws_state} and $con->{ws_state} eq 'OPEN') or
         (defined $self->{to_be_sent_length} and
          $self->{to_be_sent_length} > 0);

  my $mask = '';
  my $masked = 0;
  unless ($self->{is_server}) {
    $masked = 0b10000000;
    $self->{ws_encode_mask_key} = $mask = pack 'CCCC', rand 256, rand 256, rand 256, rand 256;
  } else {
    delete $self->{ws_encode_mask_key};
  }

  $self->{ws_sent_length} = 0;
  $self->{to_be_sent_length} = $length;

  my $length0 = $length;
  my $len = '';
  if ($length >= 2**16) {
    $length0 = 0x7F;
    $len = pack 'n', $length;
  } elsif ($length >= 0x7E) {
    $length0 = 0x7E;
    $len = pack 'Q>', $length;
  }
  $self->_ws_debug ('S', $_[2], FIN => 1, opcode => 1, mask => $mask,
                    length => $length) if $self->{DEBUG};
  $con->{writer}->write
      (DataView->new (ArrayBuffer->new_from_scalarref (\(pack ('CC', 0b10000000 | 1, $masked | $length0) .
         $len . $mask))));
} # send_text_header

sub send_binary_header ($$) {
  my ($self, $length) = @_;
  croak "Data is utf8-flagged" if utf8::is_utf8 $_[2];
  croak "Data too large" if MAX_BYTES < $length; # spec limit 2**63
  my $con = $self->{is_server} ? $self->{connection} : $self;
  croak "Bad state"
      if not (defined $con->{ws_state} and $con->{ws_state} eq 'OPEN') or
         (defined $self->{to_be_sent_length} and
          $self->{to_be_sent_length} > 0);

  my $mask = '';
  my $masked = 0;
  unless ($self->{is_server}) {
    $masked = 0b10000000;
    $self->{ws_encode_mask_key} = $mask = pack 'CCCC', rand 256, rand 256, rand 256, rand 256;
  } else {
    delete $self->{ws_encode_mask_key};
  }

  $self->{ws_sent_length} = 0;
  $self->{to_be_sent_length} = $length;

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
      (DataView->new (ArrayBuffer->new_from_scalarref (\(pack ('CC', 0b10000000 | 2, $masked | $length0) .
         $len . $mask))));
} # send_binary_header

sub send_ping ($;%) {
  my ($self, %args) = @_;
  $args{data} = '' unless defined $args{data};
  croak "Data is utf8-flagged" if utf8::is_utf8 $args{data};
  croak "Data too large" if 0x7D < length $args{data}; # spec limit 2**63
  my $con = $self->{is_server} ? $self->{connection} : $self;
  croak "Bad state"
      if not (defined $con->{ws_state} and $con->{ws_state} eq 'OPEN') or
         (defined $self->{to_be_sent_length} and
          $self->{to_be_sent_length} > 0);

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
      (DataView->new (ArrayBuffer->new_from_scalarref (\(pack ('CC', 0b10000000 | $opcode, $masked | length $args{data}) .
         $mask . $args{data}))));
} # send_ping

sub close ($;%) {
  my ($self, %args) = @_;
  my $con = $self->{is_server} ? $self->{connection} : $self;
  if (not defined $con->{state}) {
    return Promise->reject ("Connection has not been established");
  }
  if (defined $self->{request_state} or
      (defined $con->{ws_state} and $con->{ws_state} eq 'OPEN')) {
    if (defined $self->{to_be_sent_length} and
        $self->{to_be_sent_length} > 0) {
      return Promise->reject ("Body is not sent");
    }
  }

  if (defined $args{status} and $args{status} > 0xFFFF) {
    return Promise->reject ("Bad status");
  }
  if (defined $args{reason}) {
    return Promise->reject ("Reason is utf8-flagged")
        if utf8::is_utf8 $args{reason};
    return Promise->reject ("Reason is too long")
        if 0x7D < length $args{reason};
  }

  if (defined $con->{ws_state} and
      ($con->{ws_state} eq 'OPEN' or
       $con->{ws_state} eq 'CONNECTING')) {
    my $masked = 0;
    my $mask = '';
    unless ($self->{is_server}) {
      $masked = 0b10000000;
      $mask = pack 'CCCC', rand 256, rand 256, rand 256, rand 256;
    }
    my $data = '';
    my $frame_info = $self->{DEBUG} ? [$args{reason}, FIN => 1, opcode => 8, mask => $mask, length => length $data, status => $args{status}] : undef;
    if (defined $args{status}) {
      $data = pack 'n', $args{status};
      $data .= $args{reason} if defined $args{reason};
      unless ($self->{is_server}) {
        for (0..((length $data)-1)) {
          substr ($data, $_, 1) = substr ($data, $_, 1) ^ substr ($mask, $_ % 4, 1);
        }
      }
    }
    my $frame = pack ('CC', 0b10000000 | 8, $masked | length $data) .
        $mask . $data;
    if ($con->{ws_state} eq 'CONNECTING') {
      $con->{pending_frame} = $frame;
      $con->{pending_frame_info} = $frame_info if $self->{DEBUG};
    } else {
      $self->_ws_debug ('S', @$frame_info) if $self->{DEBUG};
      $con->{writer}->write (DataView->new (ArrayBuffer->new_from_scalarref (\$frame)));
      $con->{ws_state} = 'CLOSING';
      $con->{ws_timer} = AE::timer 20, 0, sub {
        if ($self->{DEBUG}) {
          my $id = $self->{is_server} ? $self->{id} : $self->{request}->{id};
          warn "$id: WS timeout (20)\n";
        }
        # XXX set exit ?
        delete $con->{ws_timer};
        $self->_receive_done;
      };
      $self->_ev ('closing');
    }
  } elsif ($self->{is_server}) {
    $self->_receive_done;
    return;
  }

  # XXX $con->{request}->{body_stream}
  $self->{no_new_request} = 1;
  if ($con->{state} eq 'initial' or
      $con->{state} eq 'waiting' or
      $con->{state} eq 'tunnel' or
      $con->{state} eq 'tunnel sending') {
    $con->{writer}->close; # can fail
    $con->{state} = 'tunnel receiving' if $con->{state} eq 'tunnel';
  }

  ## Client only (for now)
  return $self->{closed};
} # close

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
  $self->{cb}->($self, $type, @_);
  if ($type eq 'complete') {
    $self->{is_completed} = 1;
    unless ($self->{is_server}) {
      (delete $self->{request_done})->();
    }
    delete $self->{cb};
  }
} # _ev

sub is_completed ($) {
  return $_[0]->{is_completed};
} # is_completed

1;

package Web::Transport::HTTPStream::ClientConnection;
push our @ISA, qw(Web::Transport::HTTPStream::Connection
                  Web::Transport::HTTPStream::Stream); # XXX
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

## This module is not public.  It should not be used by external
## applications and modules.

# XXX restore WS support
# XXX server integration
# XXX replace {exit} by exception objects
# XXX restore debug features

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
  #'ws data' => 1, # XXX
  'tunnel' => 1,
  'tunnel receiving' => 1,
};

sub _read ($) {
  my ($self) = @_;
  return if $self->{read_running};
  $self->{read_running} = 1;

  if ($BytesDataStates->{$self->{state}} and defined $self->{receive_controller}) {
    my $req = $self->{receive_controller}->byob_request;
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

  my $view = TypedArray::Uint8Array->new (ArrayBuffer->new (1024*2));
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
          $self->{no_new_request} = 1;
          $self->{request_state} = 'sent';
          $self->{exit} = {failed => 1,
                           message => "HTTP/0.9 response to non-GET request"};
          $self->_receive_done;
          return;
        } else {
          $self->_end_of_headers;
          $self->{receive_controller}->enqueue
              (TypedArray::Uint8Array->new
                   (ArrayBuffer->new_from_scalarref
                        (\($self->{temp_buffer}))));
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
            $self->{no_new_request} = 1;
            $self->{request_state} = 'sent';
            $self->{exit} = {failed => 1,
                             message => "Header section too large"};
            $self->_receive_done;
            return;
          }
          $self->{temp_buffer} .= $1;
          #
        } else {
          if (2**18-1 + 2 < (length $self->{temp_buffer}) + (length $$ref) - (pos $$ref)) {
            $self->{no_new_request} = 1;
            $self->{request_state} = 'sent';
            $self->{exit} = {failed => 1,
                             message => "Header section too large"};
            $self->_receive_done;
            return;
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
        $self->{no_new_request} = 1;
        $self->{request_state} = 'sent';
        $self->{exit} = {failed => 1,
                         message => "Inconsistent content-length values"};
        $self->_receive_done;
        return;
      } elsif (1 == keys %length) {
        my $length = each %length;
        $length =~ s/\A0+//;
        $length ||= 0;
        if ($length eq 0+$length) { # overflow check
          $self->{unread_length} = $res->{content_length} = 0+$length;
        } else {
          $self->{no_new_request} = 1;
          $self->{request_state} = 'sent';
          $self->{exit} = {failed => 1,
                           message => "Inconsistent content-length values"};
          $self->_receive_done;
          return;
        }
      }

      if ($res->{status} == 200 and
          $self->{request}->{method} eq 'CONNECT') {
        $self->_end_of_headers;
        $self->{no_new_request} = 1;
        $self->{state} = 'tunnel';
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
          $self->_end_of_headers;
          $self->_receive_bytes_done;
          $self->{exit} = {ws => 1, failed => 1, status => 1006, reason => ''};
          $self->{no_new_request} = 1;
          $self->{request_state} = 'sent';
          $self->_receive_done;
          return;
        } else {
          $self->{ws_state} = 'OPEN';
          $self->_end_of_headers; # XXX ws => 1
          $self->_receive_bytes_done;
          $self->{no_new_request} = 1;
          $self->{state} = 'before ws frame';
          $self->{temp_buffer} = '';
          if (defined $self->{pending_frame}) {
            $self->{ws_state} = 'CLOSING';
            $self->{writer}->write
                (DataView->new (ArrayBuffer->new_from_scalarref (\($self->{pending_frame}))));
            $self->_ws_debug ('S', @{$self->{pending_frame_info}}) if $self->{DEBUG}; # XXX $self->{stream}
            $self->{ws_timer} = AE::timer 20, 0, sub {
              warn "$self->{request}->{id}: WS timeout (20)\n" if $self->{DEBUG};
              delete $self->{ws_timer};
              $self->_receive_done;
            };
          }
        }
      } elsif (100 <= $res->{status} and $res->{status} <= 199) {
        if ($self->{request}->{method} eq 'CONNECT' or
            (defined $self->{ws_state} and
             $self->{ws_state} eq 'CONNECTING')) {
          $self->{no_new_request} = 1;
          $self->{request_state} = 'sent';
          $self->{exit} = {failed => 1,
                           message => "1xx response to CONNECT or WS"};
          $self->_receive_done;
          return;
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
        $self->_end_of_headers;
        $self->{unread_length} = 0;
        $self->{state} = 'response body';
      } else {
        $self->_end_of_headers;
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
          $self->{receive_controller}->enqueue
              (TypedArray::Uint8Array->new
                   (ArrayBuffer->new_from_scalarref
                        (\substr $$ref, pos $$ref)));
          $ref = \'';
          $self->{unread_length} -= $len;
        }
      } elsif ($self->{unread_length} > 0) {
        $self->{receive_controller}->enqueue
            (TypedArray::Uint8Array->new
                 (ArrayBuffer->new_from_scalarref
                      (\substr $$ref, (pos $$ref), $self->{unread_length})));
        pos ($$ref) += $self->{unread_length};
        $self->{unread_length} = 0;
      }
      if ($self->{unread_length} <= 0) {
        $self->_receive_bytes_done;

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

        $self->{exit} = {};
        $self->_receive_done;
      }
    } else {
      $self->{receive_controller}->enqueue
          (TypedArray::Uint8Array->new
               (ArrayBuffer->new_from_scalarref
                    (\substr $$ref, pos $$ref)))
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
        $self->{no_new_request} = 1;
        $self->{request_state} = 'sent';
        $self->_receive_bytes_done;
        $self->{exit} = {};
        $self->_receive_done;
        return;
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
        my $n = hex $self->{temp_buffer};
        unless ($self->{temp_buffer} eq sprintf '%x', $n) { # overflow
          $self->{response}->{incomplete} = 1;
          $self->{no_new_request} = 1;
          $self->{request_state} = 'sent';
          $self->_receive_bytes_done;
          $self->{exit} = {};
          $self->_receive_done;
          return;
        }
        if ($n == 0) {
          $self->_receive_bytes_done;
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
          $self->{receive_controller}->enqueue
              (TypedArray::Uint8Array->new
                   (ArrayBuffer->new_from_scalarref
                        (\substr $$ref, pos $$ref)));
          $ref = \'';
          $self->{unread_length} -= $len;
        } else {
          $self->{receive_controller}->enqueue
              (TypedArray::Uint8Array->new
                   (ArrayBuffer->new_from_scalarref
                        (\substr $$ref, (pos $$ref), $self->{unread_length})));
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
          $self->{no_new_request} = 1;
          $self->{request_state} = 'sent';
          $self->_receive_bytes_done;
          $self->{exit} = {};
          $self->_receive_done;
          return;
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
        $self->{no_new_request} = 1;
        $self->{request_state} = 'sent';
        $self->_receive_bytes_done;
        $self->{exit} = {};
        $self->_receive_done;
        return;
      }
    }
  } # CHUNK
  if ($self->{state} eq 'before response trailer') {
    if ($$ref =~ /\G(.*?)\x0A\x0D?\x0A/gcs) {
      if (2**18-1 < $self->{temp_buffer} + (length $1)) {
        $self->{no_new_request} = 1;
        $self->{request_state} = 'sent';
        $self->{exit} = {};
        $self->_receive_done;
        return;
      }
      $self->{temp_buffer} += length $1;
      #
    } else {
      if (2**18-1 < $self->{temp_buffer} + (length $$ref) - (pos $$ref)) {
        $self->{no_new_request} = 1;
        $self->{request_state} = 'sent';
        $self->{exit} = {};
        $self->_receive_done;
        return;
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
        $self->{no_new_request} = 1;
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
    return $self->_ws_received ($ref, "XXX %args"); # XXX
  }
  if ($self->{state} eq 'tunnel' or $self->{state} eq 'tunnel receiving') {
    $self->{receive_controller}->enqueue
        (TypedArray::Uint8Array->new
             (ArrayBuffer->new_from_scalarref
                  (\substr $$ref, pos $$ref)))
        if (length $$ref) - (pos $$ref);
    $ref = \'';
  }
  #if ($self->{state} eq 'waiting' or
  #    $self->{state} eq 'sending' or
  #    $self->{state} eq 'tunnel sending' or
  #    $self->{state} eq 'stopped') {
  #  #
  #}
} # _process_rbuf

sub _process_rbuf_eof ($;%) {
  my ($self, %args) = @_;

warn "EOF $self->{state}";
  if ($self->{state} eq 'before response') {
    if (length $self->{temp_buffer}) {
      if ($self->{request}->{method} eq 'PUT' or
          $self->{request}->{method} eq 'CONNECT') {
        $self->{exit} = {failed => 1,
                         message => "HTTP/0.9 response to non-GET request"};
      } else {
        $self->_end_of_headers;
        $self->{receive_controller}->enqueue
            (TypedArray::Uint8Array->new
                 (ArrayBuffer->new_from_scalarref
                      (\($self->{temp_buffer}))));
        $self->_receive_bytes_done;
        $self->{exit} = {};
        $self->{response}->{incomplete} = 1 if $args{abort};
      }
    } else { # empty
      $self->{exit} = {failed => 1,
                       message => $args{error_message} || "Connection closed without response",
                       errno => $args{errno},
                       can_retry => !$args{abort} && !$self->{response_received}};
    }
  } elsif ($self->{state} eq 'response body') {
    if (defined $self->{unread_length} and $self->{unread_length} > 0) {
      $self->{response}->{incomplete} = 1;
      $self->{request_state} = 'sent';
      $self->_receive_bytes_done;
      if ($self->{response}->{version} eq '1.1') {
        $self->{exit} = {failed => 1,
                         message => $args{error_message} || "Connection truncated",
                         errno => $args{errno}};
      } else {
        $self->{exit} = {};
      }
    } else {
      if ($args{abort}) {
        if (defined $self->{unread_length}) { #$self->{unread_length} == 0
          $self->{request_state} = 'sent';
        } else {
          $self->{response}->{incomplete} = 1;
        }
      }
      $self->_receive_bytes_done;
      $self->{exit} = {};
    }
  } elsif ({
    'before response chunk' => 1,
    'response chunk size' => 1,
    'response chunk extension' => 1,
    'response chunk data' => 1,
  }->{$self->{state}}) {
    $self->{response}->{incomplete} = 1;
    $self->{request_state} = 'sent';
    $self->_receive_bytes_done;
    $self->{exit} = {};
  } elsif ($self->{state} eq 'before response trailer') {
    $self->{request_state} = 'sent';
    $self->{exit} = {};
  } elsif ($self->{state} eq 'tunnel') {
    $self->_receive_bytes_done;
    unless ($args{abort}) {
      $self->{no_new_request} = 1;
      $self->{state} = 'tunnel sending';
      return;
    }
  } elsif ($self->{state} eq 'tunnel receiving') {
    $self->_receive_bytes_done;
    $self->{exit} = {failed => $args{abort}};
  } elsif ($self->{state} eq 'before response header') {
    $self->{exit} = {failed => 1,
                     message => $args{error_message} || "Connection closed within response headers",
                     errno => $args{errno}};
  } elsif ($self->{state} eq 'before ws frame' or
           $self->{state} eq 'ws data' or
           $self->{state} eq 'ws terminating') {
    return $self->_ws_received_eof (\($self->{temp_buffer}), %args);
  }

  $self->{no_new_request} = 1;
  $self->{request_state} = 'sent' if $args{abort};
  $self->_receive_done;
} # _process_rbuf_eof

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

  my $p = $args->{parent}->{class}->create ($args->{parent})->then (sub {
    my $info = $_[0];

    $self->{info} = {};
    if ($self->{DEBUG}) { # XXX
      warn "$self->{id}: openconnection @{[scalar gmtime]}\n";
      $self->_debug_handshake_done ({});
    }

    $self->{reader} = $info->{read_stream}->get_reader ('byob');
    $self->{writer} = $info->{write_stream}->get_writer;
    #$self->_read;
    Promise->all ([
      $self->{reader}->closed->then (sub {
        if ($self->{DEBUG}) {
          my $id = $self->{id};
          warn "$id: R: EOF\n";
        }

        $self->_process_rbuf (undef);
        $self->_process_rbuf_eof;
        unless ($self->{state} eq 'tunnel sending') {
          $self->{writer}->close->catch (sub { }); # can fail
        }
        return undef;
      }, sub {
        my $data = {failed => 1, message => $_[0]}; # XXX
        my $error = Web::DOM::Error->wrap ($_[0]);

        if ($self->{DEBUG}) {
          my $id = $self->{id};
          warn "$id: R: EOF ($data->{message})\n";
        }

        if (UNIVERSAL::isa ($error, 'Streams::IOError') and
            $error->errno == ECONNRESET) {
          $self->{no_new_request} = 1;
          $self->{request_state} = 'sent';
          $self->{exit} = {failed => 1, reset => 1};
          $self->_receive_done;
        } else {
          $self->_process_rbuf (undef);
          $self->_process_rbuf_eof
              (abort => $data->{failed},
               errno => $data->{errno},
               error_message => $data->{message});
        }
        $self->{writer}->abort ('XXX'); # XXX ? also reader?

        return undef;
      }),
      $self->{writer}->closed->then (sub {
        if ($self->{DEBUG}) {
          my $id = $self->{id};
          warn "$id: S: EOF\n";
        }

        if ($self->{state} eq 'tunnel sending') {
          $self->_ev ('complete', {}); # XXX
          $self->{response}->{stream_resolve}->();
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

        if ($self->{state} eq 'tunnel sending') {
          $self->{response}->{stream_resolve}->();
          $self->_ev ('complete', {}); # XXX
        }
      }),
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
    $self->{writer}->abort ('XXX') if defined $self->{writer}; # XXX and reader?
    $onclosed->();
    die $error;
  });
} # connect

sub is_active ($) {
  return defined $_[0]->{state} && !$_[0]->{no_new_request};
} # is_active

sub abort ($;%) {
  my ($self, %args) = @_;
  if (not defined $self->{state}) {
    return Promise->reject ("Connection has not been established");
  }

  $self->{no_new_request} = 1;
  $self->{request_state} = 'sent';
  delete $self->{to_be_sent_length};
  $self->{writer}->abort ($args{message}) if defined $self->{writer}; # XXX and reader?

  return $self->{closed};
} # abort

# XXX ::Stream::
sub _send_done ($) {
  my $stream = my $con = $_[0];
  $stream->{request_state} = 'sent';
  $stream->_ev ('requestsent') unless defined $con->{ws_state};
  $stream->_both_done if $con->{state} eq 'sending';
} # _send_done

# XXX ::Stream::
sub _receive_done ($) {
  my $self = $_[0];
  return if $self->{state} eq 'stopped';

  delete $self->{timer};
  delete $self->{ws_timer};
  if (defined $self->{request_state} and
      ($self->{request_state} eq 'sending headers' or
       $self->{request_state} eq 'sending body')) {
    $self->{state} = 'sending';
  } else {
    $self->_both_done;
  }
} # _receive_done

# XXX ::Stream::
sub _both_done ($) {
  my $self = $_[0];
  if (defined $self->{request} and
      defined $self->{request_state} and
      $self->{request_state} eq 'sent') {
    if ($self->{exit}->{failed}) {
      $self->{response}->{stream_reject}->($self->{exit});

      if (defined $self->{response}->{end_of_headers}) {
        (delete $self->{response}->{end_of_headers})->();
      }

      my $rc = delete $self->{receive_controller};
      $rc->error ($self->{exit}) if defined $rc;
    } else {
      $self->{response}->{stream_resolve}->();
    }
    $self->_ev ('complete', $self->{exit}); # XXX
  }
  my $id = defined $self->{request} ? $self->{request}->{id}.': ' : '';
  delete $self->{request};
  delete $self->{response};
  delete $self->{receiving};
  delete $self->{request_state};
  delete $self->{to_be_sent_length};
  if ($self->{no_new_request}) {
    $self->{writer}->close->catch (sub { }); # can fail
    $self->{timer} = AE::timer 1, 0, sub {
      $self->{writer}->abort ("HTTP completion timer (1)"); # XXX and reader?
    };
    $self->{state} = 'stopped';
  } else {
    $self->{state} = 'waiting';
    $self->{response_received} = 0;
  }
} # _both_done

# XXX can_create_stream is_active && (if h1: no current request)

sub create_stream ($) {
  # XXX wait until $_[0]->can_create_stream becomes true
  return Promise->resolve (bless {
    connection => $_[0],
  },'Web::Transport::HTTPStream::ClientStream'); # XXX
} # create_stream

package Web::Transport::HTTPStream::ClientStream; # XXX
use Carp qw(croak);
use MIME::Base64 qw(encode_base64);
use Promised::Flow;

BEGIN {
  *_e4d = \&Web::Transport::HTTPStream::_e4d;
  *_e4d_t = \&Web::Transport::HTTPStream::_e4d_t;
  *MAX_BYTES = \&Web::Transport::HTTPStream::MAX_BYTES;
}

sub request ($) { $_[0]->{request} } # or undef
sub response ($) { $_[0]->{response} } # or undef

sub send_request ($$;%) {
  my ($stream, $req, %args) = @_;
  my $con = $stream->{connection};
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
  $con->{to_be_sent_length} = 0;
  for (@{$req->{headers} or []}) {
    croak "Bad header name |@{[_e4d $_->[0]]}|"
        unless $_->[0] =~ /\A[!\x23-'*-+\x2D-.0-9A-Z\x5E-z|~]+\z/;
    croak "Bad header value |@{[_e4d $_->[1]]}|"
        unless $_->[1] =~ /\A[\x00-\x09\x0B\x0C\x0E-\xFF]*\z/;
    my $n = $_->[0];
    $n =~ tr/A-Z/a-z/; ## ASCII case-insensitive.
    if ($n eq 'content-length' and not $req->{method} eq 'CONNECT') {
      $con->{to_be_sent_length} = $_->[1]; # XXX
      # XXX throw if multiple length?
    }
  }
  # XXX transfer-encoding
  # XXX croak if WS protocols is bad
  # XXX utf8 flag
  # XXX header size

  if (not defined $con->{state}) {
    return Promise->reject ("Connection has not been established");
  } elsif ($con->{no_new_request}) {
    return Promise->reject ("Connection is no longer in active");
  } elsif (not ($con->{state} eq 'initial' or $con->{state} eq 'waiting')) {
    return Promise->reject ("Connection is busy");
  }

  $req->{id} = $con->{id} . '.' . ++$con->{req_id};
  if ($con->{DEBUG}) { # XXX
    warn "$con->{id}: ========== @{[ref $con]}\n";
    warn "$con->{id}: startstream $req->{id} @{[scalar gmtime]}\n";
  }

  my $cb = $args{cb} || sub { };
  $con->{cb} = $cb;

  my ($r_end_of_headers, $s_end_of_headers) = promised_cv;
  my ($resolve_stream, $reject_stream);
  my $stream_closed = Promise->new
      (sub { ($resolve_stream, $reject_stream) = @_ });

  $con->{request} = $req;
  my $res = $con->{response} = {
    status => 200, reason => 'OK', version => '0.9',
    headers => [],
    end_of_headers => $s_end_of_headers,
    stream_resolve => $resolve_stream,
    stream_reject => $reject_stream,
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
  my $req_done = Promise->new (sub { $con->{request_done} = $_[0] });
  my $header = join '',
      "$method $url HTTP/1.1\x0D\x0A",
      (map { "$_->[0]: $_->[1]\x0D\x0A" } @{$req->{headers} || []}),
      "\x0D\x0A";
  if ($con->{DEBUG}) {
    for (split /\x0A/, $header) {
      warn "$req->{id}: S: @{[_e4d $_]}\n";
    }
  }
  $con->{request_state} = 'sending headers';
  my $sent = $con->{writer}->write
      (DataView->new (ArrayBuffer->new_from_scalarref (\$header)));
  $con->{request}->{body_stream} = WritableStream->new ({
    write => sub {
      my $chunk = $_[1];
      return Promise->resolve->then (sub {
        my $is_body = (defined $con->{to_be_sent_length} and
                       $con->{to_be_sent_length} > 0);
        my $is_tunnel = (defined $con->{state} and
                         ($con->{state} eq 'tunnel' or
                          $con->{state} eq 'tunnel sending'));
        die "Bad state" # XXX
            if not $is_body and not $is_tunnel;
        # XXX $chunk type
        my $byte_length = $chunk->byte_length;
        die "Data too large" # XXX
            if $is_body and $con->{to_be_sent_length} < $byte_length;
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

        if (defined $con->{ws_state} and $con->{ws_state} eq 'OPEN') {
          my $ref = \('X' x $byte_length); # XXX
          my @data;
          my $mask = $con->{ws_encode_mask_key};
          my $o = $con->{ws_sent_length};
          for (0..($byte_length-1)) {
            push @data, substr ($$ref, $_, 1) ^ substr ($mask, ($o+$_) % 4, 1);
          }
          $con->{ws_sent_length} += $byte_length;
          $con->{to_be_sent_length} -= $byte_length;
          $con->{writer}->write
              (DataView->new (ArrayBuffer->new_from_scalarref (\join '', @data)));
        } else {
          my $sent = $con->{writer}->write ($chunk);
          if ($is_body) {
            $con->{to_be_sent_length} -= $byte_length;
            if ($con->{to_be_sent_length} <= 0) {
              $sent->then (sub {
                $con->_send_done;
              });
            }
          } # $is_body
        }
      }); # XXX catch
    }, # write
    close => sub {
      # XXX fail if length not zero

      if ($con->{state} eq 'tunnel' or
          $con->{state} eq 'tunnel sending') {
        $con->{writer}->close; # can fail
        $con->{state} = 'tunnel receiving' if $con->{state} eq 'tunnel';
      }
    },
    abort => sub {
      # XXX
    },
  });
  if ($con->{to_be_sent_length} <= 0) {
    $sent = $sent->then (sub {
      $con->_send_done;
    });
  } else {
    $sent = $sent->then (sub {
      $con->{request_state} = 'sending body';
    });
  }
  $con->_read;
  $req_done->then (sub { # XXX
    warn "$con->{id}: endstream $req->{id} @{[scalar gmtime]}\n";
    warn "$con->{id}: ========== @{[ref $con]}\n";
  }) if $con->{DEBUG};
  return $sent->then (sub {
    $stream->{request} = $req;
    $stream->{response} = $stream->{receiving} = $res;
    $stream->{closed} = $stream_closed;
    return $r_end_of_headers;
  }); ## could be rejected when connection aborted
} # send_request

sub closed ($) {
  return $_[0]->{closed};
} # closed

sub DESTROY ($) {
  local $@;
  eval { die };
  warn "$$: Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

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
      return $self->_read if defined $self->{reader};
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
      if ($self->{DEBUG}) {
        my $id = ''; # XXX $transport->id;
        warn "$id: R: EOF\n";
      }
      delete $self->{timer};
      $self->_oneof (undef);
    }, sub {
      if ($self->{DEBUG}) {
        my $id = ''; # XXX $transport->id;
        warn "$id: R: EOF (@{[_e4d_t $_[0]]})\n";
      }
      delete $self->{timer};
      $self->_oneof ($_[0]);
    });

    my $p2 = $self->{writer}->closed->then (sub {
      delete $self->{writer};
      if ($self->{DEBUG}) {
        my $id = ''; # XXX $transport->id;
        warn "$id: S: EOF\n";
      }
      $self->{sending_stream}->_send_done if defined $self->{sending_stream};
    }, sub {
      delete $self->{writer};
      if ($self->{DEBUG}) {
        my $id = ''; # XXX $transport->id;
        warn "$id: S: EOF (@{[_e4d_t $_[0]]})\n";
      }
      $self->{sending_stream}->_send_done if defined $self->{sending_stream};
    }); # underlying writer closed

    return Promise->all ([$p1, $p2])->then (sub {
      my $p;
      $p = $self->{stream_controller}->close
          if defined $self->{stream_controller};
      delete $self->{stream_controller};
      $self->_terminate;
      return $p;
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
  }, 'Web::Transport::HTTPStream::ServerStream'; # XXX

  if ($con->{DEBUG}) { # XXX
    warn "$con->{id}: ========== @{[ref $con]}\n";
    warn "$con->{id}: startstream $req->{id} @{[scalar gmtime]}\n";
  }

  $req->{cb} = sub { }; # XXX
  $con->{stream_controller}->enqueue ($req);

  my ($r_end_of_headers, $s_end_of_headers) = promised_cv;
  my ($resolve_stream, $reject_stream);
  $req->{receiving} = $req->{request};
  $req->{receiving}->{end_of_headers} = $s_end_of_headers;
  $req->{request_received} = $r_end_of_headers;

  $req->{closed} = Promise->new (sub {
    $req->{closed_resolve} = $_[0];
    $req->{closed_reject} = $_[1];
  });

  return $req;
} # _new_stream

sub _read ($) {
  my $self = $_[0];
  my $read; $read = sub {
    return $self->{reader}->read (DataView->new (ArrayBuffer->new (1024*3)))->then (sub { # XXX
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
  return $read->()->catch (sub { })->then (sub { undef $read });
} # _read

sub _ondata ($$) {
  my ($self, $in) = @_;
  my $inref = \($in->manakai_to_string); # string copy!
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
        return $stream->_send_error (414, 'Request-URI Too Large');
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
        $self->{stream}->{receive_controller}->enqueue
            (TypedArray::Uint8Array->new
                 (ArrayBuffer->new_from_scalarref ($ref)));
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
        $self->{stream}->{receive_controller}->enqueue
            (TypedArray::Uint8Array->new
                 (ArrayBuffer->new_from_scalarref ($ref)));
        $self->{stream}->_receive_bytes_done;
        unless (defined $self->{stream}->{ws_key}) {
          $self->{stream}->_receive_done;
        }
      } elsif ($self->{unread_length} < $in_length) { # has redundant data
        $self->{stream}->{incomplete} = 1;
        $self->{stream}->{close_after_response} = 1;
        if (defined $self->{stream}->{ws_key}) {
          $self->{state} = 'ws handshaking';
        }
        $self->{stream}->{receive_controller}->enqueue
            (TypedArray::Uint8Array->new
                 (ArrayBuffer->new_from_scalarref ($ref),
                  0, $self->{unread_length}));
        $self->{stream}->_receive_bytes_done;
        unless (defined $self->{stream}->{ws_key}) {
          $self->{stream}->_receive_done;
        }
        return;
      } else { # unread_length > $in_length
        $self->{unread_length} -= $in_length;
        $self->{stream}->{receive_controller}->enqueue
            (TypedArray::Uint8Array->new
                 (ArrayBuffer->new_from_scalarref ($ref)));
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
  my ($self, $error) = @_;
  delete $self->{writer} if defined $error;
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
      $error = {failed => 1, message => 'Connection closed'} # XXX
          unless defined $error;
    }
    $self->{stream}->_receive_bytes_done;
    $self->{exit} = $error;
    $self->{stream}->_receive_done;
  } elsif ($self->{state} eq 'before ws frame' or
           $self->{state} eq 'ws data' or
           $self->{state} eq 'ws terminating') {
    $self->{exit} = {failed => 1, message => $error}; # XXX
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
      $self->{writer}->close if defined $self->{writer};
      delete $self->{writer};
      $self->{state} = 'end';
    }
  } elsif ($self->{state} eq 'end') {
    $self->{writer}->close if defined $self->{writer};
    delete $self->{writer};
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
  my $host_host;
  my $host_port;
  if ($stream->{request}->{method} eq 'CONNECT') {
    if (defined $host) {
      ($host_host, $host_port) = Web::Host->parse_hostport_string ($host);
      unless (defined $host_host) {
        $stream->_fatal;
        return 0;
      }
    }

    my $target = delete $stream->{target};
    $target =~ s/([\x80-\xFF])/sprintf '%%%02X', ord $1/ge;
    my ($target_host, $target_port) = Web::Host->parse_hostport_string ($target);
    unless (defined $target_host) {
      $stream->_fatal;
      return 0;
    }
    $target_url = Web::URL->parse_string ("http://$target/");
  } elsif ($stream->{target} eq '*') {
    if (defined $host) {
      ($host_host, $host_port) = Web::Host->parse_hostport_string ($host);
      unless (defined $host_host) {
        $stream->_fatal;
        return 0;
      }
      my $scheme = $stream->{connection}->_url_scheme;
      $target_url = Web::URL->parse_string ("$scheme://$host/");
      delete $stream->{target};
    } else {
      $stream->_fatal;
      return 0;
    }
  } elsif ($stream->{target} =~ m{\A/}) {
    if (defined $host) {
      ($host_host, $host_port) = Web::Host->parse_hostport_string ($host);
      unless (defined $host_host) {
        $stream->_fatal;
        return 0;
      }
    }

    my $scheme = $stream->{connection}->_url_scheme;
    my $target = delete $stream->{target};
    $target =~ s/([\x80-\xFF])/sprintf '%%%02X', ord $1/ge;
    if (defined $host_host) {
      $target_url = Web::URL->parse_string ("$scheme://$host$target");
    } else {
      my $hostport = $stream->{connection}->_url_hostport;
      $target_url = Web::URL->parse_string ("$scheme://$hostport$target");
    }
    if (not defined $target_url or not defined $target_url->host) {
      $stream->_fatal;
      return 0;
    }
  } else { # absolute URL
    my $target = delete $stream->{target};
    $target =~ s/([\x80-\xFF])/sprintf '%%%02X', ord $1/ge;
    $target_url = Web::URL->parse_string ($target);
    if (not defined $target_url or not defined $target_url->host) {
      $stream->_fatal;
      return 0;
    }

    if (defined $host) {
      ($host_host, $host_port) = Web::Host->parse_hostport_string ($host);
      unless (defined $host_host) {
        $stream->_fatal;
        return 0;
      }
    }
  }
  if (defined $host_host and defined $target_url) {
    unless ($host_host->equals ($target_url->host)) {
      $stream->_fatal;
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
        last WS_CHECK unless $stream->{request}->{target_url}->is_http_s;
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
        ]);
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
    $stream->_send_error (411, 'Length Required');
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
  $stream->{request}->{body_length} = $l;
  if ($l == 0) {
    if (defined $stream->{ws_key}) {
      $self->{state} = 'ws handshaking';
      $self->{stream}->{close_after_response} = 1;
    }
  } else {
    $self->{unread_length} = $l;
    $self->{state} = 'request body';
  }
  $stream->_end_of_headers;
  if ($l == 0 and not $stream->{request}->{method} eq 'CONNECT') {
    $stream->_receive_bytes_done;
    unless (defined $stream->{ws_key}) {
      $stream->_receive_done;
    }
  }

  return 1;
} # _request_headers

sub _timeout ($) {
  my $self = $_[0];
  delete $self->{timer};
  my $error = "Read timeout ($ReadTimeout)"; # XXX
  $self->{writer}->abort ($error);
  $self->{reader}->cancel ($error);
} # _timeout

sub received_streams ($) {
  return $_[0]->{received_streams};
} # received_streams

sub abort ($) {
  my ($self, %args) = @_;
  $self->{writer}->abort ($args{message}); # XXX
  $self->{reader}->cancel ($args{message}); # XXX
  delete $self->{writer};
  $self->{stream}->_send_done if defined $self->{stream};
  return $self->{closed};
} # abort

sub close_after_current_stream ($) {
  my $self = $_[0];
  if (defined $self->{stream}) {
    $self->{stream}->{close_after_response} = 1;
  } elsif (defined $self->{sending_stream}) {
    $self->{sending_stream}->{close_after_response} = 1;
  } else {
    if (defined $self->{writer}) {
      my $w = $self->{writer};
      $w->write (DataView->new (ArrayBuffer->new))->then (sub {
        my $error = 'Close by |close_after_current_stream|'; # XXX
        $w->abort ($error);
        $self->{reader}->cancel ($error)->catch (sub { });
      });
      delete $self->{writer};
    }
    $self->{state} = 'end';
  }
  return $self->{closed};
} # close_after_current_stream

sub closed ($) {
  return $_[0]->{closed};
} # closed

package Web::Transport::HTTPStream::ServerStream;
push our @ISA, qw(Web::Transport::HTTPStream::Stream);
use Carp qw(carp croak);
use Digest::SHA qw(sha1);
use MIME::Base64 qw(encode_base64);
use Web::Encoding;
use Web::DateTime;
use Web::DateTime::Clock;
push our @CARP_NOT, qw(Web::DOM::TypeError WritableStream);

BEGIN {
  *_e4d = \&Web::Transport::HTTPStream::_e4d;
  *_e4d_t = \&Web::Transport::HTTPStream::_e4d_t;
  *MAX_BYTES = \&Web::Transport::HTTPStream::MAX_BYTES;
}

sub request_ready ($) {
  return $_[0]->{request_received};
} # request_ready

sub send_response ($$$;%) {
  my ($stream, $response, %args) = @_;
  return Promise->reject
      (Web::DOM::TypeError->new ("|send_response| is invoked twice"))
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
      $response->{status} == 204 or
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
      return Promise->reject
          (Web::DOM::TypeError->new ("1xx response not supported"));
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
    $close = 1 if $stream->{request}->{method} eq 'CONNECT';
  }

  my @header;
  unless ($args{proxying}) {
    push @header, ['Server', encode_web_utf8 $con->server_header];

    my $dt = Web::DateTime->new_from_unix_time
        (Web::DateTime::Clock->realtime_clock->());
    push @header, ['Date', $dt->to_http_date_string];
  }

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

  if (not defined $stream->{connection}->{writer}) {
    ## Connection aborted (typically by client) before the application
    ## sends the headers
    $write_mode = 'void';
    $done = 1;
  }

  if ($write_mode eq 'void') {
    #
  } elsif ($stream->{request}->{version} != 0.9) {
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

  $stream->{response} = {};
  $stream->{response}->{body} = WritableStream->new ({
    write => sub {
      my $chunk = $_[1]; # XXX must be an ArrayBufferView
      my $wm = $stream->{write_mode} || '';
      # XXX error location
      if ($wm eq 'chunked') {
        return Promise->resolve->then (sub {
          my $dv = UNIVERSAL::isa ($chunk, 'DataView')
              ? $chunk : DataView->new ($chunk->buffer, $chunk->byte_offset, $chunk->byte_length); # or throw
          if ($dv->byte_length) {
            ## Note that some clients fail to parse chunks if there
            ## are TCP segment boundaries within a chunk (which is
            ## smaller than MSS).
        if ($stream->{DEBUG} > 1) {
          for (split /\x0A/, $dv->manakai_to_string, -1) {
            warn "$stream->{id}: S: @{[_e4d $_]}\n";
          }
        }
        my $writer = $stream->{connection}->{writer};
            $writer->write
                (DataView->new (ArrayBuffer->new_from_scalarref
                                    (\sprintf "%X\x0D\x0A%s\x0D\x0A", $dv->byte_length, $dv->manakai_to_string))); # XXX string copy!
          }
        }); # XXX catch
      } elsif ($wm eq 'raw' or $wm eq 'ws') {
        return Promise->resolve->then (sub {
          my $dv = UNIVERSAL::isa ($chunk, 'DataView')
              ? $chunk : DataView->new ($chunk->buffer, $chunk->byte_offset, $chunk->byte_length); # or throw
          croak "Not writable for now"
              if $wm eq 'ws' and
                  (not $stream->{connection}->{ws_state} eq 'OPEN' or
                   not defined $stream->{to_be_sent_length} or
                   $stream->{to_be_sent_length} <= 0);
          if (defined $stream->{to_be_sent_length}) {
            if ($stream->{to_be_sent_length} >= $dv->byte_length) {
              $stream->{to_be_sent_length} -= $dv->byte_length;
            } else {
              die Web::DOM::TypeError->new
                  (sprintf "Byte length %d is greater than expected length %d",
                       $dv->byte_length, $stream->{to_be_sent_length});
            }
          }
        if ($stream->{DEBUG} > 1) {
          for (split /\x0A/, $dv->manakai_to_string, -1) {
            warn "$stream->{id}: S: @{[_e4d $_]}\n";
          }
        }
        my $writer = $stream->{connection}->{writer};
          $writer->write ($dv);
          if ($wm eq 'raw' and
              defined $stream->{to_be_sent_length} and
              $stream->{to_be_sent_length} <= 0) {
            return $stream->_close_stream;
          }
        })->catch (sub {
          $stream->abort (message => $_[0]); # XXX
          die $_[0];
        });
      } elsif ($wm eq 'void') {
        #
      } else {
        return Promise->reject
            (Web::DOM::TypeError->new ("Response body is not writable"));
        # XXX catch
      }
    }, # write
    close => sub {
      return $stream->_close_stream;
    }, # close
    abort => sub {
      # XXX
    },
  }); # response body

  $stream->{close_after_response} = 1 if $close;
  $stream->{write_mode} = $write_mode;
  if ($done) {
    delete $stream->{to_be_sent_length};
    my $w = $stream->{response}->{body}->get_writer;
    $w->close;
    $w->release_lock;
  } else {
    $stream->{to_be_sent_length} = $to_be_sent if defined $to_be_sent;
  }

  return Promise->resolve;
} # send_response

sub _read ($) {
  return $_[0]->{connection}->_read;
} # _read

sub abort ($;%) {
  my $stream = shift;
  $stream->{connection}->abort (@_) if defined $stream->{connection};
} # abort

sub closed ($) {
  return $_[0]->{closed};
} # closed

sub _send_error ($$$;$) {
  my ($stream, $status, $status_text, $headers) = @_;
  return $stream->_close_stream if not defined $stream->{connection}->{writer};

  my $res = qq{<!DOCTYPE html><html>
<head><title>$status $status_text</title></head>
<body>$status $status_text};
  #$res .= Carp::longmess;
  $res .= qq{</body></html>\x0A};
  $stream->send_response
      ({status => $status, status_text => $status_text,
        headers => [
          @{$headers or []},
          ['Content-Type' => 'text/html; charset=utf-8'],
        ]}, close => 1, content_length => length $res)->then (sub {
    my $w = $stream->{response}->{body}->get_writer;
    $w->write (DataView->new (ArrayBuffer->new_from_scalarref (\$res)))
        unless $stream->{request}->{method} eq 'HEAD';
    return $w->close;
  });
  return;
} # _send_error

sub _fatal ($) {
  my ($req) = @_;
  my $con = $req->{connection};
  $req->_receive_done;
  $con->{state} = 'end';
  $con->{rbuf} = '';
  return $req->_send_error (400, 'Bad Request');
} # _fatal

sub _close_stream ($) {
  my $stream = $_[0];
  return unless defined $stream->{connection};
  if (not defined $stream->{write_mode}) {
    return $stream->abort (message => 'Closed without response');
  } elsif (defined $stream->{to_be_sent_length} and
           $stream->{to_be_sent_length} > 0) {
    carp sprintf "Truncated end of sent data (%d more bytes expected)",
        $stream->{to_be_sent_length}; # XXX
    $stream->{close_after_response} = 1;
    $stream->_send_done;
  } else {
    $stream->{close_after_response} = 1
        if $stream->{request}->{method} eq 'CONNECT';
    if ($stream->{write_mode} eq 'chunked') {
      # XXX trailer headers
      my $p = $stream->{connection}->{writer}->write
          (DataView->new (ArrayBuffer->new_from_scalarref (\"0\x0D\x0A\x0D\x0A")));
      $stream->_send_done;
      return $p;
    } elsif (defined $stream->{write_mode} and $stream->{write_mode} eq 'ws') {
      return $stream->close; # XXX $args
    } else {
      $stream->_send_done;
    }
  }
  return;
} # _close_stream

sub _send_done ($) {
  my $stream = $_[0];
  delete $stream->{connection}->{sending_stream};
  if (delete $stream->{close_after_response}) {
    $stream->{connection}->{writer}->close
        if defined $stream->{connection}->{writer};
    delete $stream->{connection}->{writer};
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
  my $exit = $con->{exit} || {};
  $con->{sending_stream} = $con->{stream} if not $stream->{send_done};
  delete $con->{stream};
  delete $con->{timer};
  $con->{disable_timer} = 1;
  delete $con->{unread_length};
  delete $con->{ws_timer};
  if ($stream->{close_after_response} or
      not defined $stream->{connection}->{writer}) { # _send_done already called with close_after_response
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
    $con->{writer}->close if defined $con->{writer};
    delete $con->{writer};
    $con->{state} = 'end';
  }
  delete $con->{disable_timer};
  my $error = $con->{exit} || {};
  if ($error->{failed}) { # XXX
    $stream->{closed_reject}->($error);
  } else {
    $stream->{closed_resolve}->();
  }
  if (defined $stream->{receiving} and
      defined $stream->{receiving}->{end_of_headers}) {
    $stream->{receiving}->{end_of_headers}->(Promise->reject ($error)); # XXX
  }
  delete $stream->{closed_resolve};
  delete $stream->{closed_reject};
  if ($con->{DEBUG}) { #XXX
    warn "$con->{id}: endstream $stream->{id} @{[scalar gmtime]}\n";
    warn "$con->{id}: ========== @{[ref $con]}\n";
  }
  $con->{timer} = AE::timer $ReadTimeout, 0, sub { $con->_timeout };
  delete $stream->{connection};
} # _both_done

sub DESTROY ($) {
  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

1;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
