package Web::Transport::HTTPConnection;
use strict;
use warnings;
our $VERSION = '1.0';

sub type ($) { return 'HTTP' }
sub transport ($) { $_[0]->{transport} }

sub _con_ev ($$) {
  my ($self, $type) = @_;
  if ($self->{DEBUG}) {
    my $id = $self->{transport}->id;
    if ($type eq 'openconnection') {
      my $data = $_[2];
      my $host = $data->{remote_host}->to_ascii;
      warn "$id: $type remote=$host:$data->{remote_port}\n";
    } elsif ($type eq 'startstream') {
      my $req = $_[2];
      warn "$id: ========== @{[ref $self]}\n";
      warn "$id: $type $req->{id} @{[scalar gmtime]}\n";
    } elsif ($type eq 'endstream') {
      my $req = $_[2];
      warn "$id: $type $req->{id} @{[scalar gmtime]}\n";
      warn "$id: ========== @{[ref $self]}\n";
    } else {
      warn "$id: $type @{[scalar gmtime]}\n";
    }
  }
  $self->{con_cb}->(@_);
  # XXX |closeconnection| should be fired after all |endstream|s
#XXX  delete $self->{con_cb} if $type eq 'closeconnection';
} # _con_ev

sub DESTROY ($) {
  $_[0]->abort if $_[0]->{is_server} and defined $_[0]->{transport};

  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

package Web::Transport::HTTPConnection::Stream;
use Carp qw(croak);
use AnyEvent;
use Promise;
use Encode qw(decode); # XXX
use Web::Encoding;

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

sub _ws_received ($;%) {
  my ($self, $ref, %args) = @_;
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
      $self->_ws_debug ('R', '',
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
            $self->_ev ('closing');
            my $mask = '';
            my $masked = 0;
            unless ($self->{is_server}) {
              $masked = 0b10000000;
              $mask = pack 'CCCC', rand 256, rand 256, rand 256, rand 256;
              for (0..((length $data)-1)) {
                substr ($data, $_, 1) = substr ($data, $_, 1) ^ substr ($mask, $_ % 4, 1);
              }
            }
            $self->_ws_debug ('S', defined $reason ? $reason : '',
                              FIN => 1, opcode => 8, mask => $mask,
                              length => length $data, status => $status)
                if $self->{DEBUG};
            ($self->{transport} || $self->{connection}->{transport})->push_write
                (\(pack ('CC', 0b10000000 | 8, $masked | length $data) .
                   $mask . $data));
          }
          $self->{state} = 'ws terminating';
          $self->{exit} = {status => defined $status ? $status : 1005,
                           reason => defined $reason ? $reason : '',
                           ws => 1, cleanly => 1};
          if ($self->{is_server}) {
            $self->_next;
          } else {
            $self->{timer} = AE::timer 1, 0, sub { # XXX spec
              if ($self->{DEBUG}) {
                my $id = defined $self->{request} ? $self->{request}->{id} : $self->{id};
                warn "$id: WS timeout (1)\n";
              }
              delete $self->{timer};
              $self->_next;
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
              $self->_ev ('textstart', {});
              for (@{$self->{ws_frame}->[1]}) {
                $self->_ev ('text', $_);
              }
              $self->_ev ('textend');
            } else { # binary
              $self->_ev ('datastart', {});
              for (@{$self->{ws_frame}->[1]}) {
                $self->_ev ('data', $_);
              }
              $self->_ev ('dataend');
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
          $self->_ws_debug ('S', $data, FIN => 1, opcode => 10, mask => $mask,
                            length => length $data) if $self->{DEBUG};
          unless ($self->{is_server}) {
            for (0..((length $data)-1)) {
              substr ($data, $_, 1) = substr ($data, $_, 1) ^ substr ($mask, $_ % 4, 1);
            }
          }
          ($self->{transport} || $self->{connection}->{transport})->push_write
              (\(pack ('CC', 0b10000000 | 10, $masked | length $data) .
                 $mask . $data));
          $self->_ev ('ping', (join '', @{$self->{ws_frame}->[1]}), 0);
        } elsif ($self->{ws_frame}->[0] == 10) {
          $self->_ev ('ping', (join '', @{$self->{ws_frame}->[1]}), 1);
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
    $self->_ws_debug ('S', $self->{exit}->{reason}, FIN => 1, opcode => 8,
                      mask => $mask, length => length $data,
                      status => $self->{exit}->{status}) if $self->{DEBUG};
    ($self->{transport} || $self->{connection}->{transport})->push_write
        (\(pack ('CC', 0b10000000 | 8, $masked | length $data) .
           $mask . $data));
    $self->{state} = 'ws terminating';
    $self->{no_new_request} = 1;
    $self->{request_state} = 'sent';
    $self->_next;
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
    $self->{exit} = {ws => 1, failed => 1, status => 1006, reason => ''};
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
  $self->_next;
} # _ws_received_eof

sub send_text_header ($$) {
  my ($self, $length) = @_;
  croak "Data is utf8-flagged" if utf8::is_utf8 $_[2];
  croak "Data too large" if MAX_BYTES < $length; # spec limit 2**63
  croak "Bad state"
      if not (defined $self->{ws_state} and $self->{ws_state} eq 'OPEN') or
         (defined $self->{to_be_sent_length} and $self->{to_be_sent_length} > 0);

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
  ($self->{transport} || $self->{connection}->{transport})->push_write
      (\(pack ('CC', 0b10000000 | 1, $masked | $length0) .
         $len . $mask));
} # send_text_header

sub send_binary_header ($$) {
  my ($self, $length) = @_;
  croak "Data is utf8-flagged" if utf8::is_utf8 $_[2];
  croak "Data too large" if MAX_BYTES < $length; # spec limit 2**63
  croak "Bad state"
      if not (defined $self->{ws_state} and $self->{ws_state} eq 'OPEN') or
         (defined $self->{to_be_sent_length} and $self->{to_be_sent_length} > 0);

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
  ($self->{transport} || $self->{connection}->{transport})->push_write
      (\(pack ('CC', 0b10000000 | 2, $masked | $length0) .
         $len . $mask));
} # send_binary_header

sub send_ping ($;%) {
  my ($self, %args) = @_;
  $args{data} = '' unless defined $args{data};
  croak "Data is utf8-flagged" if utf8::is_utf8 $args{data};
  croak "Data too large" if 0x7D < length $args{data}; # spec limit 2**63
  croak "Bad state"
      if not (defined $self->{ws_state} and $self->{ws_state} eq 'OPEN') or
         (defined $self->{to_be_sent_length} and $self->{to_be_sent_length} > 0);

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
  ($self->{transport} || $self->{connection}->{transport})->push_write
      (\(pack ('CC', 0b10000000 | $opcode, $masked | length $args{data}) .
         $mask . $args{data}));
} # send_ping

sub close ($;%) {
  my ($self, %args) = @_;
  if (not defined $self->{state}) {
    return Promise->reject ("Connection has not been established");
  }
  if (defined $self->{request_state} or
      (defined $self->{ws_state} and $self->{ws_state} eq 'OPEN')) {
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

  if (defined $self->{ws_state} and
      ($self->{ws_state} eq 'OPEN' or
       $self->{ws_state} eq 'CONNECTING')) {
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
    if ($self->{ws_state} eq 'CONNECTING') {
      $self->{pending_frame} = $frame;
      $self->{pending_frame_info} = $frame_info if $self->{DEBUG};
    } else {
      $self->_ws_debug ('S', @$frame_info) if $self->{DEBUG};
      ($self->{transport} || $self->{connection}->{transport})->push_write (\$frame);
      $self->{ws_state} = 'CLOSING';
      $self->{timer} = AE::timer 20, 0, sub {
        if ($self->{DEBUG}) {
          my $id = defined $self->{request} ? $self->{request}->{id} : $self->{id};
          warn "$id: WS timeout (20)\n";
        }
        # XXX set exit ?
        $self->_next;
        delete $self->{timer};
      };
      $self->_ev ('closing');
    }
  } elsif ($self->{is_server}) {
    $self->_next;
    return;
  }

  $self->{no_new_request} = 1;
  if ($self->{state} eq 'initial' or
      $self->{state} eq 'waiting' or
      $self->{state} eq 'tunnel' or
      $self->{state} eq 'tunnel sending') {
    $self->{transport}->push_shutdown
        unless $self->{transport}->write_to_be_closed;
    $self->{state} = 'tunnel receiving' if $self->{state} eq 'tunnel';
  }

  ## Client only (for now)
  return $self->{closed};
} # close

sub _ws_debug ($$$%) {
  my $self = $_[0];
  my $side = $_[1];
  my %args = @_[3..$#_];

  my $id = defined $self->{request} ? $self->{request}->{id} : $self->{id};
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
  } elsif (($self->{DEBUG} > 1 or $args{opcode} >= 8) and length $_[2]) {
    warn "$id: S: @{[_e4d $_[2]]}\n";
  }
} # _ws_debug

sub _ev ($$;$$) {
  my $self = shift;
  my $type = shift;
  my $req = $self->{is_server} ? $self : $self->{request};
  if ($self->{DEBUG}) {
    warn "$req->{id}: $type @{[scalar gmtime]}\n";
    if ($type eq 'data' and $self->{DEBUG} > 1) {
      for (split /\x0D?\x0A/, $_[0], -1) {
        warn "$req->{id}: R: @{[_e4d $_]}\n";
      }
    } elsif ($type eq 'text' and $self->{DEBUG} > 1) {
      for (split /\x0D?\x0A/, $_[0], -1) {
        warn "$req->{id}: R: @{[_e4d_t $_]}\n";
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
      warn "$req->{id}: + @{[_e4d $err]}\n" if length $err;
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
    unless ($self->{is_server}) {
      (delete $self->{request_done})->();
    }
    delete $self->{cb};
  }
} # _ev

1;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
