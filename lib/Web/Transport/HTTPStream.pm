package Web::Transport::HTTPStream;
use strict;
use warnings;
our $VERSION = '1.0';
use Carp qw(croak);
use AnyEvent;
use Encode qw(decode); # XXX
use Web::Encoding;

use constant DEBUG => $ENV{WEBUA_DEBUG} || 0;
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
        pos ($$ref) += 4;
        # XXX if client,
        $ws_failed = 'Masked frame from server';
        last WS;
      } else {
        delete $self->{ws_decode_mask_key};
        # XXX error if server
      }
      $self->_ws_debug ('R', '',
                        FIN => !!$fin,
                        RSV1 => !!($b1 & 0b01000000),
                        RSV2 => !!($b1 & 0b00100000),
                        RSV3 => !!($b1 & 0b00010000),
                        opcode => $opcode,
                        mask => $self->{ws_decode_mask_key},
                        length => $self->{unread_length}) if DEBUG;
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
        # XXX xor if ws_decode_mask_key
        push @{$self->{ws_frame}->[1]}, substr $$ref, 0, $self->{unread_length};
        #if (DEBUG > 1 or
        #    (DEBUG and $self->{ws_frame}->[0] >= 8)) {
        if (DEBUG and $self->{ws_frame}->[0] == 8) {
          if ($self->{ws_frame}->[0] == 8 and
              $self->{unread_length} > 1) {
            warn sprintf "$self->{request}->{id}: R: status=%d %s\n",
                unpack ('n', substr $$ref, 0, 2),
                _e4d substr ($$ref, 2, $self->{unread_length});
          } else {
            warn sprintf "$self->{request}->{id}: R: %s\n",
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
            my $mask = pack 'CCCC', rand 256, rand 256, rand 256, rand 256;
            for (0..((length $data)-1)) {
              substr ($data, $_, 1) = substr ($data, $_, 1) ^ substr ($mask, $_ % 4, 1);
            }
            $self->_ws_debug ('S', defined $reason ? $reason : '',
                              FIN => 1, opcode => 8, mask => $mask, length => length $data, status => $status) if DEBUG;
            $self->{transport}->push_write
                (\(pack ('CC', 0b10000000 | 8, 0b10000000 | length $data) .
                   $mask . $data));
          }
          $self->{state} = 'ws terminating';
          $self->{exit} = {status => defined $status ? $status : 1005,
                           reason => defined $reason ? $reason : '',
                           ws => 1, cleanly => 1};
          # if server, $self->_next;
          $self->{timer} = AE::timer 1, 0, sub {
            warn "$self->{request}->{id}: WS timeout (1)\n" if DEBUG;
            delete $self->{timer};
            $self->_next;
          };
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
          my $mask = pack 'CCCC', rand 256, rand 256, rand 256, rand 256;
          for (0..((length $data)-1)) {
            substr ($data, $_, 1) = substr ($data, $_, 1) ^ substr ($mask, $_ % 4, 1);
          }
          $self->_ws_debug ('S', $data, FIN => 1, opcode => 10, mask => $mask, length => length $data) if DEBUG;
          $self->{transport}->push_write
              (\(pack ('CC', 0b10000000 | 10, 0b10000000 | length $data) .
                 $mask . $data));
          $self->_ev ('ping', $data, 0);
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
    my $mask = pack 'CCCC', rand 256, rand 256, rand 256, rand 256;
    my $data = pack 'n', $self->{exit}->{status};
    $data .= $self->{exit}->{reason};
    for (0..((length $data)-1)) {
      substr ($data, $_, 1) = substr ($data, $_, 1) ^ substr ($mask, $_ % 4, 1);
    }
    # length $data must be < 126
    $self->_ws_debug ('S', $self->{exit}->{reason}, FIN => 1, opcode => 8, mask => $mask, length => length $data, status => $self->{exit}->{status}) if DEBUG;
    $self->{transport}->push_write
        (\(pack ('CC', 0b10000000 | 8, 0b10000000 | length $data) .
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
         (defined $self->{request_body_length} and $self->{request_body_length} > 0);

  $self->{ws_encode_mask_key} =
  my $mask = pack 'CCCC', rand 256, rand 256, rand 256, rand 256;
  $self->{ws_sent_length} = 0;
  $self->{request_body_length} = $length;

  my $length0 = $length;
  my $len = '';
  if ($length >= 2**16) {
    $length0 = 0x7F;
    $len = pack 'n', $length;
  } elsif ($length >= 0x7E) {
    $length0 = 0x7E;
    $len = pack 'Q>', $length;
  }
  $self->_ws_debug ('S', $_[2], FIN => 1, opcode => 1, mask => $mask, length => $length) if DEBUG;
  $self->{transport}->push_write
      (\(pack ('CC', 0b10000000 | 1, 0b10000000 | $length0) .
         $len . $mask));
} # send_text_header

sub send_binary_header ($$) {
  my ($self, $length) = @_;
  croak "Data is utf8-flagged" if utf8::is_utf8 $_[2];
  croak "Data too large" if MAX_BYTES < $length; # spec limit 2**63
  croak "Bad state"
      if not (defined $self->{ws_state} and $self->{ws_state} eq 'OPEN') or
         (defined $self->{request_body_length} and $self->{request_body_length} > 0);

  $self->{ws_encode_mask_key} =
  my $mask = pack 'CCCC', rand 256, rand 256, rand 256, rand 256;
  $self->{ws_sent_length} = 0;
  $self->{request_body_length} = $length;

  my $length0 = $length;
  my $len = '';
  if ($length >= 2**16) {
    $length0 = 0x7F;
    $len = pack 'n', $length;
  } elsif ($length >= 0x7E) {
    $length0 = 0x7E;
    $len = pack 'Q>', $length;
  }
  $self->_ws_debug ('S', $_[2], FIN => 1, opcode => 2, mask => $mask, length => $length) if DEBUG;
  $self->{transport}->push_write
      (\(pack ('CC', 0b10000000 | 2, 0b10000000 | $length0) .
         $len . $mask));
} # send_binary_header

sub send_ping ($;%) {
  my ($self, %args) = @_;
  $args{data} = '' unless defined $args{data};
  croak "Data is utf8-flagged" if utf8::is_utf8 $args{data};
  croak "Data too large" if 0x7D < length $args{data}; # spec limit 2**63
  croak "Bad state"
      if not (defined $self->{ws_state} and $self->{ws_state} eq 'OPEN') or
         (defined $self->{request_body_length} and $self->{request_body_length} > 0);

  my $mask = pack 'CCCC', rand 256, rand 256, rand 256, rand 256;
  for (0..((length $args{data})-1)) {
    substr ($args{data}, $_, 1) = substr ($args{data}, $_, 1) ^ substr ($mask, $_ % 4, 1);
  }
  my $opcode = $args{pong} ? 10 : 9;
  $self->_ws_debug ('S', $args{data}, FIN => 1, opcode => $opcode, mask => $mask, length => length $args{data}) if DEBUG;
  $self->{transport}->push_write
      (\(pack ('CC', 0b10000000 | $opcode, 0b10000000 | length $args{data}) .
         $mask . $args{data}));
} # send_ping

sub _ws_debug ($$$%) {
  my $self = $_[0];
  my $side = $_[1];
  my %args = @_[3..$#_];

  my $id = $self->{request}->{id};
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
          (defined $args{mask} ? sprintf 'mask=%02X%02X%02X%02X',
                                     unpack 'CCCC', $args{mask} : ())),
      $args{length};
  if ($args{opcode} == 8 and defined $args{status}) {
    warn "$id: S: status=$args{status} @{[_e4d $_[2]]}\n";
  } elsif ((DEBUG > 1 or $args{opcode} >= 8) and length $_[2]) {
    warn "$id: S: @{[_e4d $_[2]]}\n";
  }
} # _ws_debug

1;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
