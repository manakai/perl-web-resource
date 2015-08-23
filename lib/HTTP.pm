package HTTP;
use strict;
use warnings;
use Errno;
use MIME::Base64 qw(encode_base64);
use Digest::SHA qw(sha1);
use Encode qw(decode);
use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::Socket;
use Promise;

my $DEBUG = $ENV{WEBUA_DEBUG} || 0;

sub MAX_BYTES () { 2**31-1 }

sub new_from_host_and_port ($$$) {
  return bless {host => $_[1], port => $_[2]}, $_[0];
} # new_from_host_and_port

sub _e4d ($) {
  return $_[0] unless $_[0] =~ /[^\x20-\x5B\x5D-\x7E]/;
  my $x = $_[0];
  $x =~ s/([^\x20-\x5B\x5D-\x7E])/sprintf '\x%02X', ord $1/ge;
  return $x;
} # _e4d

sub _process_rbuf ($$;%) {
  my ($self, $handle, %args) = @_;
  if ($self->{state} eq 'before response') {
    if ($handle->{rbuf} =~ s/^.{0,4}[Hh][Tt][Tt][Pp]//s) {
      $self->{state} = 'before response header';
      $self->{response_received} = 1;
    } elsif (8 <= length $handle->{rbuf}) {
      $self->{response_received} = 1;
      if ($self->{request}->{method} eq 'PUT') {
        $self->_ev ('responseerror', {
          message => "HTTP/0.9 response to PUT request",
        });
        $self->{no_new_request} = 1;
        $self->{request_state} = 'sent';
        $self->_next;
        return;
      } else {
        $self->_ev ('headers', $self->{response});
        $self->{state} = 'response body';
        delete $self->{unread_length};
      }
    }
  } elsif ($self->{state} eq 'before response header') {
    if (2**18-1 < length $handle->{rbuf}) {
      $self->_ev ('responseerror', {
        message => "Header section too large",
      });
      $self->{no_new_request} = 1;
      $self->{request_state} = 'sent';
      $self->_next;
      return;
    } elsif ($handle->{rbuf} =~ s/^(.*?)\x0A\x0D?\x0A//s or
             ($args{eof} and $handle->{rbuf} =~ s/\A(.*)\z//s and
              $self->{response}->{incomplete} = 1)) {
      my $headers = [split /[\x0D\x0A]+/, $1, -1];
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
        $self->_ev ('responseerror', {
          message => "Inconsistent content-length values",
        });
        $self->{no_new_request} = 1;
        $self->{request_state} = 'sent';
        $self->_next;
        return;
      } elsif (1 == keys %length) {
        my $length = each %length;
        $length =~ s/\A0+//;
        $length ||= 0;
        if ($length eq 0+$length) { # overflow check
          $self->{unread_length} = $res->{content_length} = 0+$length;
        } else {
          $self->_ev ('responseerror', {
            message => "Inconsistent content-length values",
          });
          $self->{no_new_request} = 1;
          $self->{request_state} = 'sent';
          $self->_next;
          return;
        }
      }

      if ($res->{status} == 200 and
          $self->{request}->{method} eq 'CONNECT') {
        $self->_ev ('headers', $res);
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
          $self->_ev ('headers', $res);
          $self->_ev ('complete', {failed => 1, status => 1006, reason => ''});
          $self->{no_new_request} = 1;
          $self->{request_state} = 'sent';
          $self->_next;
          return;
        } else {
          $self->{ws_state} = 'OPEN';
          $self->_ev ('headers', $res, 1);
          $self->{no_new_request} = 1;
          $self->{state} = 'before ws frame';
          if (defined $self->{pending_frame}) {
            $self->{ws_state} = 'CLOSING';
            $self->{handle}->push_write ($self->{pending_frame});
            $self->_ws_debug ('S', @{$self->{pending_frame_info}}) if $DEBUG;
            $self->{timer} = AE::timer 20, 0, sub {
              warn "$self->{request}->{id}: WS timeout (20)\n" if $DEBUG;
              delete $self->{timer};
              $self->_next;
            };
          }
        }
      } elsif (100 <= $res->{status} and $res->{status} <= 199) {
        if ($self->{request}->{method} eq 'CONNECT' or
            (defined $self->{ws_state} and
             $self->{ws_state} eq 'CONNECTING')) {
          $self->_ev ('responseerror', {
            message => "1xx response to CONNECT or WS",
          });
          $self->{no_new_request} = 1;
          $self->{request_state} = 'sent';
          $self->_next;
          return;
        } else {
          push @{$res->{'1xxes'} ||= []}, {
            version => $res->{version},
            status => $res->{status},
            reason => $res->{reason},
            headers => $res->{headers},
          };
          $res->{version} = '0.9';
          $res->{status} = '200';
          $res->{reason} = 'OK';
          $res->{headers} = [];
          $self->{state} = 'before response';
        }
      } elsif ($res->{status} == 204 or
               $res->{status} == 205 or
               $res->{status} == 304 or
               $self->{request}->{method} eq 'HEAD') {
        $self->_ev ('headers', $res);
        $self->{unread_length} = 0;
        $self->{state} = 'response body';
      } else {
        $self->_ev ('headers', $res);
        if (($chunked or
             not defined $self->{unread_length} or
             $self->{unread_length} > 0) and
            ($self->{request}->{method} eq 'CONNECT' or
             (defined $self->{ws_state} and
              $self->{ws_state} eq 'CONNECTING'))) {
          $self->{response}->{incomplete} = 1;
          $self->_ev ('responseerror', {
            message => "non-empty response to CONNECT or WS",
          });
          $self->{no_new_request} = 1;
          $self->{request_state} = 'sent';
          $self->_next;
          return;
        } elsif ($chunked) {
          $self->{state} = 'before response chunk';
        } else {
          $self->{state} = 'response body';
        }
      }
    }
  }
  if ($self->{state} eq 'response body') {
    if (defined $self->{unread_length}) {
      if ($self->{unread_length} >= (my $len = length $handle->{rbuf})) {
        if ($len) {
          $self->_ev ('data', $handle->{rbuf});
          $handle->{rbuf} = '';
          $self->{unread_length} -= $len;
        }
      } elsif ($self->{unread_length} > 0) {
        $self->_ev ('data', substr $handle->{rbuf}, 0, $self->{unread_length});
        substr ($handle->{rbuf}, 0, $self->{unread_length}) = '';
        $self->{unread_length} = 0;
      }
      if ($self->{unread_length} <= 0) {
        $self->_ev ('complete', {});

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

        $self->_next;
      }
    } else {
      $self->_ev ('data', $handle->{rbuf})
          if length $handle->{rbuf};
      $handle->{rbuf} = '';
    }
  }
  if ($self->{state} eq 'before response chunk') {
    if ($handle->{rbuf} =~ /^[0-9A-Fa-f]/) {
      $self->{state} = 'response chunk size';
    } elsif (length $handle->{rbuf}) {
      $self->{response}->{incomplete} = 1;
      $self->{no_new_request} = 1;
      $self->{request_state} = 'sent';
      $self->_ev ('complete', {});
      $self->_next;
      return;
    }
  }
  if ($self->{state} eq 'response chunk size') {
    if ($handle->{rbuf} =~ s/^([0-9A-Fa-f]+)(?![0-9A-Fa-f])//) {
      my $h = $1;
      $h =~ tr/A-F/a-f/;
      $h =~ s/^0+//;
      $h ||= 0;
      my $n = hex $h;
      if (not $h eq sprintf '%x', $n) { # overflow
        $self->{response}->{incomplete} = 1;
        $self->{no_new_request} = 1;
        $self->{request_state} = 'sent';
        $self->_ev ('complete', {});
        $self->_next;
        return;
      }
      if ($n == 0) {
        $self->{state} = 'before response trailer';
      } else {
        $self->{unread_length} = $n;
        if ($handle->{rbuf} =~ s/^\x0A//) {
          $self->{state} = 'response chunk data';
        } else {
          $self->{state} = 'response chunk extension';
        }
      }
    }
  }
  if ($self->{state} eq 'response chunk extension') {
    $handle->{rbuf} =~ s/^[^\x0A]+//;
    if ($handle->{rbuf} =~ s/^\x0A//) {
      $self->{state} = 'response chunk data';
    }
  }
  if ($self->{state} eq 'response chunk data') {
    if ($self->{unread_length} > 0) {
      if ($self->{unread_length} >= (my $len = length $handle->{rbuf})) {
        $self->_ev ('data', $handle->{rbuf});
        $handle->{rbuf} = '';
        $self->{unread_length} -= $len;
      } else {
        $self->_ev ('data', substr $handle->{rbuf}, 0, $self->{unread_length});
        substr ($handle->{rbuf}, 0, $self->{unread_length}) = '';
        $self->{unread_length} = 0;
      }
    }
    if ($self->{unread_length} <= 0) {
      delete $self->{unread_length};
      if ($handle->{rbuf} =~ s/^\x0D?\x0A//) {
        $self->{state} = 'before response chunk';
      } elsif ($handle->{rbuf} =~ /^(?:\x0D[^\x0A]|[^\x0D\x0A])/) {
        $self->{response}->{incomplete} = 1;
        $self->{no_new_request} = 1;
        $self->{request_state} = 'sent';
        $self->_ev ('complete', {});
        $self->_next;
        return;
      }
    }
  }
  if ($self->{state} eq 'before response trailer') {
    if (2**18-1 < length $handle->{rbuf}) {
      $self->{no_new_request} = 1;
      $self->{request_state} = 'sent';
      $self->_ev ('complete', {});
      $self->_next;
      return;
    } elsif ($handle->{rbuf} =~ s/^(.*?)\x0A\x0D?\x0A//s) {
      $self->_ev ('complete', {});
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
      $self->_next;
      return;
    }
  }
  my $ws_failed;
  WS: {
    if ($self->{state} eq 'before ws frame') {
      my $rlength = length $handle->{rbuf};
      last WS if $rlength < 2;
      my $b1 = ord substr $handle->{rbuf}, 0, 1;
      my $b2 = ord substr $handle->{rbuf}, 1, 1;
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
        $self->{unread_length} = unpack 'n', substr $handle->{rbuf}, 2, 2;
        pos ($handle->{rbuf}) = 4;
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
        $self->{unread_length} = unpack 'Q>', substr $handle->{rbuf}, 2, 8;
        pos ($handle->{rbuf}) = 10;
        if ($self->{unread_length} > MAX_BYTES) { # spec limit=2**63
          $ws_failed = '';
          last WS;
        }
        if ($self->{unread_length} < 2**16) {
          $ws_failed = '';
          last WS;
        }
      } else {
        pos ($handle->{rbuf}) = 2;
      }
      if ($mask) {
        last WS unless $rlength >= pos ($handle->{rbuf}) + 4;
        $self->{ws_decode_mask_key} = substr $handle->{rbuf}, pos ($handle->{rbuf}), 4;
        pos ($handle->{rbuf}) += 4;
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
                        length => $self->{unread_length}) if $DEBUG;
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
      substr ($handle->{rbuf}, 0, pos $handle->{rbuf}) = '';
      $self->{state} = 'ws data';
    }
    if ($self->{state} eq 'ws data') {
      if ($self->{unread_length} > 0 and
          length ($handle->{rbuf}) >= $self->{unread_length}) {
        # XXX xor if ws_decode_mask_key
        push @{$self->{ws_frame}->[1]}, substr $handle->{rbuf}, 0, $self->{unread_length};
        #if ($DEBUG > 1 or
        #    ($DEBUG and $self->{ws_frame}->[0] >= 8)) {
        if ($DEBUG and $self->{ws_frame}->[0] == 8) {
          if ($self->{ws_frame}->[0] == 8 and
              $self->{unread_length} > 1) {
            warn sprintf "$self->{request}->{id}: R: status=%d %s\n",
                unpack ('n', substr $handle->{rbuf}, 0, 2),
                _e4d substr ($handle->{rbuf}, 2, $self->{unread_length});
          } else {
            warn sprintf "$self->{request}->{id}: R: %s\n",
                _e4d substr ($handle->{rbuf}, 0, $self->{unread_length});
          }
        }
        substr ($handle->{rbuf}, 0, $self->{unread_length}) = '';
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
            $self->{handle}->push_write
                (pack ('CC', 0b10000000 | 8, 0b10000000 | length $data) .
                 $mask . $data);
            $self->_ws_debug ('S', $reason // '', FIN => 1, opcode => 8, mask => $mask, length => length $data, status => $status) if $DEBUG;
          }
          $self->{state} = 'ws terminating';
          $self->{exit} = {status => $status, reason => $reason};
          # if server, $self->_next;
          $self->{timer} = AE::timer 1, 0, sub {
            warn "$self->{request}->{id}: WS timeout (1)\n" if $DEBUG;
            delete $self->{timer};
            $self->_next;
          };
          return;
        } elsif ($self->{ws_frame}->[0] <= 2) { # 0, 1, 2
          if ($self->{ws_frame}->[2]) { # FIN
            my $length = 0;
            if ($self->{ws_frame}->[0] == 1) {
              my $buffer = join '', @{$self->{ws_frame}->[1]};
              $self->{ws_frame}->[1] = [eval { decode 'utf-8', $buffer, Encode::FB_CROAK }]; # XXX Encoding Standard # XXX streaming decoder
              if (length $buffer) {
                $ws_failed = 'Invalid UTF-8 in text frame';
                last WS;
              }
            } else {
              for (@{$self->{ws_frame}->[1]}) {
                $length += length $_;
              }
            }
            $self->_ev ('wsmessagestart', {opcode => $self->{ws_frame}->[0],
                                           length => $length});
            for (@{$self->{ws_frame}->[1]}) {
              $self->_ev ('data', $_);
            }
            $self->_ev ('wsmessageend');
            delete $self->{ws_data_frame};
          }
        } elsif ($self->{ws_frame}->[0] == 9) {
          my $data = join '', @{$self->{ws_frame}->[1]};
          my $mask = pack 'CCCC', rand 256, rand 256, rand 256, rand 256;
          for (0..((length $data)-1)) {
            substr ($data, $_, 1) = substr ($data, $_, 1) ^ substr ($mask, $_ % 4, 1);
          }
          $self->{handle}->push_write
              (pack ('CC', 0b10000000 | 10, 0b10000000 | length $data) .
               $mask . $data);
          $self->_ws_debug ('S', $data, FIN => 1, opcode => 10, mask => $mask, length => length $data) if $DEBUG;
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
    $self->{exit} = {failed => 1, status => 1002, reason => $ws_failed};
    my $mask = pack 'CCCC', rand 256, rand 256, rand 256, rand 256;
    my $data = pack 'n', $self->{exit}->{status};
    $data .= $self->{exit}->{reason};
    for (0..((length $data)-1)) {
      substr ($data, $_, 1) = substr ($data, $_, 1) ^ substr ($mask, $_ % 4, 1);
    }
    # length $data must be < 126
    $self->{handle}->push_write
        (pack ('CC', 0b10000000 | 8, 0b10000000 | length $data) .
         $mask . $data);
    $self->_ws_debug ('S', $self->{exit}->{reason}, FIN => 1, opcode => 8, mask => $mask, length => length $data, status => $self->{exit}->{status}) if $DEBUG;
    $self->{state} = 'ws terminating';
    $self->{no_new_request} = 1;
    $self->{request_state} = 'sent';
    $self->_next;
    return;
  }
  if ($self->{state} eq 'ws terminating') {
    unless ($self->{exit}->{failed}) {
      $self->{exit}->{failed} = 1;
      $self->{exit}->{status} = 1006;
      $self->{exit}->{reason} = '';
    }
    $handle->{rbuf} = '';
  }
  if ($self->{state} eq 'tunnel') {
    $self->_ev ('data', $handle->{rbuf})
        if length $handle->{rbuf};
    $handle->{rbuf} = '';
  }
  if ($self->{state} eq 'waiting' or
      $self->{state} eq 'sending' or
      $self->{state} eq 'stopped') {
    $handle->{rbuf} = '';
  }
} # _process_rbuf

sub _process_rbuf_eof ($$;%) {
  my ($self, $handle, %args) = @_;
  if ($self->{state} eq 'before response') {
    if (length $handle->{rbuf}) {
      if ($self->{request}->{method} eq 'PUT') {
        $self->_ev ('responseerror', {
          message => "HTTP/0.9 response to PUT request",
        });
      } else {
        $self->_ev ('headers', $self->{response});
        $self->_ev ('data', $handle->{rbuf});
        # XXX
        #abort => $args{abort},
        #errno => $args{errno},
        $self->_ev ('complete', {});
      }
      $handle->{rbuf} = '';
    } else {
      $self->_ev ('responseerror', {
        message => "Connection closed without response",
        errno => $args{errno},
        can_retry => $self->{response_received},
      });
    }
  } elsif ($self->{state} eq 'response body') {
    if (defined $self->{unread_length} and $self->{unread_length} > 0) {
      $self->{response}->{incomplete} = 1;
      $self->{request_state} = 'sent';
      if ($self->{response}->{version} eq '1.1') {
        $self->_ev ('responseerror', {
          message => "Connection truncated",
          errno => $args{errno},
        });
      } else {
        $self->_ev ('complete', {});
      }
    } elsif ($args{abort} and
             defined $self->{unread_length} and $self->{unread_length} == 0) {
      $self->{request_state} = 'sent';
      $self->_ev ('complete', {});
    } else {
      $self->_ev ('complete', {});
    }
        # XXX
        #abort => $args{abort},
        #errno => $args{errno},
  } elsif ({
    'before response chunk' => 1,
    'response chunk size' => 1,
    'response chunk extension' => 1,
    'response chunk data' => 1,
  }->{$self->{state}}) {
    $self->{response}->{incomplete} = 1;
    $self->{request_state} = 'sent';
    $self->_ev ('complete', {});
  } elsif ($self->{state} eq 'before response trailer') {
    $self->{request_state} = 'sent';
    $self->_ev ('complete', {});
  } elsif ($self->{state} eq 'tunnel') {
    $self->_ev ('complete', {});
        # XXX
        #abort => $args{abort},
        #errno => $args{errno},
  } elsif ($self->{state} eq 'before response header') {
    $self->_ev ('responseerror', {
      message => "Connection closed in response header",
      errno => $args{errno},
    });
  } elsif ($self->{state} eq 'before ws frame' or
           $self->{state} eq 'ws data') {
    $self->{ws_state} = 'CLOSING';
    $self->{exit} = {failed => 1, status => 1006, reason => ''};
  } elsif ($self->{state} eq 'ws terminating') {
    $self->{ws_state} = 'CLOSING';
    if ($args{abort} and not $self->{exit}->{failed}) {
      $self->{exit}->{failed} = 1;
      $self->{exit}->{status} = 1006;
      $self->{exit}->{reason} = '';
    }
  }

  $self->{no_new_request} = 1;
  $self->{request_state} = 'sent' if $args{abort};
  $self->_next;
} # _process_rbuf_eof

sub _next ($) {
  my $self = $_[0];
  return if $self->{state} eq 'stopped';

  delete $self->{timer};
  if (defined $self->{ws_state} and $self->{ws_state} eq 'CLOSING') {
    $self->_ev ('complete', $self->{exit});
  }

  if (not $self->{no_new_request} and $self->{request_state} eq 'sending') {
    $self->{state} = 'sending';
  } else {
    delete $self->{request};
    delete $self->{response};
    $self->{request_state} = 'initial';
    (delete $self->{request_done})->() if defined $self->{request_done};
    if ($self->{no_new_request}) {
      $self->{handle}->push_shutdown;
      my $fh = $self->{handle}->fh;
      my $timer; $timer = AE::timer 1, 0, sub {
        shutdown $fh, 2;
        undef $timer;
      };
      $self->{state} = 'stopped';
    } else {
      $self->{state} = 'waiting';
    }
  }
} # _next

sub connect ($) {
  my $self = $_[0];
  return Promise->new (sub {
    my ($ok, $ng) = @_;
    tcp_connect $self->{host}, $self->{port}, sub {
      my $fh = shift or return $ng->($!);
      my $onclosed;
      my $closed = Promise->new (sub { $onclosed = $_[0] });
      $self->{handle} = AnyEvent::Handle->new
          (fh => $fh,
           oobinline => 0,
           on_read => sub {
             my ($handle) = @_;
             $self->_process_rbuf ($handle);
           },
           on_error => sub {
             my ($hdl, $fatal, $msg) = @_;
             if ($!{ECONNRESET}) {
               $self->_ev ('reset')
                   if defined $self->{request};
               $self->{no_new_request} = 1;
               $self->{request_state} = 'sent';
               $self->_next;
             } else {
               $self->_process_rbuf ($hdl, eof => 1);
               $self->_process_rbuf_eof ($hdl, abort => 1, errno => $!);
             }
             $self->{handle}->destroy;
             delete $self->{handle};
             $onclosed->();
           },
           on_eof => sub {
             my ($hdl) = @_;
             $self->_process_rbuf ($hdl, eof => 1);
             $self->_process_rbuf_eof ($hdl);
             $self->{handle}->on_drain (sub {
               shutdown $fh, 1;
               delete $self->{handle};
               $onclosed->();
             });
           });
      $self->{state} = 'initial';
      $self->{request_state} = 'initial';
      $self->{closed} = $closed;
      $ok->();
    };
  });
} # connect

sub is_active ($) {
  return defined $_[0]->{state} && !$_[0]->{no_new_request};
} # is_active

sub send_request ($$;%) {
  my ($self, $req, %args) = @_;
  my $method = $req->{method} // '';
  if (not defined $method or
      not length $method or
      $method =~ /[\x0D\x0A\x09\x20]/) {
    die "Bad |method|: |$method|";
  }
  my $url = $req->{target};
  if (not defined $url or
      not length $url or
      $url =~ /[\x0D\x0A]/ or
      $url =~ /\A[\x09\x20]/ or
      $url =~ /[\x09\x20]\z/) {
    die "Bad |target|: |$url|";
  }
  for (@{$req->{headers} or []}) {
    die "Bad header name |$_->[0]|"
        unless $_->[0] =~ /\A[!\x23-'*-+\x2D-.0-9A-Z\x5E-z|~]+\z/;
    die "Bad header value |$_->[1]|"
        unless $_->[1] =~ /\A[\x00-\x09\x0B\x0C\x0E-\xFF]*\z/;
  }
  # XXX check body_ref vs Content-Length
  # XXX transfer-encoding
  # XXX WS protocols
  # XXX utf8 flag

  if (not defined $self->{state}) {
    return Promise->reject ("Connection has not been established");
  } elsif ($self->{no_new_request}) {
    return Promise->reject ("Connection is no longer in active");
  } elsif (not ($self->{state} eq 'initial' or $self->{state} eq 'waiting')) {
    return Promise->reject ("Connection is busy");
  }

  $req->{id} = int rand 1000000;
  if ($DEBUG) {
    warn "$req->{id}: ========== $$ @{[__PACKAGE__]}\n";
    warn "$req->{id}: @{[scalar gmtime]}\n";
  }

  $self->{request} = $req;
  $self->{response} = {status => 200, reason => 'OK', version => '0.9',
                       headers => []};
  $self->{state} = 'before response';
  # XXX Connection: close
  if ($args{ws}) {
    $self->{ws_state} = 'CONNECTING';
    $self->{ws_key} = encode_base64 join ('', map { pack 'C', rand 256 } 1..16), '';
    push @{$req->{headers} ||= []},
        ['Sec-WebSocket-Key', $self->{ws_key}],
        ['Sec-WebSocket-Version', '13'];
    $self->{ws_protos} = $args{ws_protocols} || [];
    if (@{$self->{ws_protos}}) {
      push @{$req->{headers}},
          ['Sec-WebSocket-Protocol', join ',', @{$self->{ws_protos}}];
    }
    # XXX extension
  }
  $self->{request_state} = 'sending';
  my $req_done = Promise->new (sub { $self->{request_done} = $_[0] });
  AE::postpone {
    my $handle = $self->{handle} or return;
    if ($DEBUG) {
      warn "$req->{id}: S: @{[_e4d $method]} @{[_e4d $url]} HTTP/1.1\n";
      for (@{$req->{headers} || []}) {
        warn "$req->{id}: S: @{[_e4d $_->[0]]}: @{[_e4d $_->[1]]}\n";
      }
      warn "$req->{id}: S: \n";
    }
    $handle->push_write ("$method $url HTTP/1.1\x0D\x0A");
    $handle->push_write (join '', map { "$_->[0]: $_->[1]\x0D\x0A" } @{$req->{headers} || []});
    $handle->push_write ("\x0D\x0A");
    if (defined $req->{body_ref}) {
      if ($DEBUG > 1) {
        for (split /\x0D?\x0A/, ${$req->{body_ref}}, -1) {
          warn "$req->{id}: S: @{[_e4d $_]}\n";
        }
      }
      $handle->push_write (${$req->{body_ref}});
    }
    $handle->on_drain (sub {
      $self->{request_state} = 'sent';
      $self->_ev ('requestsent');
      $self->_next if $self->{state} eq 'sending';
      $_[0]->on_drain (undef);
    });
  };
  if ($DEBUG) {
    $req_done = $req_done->then (sub {
      warn "$req->{id}: ==========\n";
    });
  }
  return $req_done;
} # send_request

sub send_ws_message ($$$) {
  my $self = $_[0];
  my $type = $_[1];
  die "Unknown type" unless $type eq 'text' or $type eq 'binary';
  die "Data is utf8-flagged" if utf8::is_utf8 $_[2];
  die "Data too large"
      if MAX_BYTES < length $_[2]; # spec limit 2**63
  die "Bad state"
      unless defined $self->{ws_state} and $self->{ws_state} eq 'OPEN';

  my $mask = pack 'CCCC', rand 256, rand 256, rand 256, rand 256;
  my $data = $_[2];
  for (0..((length $data)-1)) {
    substr ($data, $_, 1) = substr ($data, $_, 1) ^ substr ($mask, $_ % 4, 1);
  }
  my $length = length $data;
  my $length0 = $length;
  my $len = '';
  if ($length >= 2**16) {
    $length0 = 0x7F;
    $len = pack 'n', $length;
  } elsif ($length >= 0x7E) {
    $length0 = 0x7E;
    $len = pack 'Q>', $length;
  }
  my $opcode = $type eq 'text' ? 1 : 2;
  $self->_ws_debug ('S', $_[2], FIN => 1, opcode => $opcode, mask => $mask, length => $length) if $DEBUG;
  $self->{handle}->push_write
      (pack ('CC', 0b10000000 | $opcode, 0b10000000 | $length0) .
       $len . $mask . $data);
} # send_ws_message

sub send_through_tunnel ($$) {
  my $self = $_[0];
  unless (defined $self->{state} and $self->{state} eq 'tunnel') {
    die "Tunnel is not open";
  }
  return unless length $_[1];
  $self->{handle}->push_write ($_[1]);
} # send_through_tunnel

sub close ($;%) {
  my ($self, %args) = @_;
  if (not defined $self->{state}) {
    return Promise->reject ("Connection has not been established");
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
    my $mask = pack 'CCCC', rand 256, rand 256, rand 256, rand 256;
    my $data = '';
    if (defined $args{status}) {
      $data = pack 'n', $args{status};
      $data .= $args{reason} // '';
      for (0..((length $data)-1)) {
        substr ($data, $_, 1) = substr ($data, $_, 1) ^ substr ($mask, $_ % 4, 1);
      }
    }
    my $frame = pack ('CC', 0b10000000 | 8, 0b10000000 | length $data) .
        $mask . $data;
    if ($self->{ws_state} eq 'CONNECTING') {
      $self->{pending_frame} = $frame;
      $self->{pending_frame_info} = [$args{reason}, FIN => 1, opcode => 8, mask => $mask, length => length $data, status => $args{status}] if $DEBUG;
    } else {
      $self->_ws_debug ('S', $args{reason}, FIN => 1, opcode => 8, mask => $mask, length => length $data, status => $args{status}) if $DEBUG;
      $self->{handle}->push_write ($frame);
      $self->{ws_state} = 'CLOSING';
      $self->{timer} = AE::timer 20, 0, sub {
        warn "$self->{request}->{id}: WS timeout (20)\n" if $DEBUG;
        # XXX set exit ?
        $self->_next;
        delete $self->{timer};
      };
      $self->_ev ('closing');
    }
  }

  $self->{no_new_request} = 1;
  if ($self->{state} eq 'initial' or
      $self->{state} eq 'waiting' or
      $self->{state} eq 'tunnel') {
    $self->{handle}->push_shutdown;
  }

  return $self->{closed};
} # close

sub abort ($) {
  my $self = $_[0];
  if (not defined $self->{state}) {
    return Promise->reject ("Connection has not been established");
  }

  $self->{no_new_request} = 1;
  $self->{request_state} = 'sent';
  if (defined $self->{request}) {
    if (defined $self->{ws_state} and not $self->{ws_state} eq 'CLOSED') {
      $self->{ws_state} = 'CLOSING';
      $self->{exit} = {failed => 1};
    } else {
      $self->_ev ('responseerror', {
        message => "Aborted",
      });
    }
  }
  $self->_next;

  return $self->{closed};
} # abort

sub onevent ($;$) {
  if (@_ > 1) {
    $_[0]->{onevent} = $_[1];
  }
  return $_[0]->{onevent} ||= sub { };
} # onevent

sub _ev ($$;$$) {
  my $self = shift;
  my $req = $self->{request};
  if ($DEBUG) {
    warn "$req->{id}: $_[0] @{[scalar gmtime]}\n";
    if ($_[0] eq 'data' and $DEBUG > 1) {
      for (split /\x0D?\x0A/, $_[1], -1) {
        warn "$req->{id}: R: @{[_e4d $_]}\n";
      }
    } elsif ($_[0] eq 'headers') {
      warn "$req->{id}: R: HTTP/$_[1]->{version} $_[1]->{status} $_[1]->{reason}\n";
      for (@{$_[1]->{headers}}) {
        warn "$req->{id}: R: @{[_e4d $_->[0]]}: @{[_e4d $_->[1]]}\n";
      }
      warn "$req->{id}: R: \n" if $DEBUG > 1;
      warn "$req->{id}: + WS established\n" if $DEBUG and $_[2];
    } elsif ($_[0] eq 'complete' or $_[0] eq 'responseerror') {
      my $err = join ' ',
          $_[1]->{reset} ? 'reset' : (),
          $self->{response}->{incomplete} ? 'incomplete' : (),
          $_[1]->{failed} ? 'failed' : (),
          $_[1]->{cleanly} ? 'cleanly' : (),
          $_[1]->{can_retry} ? 'retryable' : (),
          defined $_[1]->{status} ? 'status=' . $_[1]->{status} : (),
          defined $_[1]->{reason} ? '"' . $_[1]->{reason} . '"' : ();
      warn "$req->{id}: + @{[_e4d $err]}\n" if length $err;
    }
  }
  $self->onevent->($self, $req, @_);
} # _ev

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
          }->{$args{opcode}} // ()),
          ($args{FIN} ? 'F' : ()),
          ($args{RSV1} ? 'R1' : ()),
          ($args{RSV2} ? 'R2' : ()),
          ($args{RSV3} ? 'R3' : ()),
          (defined $args{mask} ? sprintf 'mask=%02X%02X%02X%02X',
                                     unpack 'CCCC', $args{mask} : ())),
      $args{length};
  if ($args{opcode} == 8 and defined $args{status}) {
    warn "$id: S: status=$args{status} @{[_e4d $_[2]]}\n";
  } elsif (($DEBUG > 1 or $args{opcode} >= 8) and length $_[2]) {
    warn "$id: S: @{[_e4d $_[2]]}\n";
  }
} # _ws_sent

sub DESTROY ($) {
  $_[0]->abort if defined $_[0]->{handle};
} # DESTROY

1;
