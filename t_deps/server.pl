use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Time::HiRes qw(time);
use Socket;
use Errno;
use JSON::PS;
use AnyEvent;
use AnyEvent::Socket;
use AnyEvent::Handle;
use Digest::SHA qw(sha1);
use MIME::Base64 qw(encode_base64);
use Test::Certificates;
use Test::OpenSSL;

my $host = shift;
my $port = shift || die "Usage: $0 listen-host listen-port\n";

my $input;
{
  local $/ = undef;
  $input = <>;
}

my $Commands = [split /\x0D?\x0A/, $input];

my $DUMP = $ENV{DUMP};
my $_dump_tls = {};
our $CurrentID;
my $HandshakeDone = sub { };

my $H2DEF = json_bytes2perl path (__FILE__)->parent->child ('http-frames.json')->slurp;
my $HPACK_HUFFMAN = {};
for (0..$#{$H2DEF->{hpack}->{huffman}}) {
  my $d = $H2DEF->{hpack}->{huffman}->[$_];
  $HPACK_HUFFMAN->{$d->{bits}} = $_;
}
my $HPACK_HUFFMAN_PATTERN = '(?:' . (join '|', keys %$HPACK_HUFFMAN) . ')';

my $ReceivedDumper = sub {
  return unless $DUMP;
  warn "[$_[0]->{id}] @{[time]} @{[scalar gmtime]} on_read L=@{[length $_[1]]}\n";
  warn hex_dump ($_[1]), "\n";
}; # $ReceivedDumper
my $H2ReceivedDumper = do {
  my $received = '';
  my $payload_length = 0;
  my $frame_flags = 0;
  my $frame_type = -1;
  sub {
    my $states = $_[0];
    my $id = $states->{id};
    $received .= $_[1];
    {
    if (not $payload_length and $received =~ s/^(...)(.)(.)(....)//s) {
      my $length = unpack 'N', "\x00$1";
      my $type = unpack 'C', $2;
      $frame_flags = unpack 'C', $3;
      my $flags = unpack 'b8', $3;
      my $stream_id = unpack 'N', $4;
      my $R = $stream_id & 2**32;
      $stream_id = $stream_id & (2**32-1);
      warn "[$id] H2 frame header ".(join ' ',
            {
              0 => 'DATA', 1 => 'HEADERS', 2 => 'PRIORITY',
              3 => 'RST_STREAM', 4 => 'SETTINGS', 5 => 'PUSH_PROMISE',
              6 => 'PING', 7 => 'GOAWAY', 8 => 'WINDOW_UPDATE',
              9 => 'CONTINUATION',
            }->{$type} || (),
            "($type)",
            (substr ($flags, 0, 1) ? 'END_STREAM/ACK' : ()),
            (substr ($flags, 1, 1) ? 'f1' : ()),
            (substr ($flags, 2, 1) ? 'END_HEADERS' : ()),
            (substr ($flags, 3, 1) ? 'PADDED' : ()),
            (substr ($flags, 4, 1) ? 'f4' : ()),
            (substr ($flags, 5, 1) ? 'PRIORITY' : ()),
            (substr ($flags, 6, 1) ? 'f6' : ()),
            (substr ($flags, 7, 1) ? 'f7' : ()),
            ($R ? 'R' : ()),
            "stream=$stream_id",
            "L=$length",
          )."\n" if $DUMP;
      $frame_type = $type;
      $payload_length = $length;
      if ($type == 1 or $type == 5) { # HEADERS, PUSH_PROMISE
        push @{$states->{h2_streams} ||= []}, $stream_id;
      }
    } elsif (not $payload_length) {
      return;
    }
    if ($payload_length <= length $received) {
      my $data = substr $received, 0, $payload_length;
      if ($frame_type == 1) { # HEADERS
        $states->{hpack_table} ||= [@{$H2DEF->{hpack}->{static}}];
        my $pad_length = unpack 'C', substr $data, 0, 1;
        my $e = 0;
        my $stream_dep = 0;
        my $weight = 0;
        my $o = 1;
        if ($frame_flags & 0x20) {
          $stream_dep = unpack 'N', "\x00".substr $data, $o, 3;
          $e = $stream_dep & 2**23;
          $stream_dep &= 2**23-1;
          $o += 3;
          $weight = unpack 'C', substr $data, $o, 1;
          $o += 1;
          warn "[$id] H2   ".(join ' ',
            'stream dependency=' . $stream_dep,
            ($e ? 'E' : ()),
            'weight=' . $weight,
          )."\n" if $DUMP;
        }
        substr ($data, 0, $o) = '';
        my $pad = $pad_length > 0 ? substr $data, -$pad_length : '';
        substr ($data, -$pad_length) = '' if $pad_length > 0;
        my $int = sub {
          my $result = $_[1];
          if ($result == 2**$_[0]-1) {
            my $m = 0;
            {
              my $b = unpack 'C', substr $data, 0, 1;
              $result += ($b & 0b01111111) * 2**$m;
              $m += 7;
              substr ($data, 0, 1) = '';
              redo if $b & 128;
            }
          }
          # error if overflow
          return $result;
        }; # $int
        my $str = sub {
          my $v = unpack 'C', substr $data, 0, 1;
          my $h = $v & 128;
          my $length = $v & 127;
          substr ($data, 0, 1) = '';
          $length = $int->(7, $length);
          my $s = substr $data, 0, $length;
          substr ($data, 0, $length) = '';
          if ($h) {
            my $bytes = '';
            my $desc = '';
            $s = join '', map { unpack 'B8', $_ } split //, $s;
            while (length $s) {
              if ($s =~ s/^($HPACK_HUFFMAN_PATTERN)//o) {
                $bytes .= pack 'C', $HPACK_HUFFMAN->{$1};
                $desc .= sprintf "%s (%02X) ", $1, $HPACK_HUFFMAN->{$1};
              } else {
                $desc .= sprintf "%s (pad)", $s;
                last; # or error
              }
            }
            #return "h`$bytes` ($desc)";
            return "h`$bytes`";
          } else {
            return "`$s`";
          }
        }; # $str
        while (length $data) {
          my $type = unpack 'B8', substr $data, 0, 1;
          if ($type =~ /^1/) { # indexed
            my $index = 0b01111111 & unpack 'C', substr $data, 0, 1;
            substr ($data, 0, 1) = '';
            $index = $int->(7, $index);
            my $tr = $states->{hpack_table}->[$index];
            warn "[$id] H2    $tr->[0]: $tr->[1] (#$index)\n" if $DUMP;
          } elsif ($type =~ /^01/) { # indexed literal
            my $index = 0b00111111 & unpack 'C', substr $data, 0, 1;
            substr ($data, 0, 1) = '';
            if ($index == 0) {
              my $n = $str->();
              my $v = $str->();
              warn "[$id] H2    $n=$v (indexing)\n" if $DUMP;
              unshift @{$states->{hpack_dtable}}, [$n, $v];
            } else {
              $index = $int->(6, $index);
              my $tr = $states->{hpack_table}->[$index];
              my $v = $str->();
              warn "[$id] H2    $tr->[0] (#$index): $v (indexing)\n" if $DUMP;
              unshift @{$states->{hpack_dtable}}, [$tr->[0], $v];
            }
            $states->{hpack_table} = [@{$H2DEF->{hpack}->{static}}, @{$states->{hpack_dtable}}];
          } elsif ($type =~ /^001/) { # dynamic table update
            my $size = 0b00011111 & unpack 'C', substr $data, 0, 1;
            substr ($data, 0, 1) = '';
            $size = $int->(5, $size);
            # XXX...
            warn "[$id] H2    dynamic table update size=$size\n" if $DUMP;
          } elsif ($type =~ /^000/) { # not indexed
            my $never = $type =~ /^...1/ ? ' (never indexed)' : '';
            my $index = 0b00001111 & unpack 'C', substr $data, 0, 1;
            substr ($data, 0, 1) = '';
            if ($index == 0) {
              my $n = $str->();
              my $v = $str->();
              warn "[$id] H2    $n: $v$never\n" if $DUMP;
            } else {
              $index = $int->(4, $index);
              my $tr = $states->{hpack_table}->[$index];
              my $v = $str->();
              warn "[$id] H2    $tr->[0] (#$index): $v$never\n" if $DUMP;
            }
          }
        }
        warn "[$id] H2  Pad (L=$pad_length) ", hex_dump ($pad), "\n" if $DUMP and length $pad;
      } elsif ($frame_type == 8 and 4 == length $data) { # WINDOW_SIZE
        my $v = unpack 'N', $data;
        warn "[$id] H2 ".(join ' ',
          '  Window Size Increment=' . ($v & (2**32-1)),
          ($v & 2**32 ? 'R' : ()),
        )."\n" if $DUMP;
      } elsif ($frame_type == 4) { # SETTINGS
        while ($data =~ s/^(..)(....)//s) {
          my $n = unpack 'n', $1;
          my $v = unpack 'N', $2;
          $n = {
            1 => 'HEADER_TABLE_SIZE (1)',
            2 => 'ENABLE_PUSH (2)',
            3 => 'MAX_CONCURRENT_STREAMS (3)',
            4 => 'INITIAL_WINDOW_SIZE (4)',
            5 => 'MAX_FRAME_SIZE (5)',
            6 => 'MAX_HEADER_LIST_SIZE (6)',
            16 => 'RENEG_PERMITTED (0x10)',
          }->{$n} || $n;
          warn "[$id] H2   $n=$v\n" if $DUMP;
        }
        if (length $data) {
          warn hex_dump ($data), "\n" if $DUMP;
        }
      } elsif ($frame_type == 2 and 5 == length $data) { # PRIORIRY
        my $v = unpack 'N', substr $data, 0, 4;
        my $w = unpack 'C', substr $data, 4, 1;
        warn "[$id] H2   ".(join ' ',
          ($v & 2**32 ? 'E' : ()),
          'stream dependency=' . ($v & (2**32-1)),
          'weight=' . $w,
        )."\n" if $DUMP;
      } elsif ($frame_type == 3 and 4 == length $data) { # RST_STREAM
        my $v = unpack 'N', $data;
        my $et = {
0 => 'NO_ERROR (0x0)',
1 => 'PROTOCOL_ERROR (0x1)',
2 => 'INTERNAL_ERROR (0x2)',
3 => 'FLOW_CONTROL_ERROR (0x3)',
4 => 'SETTINGS_TIMEOUT (0x4)',
5 => 'STREAM_CLOSED (0x5)',
6 => 'FRAME_SIZE_ERROR (0x6)',
7 => 'REFUSED_STREAM (0x7)',
8 => 'CANCEL (0x8)',
9 => 'COMPRESSION_ERROR (0x9)',
10 => 'CONNECT_ERROR (0xa)',
11 => 'ENHANCE_YOUR_CALM (0xb)',
12 => 'INADEQUATE_SECURITY (0xc)',
13 => 'HTTP_1_1_REQUIRED (0xd)',
        }->{$v};
        warn "[$id] H2   ".(join ' ',
          'error code=' . ($et || $v),
        )."\n" if $DUMP;
        my $info = {type => 'RST_STREAM',
                    error => $v};
        syswrite STDOUT, "[data ".(perl2json_bytes $info)."]\n";
      } elsif ($frame_type >= 7) { # GOAWAY
        my $stream_id = unpack 'N', substr $data, 0, 4;
        my $r = $stream_id & 2**32;
        $stream_id = $stream_id & (2**32-1);
        my $error = unpack 'N', substr $data, 4, 4;
        my $debug = substr $data, 8;
        my $et = {
0 => 'NO_ERROR (0x0)',
1 => 'PROTOCOL_ERROR (0x1)',
2 => 'INTERNAL_ERROR (0x2)',
3 => 'FLOW_CONTROL_ERROR (0x3)',
4 => 'SETTINGS_TIMEOUT (0x4)',
5 => 'STREAM_CLOSED (0x5)',
6 => 'FRAME_SIZE_ERROR (0x6)',
7 => 'REFUSED_STREAM (0x7)',
8 => 'CANCEL (0x8)',
9 => 'COMPRESSION_ERROR (0x9)',
10 => 'CONNECT_ERROR (0xa)',
11 => 'ENHANCE_YOUR_CALM (0xb)',
12 => 'INADEQUATE_SECURITY (0xc)',
13 => 'HTTP_1_1_REQUIRED (0xd)',
        }->{$error} || $error;
        warn "[$id] H2   ".(join ' ',
          ($r ? 'R' : ()),
          "last stream ID=$stream_id",
          "error code=$et",
        )."\n" if $DUMP;
        warn hex_dump ($debug), "\n" if $DUMP and length $debug;
        my $info = {type => 'GOAWAY',
                    error => $error,
                    #debug => $debug,
                   };
        syswrite STDOUT, "[data ".(perl2json_bytes $info)."]\n";
      } else {
        if ($DUMP) {
          warn "[$id] H2 frame payload\n";
          warn hex_dump ($data), "\n";
          warn "[$id] (end of frame)\n";
        }
      }
      substr ($received, 0, $payload_length) = '';
      $payload_length = 0;
    }
    redo;
    }
  }; # $H2ReceivedDumper
};

#sub SSL_ST_CONNECT () { 0x1000 }
#sub SSL_ST_ACCEPT () { 0x2000 }
sub SSL_CB_READ () { 0x04 }
sub SSL_CB_WRITE () { 0x08 }
sub SSL_CB_ALERT () { 0x4000 }
#sub SSL_CB_HANDSHAKE_START () { 0x10 }
sub SSL_CB_HANDSHAKE_DONE () { 0x20 }

my $cipher_suite_name = {};
$cipher_suite_name->{0x00, 0xFF} = 'empty reneg info scsv';

sub pe_b ($) {
  my $s = $_[0];
  $s =~ s/([^\x21-\x24\x26-\x7E])/sprintf '%%%02X', ord $1/ge;
  return $s;
} # pe_b

sub run_commands ($$$$);
sub run_commands ($$$$) {
  my ($context, $hdl, $states, $then) = @_;

  while (@{$states->{commands}}) {
    my $command = shift @{$states->{commands}};
    $command =~ s/^\s+//;
    $command =~ s/\s+$//;
    if ($command =~ /^#/) {
      #
    } elsif ($command =~ /^"([^"]*)"$/) {
      $hdl->push_write ($1);
    } elsif ($command =~ /^"([^"]*)"CRLF$/) {
      $hdl->push_write ("$1\x0D\x0A");
      #AE::log error => "Sent $1 CR LF";
    } elsif ($command =~ /^"([^"]*)"LF$/) {
      $hdl->push_write ("$1\x0A");
    } elsif ($command =~ /^"([^"]*)"CR$/) {
      $hdl->push_write ("$1\x0D");
    } elsif ($command =~ /^"([^"]*)"\s+x\s+([0-9]+)$/) {
      my $v = $1;
      my $n = $2;
      unless ($n eq 0+$n) {
        warn "|$n| (= @{[0+$n]}) might be overflowed";
      }
      while ($n > 2**28) {
        $hdl->push_write ($v x (2**28));
        $n -= 2**28;
      }
      $hdl->push_write ($v x $n);
    } elsif ($command =~ /^CRLF$/) {
      $hdl->push_write ("\x0D\x0A");
    } elsif ($command =~ /^LF$/) {
      $hdl->push_write ("\x0A");
    } elsif ($command =~ /^CR$/) {
      $hdl->push_write ("\x0D");
    } elsif ($command =~ /^0x([0-9A-Fa-f]{2})$/) {
      $hdl->push_write (pack 'C', hex $1);
    } elsif ($command =~ /^([0-9]+)$/) {
      $hdl->push_write (pack 'C', $1);
    } elsif ($command =~ /^client$/) {
      $hdl->push_write ($states->{client_host} . ':' . $states->{client_port});
    } elsif ($command =~ /^write\s+(sni_host)$/) {
      $hdl->push_write (defined $states->{$1} ? $states->{$1} : '(null)');
    } elsif ($command =~ /^ws-accept$/) {
      $states->{captured} =~ /^Sec-WebSocket-Key:\s*(\S+)\s*$/im;
      my $key = defined $1 ? $1 : '';
      my $sha = encode_base64 sha1 ($key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'), '';
      #warn "$key / $sha";
      $hdl->push_write ($sha);
    } elsif ($command =~ /^receive LF$/) {
      if ($states->{received} =~ /\x0A/) {
        $states->{received} =~ s/^.*?\x0A//s;
      } else {
        unshift @{$states->{commands}}, $command;
        $then->();
        return;
      }
    } elsif ($command =~ /^receive LF, end capture$/) {
      if ($states->{received} =~ /\x0A/) {
        $states->{received} =~ s/^(.*?\x0A)//s;
        $states->{captured} .= $1;
      } else {
        unshift @{$states->{commands}}, $command;
        $then->();
        return;
      }
    } elsif ($command =~ /^receive CRLFCRLF, end capture$/) {
      if ($states->{received} =~ /\x0D\x0A\x0D\x0A/) {
        $states->{received} =~ s/^(.*?\x0D\x0A\x0D\x0A)//s;
        $states->{captured} .= $1;
      } else {
        unshift @{$states->{commands}}, $command;
        $then->();
        return;
      }
    } elsif ($command =~ /^receive "([^"]+)"(, start capture|, end capture|)(, showlength|)(?:, timeout ([0-9]+)|)$/) {
      my $x = $1;
      my $capture = $2;
      my $showlength = $3;
      my $timeout = $4;
      #warn "[$states->{id}] receive [$states->{received}]";
      my $timer;
      if (defined $timeout) {
        $timer = AE::timer $timeout, 0, sub {
          $hdl->push_shutdown;
          undef $timer;
        };
      }
      if ($states->{received} =~ /\Q$x\E/) {
        AE::log error => "[$states->{id}] received length = @{[length $states->{received}]}"
            if $showlength;
        if ($capture eq ', start capture') {
          $states->{received} =~ s/^.*?(\Q$x\E)//s;
          $states->{captured} = $1;
        } elsif ($capture eq ', end capture') {
          $states->{received} =~ s/^(.*?\Q$x\E)//s;
          $states->{captured} .= $1;
        } else {
          $states->{received} =~ s/^.*?\Q$x\E//s;
        }
        undef $timer;
      } else {
        unshift @{$states->{commands}}, $command;
        $then->();
        return;
      }
    } elsif ($command =~ /^receive preface$/) {
      if (length $states->{received} >= 24) {
        if ($states->{received} =~ s{^\QPRI * HTTP/2.0\E\x0D\x0A\x0D\x0ASM\x0D\x0A\x0D\x0A}{}) {
          warn "[$states->{id}] HTTP/2 preface received\n";
          if ($DUMP) {
            $states->{dumper} = $H2ReceivedDumper;
            $states->{dumper}->($states, $states->{received});
          }
        } else {
          warn "[$states->{id}] HTTP/2 preface not found\n";
        }
      } else {
        unshift @{$states->{commands}}, $command;
        $then->();
        return;
      }
    } elsif ($command =~ /^preface$/) {
      $hdl->push_write ("PRI * HTTP/2.0\x0D\x0A\x0D\x0ASM\x0D\x0A\x0D\x0A");
    } elsif ($command =~ /^sleep ([0-9.]+)$/) {
      sleep $1;
    } elsif ($command =~ /^urgent "([^"]*)"$/) {
      send $hdl->{fh}, $1, MSG_OOB;
    } elsif ($command =~ /^ws-receive-header$/) {
      if ($states->{received} =~ /^(.)(.)/s) {
        my $fin = !!(0x80 & ord $1);
        my $rsv1 = !!(0x40 & ord $1);
        my $rsv2 = !!(0x20 & ord $1);
        my $rsv3 = !!(0x10 & ord $1);
        my $opcode = 0x0F & ord $1;
        my $has_mask = !!(0x80 & ord $2);
        my $length = 0x7F & ord $2;
        if ($length == 0x7E) {
          if ($states->{received} =~ s/^..(.)(.)//s) {
            $length = (ord $1) * 0x100 + ord $2;
          } else {
            undef $length;
          }
        } elsif ($length == 0x7F) {
          if ($states->{received} =~ s/^..(........)//s) {
            $length = unpack 'Q>', $1;
            undef $length if $length >= 2**63;
          } else {
            undef $length;
          }
        } else {
          $states->{received} =~ s/^..//s;
        }
        my $mask = "\x00\x00\x00\x00";
        if ($has_mask) {
          if ($states->{received} =~ s/^(....)//s) {
            $mask = $1;
          } else {
            undef $length;
          }
        }
        if (defined $length) {
          my $info = sprintf q{WS FIN=%d RSV=0b%d%d%d opcode=0x%X masking=%d length=%d},
              $fin, $rsv1, $rsv2, $rsv3, $opcode, $has_mask, $length;
          warn sprintf qq{[$states->{id}] @{[time]} @{[scalar gmtime]}\n%s mask=0x%02X%02X%02X%02X\n},
              $info,
              (ord substr $mask, 0, 1),
              (ord substr $mask, 1, 1),
              (ord substr $mask, 2, 1),
              (ord substr $mask, 3, 1);
          $states->{ws_length} = $length;
          $states->{ws_mask} = $mask;
          $states->{ws_opcode} = $opcode;
          syswrite STDOUT, "[data ".(perl2json_bytes $info)."]\n";
          next;
        }
      }
      unshift @{$states->{commands}}, $command;
      $then->();
      return;
    } elsif ($command =~ /^ws-receive-data$/) {
      if (length $states->{received} >= $states->{ws_length}) {
        my @data = split //, substr $states->{received}, 0, $states->{ws_length};
        substr ($states->{received}, 0, $states->{ws_length}) = '';
        if (defined $states->{ws_mask}) {
          for (0..$#data) {
            $data[$_] = $data[$_] ^ substr $states->{ws_mask}, $_ % 4, 1;
          }
        }
        my $data = join '', @data;
        if ($states->{ws_opcode} == 0x8) {
          my $code = length $data >= 2 ? ((ord substr $data, 0, 1) * 0x100 + (ord substr $data, 1, 1)) : -1;
          my $reason = length $data > 2 ? substr $data, 2 : '';
          warn "  code=$code reason:\n";
          warn hex_dump ($reason), "\n";
          syswrite STDOUT, sprintf "[data %s]\n",
              perl2json_bytes "  code=$code reason=@{[pe_b $reason]}";
        } elsif ($states->{ws_opcode} == 0x9) { # pong
          warn hex_dump ($data), "\n";
          syswrite STDOUT, sprintf "[data %s]\n",
              perl2json_bytes "  @{[pe_b $data]}";
        } else {
          if (length $data > 2**10) {
            warn hex_dump (substr $data, 0, 2**10), "\n";
            warn "...\n";
            syswrite STDOUT, sprintf "[data-length %d]\n", length $data;
          } else {
            warn hex_dump ($data), "\n";
            syswrite STDOUT, sprintf "[data %s]\n",
                perl2json_bytes "  @{[pe_b $data]}";
          }
        }
        next;
      }
      unshift @{$states->{commands}}, $command;
      $then->();
      return;
    } elsif ($command =~ /^ws-send-header((?:\s+\w+=\S*)+)$/) {
      my $args = $1;
      my $fields = {FIN => 1, RSV1 => 0, RSV2 => 0, RSV3 => 0,
                    opcode => 0, masking => 0, length => 0};
      while ($args =~ s/^\s+(\w+)=(\S*)//) {
        $fields->{$1} = $2;
      }
      $hdl->push_write (pack 'C', ($fields->{FIN} << 7) |
                                  ($fields->{RSV1} << 6) |
                                  ($fields->{RSV2} << 5) |
                                  ($fields->{RSV3} << 4) |
                                  $fields->{opcode});
      my $m = $fields->{masking} ? 0x80 : 0;
      if ($fields->{length} < 0x7E) {
        $hdl->push_write (pack 'C', $m | $fields->{length});
      } elsif ($fields->{length} < 0x10000) {
        $hdl->push_write (pack 'C', $m | 0x7E);
        $hdl->push_write (pack 'n', $fields->{length});
      } else {
        $hdl->push_write (pack 'C', $m | 0x7F);
        $hdl->push_write (pack 'Q>', $fields->{length});
      }
      if ($fields->{masking} and not $fields->{nomask}) {
        my $mask = '';
        $mask .= pack 'C', rand 256 for 1..4;
        $hdl->push_write ($mask);
        $states->{ws_send_mask} = $mask;
      }
    } elsif ($command =~ /^h2-receive-header$/) {
      if ($states->{received} =~ s/^(...)(.)(.)(....)//s) {
        my $length = unpack 'N', "\x00$1";
        my $type = unpack 'C', $2;
        my $flags = unpack 'b8', $3;
        my $stream_id = unpack 'N', $4;
        my $R = $stream_id & 2**32;
        $stream_id = $stream_id & (2**32-1);
        $states->{h2_payload_length} = $length;
        next;
      }
      unshift @{$states->{commands}}, $command;
      $then->();
      return;
    } elsif ($command =~ /^h2-receive-payload$/) {
      if ($states->{h2_payload_length} <= length $states->{received}) {
        next if $states->{h2_payload_length} <= 0;
        substr ($states->{received}, 0, $states->{h2_payload_length}) = '';
        next;
      }
      unshift @{$states->{commands}}, $command;
      $then->();
      return;
    } elsif ($command =~ /^h2-receive-headers$/) {
      if (@{$states->{h2_streams} or []}) {
        next;
      }
      unshift @{$states->{commands}}, $command;
      $then->();
      return;
    } elsif ($command =~ /^h2-send-frame((?:\s+\w+=\S*)+)$/) {
      my $args = $1;
      my $fields = {length => 0, type => 0, flags => 0, stream => 0,
                    dependency => 0, weight => 0, promised => 0};
      while ($args =~ s/^\s+(\w+)=(\S*)//) {
        $fields->{$1} = $2;
      }
      $fields->{flags} |= 1 if $fields->{ACK} or $fields->{END_STREAM};
      $fields->{flags} |= 4 if $fields->{END_HEADERS};
      $fields->{flags} |= 8 if $fields->{PADDED};
      $fields->{flags} |= 0x20 if $fields->{PRIORITY};
      $fields->{length} += 5 if $fields->{PRIORITY};
      my $payload = '';
      my $showinfo = 0;
      if ($fields->{type} == 5) { # PUSH_PROMISE
        $payload .= pack 'N', $fields->{promised};
        $fields->{length} += 4;
        $showinfo = 1;
      }
      if (defined $states->{h2_payload}) {
        my $x = join '', @{delete $states->{h2_payload}};
        $payload .= $x;
        $fields->{length} += length $x;
        $showinfo = 1;
      }
      if (defined $states->{fill} and
          ($fields->{type} == 1 or $fields->{type} == 9)) {
        $payload .= "\x3E" x $states->{fill};
        $fields->{length} += $states->{fill};
        $showinfo = 1;
      }
      if ($fields->{stream} eq 'shift') {
        $fields->{stream} = shift @{$states->{h2_streams} || []};
        $showinfo = 1;
      } elsif ($fields->{stream} eq 'last') {
        $fields->{stream} = $states->{h2_last_sent_stream};
        $showinfo = 1;
      }
      $states->{h2_last_sent_stream} = $fields->{stream}
          if not $fields->{stream_nosave} and $fields->{stream};
      if ($DUMP and $showinfo) {
        warn "Send H2 header type=$fields->{type} stream=$fields->{stream} length=$fields->{length}\n";
        warn hex_dump ($payload) . "\n" if length $payload;
      }
      my $frame = join '',
          (substr pack ('N', $fields->{length}), 1),
          (pack 'C', $fields->{type}),
          (pack 'C', $fields->{flags}),
          (pack 'N', $fields->{stream});
      $hdl->push_write ($frame);
      if ($fields->{PRIORITY}) {
        $hdl->push_write (pack 'NC',
          ($fields->{exclusive} ? 0x80 : 0x00) | $fields->{dependency},
          $fields->{weight});
      }
      if (defined $payload) {
        $hdl->push_write ($payload);
      }
    } elsif ($command =~ /^push-h2-header "([^"]+)" ("[^"]*"|authority)$/) {
      my $n = $1;
      my $v = $2;
      $n =~ s/\\x([0-9A-Fa-f]{2})/pack 'C', hex $1/ge;
      if ($v eq 'authority') {
        $v = ($ENV{SERVER_HOST_NAME} || 'hoge.test') . ':' . $port;
      } else {
        $v = substr $v, 1, -2 + length $v;
        $v =~ s/\\x([0-9A-Fa-f]{2})/pack 'C', hex $1/ge;
      }
      my $int = sub {
        if ($_[2] < 2**$_[1]-1) {
          return pack 'C', $_[0] | $_[2];
        } else {
          my $d = pack 'C', $_[0] | (2**$_[1] - 1);
          my $v = $_[2] - (2**$_[1] - 1);
          while ($v >= 128) {
            $d .= pack 'C', 128 | ($v % 128);
            $v = int ($v / 128);
          }
          $d .= pack 'C', $v;
          return $d;
        }
      }; # $int
      my $str = sub {
        return $int->(0b0_0000000, 7, length $_[0]) . $_[0];
      }; # $str
      my $data = (pack 'C', 0b0000_0000) . $str->($n) . $str->($v);
      push @{$states->{h2_payload} ||= []}, $data;
    } elsif ($command =~ /^push-hpack-dynamic-size ([0-9]+)$/) {
      my $n = $1;
      my $int = sub {
        if ($_[2] < 2**$_[1]-1) {
          return pack 'C', $_[0] | $_[2];
        } else {
          my $d = pack 'C', $_[0] | (2**$_[1] - 1);
          my $v = $_[2] - (2**$_[1] - 1);
          while ($v >= 128) {
            $d .= pack 'C', 128 | ($v % 128);
            $v = int ($v / 128);
          }
          $d .= pack 'C', $v;
          return $d;
        }
      }; # $int
      my $data = $int->(0b001_00000, 5, $n);
      push @{$states->{h2_payload} ||= []}, $data;
    } elsif ($command =~ /^h2-send-continue-frames ([0-9]+)$/) {
      my $payload_length = $1;
      while ($payload_length > 0) {
        my $length = 2**14-1;
        $length = $payload_length if $payload_length < $length;
        $payload_length -= $length;
        my $stream = $states->{h2_last_sent_stream};
        my $frame = join '',
            (substr pack ('N', $length), 1),
            (pack 'C', 9), # type
            (pack 'C', 0), # flags
            (pack 'N', $stream);
        $hdl->push_write ($frame . ('>' x $length));
      }

    } elsif ($command =~ /^h2-send-data-frames((?:\s+\w+=\S*)+)$/) {
      my $args = $1;
      my $fields = {length => 0, type => 0, flags => 0, stream => 0,
                    dependency => 0, weight => 0};
      while ($args =~ s/^\s+(\w+)=(\S*)//) {
        $fields->{$1} = $2;
      }
      if ($fields->{stream} eq 'last') {
        $fields->{stream} = $states->{h2_last_sent_stream};
      }
      $states->{h2_last_sent_stream} = $fields->{stream}
          if not $fields->{stream_nosave} and $fields->{stream};
      my $max = 2**14;
      while ($fields->{length}) {
        my $length = $fields->{length} < $max ? $fields->{length} : $max;
        $fields->{length} -= $length;
        my $last = $fields->{length} <= 0;
        $fields->{flags} |= 1 if $last and $fields->{END_STREAM};
        my $frame = join '',
            (substr pack ('N', $length), 1),
            (pack 'C', $fields->{type}),
            (pack 'C', $fields->{flags}),
            (pack 'N', $fields->{stream});
        $hdl->push_write ($frame);
        $hdl->push_write ('x' x $length);
      }
    } elsif ($command =~ /^sendcaptured$/) {
      $hdl->push_write ($states->{captured});
    } elsif ($command =~ /^close$/) {
      $hdl->push_shutdown;
    } elsif ($command =~ /^close read$/) {
      shutdown $hdl->{fh}, 0;
    } elsif ($command =~ /^reset$/) {
      setsockopt $hdl->{fh}, SOL_SOCKET, SO_LINGER, pack "II", 1, 0;
      close $hdl->{fh};
      $states->{on_error}->($hdl, 1, "reset by command");
    } elsif ($command =~ /^starttls((?:\s+\w+=\S*)*)$/) {
      my $x = $1;
      my $args = {};
      while ($x =~ s/^\s+(\w+)=(\S*)//) {
        $args->{$1} = $2;
      }
      $args->{cn} = ($ENV{SERVER_HOST_NAME} || 'hoge.test')
          if defined $args->{cn} and $args->{cn} eq '##HOST##';
      Test::Certificates->wait_create_cert ($args);
      $states->{starttls_waiting} = 1;
      $hdl->on_starttls (sub {
        delete $states->{starttls_waiting};
        $_[0]->on_starttls (undef);
        run_commands ($context, $_[0], $states, $then);
      });

      no warnings 'redefine';
      require AnyEvent::TLS;
      my $orig = \&AnyEvent::TLS::_get_session;
      *AnyEvent::TLS::_get_session = sub ($$;$$) {
        my ($self, $mode, $ref, $cn) = @_;
        my $session = $orig->(@_);

        Net::SSLeay::set_info_callback ($session, sub {
          my ($tls, $where, $ret) = @_;

          #if ($where & SSL_ST_CONNECT) {
          #}
          #if ($where & SSL_ST_ACCEPT) {
          #}

          #if ($where & SSL_CB_HANDSHAKE_START) {
          #}
          if ($where & SSL_CB_HANDSHAKE_DONE) {
            if ($DUMP) {
              warn "[$states->{id}] TLS handshake done\n";
              warn "  version=", Net::SSLeay::version ($tls), "\n";
              #XXX session_id
              warn "  resumed\n" if Net::SSLeay::session_reused ($tls);
              warn "  cipher=", Net::SSLeay::get_cipher ($tls), "\n";
              warn "  cipher size=", Net::SSLeay::get_cipher_bits ($tls), "\n";
              #$data->{tls_cert_chain} = [map { bless [$_], __PACKAGE__ . '::Certificate' } Net::SSLeay::get_peer_cert_chain ($self->{tls})];
            }
            $HandshakeDone->();
          }

          if ($where & SSL_CB_ALERT and $where & SSL_CB_READ) {
            ## <https://www.openssl.org/docs/manmaster/ssl/SSL_alert_type_string.html>
            my $level = Net::SSLeay::alert_type_string ($ret); # W F U
            my $type = Net::SSLeay::alert_desc_string_long ($ret);
            warn "[$states->{id}] TLS alert: [$level] $type\n" if $DUMP;
          }

          if ($where & SSL_CB_ALERT and $where & SSL_CB_WRITE) {
            ## <https://www.openssl.org/docs/manmaster/ssl/SSL_alert_type_string.html>
            my $level = Net::SSLeay::alert_type_string ($ret); # W F U
            my $type = Net::SSLeay::alert_desc_string_long ($ret);
            warn "[$states->{id}] Sent TLS alert: [$level] $type\n" if $DUMP;
          }
        });

        return $session;
      };

      local $CurrentID = $states->{id};
      my $server_cert_path = Test::Certificates->cert_path ('cert-chained.pem', $args);
      warn "[$states->{id}] TLS server certificate: |$server_cert_path|\n" if $DUMP;
      $hdl->starttls ('accept', {
        method => 'TLSv1_2',
        ca_file => Test::Certificates->ca_path ('cert.pem'),
        cert_file => $server_cert_path,
        key_file => Test::Certificates->cert_path ('key.pem', $args),
#        cipher_list => 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK',
        cipher_list => 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK', # modern
        #cipher_list => 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA',
        #dh => 'skip4096',
        dh => 'schmorp4096',
        prepare => sub {
          my $ctx = $_[0]->ctx;
          Net::SSLeay::CTX_set_tlsext_servername_callback ($ctx, sub {
            my $h = Net::SSLeay::get_servername ($_[0]);
            warn "[$states->{id}] TLS SNI name: |$h|\n" if $DUMP and defined $h;
            $states->{sni_host} = $h;

            Net::SSLeay::set_SSL_CTX ($_[0], $ctx);
          });
          if (exists &Net::SSLeay::P_alpn_selected) {
            Net::SSLeay::CTX_set_alpn_select_cb ($ctx, sub {
              my ($ssl, $arrayref, $data) = @_;
              warn "[$states->{id}] TLS ALPN: Client: |@{[join '| |', @$arrayref]}|\n";
              warn "[$states->{id}] TLS ALPN: Server: @{[defined $args->{alpn} ? qq{|$args->{alpn}|} : qq{(none)}]}\n";
              return $args->{alpn};
            }, undef);
          } else {
            warn "[$states->{id}] TLS ALPN can't be used on this system\n";
          }

          ## From IO::Socket::SSL
          my $can_ecdh = defined &Net::SSLeay::CTX_set_tmp_ecdh &&
              # There is a regression with elliptic curves on 1.0.1d with 64bit
              # http://rt.openssl.org/Ticket/Display.html?id=2975
              ( Net::SSLeay::OPENSSL_VERSION_NUMBER() != 0x1000104f
                    || length(pack("P",0)) == 4 );
          if ($can_ecdh) {
            my $curve = 'prime256v1';
            if ( $curve !~ /^\d+$/ ) {
              # name of curve, find NID
              $curve = Net::SSLeay::OBJ_txt2nid($curve)
                  or die "cannot find NID for curve name '$curve'";
            }
            my $ecdh = Net::SSLeay::EC_KEY_new_by_curve_name($curve)
                or die "cannot create curve for NID $curve";
            Net::SSLeay::CTX_set_tmp_ecdh ($ctx, $ecdh)
                  or die "failed to set ECDH curve context";
            Net::SSLeay::EC_KEY_free ($ecdh);
          } else {
            warn "[$states->{id}] ECDH can't be used on this system\n";
          }

          Net::SSLeay::CTX_set_tlsext_status_cb ($ctx, sub {
            my ($tls, $response) = @_;

            unless ($args->{stapling}) {
              warn "[$states->{id}] No OCSP stapling\n" if $DUMP;
              return 1;
            }

            my $res;
            if ($args->{stapling} eq 'broken') {
              $res = join '', map { pack 'C', rand 256 } 1..1 + int rand 1024;
              warn "[$states->{id}] OCSP staple = broken\n" if $DUMP;
            } else {
              $res = Test::Certificates->ocsp_response
                  ($args,
                   revoked => $args->{stapling} eq 'revoked',
                   expired => $args->{stapling} eq 'expired',
                   no_next => $args->{stapling_no_next});
              warn "[$states->{id}] OCSP staple = response\n" if $DUMP;
            }
            Test::OpenSSL::p_SSL_set_tlsext_status_ocsp_resp_data
                ($tls, $res, length $res);
            warn "[$states->{id}] OCSP stapled!\n" if $DUMP;

            return 0; # SSL_TLSEXT_ERR_OK
          });
        },
      });
      unshift @{$states->{commands}}, 'waitstarttls';
      return;
    } elsif ($command =~ /^tlsreneg(| cert\??| nocert)$/) {
      die "TLS not available" unless defined $hdl->{tls};

      my $req = $1;
      if ($req) {
        Net::SSLeay::set_verify_result ($hdl->{tls}, 0);
        my $vmode = 0;
        if ($req eq ' cert' or ' cert?') {
          $vmode |= Net::SSLeay::VERIFY_PEER ();
          $vmode |= Net::SSLeay::VERIFY_FAIL_IF_NO_PEER_CERT ()
              if $req eq ' cert';
        }
        Net::SSLeay::set_verify ($hdl->{tls}, $vmode, sub {
          my ($preverify_ok, $x509_store_ctx) = @_;
          my $depth = Net::SSLeay::X509_STORE_CTX_get_error_depth ($x509_store_ctx);
          if ($depth == 0) {
            #my $cert = Net::SSLeay::X509_STORE_CTX_get_current_cert ($x509_store_ctx);
            #return 1;
          }
          return $preverify_ok;
        });
      }

      my $list = Net::SSLeay::load_client_CA_file
          (Test::Certificates->ca_path ('cert.pem'));
      Net::SSLeay::set_client_CA_list ($hdl->{tls}, $list);

      $states->{starttls_waiting} = 1;
      $HandshakeDone = sub {
        $HandshakeDone = sub { };
        delete $states->{starttls_waiting};
        run_commands ($context, $hdl, $states, $then);
      };

      ## <https://www.openssl.org/docs/manmaster/ssl/SSL_CTX_set_session_id_context.html>
      my $sidctx = 'XXX';
      Net::SSLeay::set_session_id_context ($hdl->{tls}, $sidctx, length $sidctx);

      Net::SSLeay::renegotiate ($hdl->{tls});
      Net::SSLeay::do_handshake ($hdl->{tls});
      Net::SSLeay::set_state ($hdl->{tls}, Net::SSLeay::ST_ACCEPT ());

      unshift @{$states->{commands}}, 'waitstarttls';
      return;
    } elsif ($command =~ /^waitstarttls$/) {
      if ($states->{starttls_waiting}) {
        $then->();
        return;
      }
    } elsif ($command =~ /^stoptls$/) {
      $hdl->stoptls;
    } elsif ($command =~ /^showreceivedlength$/) {
      AE::log error => qq{[$states->{id}] length of rbuf = @{[length $states->{received}]}};
    } elsif ($command =~ /^showcaptured$/) {
      AE::log error => qq{[$states->{id}] captured = |$states->{captured}|};
    } elsif ($command =~ /^show\s+"([^"]*)"$/) {
      warn "[$states->{id}] @{[time]} @{[scalar gmtime]} $1\n";
    } elsif ($command =~ /^data\s+"([^"]*)"$/) {
      syswrite STDOUT, "[data ".(perl2json_bytes $1)."]\n";
    } elsif ($command =~ /\S/) {
      die "Unknown command: |$command|";
    }
  } # while
  $then->();
} # run_commands

my $cv = AE::cv;
$cv->begin;
my $sig = AE::signal TERM => sub { $cv->end };

sub hex_dump ($) {
  my $s = $_[0];
  my @x;
  for (my $i = 0; $i * 16 < length $s; $i++) {
    my @d = map {
      my $index = $i*16+$_;
      if ($index < length $s) {
        ord substr $s, $index, 1;
      } else {
        undef;
      }
    } 0..15;
    push @x, (join ' ', map { defined $_ ? sprintf '%02X', $_ : '  ' } @d) . '  ' .
             (join '', map { defined $_ ? ((0x20 <= $_ and $_ <= 0x7E) ? pack 'C', $_ : '.') : ' ' } @d);
  }
  return join "\n", @x;
} # hex_dump

sub dump_tls ($;%);
sub dump_tls ($;%) {
  my ($key, %args) = @_;
  my $header_length = defined $args{content_type} ? 4 : 5;
  my $id = $_dump_tls->{[split /\Q$;\E/, $key]->[0], 'id'} || '???:'.$key;
  while ($header_length <= length $_dump_tls->{$_[0]}) {
    my $record = {};
    if (defined $args{content_type}) {
      $record->{msg_type} = ord substr $_dump_tls->{$_[0]}, 0, 1;
      $record->{length} = (ord substr $_dump_tls->{$_[0]}, 1, 1) * 0x10000
                        + (ord substr $_dump_tls->{$_[0]}, 2, 1) * 0x100
                        + (ord substr $_dump_tls->{$_[0]}, 3, 1);
    } else {
      $record->{content_type} = ord substr $_dump_tls->{$_[0]}, 0, 1;
      $record->{version}->{major} = ord substr $_dump_tls->{$_[0]}, 1, 1;
      $record->{version}->{minor} = ord substr $_dump_tls->{$_[0]}, 2, 1;
      $record->{length} = (ord substr $_dump_tls->{$_[0]}, 3, 1) * 0x100
                        + (ord substr $_dump_tls->{$_[0]}, 4, 1);
    }
    if ($header_length + $record->{length} <= length $_dump_tls->{$_[0]}) {
      $record->{fragment} = substr $_dump_tls->{$_[0]}, $header_length, $record->{length};
      substr ($_dump_tls->{$_[0]}, 0, $header_length + $record->{length}) = '';
      if (defined $args{content_type}) {
        if ($record->{msg_type} == 1) { # ClientHello
          $record->{client_version}->{major} = ord substr $record->{fragment}, 0, 1;
          $record->{client_version}->{minor} = ord substr $record->{fragment}, 1, 1;
          $record->{random}->{gmt_unix_time}
              = (ord substr $record->{fragment}, 2, 1) * 0x1000000
              + (ord substr $record->{fragment}, 3, 1) * 0x10000
              + (ord substr $record->{fragment}, 4, 1) * 0x100
              + (ord substr $record->{fragment}, 5, 1);
          $record->{random}->{random_bytes} = substr $record->{fragment}, 6, 28;
          my $next = 34;
          $record->{session_id}->{length} = ord substr $record->{fragment}, $next, 1;
          $next += 1;
          $record->{session_id}->{value} = substr $record->{fragment}, $next, $record->{session_id}->{length};
          $next += $record->{session_id}->{length};
          $record->{cipher_suites}->{length} = (ord substr $record->{fragment}, $next, 1) * 0x100
                                             + (ord substr $record->{fragment}, $next + 1, 1);
          $next += 2;
          $record->{cipher_suites}->{value} = substr $record->{fragment}, $next, $record->{cipher_suites}->{length};
          $next += $record->{cipher_suites}->{length};
          $record->{compression_method}->{length} = ord substr $record->{fragment}, $next, 1;
          $next += 1;
          $record->{compression_method}->{value} = substr $record->{fragment}, $next, $record->{compression_method}->{length};
          $next += $record->{compression_method}->{length};
          if ($next <= length $record->{fragment}) {
            $record->{extensions}->{length} = (ord substr $record->{fragment}, $next, 1) * 0x100
                                            + (ord substr $record->{fragment}, $next + 1, 1);
            $next += 2;
            $record->{extensions}->{value} = substr $record->{fragment}, $next, $record->{extensions}->{length};
            $next += $record->{extensions}->{length};
          }
          warn sprintf "[%s] TLS handshake %d (%s) L=%d: %d.%d %s\n",
              $id,
              $record->{msg_type},
              'ClientHello',
              $record->{length},
              $record->{client_version}->{major},
              $record->{client_version}->{minor},
              do {
                my @c = split //, $record->{cipher_suites}->{value};
                my @v;
                while (@c) {
                  my $c1 = ord shift @c;
                  my $c2 = ord shift @c;
                  my $name = $cipher_suite_name->{$c1, $c2};
                  if (defined $name) {
                    push @v, sprintf '%02X%02X [%s]', $c1, $c2, $name;
                  } else {
                    push @v, sprintf '%02X%02X', $c1, $c2;
                  }
                }
                join ' ', @v;
              };
          warn sprintf "  random time=%d bytes=%s\n",
              $record->{random}->{gmt_unix_time},
              hex_dump $record->{random}->{random_bytes};
          warn sprintf "  sid=%s\n", hex_dump $record->{session_id}->{value};
          {
            my $next = 0;
            while ($next < length $record->{extensions}->{value}) {
              my $type = (ord substr $record->{extensions}->{value}, $next, 1) * 0x100
                       + (ord substr $record->{extensions}->{value}, $next + 1, 1);
              $next += 2;
              my $length = (ord substr $record->{extensions}->{value}, $next, 1) * 0x100
                         + (ord substr $record->{extensions}->{value}, $next + 1, 1);
              $next += 2;
              my $data = substr $record->{extensions}->{value}, $next, $length;
              $next += $length;
              if ($type == 0) {
                my $list_length = (ord substr $data, 0, 1) * 0x100
                                + (ord substr $data, 1, 1);
                my $list = substr $data, 2, $list_length;
                my $next = 0;
                my @host_name;
                while ($next < length $list) {
                  my $name_type = ord substr $list, $next, 1;
                  $next++;
                  # if $name_type == 0
                  my $host_name_length = (ord substr $list, $next, 1) * 0x100
                                       + (ord substr $list, $next+1, 1);
                  $next += 2;
                  my $host_name = substr $list, $next, $host_name_length;
                  $next += $host_name_length;
                  push @host_name, "name=$host_name";
                }
                warn sprintf "  0 (SNI) %s\n", join ', ', @host_name;
              } elsif ($type == 16) {
                my $list_length = (ord substr $data, 0, 1) * 0x100
                                + (ord substr $data, 1, 1);
                my $list = substr $data, 2, $list_length;
                my $next = 0;
                my @name;
                while ($next < length $list) {
                  my $name_length = (ord substr $list, $next, 1);
                  $next += 1;
                  my $name = substr $list, $next, $name_length;
                  $next += $name_length;
                  push @name, $name;
                }
                warn sprintf "  16 (ALPN) %s\n", join ', ', @name;
              } else {
                warn sprintf "  %d (%s) L=%d %s\n",
                    $type, {
                      0 => 'SNI',
                      5 => 'status_request',
                      10 => 'supported_groups',
                      11 => 'ec_point_formats',
                      13 => 'signature_algorithms',
                      15 => 'heartbeat',
                      16 => 'ALPN',
                      18 => 'signed_certificate_timestamp',
                      21 => 'padding',
                      23 => 'extended_master_secret',
                      35 => 'SessionTicket',
                      13172 => 'NPN',
                      30032 => 'channel_id',
                      65281 => 'renegotiation_info',
                    }->{$type} || '', $length, hex_dump $data;
              }
            }
          }
        } else {
          warn sprintf "[%s] TLS handshake %d (%s) L=%d\n",
              $id,
              $record->{msg_type},
              {
                0 => 'hello_request',
                16 => 'client_key_exchange',
              }->{$record->{msg_type}} || '',
              $record->{length};
        }
      } else {
        if (defined $_dump_tls->{$key, 'last_content_type'} and
            not $_dump_tls->{$key, 'last_content_type'} == $record->{content_type}) {
          dump_tls $key . $; . $_dump_tls->{$key, 'last_content_type'}, end => 1, content_type => $_dump_tls->{$key, 'last_content_type'};
          delete $_dump_tls->{$key, 'last_content_type'};
        }

        warn sprintf "[%s] TLS record %d (%s) %d.%d L=%d\n",
            $id,
            $record->{content_type},
            {
              22 => 'handshake',
              21 => 'alert',
              20 => 'change_cipher_spec',
              23 => 'application_data',
              24 => 'heartbeat',
            }->{$record->{content_type}} || '',
            $record->{version}->{major}, $record->{version}->{minor},
            $record->{length};
        #warn hex_dump ($record->{fragment}), "\n"
        #    unless $_dump_tls->{$key, 'changed'};

        $_dump_tls->{$key, 'changed'} = 1 if $record->{content_type} == 20;
        unless ($_dump_tls->{$key, 'changed'}) {
          if (not defined $_dump_tls->{$key, 'last_content_type'}) {
            $_dump_tls->{$key, 'last_content_type'} = $record->{content_type};
            $_dump_tls->{$key, $record->{content_type}} = '';
          }
          $_dump_tls->{$key, $record->{content_type}} .= $record->{fragment};
          dump_tls $key . $; . $record->{content_type}, content_type => $record->{content_type};
        }
      }
      next;
    }
    last;
  }
  if ($args{end} and length $_dump_tls->{$key}) {
    warn "Unexpected end of data for |$key| (L=@{[length $_dump_tls->{$key}]})"
        if defined $args{content_type} and $args{content_type} == 22;
    delete $_dump_tls->{$key};
  }
} # dump_tls

require Net::SSLeay;
require AnyEvent::Handle;
{
  my $orig = Net::SSLeay->can ('BIO_write');
  *Net::SSLeay::BIO_write = sub ($$) {
    if (defined $_dump_tls->{$_[0]}) {
      $_dump_tls->{$_[0]} .= $_[1] if defined $_[1];
      dump_tls $_[0];
    }
    goto &$orig;
  } if $DUMP;
}
{
  my $orig = AnyEvent::Handle->can ('_dotls');
  *AnyEvent::Handle::_dotls = sub {
    $_dump_tls->{$_[0]->{_rbio}} = '' if not defined $_dump_tls->{$_[0]->{_rbio}};
    if (defined $CurrentID) {
      $_dump_tls->{$_[0]->{_rbio}, 'id'} = $CurrentID;
    }
    goto &$orig;
  } if $DUMP;
}

warn "Listening $host:$port...\n" if $DUMP;
my $server = tcp_server $host, $port, sub {
  my ($fh, $client_host, $client_port) = @_;
  my $id = int rand 100000;
  warn "[$id] @{[time]} @{[scalar gmtime]} connected by $client_host:$client_port\n" if $DUMP;
  $cv->begin;
  my $states = {commands => [@$Commands], received => '', id => $id,
                client_host => $client_host, client_port => $client_port};

  my $hdl;
  my $on_error = $states->{on_error} = sub {
    my (undef, $fatal, $msg) = @_;
    if ($fatal) {
      warn "[$id] @{[time]} @{[scalar gmtime]} $msg (fatal)\n" if $DUMP;
      syswrite STDOUT, "[server done]\n";
      if (defined $hdl->{tls}) {
        Net::SSLeay::set_info_callback ($hdl->{tls}, undef);
        Net::SSLeay::set_verify ($hdl->{tls}, 0, undef);
      }
      $hdl->destroy;
      $cv->end;
    } else {
      warn "[$id] @{[time]} @{[scalar gmtime]} $msg\n" if $DUMP;
    }
  }; # $on_error

  $hdl = AnyEvent::Handle->new
      (fh => $fh,
       on_error => $on_error,
       on_eof => sub {
         warn "[$id] @{[time]} @{[scalar gmtime]} EOF\n" if $DUMP;
         $hdl->on_drain (sub {
           warn "[$id] @{[time]} @{[scalar gmtime]} drain\n" if $DUMP;
           syswrite STDOUT, "[server done]\n";
           if (defined $hdl->{tls}) {
             Net::SSLeay::set_info_callback ($hdl->{tls}, undef);
             Net::SSLeay::set_verify ($hdl->{tls}, 0, undef);
           }
           $hdl->destroy;
           $cv->end;
           $_[0]->on_drain (undef);
         });
       },
       on_read => sub {
         $states->{received} .= $_[0]->{rbuf};
         ($states->{dumper} || $ReceivedDumper)->($states, $_[0]->{rbuf});
         $_[0]->{rbuf} = '';
         run_commands 'read', $_[0], $states, sub { };
       });
  run_commands 'accepted', $hdl, $states, sub { };
};
syswrite STDOUT, "[server $host $port]\x0A";
warn "@{[scalar gmtime]} [server $host $port]\n" if $DUMP;

$cv->recv;
#warn "end";
