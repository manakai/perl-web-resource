use strict;
use warnings;
use Socket;
use AnyEvent;
use AnyEvent::Socket;
use AnyEvent::Handle;
use Digest::SHA qw(sha1);
use MIME::Base64 qw(encode_base64);

my $host = shift;
my $port = shift // die "Usage: $0 listen-host listen-port\n";

my $input;
{
  local $/ = undef;
  $input = <>;
}

my $Commands = [split /\x0D?\x0A/, $input];

sub run_commands ($$$$);
sub run_commands ($$$$) {
  my ($context, $hdl, $states, $then) = @_;

  while (@{$states->{commands}}) {
    my $command = shift @{$states->{commands}};
    $command =~ s/^\s+//;
    $command =~ s/\s+$//;
    if ($command =~ /^"([^"]*)"$/) {
      $hdl->push_write ($1);
    } elsif ($command =~ /^"([^"]*)"CRLF$/) {
      $hdl->push_write ("$1\x0D\x0A");
      #AE::log error => "Sent $1 CR LF";
    } elsif ($command =~ /^"([^"]*)"LF$/) {
      $hdl->push_write ("$1\x0A");
    } elsif ($command =~ /^"([^"]*)"CR$/) {
      $hdl->push_write ("$1\x0D");
    } elsif ($command =~ /^"([^"]*)"\s+x\s+([0-9]+)$/) {
      $hdl->push_write ($1 x $2);
    } elsif ($command =~ /^CRLF$/) {
      $hdl->push_write ("\x0D\x0A");
    } elsif ($command =~ /^LF$/) {
      $hdl->push_write ("\x0A");
    } elsif ($command =~ /^CR$/) {
      $hdl->push_write ("\x0D");
    } elsif ($command =~ /^0x([0-9A-Fa-f]{2})$/) {
      $hdl->push_write (pack 'C', hex $1);
    } elsif ($command =~ /^client$/) {
      $hdl->push_write ($states->{client_host} . ':' . $states->{client_port});
    } elsif ($command =~ /^ws-accept$/) {
      $states->{captured} =~ /^Sec-WebSocket-Key:\s*(\S+)\s*$/im;
      my $key = $1 // '';
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
        if ($length == 0xFE) {
          if ($states->{received} =~ s/^..(.)(.)//s) {
            $length = (ord $1) * 0x100 + ord $2;
          } else {
            undef $length;
          }
        } elsif ($length == 0xFF) {
          if ($states->{received} =~ s/^..(.)(.)(.)(.)//s) {
            if (0x80 & ord $1) {
              undef $length;
            } else {
              $length = (ord $1) * 0x1_00_00_00 + (ord $2) * 0x1_00_00 + (ord $3) * 0x100 + ord $4;
            }
          } else {
            undef $length;
          }
        } else {
          $states->{received} =~ s/^..//s;
        }
        my $mask = undef;
        if ($has_mask) {
          if ($states->{received} =~ s/^(....)//s) {
            $mask = $1;
          } else {
            undef $length;
          }
        }
        if (defined $length) {
          AE::log error => qq{WS FIN=%d RSV1=%d RSV2=%d RSV3=%d opcode=0x%X masking=%d length=%d mask=0x%02X%02X%02X%02X},
              $fin, $rsv1, $rsv2, $rsv3, $opcode, $has_mask, $length,
              (ord substr $mask, 0, 1),
              (ord substr $mask, 1, 1),
              (ord substr $mask, 2, 1),
              (ord substr $mask, 3, 1);
          $states->{ws_length} = $length;
          $states->{ws_mask} = $mask;
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
        AE::log error => join '', @data;
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
      if ($fields->{length} < 0xFE) {
        $hdl->push_write (pack 'C', $fields->{length});
      } elsif ($fields->{length} < 0x10000) {
        $hdl->push_write ("\xFE");
        $hdl->push_write (pack 'n', $fields->{length});
      } else {
        $hdl->push_write ("\xFF");
        $hdl->push_write (pack 'Q>', $fields->{length});
      }
      if ($fields->{masking}) {
        # XXX

      }
    } elsif ($command =~ /^close$/) {
      $hdl->push_shutdown;
    } elsif ($command =~ /^close read$/) {
      shutdown $hdl->{fh}, 0;
    } elsif ($command =~ /^reset$/) {
      setsockopt $hdl->{fh}, SOL_SOCKET, SO_LINGER, pack "II", 1, 0;
      close $hdl->{fh};
      $hdl->push_shutdown; # let $hdl report an error
    } elsif ($command =~ /^showreceivedlength$/) {
      AE::log error => qq{[$states->{id}] length of rbuf = @{[length $states->{received}]}};
    } elsif ($command =~ /^showcaptured$/) {
      AE::log error => qq{[$states->{id}] captured = |$states->{captured}|};
    } elsif ($command =~ /\S/) {
      die "Unknown command: |$command|";
    }
  } # while
  $then->();
} # run_commands

my $cv = AE::cv;
$cv->begin;
my $sig = AE::signal TERM => sub { $cv->end };

warn "Listening $host:$port...\n";
my $server = tcp_server $host, $port, sub {
  my ($fh, $client_host, $client_port) = @_;
  my $id = int rand 100000;
  warn "... $client_host:$client_port [$id]\n";
  $cv->begin;
  my $states = {commands => [@$Commands], received => '', id => $id,
                client_host => $client_host, client_port => $client_port};
  my $hdl; $hdl = AnyEvent::Handle->new
      (fh => $fh,
       on_error => sub {
         my (undef, $fatal, $msg) = @_;
         if ($fatal) {
           AE::log error => "[$id] $msg (fatal)";
           $hdl->destroy;
           $cv->end;
         } else {
           AE::log error => "[$id] $msg";
         }
       },
       on_eof => sub {
         warn "[$id] EOF\n";
         $hdl->destroy;
         $cv->end;
       },
       on_read => sub {
         $states->{received} .= $_[0]->{rbuf};
         #warn "[$id] $_[0]->{rbuf}\n";
         $_[0]->{rbuf} = '';
         run_commands 'read', $_[0], $states, sub { };
       });
  run_commands 'accepted', $hdl, $states, sub { };
};
syswrite STDOUT, "[server $host $port]\x0A";

$cv->recv;

__END__

echo -e 'receive "GET", start capture\nreceive CRLFCRLF, end capture
showcaptured\n"HTTP/1.0 101 OK"CRLF\n"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "\nws-accept\nCRLF\n"Connection: Upgrade"CRLF
CRLF\nws-receive-header\nws-receive-data\nws-send-header opcode=1 length=3
"abc"' | ./perl t_deps/server.pl 0 4355
