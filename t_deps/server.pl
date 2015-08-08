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
  }
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
