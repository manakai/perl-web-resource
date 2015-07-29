use strict;
use warnings;
use Socket;
use AnyEvent;
use AnyEvent::Socket;
use AnyEvent::Handle;

my $host = shift;
my $port = shift // die "Usage: $0 listen-host listen-port\n";

my $input;
{
  local $/ = undef;
  $input = <>;
}

my $Commands = [split /\x0D?\x0A/, $input];

sub run_commands ($$$) {
  my ($context, $hdl, $states) = @_;

  while (@{$states->{commands}}) {
    my $command = shift @{$states->{commands}};
    $command =~ s/^\s+//;
    $command =~ s/\s+$//;
    if ($command =~ /^"([^"]*)"$/) {
      $hdl->push_write ($1);
    } elsif ($command =~ /^"([^"]*)"CRLF$/) {
      $hdl->push_write ("$1\x0D\x0A");
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
    } elsif ($command =~ /^receive LF$/) {
      if ($states->{received} =~ /\x0A/) {
        $states->{received} =~ s/^.*?\x0A//s;
      } else {
        unshift @{$states->{commands}}, $command;
        return;
      }
    } elsif ($command =~ /^receive "([^"]+)"$/) {
      my $x = $1;
      if ($states->{received} =~ /\Q$x\E/) {
        $states->{received} =~ s/^.*?\Q$x\E//s;
      } else {
        unshift @{$states->{commands}}, $command;
        return;
      }
    } elsif ($command =~ /^sleep ([0-9.]+)$/) {
      sleep $1;
    } elsif ($command =~ /^urgent "([^"]*)"$/) {
      send $hdl->{fh}, $1, MSG_OOB;
    } elsif ($command =~ /^close$/) {
      $hdl->push_shutdown;
    } elsif ($command =~ /^reset$/) {
      setsockopt $hdl->{fh}, SOL_SOCKET, SO_LINGER, pack "II", 1, 0;
      close $hdl->{fh};
      $hdl->push_shutdown; # let $hdl report an error
    } elsif ($command =~ /\S/) {
      die "Unknown command: |$command|";
    }
  }
} # run_commands

my $cv = AE::cv;
warn "Listening $host:$port...\n";
my $server = tcp_server $host, $port, sub {
  my ($fh, $client_host, $client_port) = @_;
  warn "... $client_host:$client_port\n";
  $cv->begin;
  my $states = {commands => [@$Commands], received => ''};
  my $hdl; $hdl = AnyEvent::Handle->new
      (fh => $fh,
       on_error => sub {
         my (undef, $fatal, $msg) = @_;
         run_commands 'error', $_[0], $states;
         AE::log error => $msg;
         $hdl->destroy if $fatal;
         $cv->end if $fatal;
       },
       on_eof => sub {
         $hdl->destroy;
         $cv->end;
       },
       on_read => sub {
         $states->{received} .= $_[0]->{rbuf};
         $_[0]->{rbuf} = '';
         run_commands 'read', $_[0], $states;
       });
  run_commands 'accepted', $hdl, $states;
};
syswrite STDOUT, "[server $host $port]\x0A";

$cv->recv;
