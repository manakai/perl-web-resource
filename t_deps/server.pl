use strict;
use warnings;
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

my $commands = [split /\x0D?\x0A/, $input];
my $Received = '';

sub run_commands ($$) {
  my ($context, $hdl) = @_;

  while (@$commands) {
    my $command = shift @$commands;
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
    } elsif ($command =~ /^CRLF$/) {
      $hdl->push_write ("\x0D\x0A");
    } elsif ($command =~ /^LF$/) {
      $hdl->push_write ("\x0A");
    } elsif ($command =~ /^CR$/) {
      $hdl->push_write ("\x0D");
    } elsif ($command =~ /^receive LF$/) {
      if ($Received =~ /\x0A/) {
        $Received =~ s/^.*?\x0A//s;
      } else {
        unshift @$commands, $command;
        return;
      }
    } elsif ($command =~ /^sleep ([0-9.]+)$/) {
      sleep $1;
    } elsif ($command =~ /^close$/) {
      $hdl->push_shutdown;
    } elsif ($command =~ /\S/) {
      die "Unknown command: |$command|";
    }
  }
} # run_commands

my $cv = AE::cv;
warn "Listening $host:$port...\n";
my $server = tcp_server $host, $port, sub {
  my ($fh, $client_host, $client_port) = @_;
  my $hdl; $hdl = AnyEvent::Handle->new
      (fh => $fh,
       on_error => sub {
         my (undef, $fatal, $msg) = @_;
         run_commands 'error', $_[0];
         AE::log error => $msg;
         $hdl->destroy if $fatal;
         $cv->send if $fatal;
       },
       on_eof => sub {
         $hdl->destroy;
         $cv->send;
       },
       on_read => sub {
         $Received .= $_[0]->{rbuf};
         $_[0]->{rbuf} = '';
         run_commands 'read', $_[0];
       });
  run_commands 'accepted', $hdl;
};
syswrite STDOUT, "[server $host $port]\x0A";

$cv->recv;
