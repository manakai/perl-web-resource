use strict;
use warnings;
use AnyEvent::Socket;
use Web::Transport::HTTPServerConnection;

my $host = 0;
my $port = 8522;

$Web::Transport::HTTPServerConnection::ReadTimeout = $ENV{SERVER_READ_TIMEOUT}
    if $ENV{SERVER_READ_TIMEOUT};

my $cb = sub {
  my $self = $_[0];
  my $type = $_[1];
  if ($type eq 'open') {
    my $data = $_[2];
    warn "> Connection opened (Client: $data->{client_ip_addr}:$data->{client_port})\n";
  } elsif ($type eq 'close') {
    warn "> Connection closed\n";
  } else {
    warn "> $type\n";
  }
}; # $cb

my $server = tcp_server $host, $port, sub {
  Web::Transport::HTTPServerConnection->new_from_fh_and_host_and_port_and_cb
      ($_[0], $_[1], $_[2], $cb);
};

AE::cv->recv;
