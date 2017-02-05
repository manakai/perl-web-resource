use strict;
use warnings;
use Web::Transport::ProxyServerConnection;
use Data::Dumper;
use Promised::Flow;
use AnyEvent::Socket;

my $host = 0;
my $port = 8522;

my $cv = AE::cv;
$cv->begin;
#$cv->end;

my $server = tcp_server $host, $port, sub {
  $cv->begin;
  my $con = Web::Transport::ProxyServerConnection->new_from_ae_tcp_server_args ([@_]);
  promised_cleanup { $cv->end } $con->completed;
};

$cv->recv;
