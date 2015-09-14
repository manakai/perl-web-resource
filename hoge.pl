use strict;
use warnings;
use AnyEvent;
BEGIN { $ENV{WEBUA_DEBUG} //= 2 }
use HTTP;
use Data::Dumper;
use Transport::TCP;
use Transport::UNIXDomainSocket;
use Transport::TLS;
use Transport::H1CONNECT;
use Path::Tiny;
use lib path (__FILE__)->parent->child ('t_deps/lib')->stringify;
use Test::Certificates;

my $hostname = 'wiki.suikawiki.org';
my $port = 80;
#$hostname = 'localhost';
#$port = 4359;
my $host = "$hostname:$port";
my $target = q</n/HomePage>;
my $method = 'GET';
my $ws = 0;
my $ws_protos = [];
my $headers = [];
my $tls = undef;

#$hostname = 'localhost';
$port = 443;
$target = q</>;
$tls = {
  sni_host_name => 'localhost', si_host_name => 'hoge.proxy.test',
  ca_file => Test::Certificates->ca_path ('cert.pem'),
};
$tls = undef;

my $unix;

my $connect_host_name = $hostname;
my $connect_port = $port;
$connect_host_name = undef;
#$hostname = 'localhost';
#$port=5244;

push @$headers, [Host => $host];

my $http;

my $timer;
if (0) {
  $ws = 1;
  push @$headers, [Upgrade => 'websocket'], [Connection => 'Upgrade'];

  $timer = AE::timer 3, 0, sub {
    warn "close...";
    $http->close;
    undef $timer;
  };
}

my $t_tcp = Transport::TCP->new (host_name => $hostname, port => $port);
my $t_unix = Transport::UNIXDomainSocket->new (file_name => $unix);

my $transport = $t_tcp;
$transport = $t_unix if defined $unix;

if (defined $connect_host_name) {
  my $p_http = HTTP->new (transport => $transport);
  my $t_connect = Transport::H1CONNECT->new
      (http => $p_http, host_name => $connect_host_name, port => $connect_port);
  $transport = $t_connect;
}

my $t_tls = Transport::TLS->new (transport => $transport, %{$tls || {}});
$transport = $t_tls if $tls;

$http = HTTP->new (transport => $transport);

my $cv = AE::cv;

$http->onevent (sub {
  #warn $_[2], "\t", Dumper $_[3];
  if ($_[2] eq 'headers' and $_[3]) { # ws established
#    $_[0]->send_ws_message ('text', "abcde");
  }
});

$http->connect->then (sub {
  return $http->send_request_headers ({
    method => $method,
    target => $target,
    headers => $headers,
  }, ws => $ws, ws_protos => $ws_protos);
})->then (sub {
  warn "request done; close";
  return $http->close;
})->then (sub {
warn "closed";
  $cv->send;
}, sub {
warn "close aborted";
  $cv->croak (Dumper $_[0]);
});

warn "wait...";
$cv->recv;
undef $http;
undef $transport;

warn "done!";
