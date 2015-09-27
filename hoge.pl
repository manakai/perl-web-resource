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
use Transport::SOCKS4;
use Transport::SOCKS5;

my $hostname = 'wiki.suikawiki.org';
my $port = 80;
$hostname = 'serverpl2';
$port = 5414;
my $host = "$hostname:$port";
my $target = q</n/HomePage>;
my $method = 'GET';
my $ws = 0;
my $ws_protos = [];
my $headers = [];
my $tls = undef;

#$hostname = 'localhost';
#$port = 443;
$target = q</>;
$tls = {
  sni_host_name => $ENV{SERVER_HOST_NAME} || 'localhost',
  si_host_name => $ENV{SERVER_HOST_NAME} || $hostname,
  ca_file => Test::Certificates->ca_path ('cert.pem'),

  #cipher_list => 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK', # modern

};
#$tls = undef;

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

my $s4_addr = '127.0.0.1';
my $s4_port = 80;
$s4_addr = undef;
if (defined $s4_addr) {
  $hostname = 'localhost';
  $port = 1234;
}

my $s5_hostname = $hostname;
my $s5_addr;
my $s5_port = $port;
$s5_addr = undef;
$s5_hostname = undef;
if (defined $s5_addr or defined $s5_hostname) {
  $hostname = 'localhost';
  $port = 1234;
}

my $t_tcp = Transport::TCP->new (host_name => $hostname, port => $port);
my $t_unix = Transport::UNIXDomainSocket->new (file_name => $unix);

my $transport = $t_tcp;
$transport = $t_unix if defined $unix;

if (defined $s4_addr) {
  my $t_s4 = Transport::SOCKS4->new
      (transport => $transport,
       packed_address => (defined $s4_addr ? (pack 'CCCC', split /\./, $s4_addr) : undef),
       port => $s4_port);
  $transport = $t_s4;
}

if (defined $s5_addr or defined $s5_hostname) {
  my $t_s5 = Transport::SOCKS5->new
      (transport => $transport,
       packed_address => (defined $s5_addr ? (pack 'C4', split /\./, $s5_addr) : undef),
       hostname => $s5_hostname,
       port => $s5_port);
  $transport = $t_s5;
}

if (defined $connect_host_name) {
  my $p_http = HTTP->new (transport => $transport);
  my $t_connect = Transport::H1CONNECT->new
      (http => $p_http, host_name => $connect_host_name, port => $connect_port);
  $transport = $t_connect;
}

my $t_tls = Transport::TLS->new (transport => $transport, %{$tls || {}});
$transport = $t_tls if $tls;

warn $transport->layered_type;

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
