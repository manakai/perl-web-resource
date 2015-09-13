use strict;
use warnings;
use AnyEvent;
BEGIN { $ENV{WEBUA_DEBUG} //= 2 }
use HTTP;
use Data::Dumper;

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

$hostname = 'localhost';
$port = 443;
$target = q</>;
#$tls = {};

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

$http = HTTP->new_from_host_and_port
    ($hostname, $port);

my $cv = AE::cv;

$http->onevent (sub {
  #warn $_[2], "\t", Dumper $_[3];
  if ($_[2] eq 'headers' and $_[3]) { # ws established
#    $_[0]->send_ws_message ('text', "abcde");
  }
});

$http->connect (tls => $tls)->then (sub {
  return $http->send_request_headers ({
    method => $method,
    target => $target,
    headers => $headers,
  }, ws => $ws, ws_protos => $ws_protos);
})->then (sub {
  warn "request done; close";
  return $http->close;
})->then (sub {
  $cv->send;
}, sub {
  $cv->croak ($_[0]);
});

warn "wait...";
$cv->recv;
undef $http;

warn "done!";
