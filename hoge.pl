use strict;
use warnings;
use AnyEvent;
use HTTP;
use Data::Dumper;

my $hostname = 'wiki.suikawiki.org';
my $port = 80;
my $host = "$hostname:$port";
my $target = q</n/HomePage>;

my $http = HTTP->new_from_host_and_port
    ($hostname, $port);

my $cv = AE::cv;

$http->onevent (sub {
  #warn $_[2], "\t", Dumper $_[3];
});

$http->connect->then (sub {
  $http->send_request ({
    method => 'GET',
    target => $target,
    headers => [
      [Host => $host],
    ],
  });
  return $http->close;
})->then (sub {
  $cv->send;
}, sub {
  $cv->croak ($_[0]);
});

$cv->recv;

warn "done!";
