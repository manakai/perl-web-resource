use strict;
use warnings;
use AnyEvent;
use HTTP;

my $http = HTTP->new_from_host_and_port
    ('suikawiki.org', 80);

my $cv = AE::cv;

$http->ondata (sub {
  warn "Data: |$_[0]|";
});

$http->onclose (sub {
  $cv->send;
});

$http->connect->then (sub {
  return $http->send_request ({':method' => 'GET', ':request-target' => '/'});
})->catch (sub {
  $cv->croak ($_[0]);
});

$cv->recv;

warn "done!";
