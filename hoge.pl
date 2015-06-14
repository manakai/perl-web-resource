use strict;
use warnings;
use AnyEvent;
use HTTP;
use Data::Dumper;

my $http = HTTP->new_from_host_and_port
#    ('suikawiki.org', 80);
    ('irc.suikawiki.org', 6667);

my $cv = AE::cv;

$http->onresponsestart (sub {
  warn Dumper $_[0];
});

$http->ondata (sub {
  warn "Data[$_[0]]: |$_[1]|";
});

$http->onclose (sub {
  $cv->send;
});

$http->connect->then (sub {
  return $http->send_request ({method => 'GET', url => '/'});
})->catch (sub {
  $cv->croak ($_[0]);
});

$cv->recv;

warn "done!";
