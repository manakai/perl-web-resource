use strict;
use warnings;
use HTTP;

my $http = HTTP->new_from_host_and_port
    ('suikawiki.org', 80);

$http->ondata (sub {
  warn "Data: |$_[0]|";
});

$http->connect_as_cv->recv;

warn "done!";
