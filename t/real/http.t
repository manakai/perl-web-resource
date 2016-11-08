use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->parent->child
    ('t_deps/modules/*/lib');
use Test::X1;
use Test::More;
use Promised::Flow;
use Web::URL;
use Web::Transport::ConnectionClient;

for my $url (
  q<http://www.example.com>,
  q<http://www.yahoo.co.jp>,
  q<http://www.google.com>,
  q<http://hatenacorp.jp>,
) {
  test {
    my $c = shift;
    my $url = Web::URL->parse_string ($url);
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    promised_cleanup {
      done $c;
      undef $c;
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        ok ! $res->is_network_error;
        ok $res->status == 200 ||
           $res->status == 301 ||
           $res->status == 302, $res->status;
        ok ! $res->incomplete;
      } $c;
      return $client->close;
    });
  } n => 3, name => $url;
}

run_tests;
