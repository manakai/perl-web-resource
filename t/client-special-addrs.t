use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Test::Certificates;
use Promise;
use Promised::Flow;
use AnyEvent::Util qw(run_cmd);
use Web::Transport::ConnectionClient;
use Web::Host;
use Web::URL;

test {
  my $c = shift;
  my $url = Web::URL->parse_string (qq{http://127.0.53.53/foo});
  my $client = Web::Transport::ConnectionClient->new_from_url ($url);
  return $client->request (url => $url)->then (sub {
    my $res = $_[0];
    test {
      ok $res->is_network_error, $res;
      is $res->network_error_message, 'ICANN_NAME_COLLISION';
    } $c;
  })->then (sub{
    return $client->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2;

for my $addr (qw(
  0.0.0.1 224.0.10.1 255.255.255.255
)) {
  test {
    my $c = shift;
    my $url = Web::URL->parse_string (qq{http://$addr/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error, $res;
        ok $res->network_error_message;
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  } n => 2, name => $addr;
}

run_tests;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
