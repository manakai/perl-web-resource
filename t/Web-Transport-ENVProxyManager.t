use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Web::URL;
use Web::Transport::ENVProxyManager;

for (
  [{}, undef, q<http://hoge/>, [{protocol => 'tcp'}]],
  [{}, {}, q<http://hoge/>, [{protocol => 'tcp'}]],
  [{http_proxy => q<foo>}, undef, q<http://hoge/>,
   [{protocol => 'http', host => 'foo', port => undef,
     username => '', password => undef}]],
  [{http_proxy => q<foo:0324>}, undef, q<http://hoge/>,
   [{protocol => 'http', host => 'foo', port => 324,
     username => '', password => undef}]],
  [{http_proxy => q<foo:bar@hoge>}, undef, q<http://hoge/>,
   [{protocol => 'http', host => 'hoge', port => undef,
     username => 'foo', password => 'bar'}]],
  [{http_proxy => q<https://%41foo>}, undef, q<http://hoge/>,
   [{protocol => 'https', host => 'afoo', port => undef,
     username => '', password => undef}]],
  [{http_proxy => q<SOCKS4://SOCKSSERVER>}, undef, q<http://hoge/>,
   [{protocol => 'socks4', host => 'socksserver', port => undef}]],
  [{http_proxy => q<SOCKS4://SOCKSSERVER>},
   {http_proxy => q<http://foo>}, q<http://hoge/>,
   [{protocol => 'http', host => 'foo', port => undef,
     username => '', password => undef}]],
  [{socks_proxy => q<SOCKS4://SOCKSSERVER>}, undef, q<http://hoge/>,
   [{protocol => 'tcp'}]],
  [{http_proxy => q<foo>}, undef, q<https://hoge/>,
   [{protocol => 'tcp'}]],
  [{https_proxy => q<foo>}, undef, q<https://hoge/>,
   [{protocol => 'http', host => 'foo', port => undef,
     username => '', password => undef}]],
  [{ftp_proxy => q<foo>}, undef, q<ftp://hoge/>,
   [{protocol => 'http', host => 'foo', port => undef,
     username => '', password => undef}]],
  [{http_proxy => q<foo>, no_proxy => ',abc,42'}, undef, q<http://abc/>,
   [{protocol => 'tcp'}]],
  [{http_proxy => q<foo>, no_proxy => q<127.0.0.1>}, undef,
   q<http://localhost/>,
   [{protocol => 'http', host => 'foo', port => undef,
     username => '', password => undef}]],
) {
  my ($Envs, $envs, $url, $expected) = @$_;
  test {
    my $c = shift;
    local %ENV = %$Envs;
    my $pm = defined $envs ? Web::Transport::ENVProxyManager->new_from_envs ($envs) : Web::Transport::ENVProxyManager->new;
    my $result = $pm->get_proxies_for_url (Web::URL->parse_string ($url));
    isa_ok $result, 'Promise';
    $result->then (sub {
      my $proxies = $_[0];
      test {
        for (@$proxies) {
          $_->{host} = $_->{host}->stringify if defined $_->{host};
        }
        is_deeply $proxies, $expected;
        done $c;
        undef $c;
      } $c;
    }, sub {
      test {
        ok 0;
      } $c;
    });
  } n => 2, name => $url;
}

run_tests;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
