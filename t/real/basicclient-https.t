use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->parent->child
    ('t_deps/modules/*/lib');
use Test::X1;
use Test::More;
use Promised::Flow;
use Web::URL;
use Web::Transport::BasicClient;

for my $host (qw(
www.google.com
mail.google.com
github.com
gist.github.com
gist.githubusercontent.com
httpd.apache.org
soulsphere.org
whatwg.org
dom.spec.whatwg.org
www.facebook.com
helloworld.letsencrypt.org
www.hatena.ne.jp
hatena.g.hatena.ne.jp
roomhub.jp
toolbelt.herokuapp.com
www.realtokyoestate.co.jp
www.amazon.co.jp
)) {
  my $url = qq<https://$host>;
  test {
    my $c = shift;
    my $url = Web::URL->parse_string ($url);
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    promised_cleanup {
      done $c;
      undef $c;
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        ok ! $res->is_network_error;
        ok $res->status == 200 ||
           $res->status == 301 ||
           $res->status == 302 ||
           $res->status == 303 ||
           $res->status == 307 ||
           $res->status == 308 ||
           $res->status == 404, $res->status;
        ok ! $res->incomplete;
      } $c;
      return $client->close;
    });
  } n => 3, name => $url;
}

run_tests;

=head1 LICENSE

Copyright 2016-2023 Wakaba <wakaba@suikawiki.org>.

This program is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
