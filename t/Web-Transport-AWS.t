use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Web::URL;
use Web::Transport::AWS;

test {
  my $c = shift;
  my $result = Web::Transport::AWS->aws4_post_policy
      (clock => sub { time },
       access_key_id => "aeaea4444a3aa535",
       secret_access_key => "346634gae44444",
       service => "foo",
       region => "ab-ce-453",
       max_age => 5353,
       policy_conditions => [
         {foo => 1333},
         [abc => 43 => 55],
       ]);

  ok $result->{policy};
  ok $result->{"X-Amz-Signature"};
  ok $result->{"X-Amz-Credential"};
  is $result->{"X-Amz-Algorithm"}, "AWS4-HMAC-SHA256";
  ok ! $result->{"X-Amz-Security-Token"};
  like $result->{"X-Amz-Date"}, qr/\A[0-9]{4,}[0-9]{2}[0-9]{2}T[0-9]{6}Z\z/;
  
  done $c;
} n => 6, name => 'aws4_post_policy';

test {
  my $c = shift;
  my $token = "tarsegegeawg aw3t ag";
  my $result = Web::Transport::AWS->aws4_post_policy
      (clock => sub { time },
       access_key_id => "aeaea4444a3aa535",
       secret_access_key => "346634gae44444",
       security_token => $token,
       service => "foo",
       region => "ab-ce-453",
       max_age => 5353,
       policy_conditions => [
         {foo => 1333},
         [abc => 43 => 55],
       ]);

  ok $result->{policy};
  ok $result->{"X-Amz-Signature"};
  ok $result->{"X-Amz-Credential"};
  is $result->{"X-Amz-Algorithm"}, "AWS4-HMAC-SHA256";
  is $result->{"X-Amz-Security-Token"}, $token;
  like $result->{"X-Amz-Date"}, qr/\A[0-9]{4,}[0-9]{2}[0-9]{2}T[0-9]{6}Z\z/;
  
  done $c;
} n => 6, name => 'aws4_post_policy with token';

test {
  my $c = shift;

  my $url1 = Web::URL->parse_string
      ("https://foo.bar.test:436/ba/%FA5%30.aa?abc=xyy&aaa=geeee");
  my $url2 = Web::Transport::AWS->aws4_signed_url
      (clock => sub { time },
       max_age => 120,
       access_key_id => 'abcde',
       secret_access_key => 'eageeee',
       security_token => 'token',
       region => 'tweeeee',
       service => 's3',
       method => 'GET',
       url => $url1);

  like $url2->stringify, qr{^https://foo.bar.test:436/ba/%FA50.aa\?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=.+&X-Amz-Date=.+&X-Amz-Expires=120&X-Amz-SignedHeaders=host&aaa=geeee&abc=xyy&X-Amz-Signature=.+$};

  done $c;
} n => 1, name => 'aws_singed_url';

test {
  my $c = shift;

  my $url1 = Web::URL->parse_string
      ("https://abc.xx.test/ba/%FA5%30.aa?abc=xyy&aaa=geeee");
  my $url2 = Web::Transport::AWS->aws4_signed_url
      (clock => sub { time },
       max_age => 120,
       access_key_id => 'abcde',
       secret_access_key => 'eageeee',
       security_token => 'token',
       region => 'tweeeee',
       service => 's3',
       method => 'GET',
       signed_hostport => 'foo.bar.test:436',
       url => $url1);

  like $url2->stringify, qr{^https://abc.xx.test/ba/%FA50.aa\?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=.+&X-Amz-Date=.+&X-Amz-Expires=120&X-Amz-SignedHeaders=host&aaa=geeee&abc=xyy&X-Amz-Signature=.+$};

  done $c;
} n => 1, name => 'aws_singed_url with signed_hostport';

run_tests;

=head1 LICENSE

Copyright 2017-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
