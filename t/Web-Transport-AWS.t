use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
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
  like $result->{"X-Amz-Date"}, qr/\A[0-9]{4,}[0-9]{2}[0-9]{2}T[0-9]{6}Z\z/;
  
  done $c;
} n => 5, name => 'aws4_post_policy';

run_tests;

=head1 LICENSE

Copyright 2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
