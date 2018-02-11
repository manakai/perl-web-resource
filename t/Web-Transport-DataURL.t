use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Web::MIME::Type;
use Web::Transport::DataURL;

test {
  my $c = shift;

  my $mime = Web::MIME::Type->new_from_type_and_subtype ('a', 'b');

  my $body = "abc";

  my $data = Web::Transport::DataURL->new_from_mime_and_scalarref
      ($mime, \$body);
  isa_ok $data, 'Web::Transport::DataURL';
  is $data->mime_type, $mime;
  is $data->body_ref, \$body;

  done $c;
} n => 3, name => 'new';

test {
  my $c = shift;

  my $mime = Web::MIME::Type->new_from_type_and_subtype ('a', 'b');

  my $body = substr "abc\x{100}", 0, 3;

  eval {
    Web::Transport::DataURL->new_from_mime_and_scalarref
      ($mime, \$body);
  };
  like $@, qr{^Body is utf8-flagged at \Q@{[__FILE__]}\E line @{[__LINE__-3]}};

  done $c;
} n => 1, name => 'new utf8-flagged';

test {
  my $c = shift;

  my $mime = Web::MIME::Type->new_from_type_and_subtype ('a', 'b');

  eval {
    Web::Transport::DataURL->new_from_mime_and_scalarref
      ($mime, undef);
  };
  like $@, qr{^Body is not a scalar reference at \Q@{[__FILE__]}\E line @{[__LINE__-3]}};

  done $c;
} n => 1, name => 'new undef';

test {
  my $c = shift;

  my $mime = Web::MIME::Type->new_from_type_and_subtype ('a', 'b');

  eval {
    Web::Transport::DataURL->new_from_mime_and_scalarref
      ($mime, []);
  };
  like $@, qr{^Body is not a scalar reference at \Q@{[__FILE__]}\E line @{[__LINE__-3]}};

  done $c;
} n => 1, name => 'new []';

test {
  my $c = shift;

  my $mime = Web::MIME::Type->new_from_type_and_subtype ('a', 'b');

  eval {
    Web::Transport::DataURL->new_from_mime_and_scalarref
      ($mime, "abcde");
  };
  like $@, qr{^Body is not a scalar reference at \Q@{[__FILE__]}\E line @{[__LINE__-3]}};

  done $c;
} n => 1, name => 'new not ref';

run_tests;

=head1 LICENSE

Copyright 2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
