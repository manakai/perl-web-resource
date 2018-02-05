use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Test::HTCT::Parser;
use Web::URL;
use Web::Transport::DataURL::Parser;
use JSON::PS;

test {
  my $c = shift;

  my $url = Web::URL->parse_string (q<data:,foo>);

  my $parser = Web::Transport::DataURL::Parser->new;
  isa_ok $parser, 'Web::Transport::DataURL::Parser';

  my $data = $parser->parse_url ($url);
  isa_ok $data, 'Web::Transport::DataURL';
  is $data->mime_type->as_valid_mime_type, 'text/plain;charset=US-ASCII';
  is ${$data->body_ref}, 'foo';

  done $c;
} n => 4, name => 'new';

test {
  my $c = shift;

  my $url = Web::URL->parse_string (q<https://foo>);
  my $parser = Web::Transport::DataURL::Parser->new;
  eval {
    $parser->parse_url ($url);
  };
  like $@, qr{^Not a data: URL at \Q@{[__FILE__]}\E line @{[__LINE__-2]}};

  done $c;
} n => 1, name => 'new not data: URL';

my $TestDataPath = path (__FILE__)->parent->parent->child
    ('t_deps/tests/url/data');

for my $path ($TestDataPath->children (qr/^parse-.+\.json$/)) {
  test {
    my $c = shift;
    my $parser = Web::Transport::DataURL::Parser->new;
    for my $t (@{json_bytes2perl $path->slurp}) {

      # XXX These tests fail until we fix Web::URL.
      next if $t->[0] eq 'data://test:test/,X' or
              $t->[0] eq 'data://test:test/,X' or
               $t->[0] eq 'data:,X#X';

      my $url = Web::URL->parse_string ($t->[0]);
      my $data = $parser->parse_url ($url);
      if (defined $data) {
        test {
          is $data->mime_type->as_valid_mime_type, $t->[1], 'MIME type';
          is join (',', map { sprintf '%02X', ord $_ } split //, ${$data->body_ref}),
              join (',', map { sprintf '%02X', $_ } @{$t->[2] || []});
        } $c, name => $t->[0];
      } else {
        test {
          is undef, $t->[1], 'MIME type';
          ok 1;
        } $c, name => $t->[0];
      }
    }
    done $c;
  } name => ['parse', $path];
}

for my $path ($TestDataPath->children (qr/^data-uris.txt$/)) {
  for_each_test $path, {
    data => {},
    errors => {},
  }, sub {
    my ($test, $opts) = @_;

    test {
      my $c = shift;
      my $parser = Web::Transport::DataURL::Parser->new;
      my @error;
      $parser->onerror (sub {
        my %err = @_;
        push @error, join ';', map { $_ // '' }
            $err{level},
            $err{type},
            $err{value};
      });
      my $url = Web::URL->parse_string ($test->{data}->[0]);
      my $data = $parser->parse_url ($url);
      if (defined $data) {
        is $data->mime_type->as_valid_mime_type, $test->{mime}->[1]->[0], 'MIME type';
        is join (',', map { sprintf '%02X', ord $_ } split //, ${$data->body_ref}),
           join (',', map { sprintf '%02X', ord $_ } split //, $test->{body}->[0] // '');
      } else {
        is undef, $test->{mime}->[1]->[0], 'MIME type';
        ok 1;
      }
      is join ("\x0A", @error), $test->{errors}->[0] // '', 'errors';
      done $c;
    } n => 3, name => ['parse', $path, $opts->{line_number}, $test->{name}->[0] // $test->{data}->[0]];
  };
}

run_tests;

=head1 LICENSE

Copyright 2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
