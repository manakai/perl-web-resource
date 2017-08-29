use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Web::Transport::RequestConstructor;

test {
  my $c = shift;
  my ($list, $map) = Web::Transport::RequestConstructor->create_header_list (undef);
  is 0+@$list, 0;
  is 0+keys %$map, 0;
  done $c;
} n => 2, name => 'undef';

test {
  my $c = shift;
  eval {
    Web::Transport::RequestConstructor->create_header_list (0);
  };
  is $@->name, 'TypeError', $@;
  is $@->message, 'Bad headers';
  is $@->file_name, __FILE__;
  is $@->line_number, __LINE__-5;
  done $c;
} n => 4, name => 'bad argument';

test {
  my $c = shift;
  my ($list, $map) = Web::Transport::RequestConstructor->create_header_list ({
    Hoge => "ab c",
    Foo => "\x{444}",
    "a-bc" => "",
  });
  is 0+@$list, 3;
  $list = [sort { $a->[2] cmp $b->[2] } @$list];
  is $list->[0]->[0], 'a-bc';
  is $list->[0]->[1], '';
  is $list->[0]->[2], 'a-bc';
  is $list->[1]->[0], 'Foo';
  is $list->[1]->[1], "\xD1\x84";
  is $list->[1]->[2], 'foo';
  is $list->[2]->[0], 'Hoge';
  is $list->[2]->[1], 'ab c';
  is $list->[2]->[2], 'hoge';
  is 0+keys %$map, 3;
  ok $map->{hoge};
  ok $map->{foo};
  ok $map->{"a-bc"};
  done $c;
} n => 14, name => 'hashref';

test {
  my $c = shift;
  my ($list, $map) = Web::Transport::RequestConstructor->create_header_list ({
    Hoge => [],
    Foo => ["ab", " "],
    bar => undef,
  });
  is 0+@$list, 2;
  $list = [sort { $a->[2] cmp $b->[2] } @$list];
  is $list->[0]->[0], 'Foo';
  is $list->[0]->[1], 'ab';
  is $list->[0]->[2], 'foo';
  is $list->[1]->[0], 'Foo';
  is $list->[1]->[1], " ";
  is $list->[1]->[2], 'foo';
  is 0+keys %$map, 1;
  ok $map->{foo};
  ok ! $map->{hoge};
  ok ! $map->{bar};
  done $c;
} n => 11, name => 'hashref arrayref';

test {
  my $c = shift;
  my ($list, $map) = Web::Transport::RequestConstructor->create_header_list ([
    [Hoge => "ab c"],
    [Foo => "\x{444}"],
    ["a-bc" => ""],
    ["a-bc" => "0"],
  ]);
  is 0+@$list, 4;
  is $list->[0]->[0], 'Hoge';
  is $list->[0]->[1], 'ab c';
  is $list->[0]->[2], 'hoge';
  is $list->[1]->[0], 'Foo';
  is $list->[1]->[1], "\xD1\x84";
  is $list->[1]->[2], 'foo';
  is $list->[2]->[0], 'a-bc';
  is $list->[2]->[1], '';
  is $list->[2]->[2], 'a-bc';
  is $list->[3]->[0], 'a-bc';
  is $list->[3]->[1], '0';
  is $list->[3]->[2], 'a-bc';
  is 0+keys %$map, 3;
  ok $map->{hoge};
  ok $map->{foo};
  ok $map->{"a-bc"};
  done $c;
} n => 17, name => 'arrayref';

test {
  my $c = shift;
  my ($list, $map) = Web::Transport::RequestConstructor->create_header_list ([
    [Hoge => "ab c", "foo"],
    [Foo => "\x{444}"],
    ["a-bc" => "", 123],
    ["a-bc" => "0", "A-BC"],
  ]);
  is 0+@$list, 4;
  is $list->[0]->[0], 'Hoge';
  is $list->[0]->[1], 'ab c';
  is $list->[0]->[2], 'hoge';
  is $list->[1]->[0], 'Foo';
  is $list->[1]->[1], "\xD1\x84";
  is $list->[1]->[2], 'foo';
  is $list->[2]->[0], 'a-bc';
  is $list->[2]->[1], '';
  is $list->[2]->[2], 'a-bc';
  is $list->[3]->[0], 'a-bc';
  is $list->[3]->[1], '0';
  is $list->[3]->[2], 'a-bc';
  is 0+keys %$map, 3;
  ok $map->{hoge};
  ok $map->{foo};
  ok $map->{"a-bc"};
  done $c;
} n => 17, name => 'arrayref';

test {
  my $c = shift;
  eval {
    Web::Transport::RequestConstructor->create_header_list ([["a", "b"], 5]);
  };
  is $@->name, 'TypeError', $@;
  is $@->message, 'Bad headers';
  is $@->file_name, __FILE__;
  is $@->line_number, __LINE__-5;
  done $c;
} n => 4, name => 'bad arrayref';

run_tests;

=head1 LICENSE

Copyright 2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
