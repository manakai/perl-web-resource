use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Web::Transport::PKI::Name;

for my $test (
  [undef, ''],
  [{}, ''],
  [{CN => 'hoge.test'}, '[CN=(P)hoge.test]'],
  [{CN => 'hoge.test', C => 'JP'}, '[C=(P)JP],[CN=(P)hoge.test]'],
  [{CN => 'hoge', commonName => 'foo', '2.5.4.3' => 'baz'},
   '[CN=(P)baz],[CN=(P)hoge],[CN=(P)foo]'],
  [{CN => 'x', OU => 'f', O => 'g', L => 'ff', ST => 'b', C => 'z',
    emailAddress => 'abc@foo.baz'},
   '[C=(P)z],[ST=(P)b],[L=(P)ff],[O=(P)g],[OU=(P)f],[CN=(P)x],[emailAddress=(U)abc@foo.baz]'],
  [{CN => "\xFE.a"}, "[CN=(U)\x{FE}.a]"],
  [{CN => "\x{4e00}.a"}, "[CN=(U)\x{4E00}.a]"],
  [{C => '', CN => undef}, '[C=(P)]'],
  [Web::Transport::PKI::Name->create ({CN => 12}), '[CN=(P)12]'],
) {
  test {
    my $c = shift;

    my $name = Web::Transport::PKI::Name->create ($test->[0]);
    isa_ok $name, 'Web::Transport::PKI::Name';
    is $name->debug_info, $test->[1];

    done $c;
  } n => 2, name => $test->[1];
}

test {
  my $c = shift;

  my $name1 = Web::Transport::PKI::Name->create ({CN => rand});
  my $name2 = Web::Transport::PKI::Name->create ($name1);
  is $name1, $name2;
  
  done $c;
} n => 1, name => 'name';

for my $test (
  32444,
  "abc",
  [],
  sub { },
) {
  test {
    my $c = shift;

    eval {
      Web::Transport::PKI::Name->create ($test);
    };
    isa_ok $@, 'Web::Transport::TypeError';
    is $@->message, 'Bad argument';
    is $@->file_name, __FILE__;
    is $@->line_number, __LINE__-5;

    done $c;
  } n => 4, name => $test;
}

run_tests;

=head1 LICENSE

Copyright 2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
