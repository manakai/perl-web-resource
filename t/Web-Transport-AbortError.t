use strict;
use warnings;
use Path::Class;
use lib glob file (__FILE__)->dir->parent->subdir ('t_deps/modules/*/lib')->stringify;
use lib glob file (__FILE__)->dir->parent->subdir ('t_deps/lib')->stringify;
use Test::X1;
use Test::More;
use Web::Transport::AbortError;

test {
  my $c = shift;
  ok $Web::DOM::Error::L1ObjectClass->{'Web::Transport::AbortError'};
  done $c;
} n => 1, name => 'Perl Error Object Interface Level 1';

test {
  my $c = shift;
  my $e = Web::Transport::AbortError->new;
  ok + Web::Transport::Error->is_error ($e);
  my $f = Web::Transport::Error->wrap ($e);
  is $f, $e;
  isa_ok $f, 'Web::Transport::AbortError';
  done $c;
} n => 3, name => 'is_error true';

test {
  my $c = shift;

  my $error = new Web::Transport::AbortError ('Error message');
  isa_ok $error, 'Web::Transport::AbortError';
  isa_ok $error, 'Web::Transport::Error';

  is $error->name, 'AbortError';
  is $error->message, 'Error message';
  is $error->file_name, __FILE__;
  is $error->line_number, __LINE__-7;
  is $error . '', "AbortError: Error message at ".$error->file_name." line ".$error->line_number.".\n";

  done $c;
} name => 'with message', n => 7;

test {
  my $c = shift;

  my $error = new Web::Transport::AbortError;
  is $error->name, 'AbortError';
  is $error->message, 'Aborted';
  is $error->file_name, __FILE__;
  is $error->line_number, __LINE__-4;
  is $error . '', "AbortError: Aborted at ".$error->file_name." line ".$error->line_number.".\n";
  is $error->stringify, $error . '';
  done $c;
} name => 'without message', n => 6;

test {
  my $c = shift;
  my $error1 = new Web::Transport::AbortError ('hoge');
  my $error2 = new Web::Transport::AbortError ('hoge');

  ok $error1 eq $error1;
  ok not $error1 ne $error1;
  ok not $error2 eq $error1;
  ok $error2 ne $error1;
  ok $error1 ne undef;
  ok not $error1 eq undef;
  is $error1 cmp $error1, 0;
  isnt $error1 cmp $error2, 0;
  isnt $error1 . '', $error1;

  # XXX test unitinialized warning by eq/ne/cmp-ing with undef
  
  done $c;
} name => 'eq', n => 9;

run_tests;

=head1 LICENSE

Copyright 2012-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
