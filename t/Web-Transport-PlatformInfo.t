use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Web::Transport::PlatformInfo;

test {
  my $c = shift;

  my $info0 = Web::Transport::PlatformInfo->new_from_device_os_navigator
      ('desktop', 'windows', 'chrome');

  my $info = Web::Transport::PlatformInfo->new_default;
  isa_ok $info, 'Web::Transport::PlatformInfo';
  is $info->user_agent, $info0->user_agent;

  done $c;
} n => 2, name => 'new_default';

test {
  my $c = shift;

  my $info0 = Web::Transport::PlatformInfo->new_from_device_os_navigator
      ('mobile', 'android', 'chrome');

  my $info = Web::Transport::PlatformInfo->new_mobile;
  isa_ok $info, 'Web::Transport::PlatformInfo';
  is $info->user_agent, $info0->user_agent;

  done $c;
} n => 2, name => 'new_mobile';

test {
  my $c = shift;

  my $info0 = Web::Transport::PlatformInfo->new_from_device_os_navigator
      ('nonbrowser', 'linux', 'chrome');

  my $info = Web::Transport::PlatformInfo->new_nonbrowser;
  isa_ok $info, 'Web::Transport::PlatformInfo';
  is $info->user_agent, $info0->user_agent;

  done $c;
} n => 2, name => 'new_nonbrowser';

for my $test (
  [qw(desktop windows chrome)],
  [qw(desktop mac chrome)],
  [qw(desktop linux chrome)],
  [qw(tablet android chrome)],
  [qw(mobile android chrome)],
  [qw(desktop windows gecko)],
  [qw(desktop mac gecko)],
  [qw(desktop linux gecko)],
  [qw(tablet android gecko)],
  [qw(mobile android gecko)],
  [qw(desktop mac webkit)],
  [qw(tablet ios webkit)],
  [qw(mobile ios webkit)],
) {
  test {
    my $c = shift;

    my $info = Web::Transport::PlatformInfo->new_from_device_os_navigator
        (@$test[0, 1, 2]);
    isa_ok $info, 'Web::Transport::PlatformInfo';
    ok $info->user_agent;

    done $c;
  } n => 2, name => ['new_from_device_os_navigator', @$test[0, 1, 2]];
}

for my $test (
  [qw(tablet windows tasman)],
) {
  test {
    my $c = shift;

    eval {
      Web::Transport::PlatformInfo->new_from_device_os_navigator
          (@$test[0, 1, 2]);
    };
    like $@, qr{^Bad device, os, navigator combination \Q($test->[0], $test->[1], $test->[2])\E at \Q@{[__FILE__]}\E line @{[__LINE__-3]}};

    done $c;
  } n => 1, name => ['new_from_device_os_navigator', @$test[0, 1, 2]];
}

run_tests;

=head1 LICENSE

Copyright 2018-2019 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
