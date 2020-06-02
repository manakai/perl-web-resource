use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Web::Transport::DefaultCertificateManager;

test {
  my $c = shift;

  my $cm = Web::Transport::DefaultCertificateManager->new ({});
  isa_ok $cm, 'Web::Transport::DefaultCertificateManager';

  $cm->prepare->then (sub {
    my $v = $_[0];
    test {
      is $v, undef;
    } $c;
    return $cm->to_anyevent_tls_args_sync;
  })->then (sub {
    my $args = $_[0];
    test {
      my $path = delete $args->{ca_file};
      like $path->slurp, qr{-----BEGIN CERTIFICATE-----};
      is_deeply $args, {};
    } $c;
    done $c;
    undef $c;
  });
} n => 4, name => 'empty client';

test {
  my $c = shift;

  my $cm = Web::Transport::DefaultCertificateManager->new ({});
  isa_ok $cm, 'Web::Transport::DefaultCertificateManager';

  $cm->prepare (server => 1)->then (sub { test { ok 0 } $c }, sub {
    my $e = $_[0];
    test {
      isa_ok $e, 'Web::Transport::TypeError';
      is $e->name, 'TypeError';
      is $e->message, 'Bad |cert|';
      is $e->file_name, __FILE__;
      is $e->line_number, __LINE__+12;
    } $c;
    return $cm->to_anyevent_tls_args_sync;
  })->then (sub {
    my $args = $_[0];
    test {
      my $path = delete $args->{ca_file};
      like $path->slurp, qr{-----BEGIN CERTIFICATE-----};
      is_deeply $args, {};
    } $c;
    done $c;
    undef $c;
  });
} n => 8, name => 'empty server';

test {
  my $c = shift;

  my $ca_cert = rand;
  my $cert = rand;
  my $key = rand;
  my $cm = Web::Transport::DefaultCertificateManager->new ({
    ca_cert => $ca_cert,
    cert => $cert,
    key => $key,
  });
  isa_ok $cm, 'Web::Transport::DefaultCertificateManager';

  $cm->prepare (server => 1)->then (sub {
    my $v = $_[0];
    test {
      is $v, undef;
    } $c;
    return $cm->to_anyevent_tls_args_sync;
  })->then (sub {
    my $args = $_[0];
    test {
      is_deeply $args, {
        ca_cert => $ca_cert,
        cert => $cert,
        key => $key,
      };
    } $c;
    done $c;
    undef $c;
  });
} n => 3, name => 'server';

{
  package PemObj;
  sub new ($$) {
    return bless \($_[1]), $_[0];
  } # new
  sub to_pem ($) {
    return ${$_[0]};
  } # to_pem
}

test {
  my $c = shift;

  my $ca_cert = rand;
  my $cert = rand;
  my $key = rand;
  my $cm = Web::Transport::DefaultCertificateManager->new ({
    ca_cert => PemObj->new ($ca_cert),
    cert => PemObj->new ($cert),
    key => PemObj->new ($key),
  });
  isa_ok $cm, 'Web::Transport::DefaultCertificateManager';

  $cm->prepare->then (sub {
    my $v = $_[0];
    test {
      is $v, undef;
    } $c;
    return $cm->to_anyevent_tls_args_sync;
  })->then (sub {
    my $args = $_[0];
    test {
      is_deeply $args, {
        ca_cert => $ca_cert,
        cert => $cert,
        key => $key,
      };
    } $c;
    done $c;
    undef $c;
  });
} n => 3, name => 'obj';

run_tests;

=head1 LICENSE

Copyright 2018-2020 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
