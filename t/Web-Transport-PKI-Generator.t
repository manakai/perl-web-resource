use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Math::BigInt;
use Web::DateTime;
use Web::Transport::PKI::Name;
use Web::Transport::PKI::Generator;

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  my $p = $gen->create_rsa_key;
  isa_ok $p, 'Promise';

  $p->then (sub {
    my $rsa = $_[0];

    test {
      isa_ok $rsa, 'Web::Transport::PKI::RSAKey';
      like $rsa->to_pem, qr{^-----BEGIN PRIVATE KEY-----\x0D?\x0A[A-Za-z0-9/+=\x0D\x0A]+\x0D?\x0A-----END PRIVATE KEY-----\x0D?\x0A$};
    } $c;

    done $c;
    undef $c;
  });
} n => 3, name => 'create_rsa_key';

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  my $p = $gen->create_rsa_key (bits => 256);
  isa_ok $p, 'Promise';

  $p->then (sub {
    my $rsa = $_[0];

    test {
      isa_ok $rsa, 'Web::Transport::PKI::RSAKey';
      like $rsa->to_pem, qr{^-----BEGIN PRIVATE KEY-----\x0D?\x0A[A-Za-z0-9/+=\x0D\x0A]+\x0D?\x0A-----END PRIVATE KEY-----\x0D?\x0A$};
    } $c;

    done $c;
    undef $c;
  });
} n => 3, name => 'create_rsa_key bits => 256';

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  $gen->create_rsa_key->then (sub {
    my $rsa = $_[0];
    
    my $p = $gen->create_certificate (
      rsa => $rsa,
    );
    test {
      isa_ok $p, 'Promise';
    } $c;

    return $p;
  })->then (sub {
    my $cert = $_[0];

    test {
      isa_ok $cert, 'Web::Transport::PKI::Certificate';
      is $cert->version, 2, 'v3';
      is $cert->serial_number, 0;
      is $cert->not_before->to_global_date_and_time_string,
         '1970-01-01T00:00:00Z';
      is $cert->not_after->to_global_date_and_time_string,
         '1970-01-01T00:00:00Z';
      is $cert->issuer->debug_info, '';
      is $cert->subject->debug_info, '';
    } $c;

    done $c;
    undef $c;
  });
} n => 8, name => 'create_certificate default rsa';

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  $gen->create_rsa_key->then (sub {
    my $rsa = $_[0];
    
    my $p = $gen->create_certificate (
      rsa => $rsa,
      version => 0,
      serial_number => 64234444,
      not_before => 634634444,
      not_after => 76467543566,
      issuer => {CN => 'hoge.foo'},
      subject => {O => "\x{5353}\x{50000}"},
    );
    test {
      isa_ok $p, 'Promise';
    } $c;

    return $p;
  })->then (sub {
    my $cert = $_[0];

    test {
      isa_ok $cert, 'Web::Transport::PKI::Certificate';
      is $cert->version, 0, 'v1';
      is $cert->serial_number, 64234444;
      is $cert->not_before->to_unix_number, 634634444;
      is $cert->not_after->to_unix_number, 76467543566;
      is $cert->issuer->debug_info, '[CN=(P)hoge.foo]';
      is $cert->subject->debug_info, "[O=(U)\x{5353}\x{50000}]";
    } $c;

    done $c;
    undef $c;
  });
} n => 8, name => 'create_certificate primitive';

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  $gen->create_rsa_key->then (sub {
    my $rsa = $_[0];
    
    my $p = $gen->create_certificate (
      rsa => $rsa,
      version => 0,
      serial_number => Math::BigInt->from_hex ('0f642344e44'),
      not_before => Web::DateTime->new_from_unix_time (63735321144),
      not_after => Web::DateTime->new_from_unix_time (76467543566),
      issuer => Web::Transport::PKI::Name->create ({CN => 'hoge.foo'}),
      subject => Web::Transport::PKI::Name->create ({O => "\x{5353}\x{50000}"}),
    );
    test {
      isa_ok $p, 'Promise';
    } $c;

    return $p;
  })->then (sub {
    my $cert = $_[0];

    test {
      isa_ok $cert, 'Web::Transport::PKI::Certificate';
      is $cert->version, 0, 'v1';
      is $cert->serial_number, 1057672678980;
      is $cert->not_before->to_unix_number, 63735321144;
      is $cert->not_after->to_unix_number, 76467543566;
      is $cert->issuer->debug_info, '[CN=(P)hoge.foo]';
      is $cert->subject->debug_info, "[O=(U)\x{5353}\x{50000}]";
    } $c;

    done $c;
    undef $c;
  });
} n => 8, name => 'create_certificate primitive';

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  $gen->create_rsa_key->then (sub {
    my $rsa = $_[0];
    
    my $p = $gen->create_certificate;
    test {
      isa_ok $p, 'Promise';
    } $c;

    return $p;
  })->then (sub { test { ok 0 } $c }, sub {
    my $err = $_[0];

    test {
      isa_ok $err, 'Web::Transport::TypeError';
      is $err->message, 'No |rsa|';
      is $err->file_name, __FILE__;
      is $err->line_number, __LINE__-13;
    } $c;

    done $c;
    undef $c;
  });
} n => 5, name => 'create_certificate no argument';

run_tests;

=head1 LICENSE

Copyright 2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
