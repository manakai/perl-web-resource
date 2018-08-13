use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Math::BigInt;
use Web::Transport::PKI::Generator;
use Web::Transport::PKI::Parser;

for my $version (0, 1, 2) {
  test {
    my $c = shift;

    my $gen = Web::Transport::PKI::Generator->new;
    return $gen->create_rsa_key->then (sub {
      return $gen->create_certificate (
        rsa => $_[0],
        version => $version,
      );
    })->then (sub {
      my $cert = $_[0];

      test {
        is $cert->version, $version;
        is $cert->version, $cert->version;
      } $c;

      done $c;
      undef $c;
    });
  } n => 2, name => ['version', $version];
}

for my $test (
  [0, '0'],
  [43644634444, '43644634444'],
  [Math::BigInt->from_hex ('3c46309a2cc3c4b5c3b3fba25c8a695f657'),
   '328163845315970673413616206936178536347223'],
) {
  test {
    my $c = shift;

    my $gen = Web::Transport::PKI::Generator->new;
    return $gen->create_rsa_key->then (sub {
      return $gen->create_certificate (
        rsa => $_[0],
        serial_number => $test->[0],
      );
    })->then (sub {
      my $cert = $_[0];

      test {
        isa_ok $cert->serial_number, 'Math::BigInt';
        is $cert->serial_number, $cert->serial_number;
        is '' . $cert->serial_number, $test->[1];
      } $c;

      done $c;
      undef $c;
    });
  } n => 3, name => ['serial_number', $test->[0]];
}

for my $test (
  -523526664,
  -1,
  0,
  523526664,
  1534088458,
) {
  test {
    my $c = shift;

    my $cn = rand;
    my $gen = Web::Transport::PKI::Generator->new;
    return $gen->create_rsa_key->then (sub {
      return $gen->create_certificate (
        rsa => $_[0],
        not_before => $test,
      );
    })->then (sub {
      my $cert = $_[0];

      test {
        isa_ok $cert->not_before, 'Web::DateTime';
        is $cert->not_before, $cert->not_before;
        is $cert->not_before->to_unix_number, $test;
      } $c;

      done $c;
      undef $c;
    });
  } n => 3, name => ['not_before', $test];

  test {
    my $c = shift;

    my $cn = rand;
    my $gen = Web::Transport::PKI::Generator->new;
    return $gen->create_rsa_key->then (sub {
      return $gen->create_certificate (
        rsa => $_[0],
        not_after => $test,
      );
    })->then (sub {
      my $cert = $_[0];

      test {
        isa_ok $cert->not_after, 'Web::DateTime';
        is $cert->not_after, $cert->not_after;
        is $cert->not_after->to_unix_number, $test;
      } $c;

      done $c;
      undef $c;
    });
  } n => 3, name => ['not_after', $test];
}

for my $test (
  [{CN => 'twwaf'}, '[CN=(P)twwaf]'],
) {
  for my $method ('issuer', 'subject') {
    test {
      my $c = shift;

      my $cn = rand;
      my $gen = Web::Transport::PKI::Generator->new;
      return $gen->create_rsa_key->then (sub {
        return $gen->create_certificate (
          rsa => $_[0],
          $method => $test->[0],
        );
      })->then (sub {
        my $cert = $_[0];

        test {
          isa_ok $cert->$method, 'Web::Transport::PKI::Name';
          is $cert->$method, $cert->$method;
          is $cert->$method->debug_info, $test->[1];
        } $c;

        done $c;
        undef $c;
      });
    } n => 3, name => [$method, $test->[1]];
  }
}

test {
  my $c = shift;

  my $cn = rand;
  my $gen = Web::Transport::PKI::Generator->new;
  return $gen->create_rsa_key->then (sub {
    return $gen->create_certificate (
      rsa => $_[0],
      subject => {CN => $cn},
    );
  })->then (sub {
    my $cert = $_[0];

    test {
      like $cert->to_pem, qr{^-----BEGIN CERTIFICATE-----\x0D?\x0A[A-Za-z0-9/+=\x0D\x0A]+\x0D?\x0A-----END CERTIFICATE-----\x0D?\x0A$};

      my $parser = Web::Transport::PKI::Parser->new;
      my $certs = $parser->parse_pem ($cert->to_pem);
      is $certs->[0]->subject->debug_info, "[CN=(P)$cn]";
      is $certs->[0]->to_pem, $cert->to_pem;
    } $c;

    done $c;
    undef $c;
  });
} n => 3, name => 'to_pem';

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  return $gen->create_rsa_key->then (sub {
    return $gen->create_certificate (
      rsa => $_[0],
    );
  })->then (sub {
    my $cert = $_[0];

    test {
      like $cert->debug_info, qr{^v3 .+};
    } $c;

    done $c;
    undef $c;
  });
} n => 1, name => 'debug_info';

run_tests;

=head1 LICENSE

Copyright 2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
