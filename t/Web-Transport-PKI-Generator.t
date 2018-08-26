use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Math::BigInt;
use Web::DateTime;
use Web::Host;
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

for my $test (
  {in => {}, out => {}},
  {in => {ca => 1}, out => {ca => !!1,
                            digitalSignature  => !!1,
                            nonRepudiation    => !!0,
                            keyEncipherment   => !!0,
                            dataEncipherment  => !!0,
                            keyAgreement      => !!0,
                            keyCertSign       => !!1,
                            cRLSign           => !!1,
                            encipherOnly      => !!0,
                            decipherOnly      => !!0,
                            serverAuth => !!1, clientAuth => !!1,
                            SKI => 1}, name => 'ca'},
  {in => {ee => 1}, out => {ca => !!0,
                            digitalSignature  => !!1,
                            nonRepudiation    => !!0,
                            keyEncipherment   => !!1,
                            dataEncipherment  => !!0,
                            keyAgreement      => !!0,
                            keyCertSign       => !!0,
                            cRLSign           => !!0,
                            encipherOnly      => !!0,
                            decipherOnly      => !!0,
                            serverAuth => !!1, clientAuth => !!1,
                            SKI => 1}, name => 'ee'},
  {in => {ca => 1, path_len_constraint => 3},
   out => {ca => !!1,
           digitalSignature  => !!1,
           nonRepudiation    => !!0,
           keyEncipherment   => !!0,
           dataEncipherment  => !!0,
           keyAgreement      => !!0,
           keyCertSign       => !!1,
           cRLSign           => !!1,
           encipherOnly      => !!0,
           decipherOnly      => !!0,
           serverAuth => !!1, clientAuth => !!1,
           SKI => 1, path_len_constraint => 3},
   name => 'ca + pathLenConstraint'},
  {in => {crl_urls => ['http://www.test/1']},
   out => {crl_urls => ['http://www.test/1']}, name => 'crl 1'},
  {in => {crl_urls => ['http://www.test/1', 'FTP://ab/cd']},
   out => {crl_urls => ['http://www.test/1', 'FTP://ab/cd']}, name => 'crl 2'},
  {in => {crl_urls => ["http://www.test/\x{4e00}"]},
   out => {crl_urls => ["http://www.test/\x{4e00}"]}, name => 'crl utf8'},
  {in => {crl_urls => ['http://www.test/1,2']},
   out => {crl_urls => ['http://www.test/1,2']}, name => 'crl comma'},
  {in => {crl_urls => ['1' x 127]},
   out => {crl_urls => ['1' x 127]}, name => 'crl 127'},
  {in => {crl_urls => ['1' x 128]},
   out => {crl_urls => ['1' x 128]}, name => 'crl 128'},
  {in => {crl_urls => ['1' x 256]},
   out => {crl_urls => ['1' x 256]}, name => 'crl 256'},
  {in => {crl_urls => ['1' x 1024]},
   out => {crl_urls => ['1' x 1024]}, name => 'crl 1024'},
  {in => {crl_urls => ["http://www.test/\x00a"]},
   out => {crl_urls => ["http://www.test/\x00a"]}, name => 'crl null'},
  {in => {ca => 1, root_ca => 1, path_len_constraint => 3},
   out => {ca => !!1,
           digitalSignature  => !!1,
           nonRepudiation    => !!0,
           keyEncipherment   => !!0,
           dataEncipherment  => !!0,
           keyAgreement      => !!0,
           keyCertSign       => !!1,
           cRLSign           => !!1,
           encipherOnly      => !!0,
           decipherOnly      => !!0,
           SKI => 1, path_len_constraint => 3},
   name => 'root_ca'},
  {in => {aia_ocsp_url => "http://www.test/\x00a"},
   out => {aia_ocsp_url => "http://www.test/\x00a"}, name => 'ocsp null'},
  {in => {aia_ocsp_url => "http://www.test/,,a"},
   out => {aia_ocsp_url => "http://www.test/,,a"}, name => 'ocsp comma'},
  {in => {aia_ocsp_url => "http://www.test/\x{4e00}a"},
   out => {aia_ocsp_url => "http://www.test/\x{4e00}a"}, name => 'ocsp utf8'},
  {in => {aia_ca_issuers_url => "http://www.test/\x00a"},
   out => {aia_ca_issuers_url => "http://www.test/\x00a"},
   name => 'ca_issuers null'},
  {in => {aia_ca_issuers_url => "http://www.test/,,a"},
   out => {aia_ca_issuers_url => "http://www.test/,,a"},
   name => 'ca_issuers comma'},
  {in => {aia_ca_issuers_url => "http://www.test/\x{4e00}a"},
   out => {aia_ca_issuers_url => "http://www.test/\x{4e00}a"},
   name => 'ca_issuers utf8'},
  {in => {aia_ca_issuers_url => "http://www.test/\x{4e00}a",
          aia_ocsp_url => "http://abc/def\x{55000}"},
   out => {aia_ca_issuers_url => "http://www.test/\x{4e00}a",
           aia_ocsp_url => "http://abc/def\x{55000}"},
   name => 'ca_issuers and ocsp'},
  {in => {dv => 1}, out => {cp_oids => ['2.23.140.1.2.1']}, name => 'cp oids'},
  {in => {ov => 1}, out => {cp_oids => ['2.23.140.1.2.2']}, name => 'cp oids'},
  {in => {dv => 1, ov => 1},
   out => {cp_oids => ['2.23.140.1.2.1', '2.23.140.1.2.2']}, name => 'cp oids'},
  {in => {ev => '1.2.392.200081.1.1'},
   out => {cp_oids => ['1.2.392.200081.1.1', '2.23.140.1.1']}, name => 'cp oids'},
  {in => {dv => 1, policy_oids => ['1.2.392.200081.1.1']},
   out => {cp_oids => ['1.2.392.200081.1.1', '2.23.140.1.2.1']}, name => 'cp oids'},
  {in => {cps_url => "https://foo/,\x00ab"},
   out => {cp_oids => ['2.5.29.32.0'],
           cps_url => "https://foo/,\x00ab"}, name => 'cp qualifeirs'},
  {in => {cps_url => "https://foo/,\x{4e00}ab"},
   out => {cp_oids => ['2.5.29.32.0'],
           cps_url => "https://foo/,\x{4e00}ab"}, name => 'cp qualifeirs'},
  {in => {policy_user_notice_text => "https://foo/,\x{4e00}ab"},
   out => {cp_oids => ['2.5.29.32.0'],
           policy_user_notice_text => "https://foo/,\x{4e00}ab"}, name => 'cp qualifeirs'},
  {in => {cps_url => "https://foo/,\x{4e00}ab",
          policy_user_notice_text => "https://foo/,\x{4e00}ab"},
   out => {cp_oids => ['2.5.29.32.0'],
           cps_url => "https://foo/,\x{4e00}ab",
           policy_user_notice_text => "https://foo/,\x{4e00}ab"}, name => 'cp qualifeirs'},
  {in => {ov => 1,
          cps_url => "https://foo/,\x{4e00}ab",
          policy_user_notice_text => "https://foo/,\x{4e00}ab"},
   out => {cp_oids => ['2.23.140.1.2.2'],
           cps_url => "https://foo/,\x{4e00}ab",
           policy_user_notice_text => "https://foo/,\x{4e00}ab"}, name => 'cp qualifeirs'},
  {in => {san_hosts => ["foo.bar,\x00\x{4e00}ab"]},
   out => {san_hosts => ["foo.bar,\x00\x{4e00}ab"]}, name => 'san domain'},
  {in => {san_hosts => ["*.foo.bar", "abc.def."]},
   out => {san_hosts => ["*.foo.bar", "abc.def."]}, name => 'san domain'},
  {in => {san_hosts => ["*.foo.bar", "5.5.3.1",
                        Web::Host->parse_string ("1.2.3.4"),
                        Web::Host->parse_string ("[2001::4]"),
                        Web::Host->parse_string ("*.\x{4e00}abc.test")]},
   out => {san_hosts => ["*.foo.bar", "5.5.3.1",
                         Web::Host->new_from_packed_addr ("\x01\x02\x03\x04"),
                         Web::Host->new_from_packed_addr (Web::Host->parse_string ("[2001::4]")->packed_addr),
                         "%2A.xn--abc-p18d.test"]}, name => 'san domain'},
) {
  test {
    my $c = shift;

    my $gen = Web::Transport::PKI::Generator->new;
    $gen->create_rsa_key->then (sub {
      my $rsa = $_[0];
      
      return $gen->create_certificate (
        rsa => $rsa,
        version => 2,
        %{$test->{in}},
      );
    })->then (sub {
      my $cert = $_[0];
      test {
        my $expected = {
          version => 2,
          %{$test->{out}},
        };
        is $cert->version, $expected->{version};
        is $cert->ca, $expected->{ca};
        for (qw(digitalSignature nonRepudiation keyEncipherment
                dataEncipherment keyAgreement keyCertSign cRLSign
                encipherOnly decipherOnly)) {
          is $cert->key_usage ($_), $expected->{$_};
        }
        is !! ($cert->debug_info =~ m{\bSKI\b}), !!$expected->{SKI};
        is !! ($cert->debug_info =~ m{\bAKI\b}), 1;
        is_deeply $cert->crl_distribution_urls, $expected->{crl_urls} || [];
        is !! $cert->extended_key_usage ('serverAuth'), !! $expected->{serverAuth};
        is !! $cert->extended_key_usage ('clientAuth'), !! $expected->{clientAuth};
        is $cert->aia_ocsp_url, $expected->{aia_ocsp_url};
        is $cert->aia_ca_issuers_url, $expected->{aia_ca_issuers_url};
        is_deeply [sort { $a cmp $b } @{$cert->policy_oids}], $expected->{cp_oids} || [];
        is $cert->cps_url, $expected->{cps_url};
        is $cert->policy_user_notice_text, $expected->{policy_user_notice_text};
        is_deeply $cert->san_hosts, $expected->{san_hosts} || [];
      } $c;
      
      done $c;
      undef $c;
    });
  } n => 22, name => ['create_certificate options', $test->{name}];
}

run_tests;

=head1 LICENSE

Copyright 2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
