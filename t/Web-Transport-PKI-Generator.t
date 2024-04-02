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
  my $p = $gen->create_rsa_key (bits => 512);
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
} n => 3, name => 'create_rsa_key bits => 512';

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  my $p = $gen->create_rsa_key (bits => 4096);
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
} n => 3, name => 'create_rsa_key bits => 4096';

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  my $p = $gen->create_rsa_key (bits => 256);
  isa_ok $p, 'Promise';

  $p->then (sub {
    test {
      ok 0;
    } $c;
  }, sub {
    my $e = $_[0];
    test {
      is $e->name, 'TypeError';
      is $e->message, "Bad bit length |256|";
      is $e->file_name, __FILE__;
      is $e->line_number, __LINE__-13;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 5, name => 'create_rsa_key bits => 256';

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  my $p = $gen->create_ec_key;
  isa_ok $p, 'Promise';

  $p->then (sub {
    my $rsa = $_[0];

    test {
      isa_ok $rsa, 'Web::Transport::PKI::ECKey';
      like $rsa->to_pem, qr{^-----BEGIN PRIVATE KEY-----\x0D?\x0A[A-Za-z0-9/+=\x0D\x0A]+\x0D?\x0A-----END PRIVATE KEY-----\x0D?\x0A$};
    } $c;

    done $c;
    undef $c;
  });
} n => 3, name => 'create_ec_key';

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  my $name = rand;
  my $p = $gen->create_ec_key (curve => $name);
  isa_ok $p, 'Promise';

  $p->then (sub {
    test {
      ok 0;
    } $c;
  }, sub {
    my $e = $_[0];

    test {
      is $e->name, 'TypeError';
      is $e->message, "Bad curve |$name|";
      is $e->file_name, __FILE__;
      is $e->line_number, __LINE__-14;
    } $c;

    done $c;
    undef $c;
  });
} n => 5, name => 'create_ec_key bad curve';

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
      is $err->message, 'No |ca_rsa| or |ca_ec|';
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
    
    my $p = $gen->create_certificate (ca_rsa => $rsa);
    test {
      isa_ok $p, 'Promise';
    } $c;

    return $p;
  })->then (sub { test { ok 0 } $c }, sub {
    my $err = $_[0];

    test {
      isa_ok $err, 'Web::Transport::TypeError';
      is $err->message, 'No |rsa| or |ec|';
      is $err->file_name, __FILE__;
      is $err->line_number, __LINE__-13;
    } $c;

    done $c;
    undef $c;
  });
} n => 5, name => 'create_certificate no argument';

test {
  my $c = shift;

  my $o = rand;
  my $gen = Web::Transport::PKI::Generator->new;
  $gen->create_rsa_key->then (sub {
    my $rsa = $_[0];
    
    return $gen->create_certificate (
      rsa => $rsa, ca_rsa => $rsa,
      subject => {O => $o},
    );
  })->then (sub {
    my $cert = $_[0];

    test {
      isa_ok $cert, 'Web::Transport::PKI::Certificate';
      is $cert->issuer->debug_info, $cert->subject->debug_info;
      is $cert->subject->debug_info, "[O=(P)$o]";
    } $c;

    done $c;
    undef $c;
  });
} n => 3, name => 'root no explicit issuer';

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  $gen->create_rsa_key->then (sub {
    my $rsa = $_[0];
    
    my $p = $gen->create_certificate (
      rsa => $rsa,
      ca_rsa => $rsa,
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
      like $cert->debug_info, qr{SPKI=RSA};
    } $c;

    done $c;
    undef $c;
  });
} n => 9, name => 'create_certificate default rsa';

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  $gen->create_ec_key->then (sub {
    my $ec = $_[0];
    
    my $p = $gen->create_certificate (
      ec => $ec,
      ca_ec => $ec,
    );
    test {
      isa_ok $p, 'Promise';
    } $c;

    return $p;
  })->then (sub {
    my $cert = $_[0];

    test {
      isa_ok $cert, 'Web::Transport::PKI::Certificate';
      like $cert->debug_info, qr{SPKI=EC,prime256v1};
    } $c;

    done $c;
    undef $c;
  });
} n => 3, name => 'create_certificate ec';

for my $curve (qw(prime256v1 secp384r1 secp521r1)) {
  test {
    my $c = shift;

    my $gen = Web::Transport::PKI::Generator->new;
    $gen->create_ec_key (curve => $curve)->then (sub {
      my $ec = $_[0];
      
      my $p = $gen->create_certificate (
        ec => $ec,
        ca_ec => $ec,
      );
      test {
        isa_ok $p, 'Promise';
      } $c;
      
      return $p;
    })->then (sub {
      my $cert = $_[0];

      test {
        isa_ok $cert, 'Web::Transport::PKI::Certificate';
        like $cert->debug_info, qr{SPKI=EC,$curve};
      } $c;
      
      done $c;
      undef $c;
    });
  } n => 3, name => ['create_certificate ec', $curve];
}

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  $gen->create_rsa_key->then (sub {
    my $rsa = $_[0];
    
    my $p = $gen->create_certificate (
      rsa => $rsa,
      ca_rsa => $rsa,
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
} n => 8, name => 'create_certificate primitive arguments';

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  $gen->create_rsa_key->then (sub {
    my $rsa = $_[0];
    
    my $p = $gen->create_certificate (
      rsa => $rsa,
      ca_rsa => $rsa,
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
} n => 8, name => 'create_certificate object arguments';

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  $gen->create_rsa_key->then (sub {
    my $rsa = $_[0];
    
    my $p = $gen->create_certificate (
      rsa => $rsa,
      ca_rsa => $rsa,
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
} n => 8, name => 'create_certificate object arguments';

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  $gen->create_rsa_key->then (sub {
    my $rsa = $_[0];
    
    my $p = $gen->create_certificate (
      rsa => $rsa,
      ca_rsa => $rsa,
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
} n => 8, name => 'create_certificate object arguments';

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  $gen->create_rsa_key->then (sub {
    my $rsa = $_[0];
    return $gen->create_certificate (
      rsa => $rsa,
      ca_rsa => $rsa,
      not_before => 3636355677.63344,
      not_after => 7547457455.53333,
    );
  })->then (sub {
    my $cert = $_[0];
    test {
      isa_ok $cert, 'Web::Transport::PKI::Certificate';
      is $cert->not_before->to_unix_number, 3636355677;
      is $cert->not_after->to_unix_number, 7547457455;
    } $c;

    done $c;
    undef $c;
  });
} n => 3, name => 'fractional second timestamps';

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  $gen->create_rsa_key->then (sub {
    my $rsa = $_[0];
    
    my $p = $gen->create_certificate (
      rsa => $rsa,
      ca_rsa => $rsa,
      version => 0,
      serial_number => Math::BigInt->from_hex ('0f642344e44'),
      not_before => Web::DateTime->new_from_components (2049, 12, 30, 23, 59, 59),
      not_after => Web::DateTime->new_from_components (2049, 12, 31, 23, 59, 59),
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
      is $cert->not_before->to_global_date_and_time_string, '2049-12-30T23:59:59Z';
      is $cert->not_after->to_global_date_and_time_string, '2049-12-31T23:59:59Z';
    } $c;

    done $c;
    undef $c;
  });
} n => 3, name => 'timestamp 2049';

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  $gen->create_rsa_key->then (sub {
    my $rsa = $_[0];
    
    my $p = $gen->create_certificate (
      rsa => $rsa,
      ca_rsa => $rsa,
      version => 0,
      serial_number => Math::BigInt->from_hex ('0f642344e44'),
      not_before => Web::DateTime->new_from_components (2050, 12, 30, 23, 59, 59),
      not_after => Web::DateTime->new_from_components (2050, 12, 31, 23, 59, 59),
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
      is $cert->not_before->to_global_date_and_time_string, '2050-12-30T23:59:59Z';
      is $cert->not_after->to_global_date_and_time_string, '2050-12-31T23:59:59Z';
    } $c;

    done $c;
    undef $c;
  });
} n => 3, name => 'timestamp 2050';

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  Promise->all ([
    $gen->create_rsa_key,
    $gen->create_rsa_key,
  ])->then (sub {
    my ($ca_rsa, $rsa) = @{$_[0]};
    
    my $ca_cert;
    return $gen->create_certificate (
      rsa => $ca_rsa,
      ca_rsa => $ca_rsa,
      subject => {O => 'The Root CA'},
      ca => 1,
    )->then (sub {
      $ca_cert = $_[0];
      return $gen->create_certificate (
        rsa => $rsa,
        ca_rsa => $ca_rsa,
        ca_cert => $ca_cert,
      );
    })->then (sub {
      my $cert = $_[0];

      test {
        isa_ok $cert, 'Web::Transport::PKI::Certificate';
        is $cert->issuer->debug_info, '[O=(P)The Root CA]';
      } $c;

      done $c;
      undef $c;
    });
  });
} n => 2, name => 'create_certificate CA';

test {
  my $c = shift;

  my $gen = Web::Transport::PKI::Generator->new;
  Promise->all ([
    $gen->create_rsa_key,
    $gen->create_ec_key,
  ])->then (sub {
    my ($ca_rsa, $rsa) = @{$_[0]};
    
    my $ca_cert;
    return $gen->create_certificate (
      rsa => $ca_rsa,
      ca_rsa => $ca_rsa,
      subject => {O => 'The Root CA'},
      ca => 1,
    )->then (sub {
      $ca_cert = $_[0];
      return $gen->create_certificate (
        ec => $rsa,
        ca_rsa => $ca_rsa,
        ca_cert => $ca_cert,
      );
    })->then (sub {
      my $cert = $_[0];

      test {
        isa_ok $cert, 'Web::Transport::PKI::Certificate';
        is $cert->issuer->debug_info, '[O=(P)The Root CA]';
        like $cert->debug_info, qr{SPKI=EC,};
      } $c;

      done $c;
      undef $c;
    });
  });
} n => 3, name => 'create_certificate CA RSA EC';

for my $test (
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
           SKI => 1, path_len_constraint => 3},
   name => 'root_ca'},
) {
  test {
    my $c = shift;

    my $gen = Web::Transport::PKI::Generator->new;
    $gen->create_rsa_key->then (sub {
      my $rsa = $_[0];
      
      return $gen->create_certificate (
        rsa => $rsa,
        ca_rsa => $rsa,
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
        is !!$cert->must_staple, !!$expected->{must_staple};
      } $c;
      
      done $c;
      undef $c;
    });
  } n => 23, name => ['create_certificate options (root CA)', $test->{name}];
}

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
  {in => {must_staple => !!1},
   out => {must_staple => !!1}, name => 'must-staple'},
  {in => {name_constraints_permitted => [
    'foo.bar', "ab,\x00de\x{4000}", ".xa.xy", "*.foo",
    Web::Host->new_from_packed_addr ("\x01\x02\x03\x04"),
    [Web::Host->new_from_packed_addr ("\x01\x02\x03\x06"),
     Web::Host->new_from_packed_addr ("\xFF\xFF\x00\x00")],
    "abc.",
   ]},
   out => {ncs => "nameConstraints:+foo.bar nameConstraints:+ab,\x00de\x{4000} nameConstraints:+.xa.xy nameConstraints:+*.foo nameConstraints:+IP:1.2.3.4/255.255.255.255 nameConstraints:+IP:1.2.3.6/255.255.0.0 nameConstraints:+abc."},
   name => 'nameConstraints +'},
  {in => {name_constraints_excluded => [
     [Web::Host->new_from_packed_addr ("\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02"),
      Web::Host->new_from_packed_addr ("\xFE\xFF\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02")],
      Web::Host->parse_string ("\xFE\x{4000}.abc"),
   ]},
   out => {ncs => "nameConstraints:-IP:[304:102:304:102:304:102:304:102]/[feff:102:304:102:304:102:304:102] nameConstraints:-xn--vda4733a.abc"},
   name => 'nameConstraints -'},
  {in => {name_constraints_permitted => [
     Web::Host->new_from_packed_addr ("\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04"),
   ], name_constraints_excluded => [
     [Web::Host->new_from_packed_addr ("\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02"),
      Web::Host->new_from_packed_addr ("\xFE\xFF\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02")],
      Web::Host->parse_string ("\xFE\x{4000}.abc"),
   ]},
   out => {ncs => "nameConstraints:+IP:[102:304:102:304:102:304:102:304]/[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff] nameConstraints:-IP:[304:102:304:102:304:102:304:102]/[feff:102:304:102:304:102:304:102] nameConstraints:-xn--vda4733a.abc"},
   name => 'nameConstraints'},
  {in => {digest => 'sha1'}, out => {digest => 'sha1'}, name => 'digest=sha1'},
  {in => {digest => 'sha256'}, out => {digest => 'sha256'}, name => 'digest=sha256'},
  {in => {digest => 'sha384'}, out => {digest => 'sha384'}, name => 'digest=sha384'},
) {
  test {
    my $c = shift;

    my $gen = Web::Transport::PKI::Generator->new;
    Promise->all ([
      $gen->create_rsa_key,
      $gen->create_rsa_key,
    ])->then (sub {
      my ($ca_rsa, $rsa) = @{$_[0]};
      
      my $ca_cert;
      return $gen->create_certificate (
        rsa => $ca_rsa,
        ca_rsa => $ca_rsa,
        subject => {O => 'The Root CA'},
        ca => 1,
      )->then (sub {
        $ca_cert = $_[0];
        return $gen->create_certificate (
          rsa => $rsa,
          ca_rsa => $ca_rsa,
          ca_cert => $ca_cert,
          version => 2,
          %{$test->{in}},
        );
      });
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
        is !!$cert->must_staple, !!$expected->{must_staple};
        if (defined $expected->{ncs}) {
          like $cert->debug_info, qr{\Q$expected->{ncs}\E};
        } else {
          unlike $cert->debug_info, qr{nameConstraints};
        }
        if (defined $expected->{digest}) {
          like $cert->debug_info, qr{sig=@{[{
            sha1 => 'SHA-1',
            sha256 => 'SHA-256',
            sha384 => 'SHA-384',
          }->{$expected->{digest}}]}/RSA};
        } else {
          like $cert->debug_info, qr{sig=SHA-256/RSA};
        }
      } $c;
    })->catch (sub {
      my $e = $_[0];
      test {
        is $e, undef;
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  } n => 25, name => ['create_certificate options', $test->{name}];
}

run_tests;

=head1 LICENSE

Copyright 2018-2024 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
