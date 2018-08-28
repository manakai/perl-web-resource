package Web::Transport::PKI::Generator;
use strict;
use warnings;
our $VERSION = '1.0';
use Promise;
use Web::Encoding;
use Net::SSLeay;
use Web::Transport::TypeError;
use Web::Transport::NetSSLeayError;
use Web::DateTime;
use Web::Transport::PKI::Name;
use Web::Transport::PKI::RSAKey;
use Web::Transport::PKI::Parser;

push our @CARP_NOT, qw(Web::Transport::TypeError
                       Web::Transport::NetSSLeayError Promise);

Net::SSLeay::load_error_strings ();
Net::SSLeay::SSLeay_add_ssl_algorithms ();
Net::SSLeay::randomize ();

sub new ($) {
  return bless {}, $_[0];
} # new

sub create_rsa_key ($%) {
  my ($self, %args) = @_;
  return Promise->resolve->then (sub {

    my $rsa = Net::SSLeay::RSA_generate_key ($args{bits} || 2048, 65537)
        or Web::Transport::NetSSLeayError->new_current;

    return Web::Transport::PKI::RSAKey->_new ($rsa);
  });
} # create_rsa_key

sub create_certificate ($%) {
  my ($self, %args) = @_;
  return Promise->resolve->then (sub {

    die Web::Transport::TypeError->new ("No |ca_rsa|")
        if not defined $args{ca_rsa};
    die Web::Transport::TypeError->new ("No |rsa|")
        if not defined $args{rsa};
    my $is_root_ca = $args{ca_rsa} eq $args{rsa};
    die Web::Transport::TypeError->new ("No |ca_cert|")
        if not $is_root_ca and not defined $args{ca_cert};

    my $cert = Net::SSLeay::X509_new ()
        or die Web::Transport::NetSSLeayError->new_current;

    Net::SSLeay::X509_set_version
        ($cert, defined $args{version} ? $args{version} : 2)
            or die Web::Transport::NetSSLeayError->new_current;

    if (defined $args{serial_number}) {
      require Math::BigInt;
      my $n = Math::BigInt->new ($args{serial_number});
      my $se = Net::SSLeay::X509_get_serialNumber ($cert)
          or die Web::Transport::NetSSLeayError->new_current;
      Net::SSLeay::P_ASN1_INTEGER_set_dec ($se, $n);
    }

    {
      my $n = Net::SSLeay::X509_get_notBefore ($cert)
          or die Web::Transport::NetSSLeayError->new_current;
      my $dt = $args{not_before} || 0;
      $dt = Web::DateTime->new_from_unix_time ($dt)
          unless UNIVERSAL::isa ($dt, 'Web::DateTime');
      Net::SSLeay::P_ASN1_TIME_set_isotime
          ($n, $dt->to_global_date_and_time_string)
              or die Web::Transport::NetSSLeayError->new_current;
    }
    {
      my $n = Net::SSLeay::X509_get_notAfter ($cert)
          or die Web::Transport::NetSSLeayError->new_current;
      my $dt = $args{not_after} || 0;
      $dt = Web::DateTime->new_from_unix_time ($dt)
          unless UNIVERSAL::isa ($dt, 'Web::DateTime');
      Net::SSLeay::P_ASN1_TIME_set_isotime
          ($n, $dt->to_global_date_and_time_string)
              or die Web::Transport::NetSSLeayError->new_current;
    }

    {
      my $issuer = $args{issuer} ||= do {
        $args{ca_cert} ? $args{ca_cert}->subject : undef;
      };
      my $ssleay_name = Net::SSLeay::X509_get_issuer_name ($cert)
          or die Web::Transport::NetSSLeayError->new_current;
      my $name = Web::Transport::PKI::Name->create ($issuer);
      $name->modify_net_ssleay_name ($ssleay_name);
    }
    {
      my $ssleay_name = Net::SSLeay::X509_get_subject_name ($cert)
          or die Web::Transport::NetSSLeayError->new_current;
      my $name = Web::Transport::PKI::Name->create ($args{subject});
      $name->modify_net_ssleay_name ($ssleay_name);
    }

    {
      my @ext;

      push @ext, Web::Transport::ASN1->_encode ('SEQUENCE',
        join '',
        Web::Transport::ASN1->_encode ('oid', '2.5.29.17'),
        Web::Transport::ASN1->_encode (0x4,
          Web::Transport::ASN1->_encode ('SEQUENCE', join '', map {
            if (UNIVERSAL::isa ($_, 'Web::Host')) {
              if ($_->is_ip) {
                Web::Transport::ASN1->_encode (\7, $_->packed_addr); # iPAddress
              } elsif ($_->is_domain) {
                Web::Transport::ASN1->_encode (\2, encode_web_utf8 $_->to_ascii); # dNSName
              } else {
                die new Web::Transport::TypeError ("Bad host |$_|");
              }
            } else {
              Web::Transport::ASN1->_encode (\2, encode_web_utf8 $_); # dNSName
            }
          } @{$args{san_hosts}}),
        ),
      ) if @{$args{san_hosts} or []};
      
      my @aia;
      push @aia, Web::Transport::ASN1->_encode ('SEQUENCE',
        join '',
        Web::Transport::ASN1->_encode ('oid', '1.3.6.1.5.5.7.48.1'),
        Web::Transport::ASN1->_encode (\6, encode_web_utf8 $args{aia_ocsp_url}),
      ) if defined $args{aia_ocsp_url};
      push @aia, Web::Transport::ASN1->_encode ('SEQUENCE',
        join '',
        Web::Transport::ASN1->_encode ('oid', '1.3.6.1.5.5.7.48.2'),
        Web::Transport::ASN1->_encode (\6, encode_web_utf8 $args{aia_ca_issuers_url}),
      ) if defined $args{aia_ca_issuers_url};
      push @ext, Web::Transport::ASN1->_encode ('SEQUENCE',
        join '',
        Web::Transport::ASN1->_encode ('oid', '1.3.6.1.5.5.7.1.1'),
        Web::Transport::ASN1->_encode (0x4,
          Web::Transport::ASN1->_encode ('SEQUENCE', join '', @aia),
        ),
      ) if @aia;

      my @oid;
      if (defined $args{ev}) {
        my $ev = Web::Transport::ASN1->find_oid ($args{ev});
        die new Web::Transport::TypeError ("Bad EV OID |$args{ev}|")
            unless defined $ev;
        push @oid, $ev->{oid}, '2.23.140.1.1';
      }
      push @oid, map {
        my $x = Web::Transport::ASN1->find_oid ($_);
        die new Web::Transport::TypeError ("Bad policy OID |$_|")
            unless defined $x;
        $x->{oid};
      } @{$args{policy_oids} or []};
      push @oid, '2.23.140.1.2.1' if $args{dv};
      push @oid, '2.23.140.1.2.2' if $args{ov};
      my @cp;
      if (defined $args{cps_url} or
          (defined $args{policy_user_notice_text} and
           length $args{policy_user_notice_text})) {
        push @oid, '2.5.29.32.0' unless @oid; # anyPolicy
        push @cp, Web::Transport::ASN1->_encode ('SEQUENCE',
          join '',
          Web::Transport::ASN1->_encode ('oid', $oid[0]),
          Web::Transport::ASN1->_encode ('SEQUENCE',
            join '',
            (defined $args{cps_url} ? Web::Transport::ASN1->_encode ('SEQUENCE',
              join '',
              Web::Transport::ASN1->_encode ('oid', '1.3.6.1.5.5.7.2.1'),
              Web::Transport::ASN1->_encode ($args{cps_url} =~ /[^\x00-\x7F]/ ? 0x0C : 0x16, encode_web_utf8 $args{cps_url}), # UTF8String / IA5String
            ) : ()),
            ((defined $args{policy_user_notice_text} and
              length $args{policy_user_notice_text}) ? Web::Transport::ASN1->_encode ('SEQUENCE',
              join '',
              Web::Transport::ASN1->_encode ('oid', '1.3.6.1.5.5.7.2.2'),
              Web::Transport::ASN1->_encode ('SEQUENCE',
                join '',
                Web::Transport::ASN1->_encode (0x0C, encode_web_utf8 $args{policy_user_notice_text}), # UTF8String
              ),
            ) : ()),
          ),
        );
        shift @oid;
      }
      push @cp, Web::Transport::ASN1->_encode ('SEQUENCE',
        join '',
        Web::Transport::ASN1->_encode ('oid', $_),
      ) for @oid;
      push @ext, Web::Transport::ASN1->_encode ('SEQUENCE',
        join '',
        Web::Transport::ASN1->_encode ('oid', '2.5.29.32'),
        Web::Transport::ASN1->_encode (0x4,
          Web::Transport::ASN1->_encode ('SEQUENCE', join '', @cp),
        ),
      ) if @cp;

      push @ext, Web::Transport::ASN1->_encode ('SEQUENCE',
        join '',
        Web::Transport::ASN1->_encode ('oid', '1.3.6.1.5.5.7.1.24'),
        Web::Transport::ASN1->_encode (0x4, "\x30\x03\x02\x01\x05"),
      ) if $args{must_staple};

      last unless @ext;

      my $csr_der = Web::Transport::ASN1->_encode ('SEQUENCE',
        join '',
        Web::Transport::ASN1->_encode ('SEQUENCE',
          join '',
          Web::Transport::ASN1->_encode (0x2, "\x00"), # version
          Web::Transport::ASN1->_encode ('SEQUENCE', ""), # subject : Name
          Web::Transport::ASN1->_encode ('SEQUENCE', # subjectPKInfo
            join '',
            Web::Transport::ASN1->_encode ('SEQUENCE',
              Web::Transport::ASN1->_encode ('oid', '0.0'),
            ),
            Web::Transport::ASN1->_encode (0x3, "\x00"),
          ),
          Web::Transport::ASN1->_encode (\0, # attributes
            Web::Transport::ASN1->_encode ('SEQUENCE',
              join '',
              Web::Transport::ASN1->_encode ('oid', '1.2.840.113549.1.9.14'),
              Web::Transport::ASN1->_encode ('SET',
                join '',
                Web::Transport::ASN1->_encode ('SEQUENCE', join '', @ext),
              ),
            ),
          ),
        ), # certifciationRequestInfo
        Web::Transport::ASN1->_encode ('SEQUENCE', # signatureAlgorithm
          Web::Transport::ASN1->_encode ('oid', '0.0'), # XXX
        ),
        Web::Transport::ASN1->_encode (0x3, "\x00"),
      );

      my $bio = Net::SSLeay::BIO_new (Net::SSLeay::BIO_s_mem ())
          or die Web::Transport::NetSSLeayError->new_current;
      Net::SSLeay::BIO_write ($bio, $csr_der)
          or die Web::Transport::NetSSLeayError->new_current;
      my $csr = Net::SSLeay::d2i_X509_REQ_bio ($bio)
          or die Web::Transport::NetSSLeayError->new_current;

      Net::SSLeay::P_X509_copy_extensions ($csr, $cert, 0)
          or die Web::Transport::NetSSLeayError->new_current;

      Net::SSLeay::BIO_free ($bio);
      Net::SSLeay::X509_REQ_free ($csr);
    }

    my @arg;
    push @arg, &Net::SSLeay::NID_basic_constraints => 'critical,CA:TRUE'
        . (defined $args{path_len_constraint} ? ',pathlen:' . (0+$args{path_len_constraint}) : '')
        if $args{ca};
    push @arg, &Net::SSLeay::NID_basic_constraints => 'critical,CA:FALSE'
        if $args{ee} and not $args{ca};
    my $ku = {};
    $ku->{digitalSignature} = $ku->{keyEncipherment} = 1 if $args{ee};
    $ku->{digitalSignature} = $ku->{keyCertSign} = $ku->{cRLSign} = 1 if $args{ca};
    push @arg, &Net::SSLeay::NID_key_usage => 'critical,' . join ',', keys %$ku
        if keys %$ku;
    push @arg, &Net::SSLeay::NID_subject_key_identifier => 'hash'
        if $args{ca} or $args{ee};
    push @arg, &Net::SSLeay::NID_crl_distribution_points => do {
      my $der = Web::Transport::ASN1->_encode ('SEQUENCE',
        join '', map {
          Web::Transport::ASN1->_encode ('SEQUENCE', # DistributionPoint
            Web::Transport::ASN1->_encode (\0, # distributionPoint
              Web::Transport::ASN1->_encode (\0, # fullName
                Web::Transport::ASN1->_encode (\6, # uniformResourceIdentifier
                  encode_web_utf8 $_,
                ),
              ),
            ),
          ),
        } @{$args{crl_urls}}
      );
      'DER:' . join '', map { sprintf '%02X', ord $_ } split //, $der;
    } if @{$args{crl_urls} or []};
    push @arg, &Net::SSLeay::NID_authority_key_identifier => 'keyid';
    #&Net::SSLeay::NID_authority_key_identifier => 'issuer';
    if (($args{ca} and not $is_root_ca) or $args{ee}) {
      push @arg, &Net::SSLeay::NID_ext_key_usage => 'serverAuth,clientAuth';
    }
    #&Net::SSLeay::NID_subject_alt_name => 'DNS:s1.dom.com,DNS:s2.dom.com,DNS:s3.dom.com',

    if (@arg) {
      my $ca_cert = defined $args{ca_cert} ? $args{ca_cert}->to_net_ssleay_x509 : $cert;
      Net::SSLeay::P_X509_add_extensions ($cert, $ca_cert, @arg)
          or die Web::Transport::NetSSLeayError->new_current;
      # don't free $ca_cert until here.
    }

    my $digest = Net::SSLeay::EVP_get_digestbyname ('sha256')
        or die Web::Transport::NetSSLeayError->new_current;

    Net::SSLeay::X509_set_pubkey ($cert, $args{rsa}->to_net_ssleay_pkey)
        or die Web::Transport::NetSSLeayError->new_current;

    Net::SSLeay::X509_sign ($cert, $args{ca_rsa}->to_net_ssleay_pkey, $digest)
        or die Web::Transport::NetSSLeayError->new_current;
    # don't free $args{rsa} until this line.

    my $pem = Net::SSLeay::PEM_get_string_X509 ($cert);
    my $parser = Web::Transport::PKI::Parser->new;
    my $result = $parser->parse_pem ($pem);
    
    Net::SSLeay::X509_free ($cert);

    return $result->[0];
  });
} # create_certifciate

1;

=head1 LICENSE

Copyright 2016-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
