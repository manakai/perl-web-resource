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
      my $ssleay_name = Net::SSLeay::X509_get_issuer_name ($cert)
          or die Web::Transport::NetSSLeayError->new_current;
      my $name = Web::Transport::PKI::Name->create ($args{issuer});
      $name->modify_net_ssleay_name ($ssleay_name);
    }
    {
      my $ssleay_name = Net::SSLeay::X509_get_subject_name ($cert)
          or die Web::Transport::NetSSLeayError->new_current;
      my $name = Web::Transport::PKI::Name->create ($args{subject});
      $name->modify_net_ssleay_name ($ssleay_name);
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
            Web::Transport::ASN1->_encode (0, # distributionPoint
              Web::Transport::ASN1->_encode (0, # fullName
                Web::Transport::ASN1->_encode (6, # uniformResourceIdentifier
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
    if (($args{ca} and not $args{root_ca}) or $args{ee}) {
      push @arg, &Net::SSLeay::NID_ext_key_usage => 'serverAuth,clientAuth';
    }
    #&Net::SSLeay::NID_netscape_cert_type => 'server',
    #&Net::SSLeay::NID_subject_alt_name => 'DNS:s1.dom.com,DNS:s2.dom.com,DNS:s3.dom.com',
    if (@arg) {
      Net::SSLeay::P_X509_add_extensions ($cert, $cert, @arg)
          or die Web::Transport::NetSSLeayError->new_current;
    }

    my $digest = Net::SSLeay::EVP_get_digestbyname ('sha256')
        or die Web::Transport::NetSSLeayError->new_current;

    die Web::Transport::TypeError->new ("No |rsa|") unless defined $args{rsa};
    Net::SSLeay::X509_set_pubkey ($cert, $args{rsa}->to_net_ssleay_pkey)
        or die Web::Transport::NetSSLeayError->new_current;
    Net::SSLeay::X509_sign ($cert, $args{rsa}->to_net_ssleay_pkey, $digest)
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
