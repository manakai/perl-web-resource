package Web::Transport::PKI::Certificate;
use strict;
use warnings;
our $VERSION = '1.0';
use Net::SSLeay;
#use Web::Transport::NetSSLeayError;
use Web::Encoding;
use Web::Transport::Base64;
use Web::Transport::ASN1;
use Web::DateTime::Parser;
use Web::Transport::PKI::Name;

sub _new ($$$) {
  return  bless {parsed => $_[1], der_ref => $_[2]}, $_[0];
} # _new

#  my $bio = Net::SSLeay::BIO_new (Net::SSLeay::BIO_s_mem ());
#  Net::SSLeay::BIO_write ($bio, $_[1]);
#
#  my $cert = Net::SSLeay::PEM_read_bio_X509 ($bio)
#      or Web::Transport::NetSSLeayError->new_current;
#
#  Net::SSLeay::BIO_free ($bio);

sub version ($) {
  #return Net::SSLeay::X509_get_version $_[0]->{cert};
  return $_[0]->{version} if defined $_[0]->{version};

  my $v = $_[0]->{parsed}->{tbsCertificate}->{version}->[2];
  $v = Web::Transport::ASN1::decode_der $v if defined $v;
  if (defined $v and $v->[0]->[0] eq 'int') {
    return $_[0]->{version} = 0+$v->[0]->[1];
  }

  return $_[0]->{version} = 0; # v1 (default)
} # version

sub serial_number ($) {
  #return Net::SSLeay::P_ASN1_INTEGER_get_dec
  #    Net::SSLeay::X509_get_serialNumber $_[0]->{cert};

  return $_[0]->{serial_number} if defined $_[0]->{serial_number};
  require Math::BigInt;
  my $v = $_[0]->{parsed}->{tbsCertificate}->{serialNumber} || ['int', 0];
  if ($v->[0] eq 'int') {
    $_[0]->{serial_number} = Math::BigInt->new ($v->[1]);
  } elsif ($v->[0] eq 'bigint') {
    $_[0]->{serial_number} = Math::BigInt->from_hex ($v->[1]);
  } else {
    $_[0]->{serial_number} = Math::BigInt->new (0);
  }

  return $_[0]->{serial_number};
} # serial_number

sub not_before ($) {
  #return Web::DateTime::Parser->parse_js_date_time_string
  #    (Net::SSLeay::P_ASN1_TIME_get_isotime
  #     Net::SSLeay::X509_get_notBefore $_[0]->{cert});

  return $_[0]->{not_before} if exists $_[0]->{not_before};
  my $v = $_[0]->{parsed}->{tbsCertificate}->{validity}->{notBefore} // [''];
  my $parser = Web::DateTime::Parser->new;
  $parser->onerror (sub { });
  if ($v->[0] eq 'UTCTime') {
    return $_[0]->{not_before} = $parser->parse_pkix_utc_time_string ($v->[1]); # or undef
  } elsif ($v->[0] eq 'GeneralizedTime') {
    return $_[0]->{not_before} = $parser->parse_pkix_generalized_time_string ($v->[1]); # or undef
  } else {
    return $_[0]->{not_before} = undef;
  }
} # not_before

sub not_after ($) {
  #return Web::DateTime::Parser->parse_js_date_time_string
  #    (Net::SSLeay::P_ASN1_TIME_get_isotime
  #     Net::SSLeay::X509_get_notAfter $_[0]->{cert});

  return $_[0]->{not_after} if exists $_[0]->{not_after};
  my $v = $_[0]->{parsed}->{tbsCertificate}->{validity}->{notAfter} // [''];
  my $parser = Web::DateTime::Parser->new;
  $parser->onerror (sub { });
  if ($v->[0] eq 'UTCTime') {
    return $_[0]->{not_after} = $parser->parse_pkix_utc_time_string ($v->[1]); # or undef
  } elsif ($v->[0] eq 'GeneralizedTime') {
    return $_[0]->{not_after} = $parser->parse_pkix_generalized_time_string ($v->[1]); # or undef
  } else {
    return $_[0]->{not_after} = undef;
  }
} # not_after

sub issuer ($) {
  # ... (Net::SSLeay::X509_get_issuer_name $_[0]->{cert});

  return $_[0]->{issuer} ||= Web::Transport::PKI::Name->_new
      (Web::Transport::ASN1->read_name
          ($_[0]->{parsed}->{tbsCertificate}->{issuer}));
} # issuer

sub subject ($) {
  # ... (Net::SSLeay::X509_get_subject_name $_[0]->{cert});

  return $_[0]->{subject} ||= Web::Transport::PKI::Name->_new
      (Web::Transport::ASN1->read_name
          ($_[0]->{parsed}->{tbsCertificate}->{subject}));
} # subject

my $ExtDefs = {
  '2.5.29.15' => { # keyUsage
    type => 'bits',
  },
  '2.5.29.19' => { # basicConstraints
    type => 'SEQUENCE',
    def => [
      {name => 'cA', types => {BOOLEAN => 1}, optional => 1},
      {name => 'pathLenConstraint', types => {int => 1, bigint => 0},
       optional => 1},
    ],
  },
  '2.5.29.31' => { # cRLDistributionPoints
    type => 'SEQUENCE OF',
    def => [
      {name => 'distributionPoint', seq => 0, optional => 1,
       decode => ['CHOICE', [
         {name => 'fullName', decode => ['GeneralNames']}, # 0
         {name => 'nameRelativeToCRLIssuer', decode => ['RDN']}, # 1
       ]]},
      {name => 'reasons', seq => 1, optional => 1,
       decode => 1},
      {name => 'cRLIssuer', seq => 2, optional => 1,
       decode => ['GeneralNames']},
    ],
  },
  '2.5.29.37' => { # extKeyUsage
    type => 'SEQUENCE OF',
    subtype => 'oid',
  },
};

sub _ext ($$) {
  my ($self, $oid) = @_;
  return $self->{exts}->{$oid} if exists $self->{exts}->{$oid};

  for (@{$self->{parsed}->{tbsCertificate}->{extensions}}) {
    if ($_->[0] eq $oid) {
      my $def = $ExtDefs->{$oid} or die "No definition for |$oid|";
      my $v = Web::Transport::ASN1::decode_der $_->[2], depth => 10;
      if ($def->{type} eq 'SEQUENCE') {
        $_->[3] = Web::Transport::ASN1->read_sequence ($def->{def}, $v->[0]);
      } elsif ($def->{type} eq 'SEQUENCE OF') {
        if (defined $v and $v->[0]->[0] eq 'SEQUENCE') {
          if (defined $def->{def}) {
            my $r = [];
            for (@{$v->[0]->[1]}) {
              my $w = Web::Transport::ASN1->read_sequence ($def->{def}, $_);
              next unless defined $w;
              push @$r, $w;
            }
            $_->[3] = $r;
          } elsif (defined $def->{subtype}) {
            my $r = [];
            for (@{$v->[0]->[1]}) {
              push @$r, $_ if $_->[0] eq $def->{subtype};
            }
            $_->[3] = $r;
          }
        }
      } elsif ($def->{type} eq 'bits') {
        if (defined $v and $v->[0]->[0] eq 'bytes') {
          $_->[3] = $v->[0]->[1];
        }
      }
      return $self->{exts}->{$oid} = undef unless defined $_->[3];
      return $self->{exts}->{$oid} = $_;
    }
  }

  return $self->{exts}->{$oid} = undef;
} # _ext

sub ca ($) {
  my $self = $_[0];
  my $v = $self->_ext ("2.5.29.19");
  return undef unless defined $v;
  return !! $v->[3]->{cA}->[1];
} # ca

sub path_len_constraint ($) {
  my $self = $_[0];
  return (($self->_ext ('2.5.29.19') or [])->[3]->{pathLenConstraint}->[1]); # or undef
} # path_len_constraint

sub key_usage ($$) {
  my ($self, $field) = @_;
  my $x = {
    digitalSignature  => 7,
    nonRepudiation    => 6, contentCommitment => 6,
    keyEncipherment   => 5,
    dataEncipherment  => 4,
    keyAgreement      => 3,
    keyCertSign       => 2,
    cRLSign           => 1,
    encipherOnly      => 0,
    decipherOnly      => 15,
  }->{$field};
  return undef unless defined $x;
  my $v = $self->_ext ('2.5.29.15');
  return undef unless defined $v;
  return !! vec ($v->[3] // "", $x, 1);
} # key_usage

sub crl_distribution_urls ($) {
  my $self = $_[0];
  my $v = $self->_ext ('2.5.29.31') || [];
  my $r = [];
  for (@{$v->[3] or []}) {
    my $w = $_->{distributionPoint} || [];
    next unless $w->[0] eq 'fullName';
    for (@{$w->[1]}) {
      if ($_->[0] eq 'uniformResourceIdentifier') {
        push @$r, decode_web_utf8 $_->[2]; # IA5String
      }
    }
  }
  return $r;
} # crl_distribution_urls

sub _xuoids ($) {
  my $self = $_[0];
  for (@{($self->_ext ('2.5.29.37') or [])->[3] or []}) {
    if ($_->[0] eq 'oid') {
      $self->{xuoids}->{$_->[1]} = 1;
    }
  }
  return $self->{xuoids};
} # _xuoids

sub extended_key_usage ($$) {
  my ($self, $_oid) = @_;
  my $oids = $self->_xuoids;
  my $oid = Web::Transport::ASN1->find_oid ($_oid);
  return undef unless defined $oid;
  return $oids->{$oid->{oid}};
} # extended_key_usage

sub to_pem ($) {
  #return Net::SSLeay::PEM_get_string_X509 $_[0]->{cert};

  my $s = encode_web_base64 ${$_[0]->{der_ref}};
  $s =~ s/(.{64})/$1\x0D\x0A/g;
  $s =~ s/\x0D\x0A\z//;
  return join "\x0D\x0A",
      "-----BEGIN CERTIFICATE-----",
      $s,
      "-----END CERTIFICATE-----",
      "";
} # to_pem

sub debug_info ($) {
  my $self = $_[0];

  my @r;
  push @r, "v" . (1 + $self->version);
  push @r, 'I=' . $self->issuer->debug_info;
  push @r, 'S=' . $self->subject->debug_info;
  my @san; # XXX = Net::SSLeay::X509_get_subjectAltNames $cert;
  while (@san) {
    my $type = (shift @san);
    $type = {
      2 => 'DNS',
      7 => 'IP', # XXX decode value
    }->{$type} || $type;
    push @r, 'SAN.'.$type . '=' . (shift @san);
  }
  require Math::BigInt;
  push @r, '#=' . $self->serial_number->as_hex;
  push @r, 'notbefore=' . $self->not_before->to_global_date_and_time_string
      if defined $self->not_before;
  push @r, 'notafter=' . $self->not_after->to_global_date_and_time_string
      if defined $self->not_after;

  push @r, 'CA' if $self->ca;
  push @r, 'pathLenConstraint=' . $self->path_len_constraint
      if defined $self->path_len_constraint;

  for (qw(
    digitalSignature
    nonRepudiation
    keyEncipherment
    dataEncipherment
    keyAgreement
    keyCertSign
    cRLSign
    encipherOnly
    decipherOnly
  )) {
    push @r, $_ if $self->key_usage ($_);
  }

  for (@{$self->crl_distribution_urls}) {
    push @r, 'CRL=' . $_;
  }

  my $oids = $self->_xuoids;
  for (sort { $a cmp $b } keys %$oids) {
    my $oid = Web::Transport::ASN1->find_oid ($_);
    push @r, 'extKeyUsage=' . ($oid->{short_name} // $oid->{long_name} // $oid->{oid});
  }

  my @type; # XXX = Net::SSLeay::P_X509_get_netscape_cert_type $cert;
  if (@type) {
    push @r, 'netscapecerttype=' . join ',', @type;
  }

  #XXX
  #require Web::Transport::OCSP;
  #if (Web::Transport::OCSP->_x509_has_must_staple ($cert)) {
  #  push @r, 'must-staple';
  #}

  for (@{$self->{parsed}->{tbsCertificate}->{extensions}}) {
    my $n = {
      '2.5.29.14' => 'SKI',
      '2.5.29.35' => 'AKI',
    }->{$_->[0]};
    if (defined $n) {
      push @r, $n;
    } elsif (not defined $ExtDefs->{$_->[0]}) {
      push @r, $_->[0];
    }
  }

  return join ' ', @r;
} # debug_info

sub DESTROY ($) {
  #Net::SSLeay::X509_free ($_[0]->{cert});
} # DESTROY

1;

=head1 LICENSE

Copyright 2016-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
