package Test::Certificates;
use strict;
use warnings;
use Path::Tiny;
use Promise;
use Web::DateTime::Parser;
use Web::Transport::OCSP;
use Web::Transport::PKI::Generator;
use Web::Transport::PKI::Parser;

my $root_path = path (__FILE__)->parent->parent->parent->parent->absolute;
my $cert_path = $root_path->child ('local/cert');
my $cn = $ENV{SERVER_HOST_NAME} || 'hoge.test';
$cert_path->mkpath;
my $DUMP = $ENV{DUMP} || $ENV{PROMISED_COMMAND_DEBUG};
my $RSA = 1;

sub ca_path ($$) {
  return $cert_path->child ("ca-" . $_[1]);
} # ca_path

sub escape ($) {
  my $s = $_[0];
  $s =~ s/([^0-9a-z])/sprintf '_%02X', ord $1/ge;
  return $s;
} # escape

sub cert_path ($$;$) {
  my (undef, undef, $cert_args) = @_;
  return $cert_path->child (escape ($cert_args->{host} || $cn) . '-'
      . ($cert_args->{no_san} ? 'nosan-' : '')
      . ($cert_args->{must_staple} ? 'muststaple-' : '')
      . (defined $cert_args->{cn} ? 'cn-' . (escape $cert_args->{cn}) . '-' : '')
      . (defined $cert_args->{cn2} ? 'cn2-' . (escape $cert_args->{cn2}) . '-' : '')
      . $_[1]);
} # cert_path

sub cert_name ($) {
  return $cn;
} # cert_name

sub x ($) {
  warn "\$ $_[0]\n" if $DUMP;
  system ($_[0]) == 0 or die "|$_[0]| failed: $?";
} # x

sub generate_ca_cert ($) {
  return shift->generate_ca_cert_p->to_cv->recv;
}

sub generate_ca_cert_p ($) {
  my $class = $_[0];
  my $ca_key_path = $class->ca_path ('key.pem');
  unless ($ca_key_path->is_file) {
    my $ca_cert_path = $class->ca_path ('cert.pem');
    my $gen = Web::Transport::PKI::Generator->new;
    ($RSA ? $gen->create_rsa_key->then (sub { [rsa => $_[0]] }) : $gen->create_ec_key->then (sub { [ec => $_[0]] }))->then (sub {
      my ($type, $key) = @{$_[0]};
      my $ca_name = {CN => "ca.test"};
      $ca_key_path->spew ($key->to_pem);
      return $gen->create_certificate (
        subject => $ca_name,
        issuer => $ca_name,
        ca => 1,
        not_before => time - 3600,
        not_after => time + 3600*24*366*100,
        serial_number => 1,
        $type => $key,
        "ca_" . $type => $key,
      );
    })->then (sub {
      my $cert = $_[0];
      $ca_cert_path->spew ($cert->to_pem);
    });
  }
  return Promise->resolve;
} # generate_ca_cert_p

sub generate_certs ($$) {
  my ($class, $cert_args) = @_;

  my $lock_path = $cert_args->{intermediate} ? $class->ca_path ('lock') : $class->cert_path ('lock', {host => 'intermediate'});
  my $lock = $lock_path->openw ({locked => 1});

  warn "\n\n";
  warn "======================\n";
  warn "$$: @{[scalar gmtime]}: Generating certificate (@{[$class->cert_path ('', $cert_args)]})...\n";
  
  return $class->generate_ca_cert_p->then (sub {
    my $ica_key_path = $cert_args->{intermediate} ? $class->ca_path ('key.pem') : $class->cert_path ('key.pem', {host => 'intermediate'});
    my $ca_cert_path = $class->ca_path ('cert.pem');
    my $ica_cert_path = $cert_args->{intermediate} ? $ca_cert_path : $class->cert_path ('cert.pem', {host => 'intermediate'});
    my $chained_ca_cert_path = $cert_args->{intermediate} ? $ca_cert_path : $class->cert_path ('cert-chained.pem', {host => 'intermediate'});

  my $ca_name = {CN => "ca.test"};
  my $ica_subj = $cert_args->{intermediate} ? {CN => 'intermediate'} : $ca_name;
  my $subject_name = $cert_args->{host} || $cn;
  my $server_subj = {CN => (defined $cert_args->{cn} ? $cert_args->{cn} : $subject_name)};
  $server_subj->{"2.5.4.3"} = $cert_args->{cn2} if defined $cert_args->{cn2};

    my $gen = Web::Transport::PKI::Generator->new;
    my $parser = Web::Transport::PKI::Parser->new;
    my $server_cert_path = $class->cert_path ('cert.pem', $cert_args);
    my $chained_cert_path = $class->cert_path ('cert-chained.pem', $cert_args);
    
    my $server_key_path = $class->cert_path ('key.pem', $cert_args);
    my $p = ($RSA ? $gen->create_rsa_key->then (sub { [rsa => $_[0]] }) : $gen->create_ec_key->then (sub { [ec => $_[0]] }))->then (sub {
      my ($type, $key) = @{$_[0]};
      $server_key_path->spew ($key->to_pem);
      return $gen->create_certificate (
      #issuer => $ica_subj,
      subject => $server_subj,
      ($cert_args->{no_san} ? () : (san_hosts => [$subject_name])),
      ca => $cert_args->{intermediate},
      ee => ! $cert_args->{intermediate},
      must_staple => $cert_args->{must_staple},
      not_before => time - 3600,
      not_after => time + 3600,
      serial_number => int rand 10000000,
      'ca_' . $type => $parser->parse_pem ($ica_key_path->slurp)->[0],
      ca_cert => $parser->parse_pem ($ica_cert_path->slurp)->[0],
      $type => $key,
    );
  })->then (sub {
    my $cert = $_[0];
    $server_cert_path->spew ($cert->to_pem);
    x "cat \Q$server_cert_path\E \Q$ica_cert_path\E > \Q$chained_cert_path\E";
    x "cat \Q$ca_cert_path\E >> \Q$chained_cert_path\E";
    });
    return $p;
  })->then (sub {
    warn "$$: @{[scalar gmtime]}: Certificate generation done\n";

    undef $lock;
  });
} # generate_certs

sub wait_create_cert ($$) {
  return shift->wait_create_cert_p (@_)->to_cv->recv;
}

sub wait_create_cert_p ($$) {
  my ($class, $cert_args) = @_;
  if ($ENV{RECREATE_CERTS} or
      ($_[0]->ca_path ('cert.pem')->is_file and
       $_[0]->ca_path ('cert.pem')->stat->mtime + 60*60*24 < time)) {
    warn "Recreate certificates...\n";
    x "rm \Q$cert_path\E/*.pem || true";
  }
  my $cert_pem_path = $class->cert_path ('cert.pem', $cert_args);
  return Promise->resolve->then (sub {
    unless ($cert_pem_path->is_file) {
      return Promise->resolve->then (sub {
        return $class->generate_certs ({host => 'intermediate', intermediate => 1})
            unless $class->cert_path ('cert.pem', {host => 'intermediate'})->is_file;
      })->then (sub {
        return $class->generate_certs ($cert_args);
      });
    }
  })->then (sub {
    require Net::SSLeay;
    require Web::DateTime::Parser;

  my $bio = Net::SSLeay::BIO_new (Net::SSLeay::BIO_s_mem ());
  my $rv = Net::SSLeay::BIO_write ($bio, $cert_pem_path->slurp);
  my $x509 = Net::SSLeay::PEM_read_bio_X509 ($bio);
  Net::SSLeay::BIO_free ($bio);
  die "Failed to parse |$cert_pem_path|" unless $x509;

  my $parser = Web::DateTime::Parser->new;
  my $dt = $parser->parse_global_date_and_time_string
      (Net::SSLeay::P_ASN1_TIME_get_isotime
           (Net::SSLeay::X509_get_notBefore ($x509)));
  my $tt = $dt->to_unix_number;

  my $delta = $tt - time;
  if ($delta > 0) {
    warn "Wait $delta seconds...\n";
    sleep $delta;
  }
    Net::SSLeay::X509_free($x509);
  });
} # wait_create_cert_p

sub ocsp_response ($$;%) {
  my ($class, $cert_args, %args) = @_;

  my $cert_path = $class->cert_path ('cert.pem', $cert_args);
  my $cert_chained_path = $class->cert_path ('cert-chained.pem', $cert_args);

  my $bio = Net::SSLeay::BIO_new (Net::SSLeay::BIO_s_mem ());
  my $rv = Net::SSLeay::BIO_write ($bio, $cert_path->slurp);
  my $x509 = Net::SSLeay::PEM_read_bio_X509 ($bio);
  Net::SSLeay::BIO_free ($bio);
  die "Failed to parse |$cert_path|" unless $x509;
  my $sn = Net::SSLeay::X509_get_subject_name ($x509);
  my $subj = Net::SSLeay::X509_NAME_print_ex ($sn, Net::SSLeay::XN_FLAG_RFC2253 (), 0);
  my $sno = Net::SSLeay::P_ASN1_INTEGER_get_hex (Net::SSLeay::X509_get_serialNumber ($x509));
  Net::SSLeay::X509_free($x509);

  my $index_path = $root_path->child ('local/temp/' . int rand 10000);
  $index_path->parent->mkpath;

  my $status = 'V';
  my $rdate = '';
  my $xdate = '';
  if ($args{revoked}) {
    $status = 'R';
    #$rdate = '160101000000Z';
    $rdate = '';
  }
  if ($args{expired}) {
    $xdate = '150101000000Z';
    $status = 'E';
  }

  my $index = [];
  push @$index, join "\t", $status, $xdate, $rdate, $sno, 'unknown', $subj;
  $index_path->spew ((join "\n", @$index) . "\n");

  my $res_path = $root_path->child ('local/temp/' . int rand 10000);
  $res_path->parent->mkpath;

  warn "opsnssl ocsp...\n" if $DUMP;
  (system 'openssl', 'ocsp',
       '-index' => $index_path,
       '-CAfile' => $class->cert_path ('cert-chained.pem', {host => 'intermediate'}),
       '-CA' => $class->cert_path ('cert.pem', {host => 'intermediate'}),
       '-rkey' => $class->cert_path ('key.pem', {host => 'intermediate'}),
       '-rsigner' => $class->cert_path ('cert.pem', {host => 'intermediate'}),
       '-issuer' => $class->cert_path ('cert.pem', {host => 'intermediate'}),
       '-cert' => $cert_chained_path,
       ($args{no_next} ? () : ('-ndays' => 1)),
       #'-text', # DEBUG
       '-respout' => $res_path) == 0
      or die $?;
  warn "OCSP response generated: |$res_path|\n" if $DUMP;

  die "|$res_path| not found" unless $res_path->is_file;
  my $der = $res_path->slurp; # DER encoded

  warn "Check OCSP response's timestamp...\n" if $DUMP;
  my $parsed = Web::Transport::OCSP->parse_response_byte_string ($der);
  my $dtp = Web::DateTime::Parser->new;
  my $max = time;
  for (values %{$parsed->{responses} or {}}) {
    next unless defined $_->{update};
    my $dt = $dtp->parse_pkix_generalized_time_string ($_->{this_update});
    my $t = $dt->to_unix_number;
    $max = $t if $t > $max;
  }
  my $delta = $max - time;
  if ($delta > 0) {
    warn "Wait for $delta seconds for OCSP response...\n";
    sleep $delta;
  }
  warn "OK!\n" if $DUMP;

  return $der;
} # ocsp_response

1;

=head1 LICENSE

Copyright 2007-2024 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
