package Test::Certificates;
use strict;
use warnings;
use Path::Tiny;
use File::Temp;
use Web::DateTime::Parser;
use Web::Transport::OCSP;

my $root_path = path (__FILE__)->parent->parent->parent->parent->absolute;
my $cert_path = $root_path->child ('local/cert');
my $cn = $ENV{SERVER_HOST_NAME} || 'hoge.test';
$cert_path->mkpath;

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
  system ($_[0]) == 0 or die $?;
} # x

sub generate_certs ($$) {
  my ($class, $cert_args) = @_;

  my $ca_name = "/CN=ca.test";
  my $ca_key_path = $class->ca_path ('key.pem');
  my $ca_cert_path = $class->ca_path ('cert.pem');
  my $ecname = 'prime256v1';
  unless ($ca_key_path->is_file) {
    my $ca_subj = $ca_name;
    if (0) {
      x "openssl genrsa -out \Q$ca_key_path\E 2048";
      x "openssl req -new -x509 -nodes -days 1 -key \Q$ca_key_path\E -out \Q$ca_cert_path\E -subj \Q$ca_subj\E -sha256 -set_serial @{[time]}";
    } else {
      x "openssl ecparam -name $ecname -out \Q$ca_key_path\E -genkey";
      x "openssl req -new -x509 -nodes -days 1 -key \Q$ca_key_path\E -out \Q$ca_cert_path\E -subj \Q$ca_subj\E -set_serial @{[time]}";
    }
    sleep 1;
  }

  my $subject_name = $cert_args->{host} || $cn;
  my $subject_type = 'DNS';
  if ($subject_name =~ s/^IPv4://) {
    $subject_type = 'IP';
  } elsif ($subject_name =~ s/^mailto://) {
    $subject_type = 'email';
  }

  my $server_key_path = $_[0]->cert_path ('key.pem', $cert_args);
  x "openssl ecparam -name $ecname -out \Q$server_key_path\E -genkey";

  my $server_req_path = $_[0]->cert_path ('req.pem', $cert_args);
  my $config_path = $_[0]->cert_path ('openssl.cnf', $cert_args);
  my @conf = q{[exts]};
  push @conf, qq{subjectAltName=$subject_type:$subject_name} unless $cert_args->{no_san};
  if ($cert_args->{must_staple}) {
    push @conf,
        q{1.3.6.1.5.5.7.1.24 = DER:3003020105};
        #q{tlsfeature = status_request};
  }
  $config_path->spew (join "\n", @conf);
  #my $server_subj = '/';
  #my $server_subj = '/subjectAltName=DNS.1='.$subject_name;
  my $server_subj = '/CN='.(defined $cert_args->{cn} ? $cert_args->{cn} : $subject_name);
  $server_subj .= '/CN=' . $cert_args->{cn2} if defined $cert_args->{cn2};
  if (0) {
    x "openssl req -newkey rsa:2048 -days 1 -nodes -keyout \Q$server_key_path\E -out \Q$server_req_path\E -subj \Q$server_subj\E";# -config \Q$config_path\E $no_san ? '' : -reqexts san";
  } else {
    x "openssl req -days 1 -new -nodes -key \Q$server_key_path\E -out \Q$server_req_path\E -subj \Q$server_subj\E";# -config \Q$config_path\E $cert_args->{no_san} ? '' : -reqexts san";
  }

  if (0) {
    my $server_key1_path = $_[0]->cert_path ('key-pkcs1.pem', $cert_args);
    x "openssl rsa -in \Q$server_key_path\E -out \Q$server_key1_path\E";
  }

  my $server_cert_path = $_[0]->cert_path ('cert.pem', $cert_args);
  x "openssl x509 -req -in \Q$server_req_path\E -days 1 -CA \Q$ca_cert_path\E -CAkey \Q$ca_key_path\E -out \Q$server_cert_path\E -set_serial @{[time]} -extfile \Q$config_path\E -extensions exts";

  my $server_p12_path = $_[0]->cert_path ('keys.p12', $cert_args);
  x "openssl pkcs12 -export -passout pass: -in \Q$server_cert_path\E -inkey \Q$server_key_path\E -out \Q$server_p12_path\E";
} # generate_certs

sub wait_create_cert ($$) {
  my ($class, $cert_args) = @_;
  if ($ENV{RECREATE_CERTS} or
      ($_[0]->ca_path ('cert.pem')->is_file and
       $_[0]->ca_path ('cert.pem')->stat->mtime + 60*60*24 < time)) {
    system "rm \Q$cert_path\E/*.pem";
  }
  my $cert_pem_path = $_[0]->cert_path ('cert.pem', $cert_args);
  unless ($cert_pem_path->is_file) {
    $class->generate_certs ($cert_args);
  }

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
} # wait_create_cert

sub ocsp_response ($$;%) {
  my ($class, $cert_args, %args) = @_;

  my $cert_path = $class->cert_path ('cert.pem', $cert_args);

  my $bio = Net::SSLeay::BIO_new (Net::SSLeay::BIO_s_mem ());
  my $rv = Net::SSLeay::BIO_write ($bio, $cert_path->slurp);
  my $x509 = Net::SSLeay::PEM_read_bio_X509 ($bio);
  Net::SSLeay::BIO_free ($bio);
  die "Failed to parse |$cert_path|" unless $x509;
  my $sn = Net::SSLeay::X509_get_subject_name ($x509);
  my $subj = Net::SSLeay::X509_NAME_print_ex ($sn, Net::SSLeay::XN_FLAG_RFC2253 (), 0);
  my $sno = Net::SSLeay::P_ASN1_INTEGER_get_hex (Net::SSLeay::X509_get_serialNumber ($x509));
  Net::SSLeay::X509_free($x509);

  my $index_file = File::Temp->new;
  my $index_path = path ($index_file->filename);

  my $status = 'V';
  my $rdate = '';
  my $xdate = '';
  if ($args{revoked}) {
    $status = 'R';
    $rdate = '160101000000Z';
  }
  if ($args{expired}) {
    $xdate = '150101000000Z';
    $status = 'E';
  }

  my $index = [];
  push @$index, join "\t", $status, $xdate, $rdate, $sno, 'unknown', $subj;
  $index_path->spew ((join "\n", @$index) . "\n");

  my $res_file = File::Temp->new;
  my $res_path = path ($res_file->filename);
  
  (system 'openssl', 'ocsp',
       '-index' => $index_path,
       '-CA' => $class->ca_path ('cert.pem'),
       '-rkey' => $class->ca_path ('key.pem'),
       '-rsigner' => $class->ca_path ('cert.pem'),
       '-issuer' => $class->ca_path ('cert.pem'),
       '-cert' => $cert_path,
       ($args{no_next} ? () : ('-ndays' => 1)),
       #'-text', # DEBUG
       '-respout' => $res_path) == 0
      or die $?;

  my $der = $res_path->slurp; # DER encoded

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

  return $der;
} # ocsp_response

1;
