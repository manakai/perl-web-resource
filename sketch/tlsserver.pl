use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('lib');
use Web::Host;
use Web::URL;
use Web::Transport::TCPTransport;
use Web::Transport::TLSTransport;
use Web::Transport::HTTPServerConnection;
use AnyEvent::Socket;
use Test::Certificates;
use Promise;
use Promised::Flow;
use AnyEvent;

my $tls_port = 6333;
my $TLSOrigin = Web::URL->parse_string ("https://tlstestserver.test:$tls_port");


{
  use Web::Transport::PKI::Parser;
  use Web::DateTime::Parser;
  
  my $DUMP = 1; #$ENV{DUMP};
  my $_dump_tls = {};

  #sub SSL_ST_CONNECT () { 0x1000 }
#sub SSL_ST_ACCEPT () { 0x2000 }
sub SSL_CB_READ () { 0x04 }
sub SSL_CB_WRITE () { 0x08 }
sub SSL_CB_ALERT () { 0x4000 }
#sub SSL_CB_HANDSHAKE_START () { 0x10 }
sub SSL_CB_HANDSHAKE_DONE () { 0x20 }

my $cipher_suite_name = {};
$cipher_suite_name->{0x00, 0xFF} = 'empty reneg info scsv';

  
sub hex_dump ($) {
  my $s = $_[0];
  my @x;
  for (my $i = 0; $i * 16 < length $s; $i++) {
    my @d = map {
      my $index = $i*16+$_;
      if ($index < length $s) {
        ord substr $s, $index, 1;
      } else {
        undef;
      }
    } 0..15;
    push @x, (join ' ', map { defined $_ ? sprintf '%02X', $_ : '  ' } @d) . '  ' .
             (join '', map { defined $_ ? ((0x20 <= $_ and $_ <= 0x7E) ? pack 'C', $_ : '.') : ' ' } @d);
  }
  return join "\n", @x;
} # hex_dump

sub dump_tls ($;%);
sub dump_tls ($;%) {
  my ($key, %args) = @_;
  my $header_length = defined $args{content_type} ? 4 : 5;
  my $id = $_dump_tls->{[split /\Q$;\E/, $key]->[0], 'id'} || '???:'.$key;
  while ($header_length <= length $_dump_tls->{$_[0]}) {
    my $record = {};
    if (defined $args{content_type}) {
      $record->{msg_type} = ord substr $_dump_tls->{$_[0]}, 0, 1;
      $record->{length} = (ord substr $_dump_tls->{$_[0]}, 1, 1) * 0x10000
                        + (ord substr $_dump_tls->{$_[0]}, 2, 1) * 0x100
                        + (ord substr $_dump_tls->{$_[0]}, 3, 1);
    } else {
      $record->{content_type} = ord substr $_dump_tls->{$_[0]}, 0, 1;
      $record->{version}->{major} = ord substr $_dump_tls->{$_[0]}, 1, 1;
      $record->{version}->{minor} = ord substr $_dump_tls->{$_[0]}, 2, 1;
      $record->{length} = (ord substr $_dump_tls->{$_[0]}, 3, 1) * 0x100
                        + (ord substr $_dump_tls->{$_[0]}, 4, 1);
    }
    if ($header_length + $record->{length} <= length $_dump_tls->{$_[0]}) {
      $record->{fragment} = substr $_dump_tls->{$_[0]}, $header_length, $record->{length};
      substr ($_dump_tls->{$_[0]}, 0, $header_length + $record->{length}) = '';
      if (defined $args{content_type}) {
        if ($record->{msg_type} == 1 or # ClientHello
            $record->{msg_type} == 2) { # ServerHello
          if ($record->{msg_type} == 1) {
            $record->{client_version}->{major} = ord substr $record->{fragment}, 0, 1;
            $record->{client_version}->{minor} = ord substr $record->{fragment}, 1, 1;
          } else {
            $record->{server_version}->{major} = ord substr $record->{fragment}, 0, 1;
            $record->{server_version}->{minor} = ord substr $record->{fragment}, 1, 1;
          }
          $record->{random}->{gmt_unix_time}
              = (ord substr $record->{fragment}, 2, 1) * 0x1000000
              + (ord substr $record->{fragment}, 3, 1) * 0x10000
              + (ord substr $record->{fragment}, 4, 1) * 0x100
              + (ord substr $record->{fragment}, 5, 1);
          $record->{random}->{random_bytes} = substr $record->{fragment}, 6, 28;
          my $next = 34;
          $record->{session_id}->{length} = ord substr $record->{fragment}, $next, 1;
          $next += 1;
          $record->{session_id}->{value} = substr $record->{fragment}, $next, $record->{session_id}->{length};
          $next += $record->{session_id}->{length};
          if ($record->{msg_type} == 1) { # ClientHello
            $record->{cipher_suites}->{length} = (ord substr $record->{fragment}, $next, 1) * 0x100
                                               + (ord substr $record->{fragment}, $next + 1, 1);
            $next += 2;
            $record->{cipher_suites}->{value} = substr $record->{fragment}, $next, $record->{cipher_suites}->{length};
            $next += $record->{cipher_suites}->{length};
          } else {
            $record->{cipher_suites}->{length} = 1;
            $record->{cipher_suites}->{value} = substr $record->{fragment}, $next, 2;
            $next += 2;
          }
          $record->{compression_method}->{length} = ord substr $record->{fragment}, $next, 1;
          $next += 1;
          $record->{compression_method}->{value} = substr $record->{fragment}, $next, $record->{compression_method}->{length};
          $next += $record->{compression_method}->{length};
          if ($next <= length $record->{fragment}) {
            $record->{extensions}->{length} = (ord substr $record->{fragment}, $next, 1) * 0x100
                                            + (ord substr $record->{fragment}, $next + 1, 1);
            $next += 2;
            $record->{extensions}->{value} = substr $record->{fragment}, $next, $record->{extensions}->{length};
            $next += $record->{extensions}->{length};
          }
          warn sprintf "[%s] TLS handshake %d (%s) L=%d: %d.%d %s\n",
              $id,
              $record->{msg_type},
              ($record->{msg_type} == 1 ? 'ClientHello' : 'ServerHello'),
              $record->{length},
              ($record->{msg_type} == 1 ? $record->{client_version}->{major} : $record->{server_version}->{major}),
              ($record->{msg_type} == 1 ? $record->{client_version}->{minor} : $record->{server_version}->{minor}),
              do {
                my @c = split //, $record->{cipher_suites}->{value};
                my @v;
                while (@c) {
                  my $c1 = ord shift @c;
                  my $c2 = ord shift @c;
                  my $name = $cipher_suite_name->{$c1, $c2};
                  if (defined $name) {
                    push @v, sprintf '%02X%02X [%s]', $c1, $c2, $name;
                  } else {
                    push @v, sprintf '%02X%02X', $c1, $c2;
                  }
                }
                join ' ', @v;
              };
          warn sprintf "  random time=%d bytes=%s\n",
              $record->{random}->{gmt_unix_time},
              hex_dump $record->{random}->{random_bytes};
          warn sprintf "  sid=%s\n", hex_dump $record->{session_id}->{value};
          {
            my $next = 0;
            while ($next < length $record->{extensions}->{value}) {
              my $type = (ord substr $record->{extensions}->{value}, $next, 1) * 0x100
                       + (ord substr $record->{extensions}->{value}, $next + 1, 1);
              $next += 2;
              my $length = (ord substr $record->{extensions}->{value}, $next, 1) * 0x100
                         + (ord substr $record->{extensions}->{value}, $next + 1, 1);
              $next += 2;
              my $data = substr $record->{extensions}->{value}, $next, $length;
              $next += $length;
              if ($type == 0) {
                my $list_length = (ord substr $data, 0, 1) * 0x100
                                + (ord substr $data, 1, 1);
                my $list = substr $data, 2, $list_length;
                my $next = 0;
                my @host_name;
                while ($next < length $list) {
                  my $name_type = ord substr $list, $next, 1;
                  $next++;
                  # if $name_type == 0
                  my $host_name_length = (ord substr $list, $next, 1) * 0x100
                                       + (ord substr $list, $next+1, 1);
                  $next += 2;
                  my $host_name = substr $list, $next, $host_name_length;
                  $next += $host_name_length;
                  push @host_name, "name=$host_name";
                }
                warn sprintf "  0 (SNI) %s\n", join ', ', @host_name;
              } elsif ($type == 16) {
                my $list_length = (ord substr $data, 0, 1) * 0x100
                                + (ord substr $data, 1, 1);
                my $list = substr $data, 2, $list_length;
                my $next = 0;
                my @name;
                while ($next < length $list) {
                  my $name_length = (ord substr $list, $next, 1);
                  $next += 1;
                  my $name = substr $list, $next, $name_length;
                  $next += $name_length;
                  push @name, $name;
                }
                warn sprintf "  16 (ALPN) %s\n", join ', ', @name;
              } else {
                warn sprintf "  %d (%s) L=%d %s\n",
                    $type, {
                      0 => 'SNI',
                      5 => 'status_request',
                      10 => 'supported_groups',
                      11 => 'ec_point_formats',
                      13 => 'signature_algorithms',
                      15 => 'heartbeat',
                      16 => 'ALPN',
                      18 => 'signed_certificate_timestamp',
                      21 => 'padding',
                      23 => 'extended_master_secret',
                      35 => 'SessionTicket',
                      13172 => 'NPN',
                      30032 => 'channel_id',
                      65281 => 'renegotiation_info',
                    }->{$type} || '', $length, hex_dump $data;
              }
            }
          }
        } elsif ($record->{msg_type} == 11) { # certificate
          my $next = 0;
          $record->{certificates}->{length} = (ord substr $record->{fragment}, $next, 1) * 0x1000
              + (ord substr $record->{fragment}, $next + 1, 1) * 0x100
              + (ord substr $record->{fragment}, $next + 2, 1);
          $next += 3;
          $record->{certificates}->{items} = [];
          while ($next < length $record->{fragment}) {
            push @{$record->{certificates}->{items}}, my $item = {};
            $item->{length} = (ord substr $record->{fragment}, $next, 1) * 0x1000
              + (ord substr $record->{fragment}, $next + 1, 1) * 0x100
              + (ord substr $record->{fragment}, $next + 2, 1);
            $next += 3;
            $item->{bytes} = substr $record->{fragment}, $next, $item->{length};
            $next += $item->{length};
          }

          warn sprintf "[%s] TLS handshake %d (%s) L=%d\n",
              $id,
              $record->{msg_type},
              'Certificate',
              $record->{length};
          my $parser = Web::Transport::PKI::Parser->new;
          for my $item (@{$record->{certificates}->{items}}) {
            warn sprintf "  Certificate L=%d\n", $item->{length};
            
            my $cert = $parser->parse_certificate_der ($item->{bytes});
            warn sprintf "    %s\n", $cert->debug_info;
          }
        } else {
          warn sprintf "[%s] TLS handshake %d (%s) L=%d\n",
              $id,
              $record->{msg_type},
              {
                0 => 'hello_request',
                #1
                #2
                4 => 'new_session_ticket',
                #11 => 'certificate',
                12 => 'server_key_exchange',
                13 => 'certificate_request',
                14 => 'server_hello_done',
                15 => 'certificate_verify',
                16 => 'client_key_exchange',
                17 => 'client_certificate_request',
                20 => 'finished',
              }->{$record->{msg_type}} || '',
              $record->{length};
        }
      } else {
        if (defined $_dump_tls->{$key, 'last_content_type'} and
            not $_dump_tls->{$key, 'last_content_type'} == $record->{content_type}) {
          dump_tls $key . $; . $_dump_tls->{$key, 'last_content_type'}, end => 1, content_type => $_dump_tls->{$key, 'last_content_type'};
          delete $_dump_tls->{$key, 'last_content_type'};
        }

        warn sprintf "[%s] TLS record %d (%s) %d.%d L=%d\n",
            $id,
            $record->{content_type},
            {
              22 => 'handshake',
              21 => 'alert',
              20 => 'change_cipher_spec',
              23 => 'application_data',
              24 => 'heartbeat',
            }->{$record->{content_type}} || '',
            $record->{version}->{major}, $record->{version}->{minor},
            $record->{length};
        #warn hex_dump ($record->{fragment}), "\n"
        #    unless $_dump_tls->{$key, 'changed'};

        $_dump_tls->{$key, 'changed'} = 1 if $record->{content_type} == 20;
        unless ($_dump_tls->{$key, 'changed'}) {
          if (not defined $_dump_tls->{$key, 'last_content_type'}) {
            $_dump_tls->{$key, 'last_content_type'} = $record->{content_type};
            $_dump_tls->{$key, $record->{content_type}} = '';
          }
          $_dump_tls->{$key, $record->{content_type}} .= $record->{fragment};
          dump_tls $key . $; . $record->{content_type}, content_type => $record->{content_type};
        }
      }
      next;
    }
    last;
  }
  if ($args{end} and length $_dump_tls->{$key}) {
    warn "Unexpected end of data for |$key| (L=@{[length $_dump_tls->{$key}]})"
        if defined $args{content_type} and $args{content_type} == 22;
    delete $_dump_tls->{$key};
  }
} # dump_tls

require Net::SSLeay;
require AnyEvent::Handle;
{
  my $orig = Net::SSLeay->can ('BIO_write');
  *Net::SSLeay::BIO_write = sub ($$) {
    if (defined $_dump_tls->{$_[0]}) {
      $_dump_tls->{$_[0]} .= $_[1] if defined $_[1];
      dump_tls $_[0];
    }
    goto &$orig;
  } if $DUMP;
}
$Web::Transport::TLSTransport::debug_read = sub {
  if (defined $_dump_tls->{$_[0]}) {
    $_dump_tls->{$_[0]} .= $_[1] if defined $_[1];
    dump_tls $_[0];
  }
};
{
  my $orig = AnyEvent::Handle->can ('_dotls');
  *AnyEvent::Handle::_dotls = sub {
    $_dump_tls->{$_[0]->{_rbio}} = '' if not defined $_dump_tls->{$_[0]->{_rbio}};
    goto &$orig;
  } if $DUMP;
}
$Web::Transport::TLSTransport::debug_set_io = sub {
  $_dump_tls->{$_[0]} = '' if not defined $_dump_tls->{$_[0]};
  $_dump_tls->{$_[0], 'id'} = "$_[2]R";
  $_dump_tls->{$_[1]} = '' if not defined $_dump_tls->{$_[1]};
  $_dump_tls->{$_[1], 'id'} = "$_[2]W";
};

}

my $GlobalCV = AE::cv;
$GlobalCV->begin;

my $HandleRequestHeaders = {};
  my $cb = sub {
    my ($self, $type) = @_;
    if ($type eq 'headers') {
      my $req = $_[2];
      my $handler = $HandleRequestHeaders->{$req->{target_url}->path} ||
                    $HandleRequestHeaders->{$req->{target_url}->hostport};
      if (defined $handler) {
        $self->{body} = '';
        $handler->($self, $req);
      } elsif ($req->{target_url}->path eq '/') {
        $self->send_response_headers
            ({status => 404, status_text => 'Not Found (/)'}, close => 1);
        $self->close_response;
      } else {
        die "No handler for |@{[$req->{target_url}->stringify]}|";
      }
    } elsif ($type eq 'data') {
      $self->{body} .= $_[2];
      $self->{ondata}->($_[2], $_[3]) if $self->{ondata};
    } elsif ($type eq 'text') {
      $self->{text} .= $_[2];
    } elsif ($type eq 'dataend' or $type eq 'textend' or
             $type eq 'ping' or $type eq 'complete') {
      $self->{$type}->($_[2], $_[3]) if $self->{$type};
      if ($type eq 'complete') {
        delete $self->{$_} for qw(ondata dataend textend ping complete);
      }
    }
  }; # $cb
  my $con_cb = sub {
    my ($self, $type) = @_;
    if ($type eq 'startstream') {
      return $cb;
    }
  }; # $con_cb

my $host = '0';
  {
    package TLSTestResolver;
    sub new {
      return bless {}, $_[0];
    }
    sub resolve ($$) {
      return Promise->resolve (Web::Host->parse_string ($host));
    }
  }

use Web::Transport::PKI::Generator;
my $gen = Web::Transport::PKI::Generator->new;
my $Certs = {};
$gen->create_rsa_key->then (sub {
  my $ca_rsa = $_[0];
  my $name = "The " . path (__FILE__)->absolute . " Root CA (" . rand . ")";
  return $gen->create_certificate (
    rsa => $ca_rsa,
    ca_rsa => $ca_rsa,
    subject => {O => $name},
    issuer => {O => $name},
    not_before => time - 60,
    not_after => time + 60*60*100,
    serial_number => 1,
    ca => 1,
  )->then (sub {
    my $ca_cert = $_[0];

    $Certs->{ca_key} = $ca_rsa;
    $Certs->{ca_cert} = $ca_cert;
    return Promise->all ([
      $gen->create_rsa_key,
    ])->then (sub {
      my $i_rsa = $_[0]->[0];
      return $gen->create_certificate (
          rsa => $i_rsa,
          ca_rsa => $ca_rsa,
          ca_cert => $ca_cert,
          not_before => time - 30,
          not_after => time + 30*24*60*60,
          serial_number => int rand 10000000,
          subject => {CN => "i.test"},
          san_hosts => ["i.test"],
          ca => 1,
        )->then (sub {
          my $i_cert = $_[0];

          $Certs->{i_cert} = $i_cert;
          $Certs->{i_key} = $i_rsa;

      return Promise->all ([
        $gen->create_rsa_key,
      ])->then (sub {
        my $rsa = $_[0]->[0];
        return $gen->create_certificate (
          rsa => $rsa,
          ca_rsa => $i_rsa,
          ca_cert => $i_cert,
          not_before => time - 30,
          not_after => time + 30*24*60*60,
          serial_number => int rand 10000000,
          subject => {CN => "hoge.test"},
          san_hosts => ["hoge.test"],
          ee => 1,
        )->then (sub {
          my $cert = $_[0];

          $Certs->{ee_cert} = $cert;
          $Certs->{ee_key} = $rsa;

          warn $cert->to_pem;
        });
        });
      });
    });
  });
})->to_cv->recv;

#path ("/tmp/root.pem")->spew ($Certs->{ca_cert}->to_pem);
#path ("/tmp/intermediate.pem")->spew ($Certs->{i_cert}->to_pem);
#path ("/tmp/e.pem")->spew ($Certs->{ee_cert}->to_pem);

  my $cert_args = {host => 'tlstestserver.test'};
  Test::Certificates->wait_create_cert ($cert_args);
  our $tls_server = tcp_server $host, $tls_port, sub {
    my $tcp = Web::Transport::TCPTransport->new
        (fh => $_[0], server => 1,
         host => Web::Host->parse_string ($_[1]), port => $_[2]);
    my $tls = Web::Transport::TLSTransport->new
        (server => 1, transport => $tcp,

         #ca_file => Test::Certificates->ca_path ('cert.pem'),
         #cert_file => Test::Certificates->cert_path ('cert-chained.pem', $cert_args),
         #key_file => Test::Certificates->cert_path ('key.pem', $cert_args),
         
         #cert_file => Test::Certificates->ca_path ('cert.pem'),
         #key_file => Test::Certificates->ca_path ('key.pem'),

         ca => $Certs->{ca_cert}->to_pem,
         cert => $Certs->{ee_cert}->to_pem . "\n" . $Certs->{i_cert}->to_pem . "\n" . $Certs->{ca_cert}->to_pem,
         key => $Certs->{ee_key}->to_pem,

         #cert => $Certs->{ca_cert}->to_pem,
         #key => $Certs->{ca_key}->to_pem,
        );
    my $con = Web::Transport::HTTPServerConnection->new
        (transport => $tls, cb => $con_cb);
    $GlobalCV->begin;
    promised_cleanup { $GlobalCV->end } $con->closed;
  };

  warn "URL: ", $TLSOrigin->stringify, "\n";
#$GlobalCV->end;
$GlobalCV->recv;

## License: Public Domain.
