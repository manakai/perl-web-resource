use strict;
use warnings;
use Path::Tiny;
use Socket;
use AnyEvent;
use AnyEvent::Socket;
use AnyEvent::Handle;
use Digest::SHA qw(sha1);
use MIME::Base64 qw(encode_base64);

my $host = shift;
my $port = shift // die "Usage: $0 listen-host listen-port\n";

my $input;
{
  local $/ = undef;
  $input = <>;
}

my $Commands = [split /\x0D?\x0A/, $input];

my $_dump_tls = {};
our $CurrentID;

sub run_commands ($$$$);
sub run_commands ($$$$) {
  my ($context, $hdl, $states, $then) = @_;

  while (@{$states->{commands}}) {
    my $command = shift @{$states->{commands}};
    $command =~ s/^\s+//;
    $command =~ s/\s+$//;
    if ($command =~ /^#/) {
      #
    } elsif ($command =~ /^"([^"]*)"$/) {
      $hdl->push_write ($1);
    } elsif ($command =~ /^"([^"]*)"CRLF$/) {
      $hdl->push_write ("$1\x0D\x0A");
      #AE::log error => "Sent $1 CR LF";
    } elsif ($command =~ /^"([^"]*)"LF$/) {
      $hdl->push_write ("$1\x0A");
    } elsif ($command =~ /^"([^"]*)"CR$/) {
      $hdl->push_write ("$1\x0D");
    } elsif ($command =~ /^"([^"]*)"\s+x\s+([0-9]+)$/) {
      $hdl->push_write ($1 x $2);
    } elsif ($command =~ /^CRLF$/) {
      $hdl->push_write ("\x0D\x0A");
    } elsif ($command =~ /^LF$/) {
      $hdl->push_write ("\x0A");
    } elsif ($command =~ /^CR$/) {
      $hdl->push_write ("\x0D");
    } elsif ($command =~ /^0x([0-9A-Fa-f]{2})$/) {
      $hdl->push_write (pack 'C', hex $1);
    } elsif ($command =~ /^client$/) {
      $hdl->push_write ($states->{client_host} . ':' . $states->{client_port});
    } elsif ($command =~ /^ws-accept$/) {
      $states->{captured} =~ /^Sec-WebSocket-Key:\s*(\S+)\s*$/im;
      my $key = $1 // '';
      my $sha = encode_base64 sha1 ($key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'), '';
      #warn "$key / $sha";
      $hdl->push_write ($sha);
    } elsif ($command =~ /^receive LF$/) {
      if ($states->{received} =~ /\x0A/) {
        $states->{received} =~ s/^.*?\x0A//s;
      } else {
        unshift @{$states->{commands}}, $command;
        $then->();
        return;
      }
    } elsif ($command =~ /^receive LF, end capture$/) {
      if ($states->{received} =~ /\x0A/) {
        $states->{received} =~ s/^(.*?\x0A)//s;
        $states->{captured} .= $1;
      } else {
        unshift @{$states->{commands}}, $command;
        $then->();
        return;
      }
    } elsif ($command =~ /^receive CRLFCRLF, end capture$/) {
      if ($states->{received} =~ /\x0D\x0A\x0D\x0A/) {
        $states->{received} =~ s/^(.*?\x0D\x0A\x0D\x0A)//s;
        $states->{captured} .= $1;
      } else {
        unshift @{$states->{commands}}, $command;
        $then->();
        return;
      }
    } elsif ($command =~ /^receive "([^"]+)"(, start capture|, end capture|)(, showlength|)(?:, timeout ([0-9]+)|)$/) {
      my $x = $1;
      my $capture = $2;
      my $showlength = $3;
      my $timeout = $4;
      #warn "[$states->{id}] receive [$states->{received}]";
      my $timer;
      if (defined $timeout) {
        $timer = AE::timer $timeout, 0, sub {
          $hdl->push_shutdown;
          undef $timer;
        };
      }
      if ($states->{received} =~ /\Q$x\E/) {
        AE::log error => "[$states->{id}] received length = @{[length $states->{received}]}"
            if $showlength;
        if ($capture eq ', start capture') {
          $states->{received} =~ s/^.*?(\Q$x\E)//s;
          $states->{captured} = $1;
        } elsif ($capture eq ', end capture') {
          $states->{received} =~ s/^(.*?\Q$x\E)//s;
          $states->{captured} .= $1;
        } else {
          $states->{received} =~ s/^.*?\Q$x\E//s;
        }
        undef $timer;
      } else {
        unshift @{$states->{commands}}, $command;
        $then->();
        return;
      }
    } elsif ($command =~ /^sleep ([0-9.]+)$/) {
      sleep $1;
    } elsif ($command =~ /^urgent "([^"]*)"$/) {
      send $hdl->{fh}, $1, MSG_OOB;
    } elsif ($command =~ /^ws-receive-header$/) {
      if ($states->{received} =~ /^(.)(.)/s) {
        my $fin = !!(0x80 & ord $1);
        my $rsv1 = !!(0x40 & ord $1);
        my $rsv2 = !!(0x20 & ord $1);
        my $rsv3 = !!(0x10 & ord $1);
        my $opcode = 0x0F & ord $1;
        my $has_mask = !!(0x80 & ord $2);
        my $length = 0x7F & ord $2;
        if ($length == 0xFE) {
          if ($states->{received} =~ s/^..(.)(.)//s) {
            $length = (ord $1) * 0x100 + ord $2;
          } else {
            undef $length;
          }
        } elsif ($length == 0xFF) {
          if ($states->{received} =~ s/^..(.)(.)(.)(.)//s) {
            if (0x80 & ord $1) {
              undef $length;
            } else {
              $length = (ord $1) * 0x1_00_00_00 + (ord $2) * 0x1_00_00 + (ord $3) * 0x100 + ord $4;
            }
          } else {
            undef $length;
          }
        } else {
          $states->{received} =~ s/^..//s;
        }
        my $mask = undef;
        if ($has_mask) {
          if ($states->{received} =~ s/^(....)//s) {
            $mask = $1;
          } else {
            undef $length;
          }
        }
        if (defined $length) {
          AE::log error => qq{WS FIN=%d RSV1=%d RSV2=%d RSV3=%d opcode=0x%X masking=%d length=%d mask=0x%02X%02X%02X%02X},
              $fin, $rsv1, $rsv2, $rsv3, $opcode, $has_mask, $length,
              (ord substr $mask, 0, 1),
              (ord substr $mask, 1, 1),
              (ord substr $mask, 2, 1),
              (ord substr $mask, 3, 1);
          $states->{ws_length} = $length;
          $states->{ws_mask} = $mask;
          next;
        }
      }
      unshift @{$states->{commands}}, $command;
      $then->();
      return;
    } elsif ($command =~ /^ws-receive-data$/) {
      if (length $states->{received} >= $states->{ws_length}) {
        my @data = split //, substr $states->{received}, 0, $states->{ws_length};
        substr ($states->{received}, 0, $states->{ws_length}) = '';
        if (defined $states->{ws_mask}) {
          for (0..$#data) {
            $data[$_] = $data[$_] ^ substr $states->{ws_mask}, $_ % 4, 1;
          }
        }
        AE::log error => join '', @data;
        next;
      }
      unshift @{$states->{commands}}, $command;
      $then->();
      return;
    } elsif ($command =~ /^ws-send-header((?:\s+\w+=\S*)+)$/) {
      my $args = $1;
      my $fields = {FIN => 1, RSV1 => 0, RSV2 => 0, RSV3 => 0,
                    opcode => 0, masking => 0, length => 0};
      while ($args =~ s/^\s+(\w+)=(\S*)//) {
        $fields->{$1} = $2;
      }
      $hdl->push_write (pack 'C', ($fields->{FIN} << 7) |
                                  ($fields->{RSV1} << 6) |
                                  ($fields->{RSV2} << 5) |
                                  ($fields->{RSV3} << 4) |
                                  $fields->{opcode});
      if ($fields->{length} < 0xFE) {
        $hdl->push_write (pack 'C', $fields->{length});
      } elsif ($fields->{length} < 0x10000) {
        $hdl->push_write ("\xFE");
        $hdl->push_write (pack 'n', $fields->{length});
      } else {
        $hdl->push_write ("\xFF");
        $hdl->push_write (pack 'Q>', $fields->{length});
      }
      if ($fields->{masking}) {
        # XXX

      }
    } elsif ($command =~ /^close$/) {
      $hdl->push_shutdown;
    } elsif ($command =~ /^close read$/) {
      shutdown $hdl->{fh}, 0;
    } elsif ($command =~ /^reset$/) {
      setsockopt $hdl->{fh}, SOL_SOCKET, SO_LINGER, pack "II", 1, 0;
      close $hdl->{fh};
      $hdl->push_shutdown; # let $hdl report an error
    } elsif ($command =~ /^starttls$/) {
      my $root_path = path (__FILE__)->parent->parent->absolute;
      my $cert_path = $root_path->child ('local/cert');
      my $cn = $ENV{SERVER_HOST_NAME} // 'hoge.test';
      unless ($cert_path->child ($cn . '-key-pkcs1.pem')->is_file) {
        system $root_path->child ('perl'), $root_path->child ('t_deps/bin/generate-certs-for-tests.pl'), $cert_path, $cn;
        sleep 2;
      }
      $states->{starttls_waiting} = 1;
      $hdl->on_starttls (sub {
        delete $states->{starttls_waiting};
        $_[0]->on_starttls (undef);
        run_commands ($context, $_[0], $states, $then);
      });
      local $CurrentID = $states->{id};
      $hdl->starttls ('accept', {
        ca_path => $cert_path->child ('ca-cert.pem'),
        cert_file => $cert_path->child ($cn . '-cert.pem'),
        key_file => $cert_path->child ($cn . '-key-pkcs1.pem'),
        #cipher_list => 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK',
        cipher_list => 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA',
      });
      unshift @{$states->{commands}}, 'waitstarttls';
      return;
    } elsif ($command =~ /^waitstarttls$/) {
      if ($states->{starttls_waiting}) {
        $then->();
        return;
      }
    } elsif ($command =~ /^stoptls$/) {
      $hdl->stoptls;
    } elsif ($command =~ /^showreceivedlength$/) {
      AE::log error => qq{[$states->{id}] length of rbuf = @{[length $states->{received}]}};
    } elsif ($command =~ /^showcaptured$/) {
      AE::log error => qq{[$states->{id}] captured = |$states->{captured}|};
    } elsif ($command =~ /^show\s+"([^"]*)"$/) {
      AE::log error => $1;
    } elsif ($command =~ /\S/) {
      die "Unknown command: |$command|";
    }
  } # while
  $then->();
} # run_commands

my $cv = AE::cv;
$cv->begin;
my $sig = AE::signal TERM => sub { $cv->end };

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
  my $id = $_dump_tls->{[split /\Q$;\E/, $key]->[0], 'id'} // '???:'.$key;
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
        if ($record->{msg_type} == 1) { # ClientHello
          $record->{client_version}->{major} = ord substr $record->{fragment}, 0, 1;
          $record->{client_version}->{minor} = ord substr $record->{fragment}, 1, 1;
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
          $record->{cipher_suites}->{length} = (ord substr $record->{fragment}, $next, 1) * 0x100
                                             + (ord substr $record->{fragment}, $next + 1, 1);
          $next += 2;
          $record->{cipher_suites}->{value} = substr $record->{fragment}, $next, $record->{cipher_suites}->{length};
          $next += $record->{cipher_suites}->{length};
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
              'ClientHello',
              $record->{length},
              $record->{client_version}->{major},
              $record->{client_version}->{minor},
              do {
                my @c = split //, $record->{cipher_suites}->{value};
                my @v;
                while (@c) {
                  my $c1 = ord shift @c;
                  my $c2 = ord shift @c;
                  push @v, sprintf '%02X,%02X', $c1, $c2;
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
                      16 => 'ALPN',
                      18 => 'signed_certificate_timestamp',
                      21 => 'padding',
                      23 => 'extended_master_secret',
                      35 => 'SessionTicket',
                      13172 => 'NPN',
                      30032 => 'channel_id',
                      65281 => 'renegotiation_info',
                    }->{$type} // '', $length, hex_dump $data;
              }
            }
          }
        } else {
          warn sprintf "[%s] TLS handshake %d (%s) L=%d\n",
              $id,
              $record->{msg_type},
              {
                0 => 'hello_request',
                16 => 'client_key_exchange',
              }->{$record->{msg_type}} // '',
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
            }->{$record->{content_type}} // '',
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

my $DUMP = $ENV{DUMP};

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
{
  my $orig = AnyEvent::Handle->can ('_dotls');
  *AnyEvent::Handle::_dotls = sub {
    $_dump_tls->{$_[0]->{_rbio}} //= '';
    if (defined $CurrentID) {
      $_dump_tls->{$_[0]->{_rbio}, 'id'} = $CurrentID;
    }
    goto &$orig;
  } if $DUMP;
}

warn "Listening $host:$port...\n";
my $server = tcp_server $host, $port, sub {
  my ($fh, $client_host, $client_port) = @_;
  my $id = int rand 100000;
  warn "[$id] connected by $client_host:$client_port\n" if $DUMP;
  $cv->begin;
  my $states = {commands => [@$Commands], received => '', id => $id,
                client_host => $client_host, client_port => $client_port};

  my $hdl; $hdl = AnyEvent::Handle->new
      (fh => $fh,
       on_error => sub {
         my (undef, $fatal, $msg) = @_;
         if ($fatal) {
           warn "[$id] $msg (fatal)\n" if $DUMP;
           $hdl->destroy;
           $cv->end;
         } else {
           warn "[$id] $msg\n" if $DUMP;
         }
       },
       on_eof => sub {
         warn "[$id] EOF\n" if $DUMP;
         $hdl->destroy;
         $cv->end;
       },
       on_read => sub {
         $states->{received} .= $_[0]->{rbuf};
         if ($DUMP) {
           warn "[$id]\n";
           warn hex_dump ($_[0]->{rbuf}), "\n";
         }
         $_[0]->{rbuf} = '';
         run_commands 'read', $_[0], $states, sub { };
       });
  run_commands 'accepted', $hdl, $states, sub { };
};
syswrite STDOUT, "[server $host $port]\x0A";

$cv->recv;

__END__

echo -e 'receive "GET", start capture\nreceive CRLFCRLF, end capture
showcaptured\n"HTTP/1.0 101 OK"CRLF\n"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "\nws-accept\nCRLF\n"Connection: Upgrade"CRLF
CRLF\nws-receive-header\nws-receive-data\nws-send-header opcode=1 length=3
"abc"' | ./perl t_deps/server.pl 0 4355
