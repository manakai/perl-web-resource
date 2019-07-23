package Web::Transport::TLSStream;
use strict;
use warnings;
our $VERSION = '4.0';
use Streams::_Common;
use Streams::IOError;
use Web::Transport::Error;
use Web::Transport::TypeError;
use Web::Transport::ProtocolError;
use ArrayBuffer;
use DataView;
use Streams::Devel;
use AnyEvent;
use Promise;
use Promised::Flow;
use Web::Host;
use Net::SSLeay;
use AnyEvent::TLS;
use Web::Transport::NetSSLeayError;
use Web::Transport::OCSP;
use Web::Transport::PKI::Parser;

push our @CARP_NOT, qw(
  Web::Transport::Error Web::Transport::TypeError Streams::IOError
  Web::Transport::NetSSLeayError Web::Transport::ProtocolError
  ReadableStream WritableStream
  Web::Transport::DefaultCertificateManager
  Web::Transport::CustomStream
  Web::Transport::TCPStream
  Web::Transport::UnixStream
  Web::Transport::TLSStream
  Web::Transport::SOCKS4Stream
  Web::Transport::SOCKS5Stream
  Web::Transport::H1CONNECTStream
);

# XXX alert stream
#sub has_alert ($) { return $_[0]->{has_alert} }

## OpenSSL constants
#sub SSL_ST_CONNECT () { 0x1000 }
#sub SSL_ST_ACCEPT () { 0x2000 }
#sub SSL_ST_MASK () { 0x0FFF }
#sub SSL_CB_LOOP () { 0x01 }
#sub SSL_CB_EXIT () { 0x02 }
sub SSL_CB_READ () { 0x04 }
#sub SSL_CB_WRITE () { 0x08 }
sub SSL_CB_ALERT () { 0x4000 }
use constant ERROR_SYSCALL => Net::SSLeay::ERROR_SYSCALL ();
use constant ERROR_WANT_READ => Net::SSLeay::ERROR_WANT_READ ();

sub match_cn($$$) {
   my ($name, $cn, $type) = @_;

   # remove leading and trailing garbage
   for ($name, $cn) {
      s/[\x00-\x1f]+$//;
      s/^[\x00-\x1f]+//;
    }

   my $pattern;

   ### IMPORTANT!
   # we accept only a single wildcard and only for a single part of the FQDN
   # e.g *.example.org does match www.example.org but not bla.www.example.org
   # The RFCs are in this regard unspecific but we don't want to have to
   # deal with certificates like *.com, *.co.uk or even *
   # see also http://nils.toedtmann.net/pub/subjectAltName.txt
   if ($type == 2 and $name =~m{^([^.]*)\*(.+)} ) {
      $pattern = qr{^\Q$1\E[^.]*\Q$2\E$}i;
   } elsif ($type == 1 and $name =~m{^\*(\..+)$} ) {
      $pattern = qr{^[^.]*\Q$1\E$}i;
   } else {
      $pattern = qr{^\Q$name\E$}i;
   }

   $cn =~ $pattern
}

# taken verbatim from IO::Socket::SSL, then changed to take advantage of
# AnyEvent utilities.
sub verify_hostname($$) {
   my ($cert, $cn) = @_;
   my $scheme = [0, 2, 1]; # rfc2818

   my $cert_cn = Net::SSLeay::X509_NAME_get_text_by_NID
       (Net::SSLeay::X509_get_subject_name ($cert),
        Net::SSLeay::NID_commonName ());
   my @cert_alt = Net::SSLeay::X509_get_subjectAltNames ($cert);

   # rfc2460 - convert to network byte order
   require AnyEvent::Socket;
   my $ip = AnyEvent::Socket::parse_address ($cn);

   my $alt_dns_count;

   while (my ($type, $name) = splice @cert_alt, 0, 2) {
      if ($type == Net::SSLeay::GEN_IPADD ()) {
         # $name is already packed format (inet_xton)
         return 1 if $ip eq $name;
      } elsif ($type == Net::SSLeay::GEN_DNS ()) {
         $alt_dns_count++;

         return 1 if match_cn $name, $cn, $scheme->[1];
      }
   }

   if ($scheme->[2] == 2
       || ($scheme->[2] == 1 && !$alt_dns_count)) {
      return 1 if match_cn $cert_cn, $cn, $scheme->[0];
   }

   0
}

sub _debug_info ($$) {
  my $info = $_[0];
  my $debug = $_[1];
  my $prefix = "$info->{id}:";

  if (defined $info->{openssl_version}) {
    warn "$prefix OpenSSL: $info->{openssl_version}->[0]\n";
    if ($debug > 1) {
      warn "$prefix   $info->{openssl_version}->[1]\n";
      warn "$prefix   $info->{openssl_version}->[2]\n";
      warn "$prefix   $info->{openssl_version}->[3]\n";
    }
  }
  if ($debug > 1) {
    if (defined $info->{net_ssleay_version}) {
      warn "$prefix Net::SSLeay: $info->{net_ssleay_version} $info->{net_ssleay_path}\n";
    }
  }

  if (defined $info->{tls_protocol}) {
    my $ver = $info->{tls_protocol} == 0x0301 ? '1.0' :
              $info->{tls_protocol} == 0x0302 ? '1.1' :
              $info->{tls_protocol} == 0x0303 ? '1.2' :
              $info->{tls_protocol} == 0x0304 ? '1.3' :
              sprintf '0x%04X', $info->{tls_protocol};
    warn "$prefix TLS version: $ver\n";
  }
  if (defined $info->{tls_cipher}) {
    warn "$prefix Cipher suite: $info->{tls_cipher} ($info->{tls_cipher_usekeysize})\n";
  }
  warn "$prefix Resumed session\n" if $info->{tls_session_resumed};
  my $i = 0;
  for (@{$info->{tls_cert_chain} or []}) {
    if (defined $_) {
      warn "$prefix #$i: @{[$_->debug_info]}\n";
    } else {
      warn "$prefix #$i: ?\n";
    }
    $i++;
  }
  if (defined (my $result = $info->{stapling_result})) {
    if ($result->{failed}) {
      warn "$prefix OCSP stapling: NG - $result->{message}\n";
    } else {
      warn "$prefix OCSP stapling: OK\n";
    }
    if (defined (my $res = $result->{response})) {
      #warn "$prefix   Status=$res->{response_status} Produced=$res->{produced}\n";
      #for my $r (values %{$res->{responses} or {}}) {
      #  warn "$prefix   - Status=$r->{cert_status} Revocation=$r->{revocation_time} ThisUpdate=$r->{this_update} NextUpdate=$r->{next_update}\n";
      #}
      for (@$res) {
        my $r = $_->[2];
        warn "$prefix   - Status=$r->{statusType} Revocation=$r->{revocationTime} ThisUpdate=$r->{thisUpdate} NextUpdate=$r->{nextUpdate}\n";
      }
    }
  } elsif (defined $info->{tls_protocol}) {
    warn "$prefix OCSP stapling: N/A\n";
  }
} # _debug_info

sub _tep ($) {
  return Promise->reject (Web::Transport::TypeError->new ($_[0]));
} # _tep

sub _pe ($) {
  return Web::Transport::ProtocolError->new ($_[0]);
} # _pe

## server : boolean : This end point is server (true) or client (false).
##
## parent : stream options : The options to create the underlying
## transport.  Required.
##
## certificate_manager : certificate manager : The certificate manager
## used to set the server certificates and to verify peer
## certificates.  Defaulted to the platform's default.  Required when
## |server| is true.
##
## cert, cert_file, key, key_file, ca_file, ca_path, ca_cert : Synonym
## for specifying a default |certificate_manager| with these options,
## kept only for backward compatibility.
##
## host : Web::Host? : The host of the server.  Required when |server|
## is false.
##
## si_host : Web::Host? : The host of the server, used to verify the
## service identity.  Defaulted to |host| value.  This option should
## not be used by normal applications.
##
## sni_host : Web::Host? : The host of the server, used to send the
## SNI extension's field.  Defaulted to |host| value.  This option
## should not be used by normal applications.
##
## protocol_clock : clock : The clock, used to obtain timestamps.
## Defaulted to the |Web::DateTime::Clock->realtime_clock|.  Note that
## this option does not affect any OpenSSL's internal verification
## process for, e.g., X.509 certificates.
##
## insecure : boolean : If true, the server protocol and certificate
## verification steps are skipped.
##
## signal : AbortSignal? : The abort signal that could abort the
## stream initialization steps.
##
## debug : debug option? : The debug option.
sub create ($$) {
  my ($class, $args) = @_;

  my $cm = $args->{certificate_manager};
  unless (defined $cm) {
    require Web::Transport::DefaultCertificateManager;
    $cm = Web::Transport::DefaultCertificateManager->new ($args);
  }

  unless ($args->{server}) {
    $args->{si_host} = $args->{host} unless defined $args->{si_host};
    $args->{sni_host} = $args->{host} unless defined $args->{sni_host};
    return _tep "Bad |host|" unless defined $args->{si_host};
    return _tep "Bad |host|" unless defined $args->{sni_host};
  }

  return _tep "Bad |parent|"
      unless defined $args->{parent} and ref $args->{parent} eq 'HASH' and
             defined $args->{parent}->{class};

  $args->{protocol_clock} ||= do {
    require Web::DateTime::Clock;
    Web::DateTime::Clock->realtime_clock;
  };

  my $info = {
    type => 'TLS',
    layered_type => 'TLS',
    server => !!$args->{server},
  };

  my $rc;
  my $wc;
  my ($r_closed, $s_closed) = promised_cv;

  my $wview;
  my $wresolve;
  my $wreject;

  my $tls;
  my $tls_ctx;
  my $rbio;
  my $wbio;
  my $process_tls;
  my $verify_error;

  my $handshake_ok;
  my $handshake_ng;
  my $handshake = Promise->new (sub {
    $handshake_ok = $_[0];
    $handshake_ng = $_[1];
  });

  my $t_r;
  my $t_w;
  my $t_read = sub { return Promise->resolve };
  my $t_read_pause;
  my $t_read_pausing;

  my $close; $close = sub {
    if (defined $tls) {
      Net::SSLeay::set_info_callback ($tls, undef);
      Net::SSLeay::set_verify ($tls, 0, undef);
      Net::SSLeay::free ($tls);
      undef $tls;
      $process_tls = sub { };
    }
    undef $rbio;
    undef $wbio;
    undef $tls_ctx;
    $s_closed->();
    $close = sub { };
  }; # $close

  my $signal;
  my $abort = sub {
    if (defined $signal) {
      $signal->manakai_onabort (undef);
      undef $signal;
    }

    if (defined $handshake_ok) {
      $verify_error = $tls && Net::SSLeay::get_verify_result ($tls);
      $handshake_ng->($_[0]);
      $handshake_ok = $handshake_ng = undef;
    }
    if (defined $rc) {
      eval { $rc->error ($_[0]) };
      my $req = $rc->byob_request;
      $req->manakai_respond_zero if defined $req;
      undef $rc;
    }
    if (defined $wc) {
      $wc->error ($_[0]);
      undef $wc;
    }
    if (defined $wreject) {
      $wreject->($_[0]);
      $wview = $wresolve = $wreject = undef;
    }

    if (defined $tls) {
      Net::SSLeay::set_quiet_shutdown ($tls, 1);
      Net::SSLeay::shutdown ($tls);
    }
    if (defined $t_w) {
      $t_w->abort ($_[0]);
      undef $t_w;
    }
    if (defined $t_r) {
      $t_r->cancel ($_[0])->catch (sub { });
      undef $t_r;
    }
    $close->();
    return 0; # no retry
  }; # $abort

  my $_process_tls = sub {
    Net::SSLeay::ERR_clear_error ();
    my $retry = 0;
    my $acted = 0;

    if (defined $wview) {
      my $r = eval { Net::SSLeay::write ($tls, $wview->manakai_to_string) };
      if ($@) {
        $wreject->();
        $wview = $wresolve = $wreject = undef;
        return;
      }
      if ($r <= 0) {
        $r = Net::SSLeay::get_error ($tls, $r);
        if ($r == ERROR_SYSCALL) {
          return $abort->(Streams::IOError->new ($!));
        } elsif ($r != ERROR_WANT_READ and $r != ERROR_SYSCALL) {
          return $abort->(Web::Transport::NetSSLeayError->new_current);
        } else {
          $retry = 1;
        }
      } else {
        note_buffer_copy $r, "TLS writer", "TLS";
        $wview = DataView->new
            ($wview->buffer,
             $wview->byte_offset + $r, $wview->byte_length - $r);
        $retry = $wview->byte_length > 0;
        unless ($retry) {
          $wresolve->();
          $wview = $wresolve = $wreject = undef;
        }
        $acted = 1;
      }
    } # $wview

    my $received_eof;
    while (1) {
      my $req = defined $rc ? $rc->byob_request : undef;
      my $read;
      if (defined $req) {
        $read = Net::SSLeay::read ($tls, $req->view->byte_length);
        if (defined $read and length $read) {
          note_buffer_copy length $read, "TLS", "TLS reader";
          my $src = ArrayBuffer->new_from_scalarref (\$read);
          $src->manakai_label ('TLS reader');
          ArrayBuffer::_copy_data_block_bytes
              $req->view->buffer, $req->view->byte_offset,
              $src, 0, $src->byte_length; # XXX this is arraybuffer internal
          $req->respond ($src->byte_length);
          $acted = 1;
          next;
        }
      } else {
        $read = Net::SSLeay::read ($tls, $Streams::_Common::DefaultBufferSize);
        if (defined $read and length $read) {
          note_buffer_copy length $read, "TLS", "TLS reader";
          my $src = ArrayBuffer->new_from_scalarref (\$read);
          $src->manakai_label ('TLS reader');
          $rc->enqueue (DataView->new ($src)) if defined $rc;
          $acted = 1;
          next;
        }
      }

      if (defined $read) { # EOF
        $received_eof = 1;
        last;
      } else { # error
        my $r = Net::SSLeay::get_error ($tls, -1); # -1 is not neccessarily correct, but Net::SSLeay doesn't tell us
        if ($r == ERROR_SYSCALL) {
          return $abort->(Streams::IOError->new ($!));
        } elsif ($r != ERROR_WANT_READ and $r != ERROR_SYSCALL) {
          return $abort->(Web::Transport::NetSSLeayError->new_current);
        }
        last;
      }
    } # while 1

    while (1){
      my $read = Net::SSLeay::BIO_read ($wbio, $Streams::_Common::DefaultBufferSize);
      if (defined $read and length $read) {
        note_buffer_copy length $read, "TLS", "Underlying transport writer of TLS";
        if (defined $t_w) {
          my $ab = ArrayBuffer->new_from_scalarref (\$read);
          $ab->manakai_label ('TLS underlying transport writer');
          my $p = $t_w->write (DataView->new ($ab));
          if (not defined $t_w->desired_size or $t_w->desired_size <= 0) {
            $p->then ($process_tls);
            return 0; # no retry
          }
        }
        $acted = 1;
      } else {
        last;
      }
    }

    if (defined $handshake_ok and
        Net::SSLeay::state ($tls) == Net::SSLeay::ST_OK ()) {
      $handshake_ok->();
      $handshake_ok = $handshake_ng = undef;
    }

    if ($received_eof) {
      return $abort->(_pe "Underlying transport closed during TLS handshake")
          if defined $handshake_ok;
      if (defined $rc) {
        $rc->close;
        my $req = $rc->byob_request;
        $req->manakai_respond_zero if defined $req;
        undef $rc;
      }
      return $close->() unless defined $wc;
      $acted = 1;
    }

    $t_read_pause = 1 if
        not defined $handshake_ok and
        not $acted and
        defined $rc and
        not defined $rc->byob_request;

    return $retry;
  }; # $_process_tls
  $process_tls = sub {
    return unless defined $tls;
    $t_read_pause = 0;
    my $retry = $_process_tls->();
    return $process_tls->() if $retry;
    return undef;
  }; # $process_tls

  $info->{readable} = ReadableStream->new ({
    type => 'bytes',
    auto_allocate_chunk_size => $Streams::_Common::DefaultBufferSize,
    start => sub {
      $rc = $_[1];
    },
    pull => sub {
      if ($t_read_pausing) {
        $t_read_pause = 0;
        $t_read_pausing = 0;
        return $t_read->()->catch ($abort);
      }
    },
    cancel => sub {
      $abort->(defined $_[1] ? $_[1] : "$class reader canceled");
    },
  });
  $info->{writable} = WritableStream->new ({
    start => sub {
      $wc = $_[1];
    },
    write => sub {
      my $view = $_[1];
      return Promise->resolve->then (sub {
        die Web::Transport::TypeError->new ("The argument is not an ArrayBufferView")
            unless UNIVERSAL::isa ($view, 'ArrayBufferView');
        return if $view->byte_length == 0; # or throw

        $wview = DataView->new
            ($view->buffer, $view->byte_offset, $view->byte_length); # or throw

        my $written = Promise->new (sub {
          $wresolve = $_[0];
          $wreject = $_[1];
        });

        $process_tls->();

        return $written;
      })->catch (sub {
        $abort->($_[0]);
        die $_[0];
      });
    }, # write
    close => sub {
      Net::SSLeay::shutdown ($tls);
      
      $process_tls->();

      my $wait;
      if (defined $t_w) {
        $wait = $t_w->close;
        undef $t_w;
      }

      undef $wc;
      $close->() if not defined $rc;

      return $wait;
    },
    abort => sub {
      $abort->(defined $_[1] ? $_[1] : "$class writer aborted");
    },
  });
  my ($r_parent_closed, $s_parent_closed) = promised_cv;
  $info->{closed} = Promise->all ([$r_closed, $r_parent_closed]);

  my $parent = {%{$args->{parent}}};
  $parent->{debug} = $args->{debug}
      if $args->{debug} and not defined $parent->{debug};
  $signal = $parent->{signal} = $args->{signal}; # or undef
  my $certs = [];
  my @verify;
  my $cert_args;
  Promise->resolve->then (sub {
    return $cm->prepare (server => $args->{server});
  })->then (sub {
    return Promise->all ([
      $cm->to_anyevent_tls_args_sync,
      $parent->{class}->create ($parent),
    ]);
  })->then (sub {
    $cert_args = $_[0]->[0];
    $info->{parent} = $_[0]->[1];
    $info->{layered_type} .= '/' . $info->{parent}->{layered_type};

    $info->{id} = $info->{parent}->{id} . 's';
    if ($args->{debug}) {
      my $action = $args->{server} ? 'start as server' : 'start as client';
      if (defined $args->{si_host} and defined $args->{sni_host}) {
        warn "$info->{id}: $info->{type}: $action (SNI |@{[$args->{si_host}->to_ascii]}|, SI |@{[$args->{sni_host}->to_ascii]}|)\n";
      } else {
        warn "$info->{id}: $info->{type}: $action\n";
      }
    }

    (delete $info->{parent}->{closed})->then ($s_parent_closed);
    $t_r = (delete $info->{parent}->{readable})->get_reader ('byob');
    $t_w = (delete $info->{parent}->{writable})->get_writer;
    $t_read = sub {
      return promised_until {
        if ($t_read_pausing) {
          $t_read_pausing = 1;
          return 'done';
        }
        my $view = DataView->new (ArrayBuffer->new ($Streams::_Common::DefaultBufferSize));
        $view->buffer->manakai_label ('TLS underlying transport reader');
        return $t_r->read ($view)->then (sub {
          my $v = $_[0];
          if ($v->{done}) {
            $process_tls->();

            if (defined $handshake_ok) {
              $abort->(_pe "Underlying transport closed during TLS handshake");
              return 'done';
            }

            ## Implementation does not always send TLS closure alert.
            if (defined $rc) {
              $rc->close;
              my $req = $rc->byob_request;
              $req->manakai_respond_zero if defined $req;
            undef $rc;
            }
            $close->() if not defined $wc;
            undef $t_r;
            return 'done';
          } else {
            Net::SSLeay::BIO_write ($rbio, $v->{value}->manakai_to_string);
            note_buffer_copy $v->{value}->byte_length,
                $v->{value}->buffer->debug_info, "TLS";
            $process_tls->();
            return not 'done';
          }
        });
      };
    }; # $t_read
    $t_read->()->catch ($abort);
    $t_r->closed->catch ($abort)->then (sub { undef $t_read });
    $t_w->closed->catch ($abort);

    if (defined $signal) {
      if ($signal->aborted) {
        my $error = $signal->manakai_error;
        $abort->($error);
        die $error;
      } else {
        $signal->manakai_onabort (sub {
          $abort->($signal->manakai_error);
        });
      }
    }

    my $vmode;
    if ($args->{insecure} and not $args->{verify}) {
      $vmode = Net::SSLeay::VERIFY_NONE ();
    } else {
      $args->{verify} = 1 unless defined $args->{verify};
      $vmode = Net::SSLeay::VERIFY_PEER ();
      $vmode |= Net::SSLeay::VERIFY_FAIL_IF_NO_PEER_CERT ()
          if $args->{verify_require_client_cert};
      $vmode |= Net::SSLeay::VERIFY_CLIENT_ONCE ()
          if $args->{verify_client_once};
    }

    my $tls_args = {map { $_ => $args->{$_} } grep { defined $args->{$_} } qw(
      method sslv2 sslv3 tlsv1 tlsv1_1 tlsv1_2
      verify verify_require_client_cert verify_peername verify_cb
      verify_client_once
      check_crl dh_file dh dh_single_use cipher_list session_ticket
    )};
    #prepare

    # XXX
    ## AnyEvent (7.16 Fri Jul 19 18:00:21 CEST 2019) changed default
    ## |dh| value from |schmorp1539| to |ffdhe3072| but some
    ## environments we support do not have it :-<
    $tls_args->{dh} //= 'schmorp1539';

    $tls_ctx = AnyEvent::TLS->new (
      %$tls_args,
      %$cert_args,
    );
    $tls = Net::SSLeay::new ($tls_ctx->ctx);
    $info->{openssl_version} = [
      Net::SSLeay::SSLeay_version (0),
      Net::SSLeay::SSLeay_version (2),
      Net::SSLeay::SSLeay_version (3),
      Net::SSLeay::SSLeay_version (4),
    ];
    $info->{net_ssleay_version} = $Net::SSLeay::VERSION;
    $info->{net_ssleay_path} = $INC{"Net/SSLeay.pm"};
    if ($args->{server}) {
      die Web::Transport::TypeError->new ("Bad |cert|") unless
          defined $cert_args->{cert} or defined $cert_args->{cert_file};
      die Web::Transport::TypeError->new ("Bad |key|") unless
          defined $cert_args->{key} or defined $cert_args->{key_file};

      Net::SSLeay::set_accept_state ($tls);
      Net::SSLeay::CTX_set_tlsext_servername_callback ($tls_ctx->ctx, sub {
        my $sn = Net::SSLeay::get_servername ($_[0]);
        $info->{sni_host} = Web::Host->parse_string ($sn) if defined $sn;
        if (defined $info->{sni_host}) {
          my $ca = $cm->to_anyevent_tls_args_for_host_sync ($info->{sni_host});
          if (defined $ca) {
            die Web::Transport::TypeError->new ("Bad |cert|") unless
                defined $ca->{cert} or defined $ca->{cert_file};
            die Web::Transport::TypeError->new ("Bad |key|") unless
                defined $ca->{key} or defined $ca->{key_file};

            my $cx = AnyEvent::TLS->new (%$tls_args, %$ca);
            Net::SSLeay::set_SSL_CTX ($tls, $cx->ctx);
            undef $cx;
            return;
          }
        }
        Net::SSLeay::set_SSL_CTX ($tls, $tls_ctx->ctx);
      });
      #$info->{tls_stapling} = undef;
    } else { # client
      Net::SSLeay::set_connect_state ($tls);
      if (defined $args->{sni_host} and $args->{sni_host}->is_domain) {
        Net::SSLeay::set_tlsext_host_name ($tls, $args->{sni_host}->stringify);
      }

      ## <https://www.openssl.org/docs/manmaster/ssl/SSL_CTX_set_verify.html>
      Net::SSLeay::set_verify $tls, $vmode, sub {
        my ($preverify_ok, $x509_store_ctx) = @_;
        my $depth = Net::SSLeay::X509_STORE_CTX_get_error_depth ($x509_store_ctx);
        my $cert = Net::SSLeay::X509_STORE_CTX_get_current_cert ($x509_store_ctx);
        $certs->[$depth] = Net::SSLeay::PEM_get_string_X509 ($cert);

        if ($depth == 0) {
          if (defined $args->{si_host}) {
            ## Delay the SI verification to keep verify callback's
            ## runtime minimum.
            push @verify, Promise->resolve->then (sub {
              return if not defined $tls; # aborted
              # XXX If ipaddr
              my $ok = verify_hostname $cert, $args->{si_host}->stringify;
              $abort->(_pe "Service Identity verification error") unless $ok;
            });
          }

          # XXX hook to verify the client cert
        }
        return $preverify_ok;
      };

      Net::SSLeay::set_tlsext_status_type
          $tls, Net::SSLeay::TLSEXT_STATUSTYPE_ocsp ();
      Net::SSLeay::CTX_set_tlsext_status_cb $tls_ctx->ctx, sub {
        my ($tls, $response) = @_;
        my $result = Web::Transport::OCSP->check_ssleay_ocsp_response
            ($tls, $response, $args->{protocol_clock});

        return 1 unless defined $result; # no OCSP response

        $info->{tls_stapling} = $result;
        $result->{error} = _pe $result->{error} if defined $result->{error};
        return ! $result->{fatal};
      };

      ## XXX As Net::SSLeay does not export OpenSSL's
      ## |SSL_CTX_set_client_cert_cb| function, it's not possible to
      ## hook when a client certificate is requested.
      #Net::SSLeay::CTX_set_client_cert_callback ($tls_ctx->ctx, sub {
      #});
    }
    # XXX session ticket
    # XXX ALPN

    ## <https://www.openssl.org/docs/manmaster/ssl/SSL_CTX_set_info_callback.html>
    Net::SSLeay::set_info_callback ($tls, sub {
      my ($tls, $where, $ret) = @_;
      if ($where & SSL_CB_ALERT and $where & SSL_CB_READ) {
        ## <https://www.openssl.org/docs/manmaster/ssl/SSL_alert_type_string.html>
        my $level = Net::SSLeay::alert_type_string ($ret); # W F U
        my $type = Net::SSLeay::alert_desc_string_long ($ret);
        if ($level eq 'W' and not $type eq 'close notify') {
          #XXX $self->{has_alert} = 1;
          # XXXAE::postpone { $self->{cb}->($self, 'alert', {message => $type}) };
        }
      }
    });

    # MODE_ENABLE_PARTIAL_WRITE | MODE_ACCEPT_MOVING_WRITE_BUFFER
    Net::SSLeay::set_mode ($tls, 1 | 2);
    $rbio = Net::SSLeay::BIO_new (Net::SSLeay::BIO_s_mem ());
    $wbio = Net::SSLeay::BIO_new (Net::SSLeay::BIO_s_mem ());

    Net::SSLeay::set_bio ($tls, $rbio, $wbio);

    $process_tls->();

  })->catch ($abort);

  return $handshake->then (sub {
    return Promise->all (\@verify);
  })->finally (sub {
    my $parser = Web::Transport::PKI::Parser->new;
    for my $depth (0..$#$certs) {
      $info->{tls_cert_chain}->[$depth] = $parser->parse_pem ($certs->[$depth])->[0]
          if defined $certs->[$depth];
    }
  })->then (sub {
    $info->{tls_protocol} = Net::SSLeay::version ($tls);
    #XXX session_id
    $info->{tls_session_resumed} = Net::SSLeay::session_reused ($tls);
    $info->{tls_cipher} = Net::SSLeay::get_cipher ($tls);
    $info->{tls_cipher_usekeysize} = Net::SSLeay::get_cipher_bits ($tls);

    ## Check must-staple flag
    if (not defined $info->{tls_stapling} and
        defined $info->{tls_cert_chain}->[0] and
        $info->{tls_cert_chain}->[0]->must_staple) {
      my $error = _pe "There is no stapled OCSP response, which is required by the certificate";
      $abort->($error);
      die $error;
    }

    if ($args->{debug}) {
      warn "$info->{id}: $info->{type}: ready\n";
      _debug_info $info, $args->{debug};
      $info->{closed}->then (sub {
        warn "$info->{id}: $info->{type}: closed\n";
      });
    }

    return $info;
  })->catch (sub {
    if (not defined $info->{tls_protocol} and $tls) {
      $info->{tls_protocol} = Net::SSLeay::version ($tls);
      #XXX session_id
      $info->{tls_session_resumed} = Net::SSLeay::session_reused ($tls);
      $info->{tls_cipher} = Net::SSLeay::get_cipher ($tls);
      $info->{tls_cipher_usekeysize} = Net::SSLeay::get_cipher_bits ($tls);
    }

    my $error;
    if (defined $info->{tls_stapling} and
        not $info->{tls_stapling}->{ok}) {
      $error = Web::Transport::Error->wrap ($info->{tls_stapling}->{error});
    } else {
      if ($verify_error) {
        ## <https://www.openssl.org/docs/manmaster/man3/SSL_get_verify_result.html>
        ## <https://www.openssl.org/docs/manmaster/man1/verify.html#DIAGNOSTICS>
        ## <https://metacpan.org/pod/Net::SSLeay#Low-level-API%3A-SSL_*-related-functions>
        my $s = Net::SSLeay::X509_verify_cert_error_string ($verify_error);
        $error = _pe "Certificate verification error $verify_error - $s";
      } else {
        $error = Web::Transport::Error->wrap ($_[0]);
      }
    }

    if ($args->{debug} and defined $info->{id}) {
      warn "$info->{id}: $info->{type}: failed ($error)\n";
      _debug_info $info, $args->{debug};
    }

    # XXX pass $info to application

    die $error;
  });
} # start

1;

## This module partially derived from AnyEvent.
## <http://cpansearch.perl.org/src/MLEHMANN/AnyEvent-7.11/COPYING>
## > This module is licensed under the same terms as perl itself.

# XXX Web compatibility of service identity check

=head1 LICENSE

Copyright 2016-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
