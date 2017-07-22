package Web::Transport::TLSStream;
use strict;
use warnings;
our $VERSION = '2.0';
use Streams::IOError;
use Web::DOM::Error;
use Web::DOM::TypeError;
use ArrayBuffer;
use DataView;
use Streams::Devel;
use AnyEvent;
use Promise;
use Promised::Flow;
use Net::SSLeay;
use AnyEvent::TLS;
use Web::Transport::OCSP;

push our @CARP_NOT, qw(
  Web::DOM::Error Web::DOM::TypeError Streams::IOError
  Web::Transport::TLSStream::OpenSSLError
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


sub _te ($) {
  return Web::DOM::TypeError->new ($_[0]);
} # _te

sub _tep ($) {
  return Promise->reject (Web::DOM::TypeError->new ($_[0]));
} # _tep

sub create ($$) {
  my ($class, $args) = @_;

  unless ($args->{server}) {
    ## Options |si_host| and |sni_host| are supported for testing.
    ## General-purpose application should only use |host| option.
    $args->{si_host} = $args->{host} unless defined $args->{si_host};
    $args->{sni_host} = $args->{host} unless defined $args->{sni_host};
    return _tep "Bad |host|" unless defined $args->{si_host};
    return _tep "Bad |host|" unless defined $args->{sni_host};
  }
  return _tep "Bad |parent|"
      unless defined $args->{parent} and ref $args->{parent} eq 'HASH' and
             defined $args->{parent}->{class};

  ## Note that |protocol_clock| option does not affect any OpenSSL's
  ## internal verification process for, e.g., X.509 certificates.
  $args->{protocol_clock} ||= do {
    require Web::DateTime::Clock;
    Web::DateTime::Clock->realtime_clock;
  };

  my $info = {
    type => 'TLS',
    layered_type => 'TLS',
    #XXX id => $args->{id},
    is_server => !!$args->{server},
  };

  my $rc;
  my $wc;

  my $wview;
  my $wresolve;
  my $wreject;

  my $tls;
  my $tls_ctx;
  my $rbio;
  my $wbio;
  my $process_tls;

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

  my $close = sub {
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
  }; # $close

  my $abort = sub {
    if (defined $handshake_ok) {
      $handshake_ng->($_[0]);
      $handshake_ok = $handshake_ng = undef;
    }
    if (defined $rc) {
      $rc->error ($_[0]);
      undef $rc;
    }
    if (defined $wc) {
      $wc->error ($_[0]);
      undef $wc;
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
          return $abort->(Web::Transport::TLSStream::OpenSSLError->new_current);
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
        $read = Net::SSLeay::read ($tls, 1024);
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
          return $abort->(Web::Transport::TLSStream::OpenSSLError->new_current);
        }
        last;
      }
    } # while 1

    while (1){
      my $read = Net::SSLeay::BIO_read ($wbio);
      if (defined $read and length $read) {
        note_buffer_copy length $read, "TLS", "Underlying transport writer of TLS";
        if (defined $t_w) {
          my $ab = ArrayBuffer->new_from_scalarref (\$read);
          $ab->manakai_label ('TLS underlying transport writer');
          my $p = $t_w->write (DataView->new ($ab));
          if ($t_w->desired_size <= 0) {
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
      return $abort->(_te "Underlying transport closed during TLS handshake")
          if defined $handshake_ok;
      if (defined $rc) {
        $rc->close;
        my $req = $rc->byob_request;
        $req->respond (0) if defined $req;
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

  $info->{read_stream} = ReadableStream->new ({
    type => 'bytes',
    auto_allocate_chunk_size => 1024*2,
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
  $info->{write_stream} = WritableStream->new ({
    start => sub {
      $wc = $_[1];
    },
    write => sub {
      my $view = $_[1];
      return Promise->resolve->then (sub {
        die _te "The argument is not an ArrayBufferView"
            unless UNIVERSAL::isa ($view, 'ArrayBufferView'); # XXX location
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

  $args->{parent}->{class}->create ($args->{parent})->then (sub {
    $info->{parent} = $_[0];
    $info->{layered_type} .= '/' . $info->{parent}->{layered_type};
    #XXX $self->{id} = $self->{transport}->id . 's';

    $t_r = (delete $info->{parent}->{read_stream})->get_reader ('byob');
    $t_w = (delete $info->{parent}->{write_stream})->get_writer;
    $t_read = sub {
      return $t_read_pausing = 1 if $t_read_pausing;
      my $view = DataView->new (ArrayBuffer->new (1024));
      $view->buffer->manakai_label ('TLS underlying transport reader');
      return $t_r->read ($view)->then (sub {
        my $v = $_[0];
        if ($v->{done}) {
          $process_tls->();

          return $abort->(_te "Underlying transport closed during TLS handshake")
              if defined $handshake_ok;

          ## Implementation does not always send TLS closure alert.
          if (defined $rc) {
            $rc->close;
            my $req = $rc->byob_request;
            $req->respond (0) if defined $req;
            undef $rc;
          }
          $close->() if not defined $wc;
          undef $t_r;
          return;
        } else {
          Net::SSLeay::BIO_write ($rbio, $v->{value}->manakai_to_string);
          note_buffer_copy $v->{value}->byte_length,
              $v->{value}->buffer->debug_info, "TLS";
          $process_tls->();
          return $t_read->();
        }
      });
    }; # $t_read
    $t_read->()->catch ($abort);
    $t_r->closed->catch ($abort)->then (sub { undef $t_read });
    $t_w->closed->catch ($abort);

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

    $tls_ctx = AnyEvent::TLS->new (%$args);
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
      Net::SSLeay::set_accept_state ($tls);
      Net::SSLeay::CTX_set_tlsext_servername_callback ($tls_ctx->ctx, sub {
        $info->{sni_host_name} = Net::SSLeay::get_servername ($_[0]);
        # XXX hook for the application to choose a certificate
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
        $info->{tls_cert_chain}->[$depth]
            = bless [Net::SSLeay::PEM_get_string_X509 ($cert)],
                __PACKAGE__ . '::Certificate';

        if ($depth == 0) {
          if (defined $args->{si_host}) {
            # XXX If ipaddr
            return 0 unless verify_hostname $cert, $args->{si_host}->stringify;
          }

          # XXX hook to verify the client cert
        }
        return $preverify_ok;
      };

      Net::SSLeay::set_tlsext_status_type
          $tls, Net::SSLeay::TLSEXT_STATUSTYPE_ocsp ();
      Net::SSLeay::CTX_set_tlsext_status_cb $tls_ctx->ctx, sub {
        my ($tls, $response) = @_;
        unless ($response) {
          return 1;
        }

        my $status = Net::SSLeay::OCSP_response_status ($response);
        if ($status != Net::SSLeay::OCSP_RESPONSE_STATUS_SUCCESSFUL ()) {
          #$info->{tls_stapling}->{ok} = 0;
          $info->{tls_stapling}->{response_status} = $status;
          $info->{tls_stapling}->{error} = _te "OCSP response failed ($status)";
          return 1;
        }

        unless (eval { Net::SSLeay::OCSP_response_verify ($tls, $response) }) {
          #$info->{tls_stapling}->{ok} = 0;
          $info->{tls_stapling}->{error} = _te "OCSP response verification failed";
          return 1;
        }

        my $cert = Net::SSLeay::get_peer_certificate ($tls);
        my $certid = eval { Net::SSLeay::OCSP_cert2ids ($tls, $cert) };
        unless ($certid) {
          #$info->{tls_stapling}->{ok} = 0;
          $info->{tls_stapling}->{error} = _te "Can't get certid from certificate: $@";
          return 1;
        }
        $certid = substr $certid, 2; # remove SEQUENCE header

        my $res = Web::Transport::OCSP->parse_response_byte_string
            (Net::SSLeay::i2d_OCSP_RESPONSE ($response));
        my $error = Web::Transport::OCSP->check_cert_id_with_response
            ($res, $certid, $args->{protocol_clock});
        if (not defined $error) {
          $info->{tls_stapling}->{ok} = 1;
          $info->{tls_stapling}->{response} = $res;
          return 1;
        } else {
          #$info->{tls_stapling}->{ok} = 0;
          $info->{tls_stapling}->{response} = $res;
          $info->{tls_stapling}->{error} = _te $error;
          return 0;
        }
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
    $info->{tls_protocol} = Net::SSLeay::version ($tls);
    #XXX session_id
    $info->{tls_session_resumed} = Net::SSLeay::session_reused ($tls);
    $info->{tls_cipher} = Net::SSLeay::get_cipher ($tls);
    $info->{tls_cipher_usekeysize} = Net::SSLeay::get_cipher_bits ($tls);

    ## Check must-staple flag
    if (not defined $info->{tls_stapling} and
        defined $info->{tls_cert_chain}->[0] and
        Web::Transport::OCSP->x509_has_must_staple ($info->{tls_cert_chain}->[0])) {
      return $abort->(_te "There is no stapled OCSP response, which is required by the certificate");
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

    # XXX pass $info to application
    if (defined $info->{tls_stapling} and
        not $info->{tls_stapling}->{ok}) {
      die Web::DOM::Error->wrap ($info->{tls_stapling}->{error});
    } else {
      my $n = $tls && Net::SSLeay::get_verify_result ($tls);
      if ($n) {
        my $s = Net::SSLeay::X509_verify_cert_error_string ($n);
        die _te "Certificate verification error $n - $s";
      } else {
        die Web::DOM::Error->wrap ($_[0]);
      }
    }
  });
} # start

package Web::Transport::TLSStream::OpenSSLError;
use Web::DOM::Exception;
push our @ISA, qw(Web::DOM::Exception);

$Web::DOM::Error::L1ObjectClass->{(__PACKAGE__)} = 1;

sub new_current ($) {
  my $self = $_[0]->SUPER::new ('', 'OpenSSL error');
  $self->{errno} = Net::SSLeay::ERR_get_error ();
  $self->{message} = Net::SSLeay::ERR_error_string ($self->{errno});
  return $self;
} # new_current

package Web::Transport::TLSStream::Certificate;

sub debug_info ($) {
  my $bio = Net::SSLeay::BIO_new (Net::SSLeay::BIO_s_mem ());
  Net::SSLeay::BIO_write ($bio, $_[0]->[0]);
  my $cert = Net::SSLeay::PEM_read_bio_X509 ($bio);
  return 'Bad certificate' unless $cert;

  my @r;
  my $ver = Net::SSLeay::X509_get_version $cert;
  push @r, "version=$ver";
  my $in = Net::SSLeay::X509_get_issuer_name $cert;
  push @r, 'I=' . Net::SSLeay::X509_NAME_print_ex ($in, Net::SSLeay::XN_FLAG_RFC2253 (), 0);
  my $sn = Net::SSLeay::X509_get_subject_name $cert;
  push @r, 'S=' . Net::SSLeay::X509_NAME_print_ex ($sn, Net::SSLeay::XN_FLAG_RFC2253 (), 0);
  my @san = Net::SSLeay::X509_get_subjectAltNames $cert;
  while (@san) {
    my $type = (shift @san);
    $type = {
      2 => 'DNS',
      7 => 'IP', # XXX decode value
    }->{$type} || $type;
    push @r, 'SAN.'.$type . '=' . (shift @san);
  }
  push @r, '#=' . Net::SSLeay::P_ASN1_INTEGER_get_hex Net::SSLeay::X509_get_serialNumber $cert;
  {
    my $time = Net::SSLeay::X509_get_notBefore $cert;
    push @r, 'notbefore=' . Net::SSLeay::P_ASN1_TIME_get_isotime $time;
  }
  {
    my $time = Net::SSLeay::X509_get_notAfter $cert;
    push @r, 'notafter=' . Net::SSLeay::P_ASN1_TIME_get_isotime $time;
  }
  my @type = Net::SSLeay::P_X509_get_netscape_cert_type $cert;
  if (@type) {
    push @r, 'netscapecerttype=' . join ',', @type;
  }
  if (Web::Transport::OCSP->x509_has_must_staple ($_[0])) {
    push @r, 'must-staple';
  }

  Net::SSLeay::BIO_free ($bio);
  Net::SSLeay::X509_free ($cert);

  return join ' ', @r;
} # debug_info

1;

## This module partially derived from AnyEvent.
## <http://cpansearch.perl.org/src/MLEHMANN/AnyEvent-7.11/COPYING>
## > This module is licensed under the same terms as perl itself.

# XXX Web compatibility of service identity check

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut