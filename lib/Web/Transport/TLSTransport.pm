package Web::Transport::TLSTransport;
use strict;
use warnings;
our $VERSION = '3.0';
use Carp qw(croak carp);
use AnyEvent;
use Promise;
use Net::SSLeay;
use AnyEvent::TLS;
use Web::Transport::OCSP;
use Web::Transport::PKI::Parser;

## Note that |protocol_clock| option does not affect any OpenSSL's
## internal verification process for, e.g., X.509 certificates.

sub new ($%) {
  my $self = bless {}, shift;
  $self->{args} = {@_};
  $self->{server} = delete $self->{args}->{server};
  unless ($self->{server}) {
    carp "|si_host| is not defined" unless defined $self->{args}->{si_host};
    carp "|sni_host| is not defined" unless defined $self->{args}->{sni_host};
  }
  $self->{args}->{protocol_clock} ||= do {
    require Web::DateTime::Clock;
    Web::DateTime::Clock->realtime_clock;
  };
  $self->{transport} = delete $self->{args}->{transport};
  $self->{id} = $self->{transport}->id . 's';
  return $self;
} # new

sub id ($) {
  return $_[0]->{id};
} # id

sub type ($) { return 'TLS' }
sub layered_type ($) { return $_[0]->type . '/' . $_[0]->{transport}->layered_type }
sub info ($) { return $_[0]->{info} } # or undef

sub request_mode ($;$) {
  if (@_ > 1) {
    if ($_[1] eq 'HTTP proxy') {
      $_[0]->{request_mode} = 'HTTP proxy';
    } else {
      delete $_[0]->{request_mode};
    }
  }
  return $_[0]->{request_mode} || 'default';
} # request_mode

sub has_alert ($) { return $_[0]->{has_alert} }

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
use constant ERROR_WANT_WRITE => Net::SSLeay::ERROR_WANT_WRITE ();

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

sub start ($$;%) {
  my $self = $_[0];
  croak "Bad state (TLSTransport::start)" if not defined $self->{args};
  $self->{cb} = $_[1];
  my $args = delete $self->{args};

  my $cm = $args->{certificate_manager};
  unless (defined $cm) {
    require Web::Transport::DefaultCertificateManager;
    $cm = Web::Transport::DefaultCertificateManager->new ($args);
  }
  
  $self->{_certs} = [];
  my @verify;
  my $p = Promise->new (sub { $self->{starttls_done} = [$_[0], $_[1]] });

  my $cert_args;
  Promise->resolve->then (sub {
    return $cm->prepare (server => $args->{server});
  })->then (sub {
    return $cm->to_anyevent_tls_args_sync;
  })->then (sub {
    $cert_args = $_[0];
    $self->{transport}->start (sub {
      my $type = $_[1];
    if ($type eq 'readdata') {
      Net::SSLeay::BIO_write ($self->{_rbio}, ${$_[2]});
      $self->_tls;
    } elsif ($type eq 'readeof') {
      unless ($self->{read_closed}) {
        my $data = $_[2];
        $data->{message} = 'Underlying transport closed before TLS closure'
            unless defined $data->{message};
        if (defined $self->{starttls_done}) {
          $data->{failed} = 1;
          (delete $self->{starttls_done})->[1]->($data);
        }
        if ($self->{started}) {
          AE::postpone { $self->{cb}->($self, 'readeof', $data) };
        }
        $self->{read_closed} = 1;
        $self->_close if $self->{write_closed};
      } else {
        #warn join ' ', "transport readeof", %{$_[2]};
      }
    } elsif ($type eq 'writeeof') {
      unless ($self->{write_closed}) {
        my $data = $_[2];
        $data->{message} = 'Underlying transport closed before TLS closure'
            unless defined $data->{message};
        if (defined $self->{starttls_done}) {
          $data->{failed} = 1;
          (delete $self->{starttls_done})->[1]->($data);
        }
        if ($self->{started}) {
          AE::postpone { $self->{cb}->($self, 'writeeof', $data) };
        }
        $self->{write_closed} = 1;
        $self->_close if $self->{read_closed};
      } else {
        #warn join ' ', "transport writeeof", %{$_[2]};
      }
    } elsif ($type eq 'open') {
      #
    } elsif ($type eq 'close') {
      if (defined $self->{starttls_done}) {
        (delete $self->{starttls_done})->[1]->({failed => 1, message => "Connection closed by a TLS error"});
      }
      if ($self->{started}) {
        AE::postpone { (delete $self->{cb})->($self, 'close') };
      } else {
        delete $self->{cb};
      }
      #delete $self->{transport};
    }
  })->then (sub {
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

    $self->{tls_ctx} = AnyEvent::TLS->new (
      %$tls_args,
      %$cert_args,
    );
    my $tls = $self->{tls} = Net::SSLeay::new ($self->{tls_ctx}->ctx);
    $self->{starttls_data} = {
      openssl_version => [
        Net::SSLeay::SSLeay_version (0),
        Net::SSLeay::SSLeay_version (2),
        Net::SSLeay::SSLeay_version (3),
        Net::SSLeay::SSLeay_version (4),
      ],
      net_ssleay_version => $Net::SSLeay::VERSION,
      net_ssleay_path => $INC{"Net/SSLeay.pm"},
    };
    $self->{starttls_data}->{ca_file} = $cert_args->{ca_file};
    $self->{starttls_data}->{ca_cert} = $cert_args->{ca_cert};
    if ($self->{server}) {
      ## Disable TLS 1.3 for now, for backcompat
      Net::SSLeay::set_max_proto_version ($tls, Net::SSLeay::TLS1_2_VERSION ());
      
      Net::SSLeay::set_accept_state ($tls);
      Net::SSLeay::CTX_set_tlsext_servername_callback ($self->{tls_ctx}->ctx, sub {
        $self->{starttls_data}->{sni_host_name} = Net::SSLeay::get_servername ($_[0]);
        # XXX hook for the application to choose a certificate
        Net::SSLeay::set_SSL_CTX ($tls, $self->{tls_ctx}->ctx);
      });
      $self->{starttls_data}->{stapling_result} = undef; # not applicable
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
        $self->{_certs}->[$depth] = Net::SSLeay::PEM_get_string_X509 ($cert);
        
        if ($depth == 0) {
          if (defined $args->{si_host}) {
            # XXX If ipaddr
            return 0 unless verify_hostname $cert, $args->{si_host}->stringify;
          }

          # XXX hook to verify the client cert
        }
        return $preverify_ok;
      };

      $self->{starttls_data}->{stapling_result} = undef;
      Net::SSLeay::set_tlsext_status_type
          $tls, Net::SSLeay::TLSEXT_STATUSTYPE_ocsp ();
      Net::SSLeay::CTX_set_tlsext_status_cb $self->{tls_ctx}->ctx, sub {
        my ($tls, $response) = @_;
        my $result = Web::Transport::OCSP->check_ssleay_ocsp_response
            ($tls, $response, $args->{protocol_clock});

        unless (defined $result) { # no OCSP response
          $self->{starttls_data}->{stapling_result} = undef;
          return 1;
        }

        $self->{starttls_data}->{stapling_result}
            = {failed => ! $result->{ok},
               message => $result->{error},
               response => (defined $result->{response} ? $result->{response} :
                            defined $result->{response_status} ? {response_status => $result->{response_status}} : undef)};
        return ! $result->{fatal};
      };

      ## XXX As Net::SSLeay does not export OpenSSL's
      ## |SSL_CTX_set_client_cert_cb| function, it's not possible to
      ## hook when a client certificate is requested.
      #Net::SSLeay::CTX_set_client_cert_callback ($self->{tls_ctx}->ctx, sub {
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
          $self->{has_alert} = 1;
          AE::postpone { $self->{cb}->($self, 'alert', {message => $type}) };
        }
      }
    });

    # MODE_ENABLE_PARTIAL_WRITE | MODE_ACCEPT_MOVING_WRITE_BUFFER
    Net::SSLeay::set_mode ($tls, 1 | 2);
    $self->{_rbio} = Net::SSLeay::BIO_new (Net::SSLeay::BIO_s_mem ());
    $self->{_wbio} = Net::SSLeay::BIO_new (Net::SSLeay::BIO_s_mem ());

    Net::SSLeay::set_bio ($tls, $self->{_rbio}, $self->{_wbio});
    ($Web::Transport::TLSTransport::debug_set_io || sub { })->($self->{_rbio}, $self->{_wbio}, $self->{id});

      $self->{wq} = [];
      $self->_tls;
    })->catch (sub { # start
      if (defined $self->{starttls_done}) {
        (delete $self->{starttls_done})->[1]->($_[0]);
      } else {
        #warn $_[0];
      }
    }); # start
    return undef;
  });

  return $p->then (sub {
    return Promise->all (\@verify);
  })->then (sub {
    $self->{cb}->($self, 'open');
  })->catch (sub {
    delete $self->{cb};

    my $data = $self->{starttls_data};
    if (defined $data and not defined $data->{tls_protocol} and $self->{tls}) {
      $data->{tls_protocol} = Net::SSLeay::version ($self->{tls});
      #XXX session_id
      $data->{tls_session_resumed} = Net::SSLeay::session_reused ($self->{tls});
      $data->{tls_cipher} = Net::SSLeay::get_cipher ($self->{tls});
      $data->{tls_cipher_usekeysize} = Net::SSLeay::get_cipher_bits ($self->{tls});
    }
    $self->{info} = $data;

    if (defined $data and defined $data->{stapling_result} and
        $data->{stapling_result}->{failed}) {
      die {failed => 1, message => $data->{stapling_result}->{message}};
    } else {
      my $n = $self->{tls} && Net::SSLeay::get_verify_result ($self->{tls});
      if ($n) {
        my $s = Net::SSLeay::X509_verify_cert_error_string ($n);
        die {failed => 1, message => "Certificate verification error $n - $s"};
      } elsif (ref $_[0] eq 'HASH') {
        die $_[0];
      } else {
        die {failed => 1, message => $_[0]};
      }
    }
  });
} # start

sub read_closed ($) { return $_[0]->{read_closed} }
sub write_closed ($) { return $_[0]->{write_closed} }
sub write_to_be_closed ($) { return $_[0]->{write_closed} || $_[0]->{write_shutdown} }

sub push_write ($$;$$) {
  my ($self, $ref, $offset, $length) = @_;
  croak "Bad state (TLSTransport::push_write)" if not defined $self->{wq} or $self->{write_shutdown};
  croak "Data is utf8-flagged" if utf8::is_utf8 $$ref;
  $offset = 0 unless defined $offset;
  croak "Bad offset" if $offset > length $$ref;
  $length = (length $$ref) - $offset unless defined $length;
  croak "Bad length" if $offset + $length > length $$ref;
  return if $length <= 0;
  push @{$self->{wq}}, [$ref, $length, $offset];
  $self->_tls;
} # push_write

sub push_promise ($) {
  my $self = $_[0];
  croak "Bad state (TLSTransport::push_promise)" if not defined $self->{wq} or $self->{write_shutdown};
  my ($ok, $ng);
  my $p = Promise->new (sub { ($ok, $ng) = @_ });
  push @{$self->{wq}}, [$ok, $ng];
  $self->_tls;
  return $p;
} # push_promise

sub push_shutdown ($) {
  my $self = $_[0];
  croak "Bad state (TLSTransport::push_shutdown)" if not defined $self->{wq} or $self->{write_shutdown};
  my ($ok, $ng);
  my $p = Promise->new (sub { ($ok, $ng) = @_ });
  push @{$self->{wq}}, [sub {
    Net::SSLeay::shutdown ($self->{tls});
    $self->{shutdown_after_tls} = 1;
    $self->{write_closed} = 1;
    AE::postpone { $self->{cb}->($self, 'writeeof', {}) };
    $ok->();
  }, $ng];
  $self->{write_shutdown} = 1;
  $self->_tls;
  return $p;
} # push_shutdown

sub _tls ($) {
  my ($self) = @_;

  Net::SSLeay::ERR_clear_error ();
  while (@{$self->{wq}}) {
    my $w = shift @{$self->{wq}};
    if (@$w == 3) { # data
      my $r = Net::SSLeay::write ($self->{tls}, substr ${$w->[0]}, $w->[2], $w->[1]);
      if ($r <= 0) {
        $r = Net::SSLeay::get_error ($self->{tls}, $r);
        if ($r != ERROR_WANT_READ and
            $r != ERROR_WANT_WRITE and
            $r != ERROR_SYSCALL) {
          my $data = {failed => 1};
          if ($r == ERROR_SYSCALL) {
            $data->{errno} = 0+$!;
            $data->{message} = "$!";
          } else {
            $data->{openssl_error} = Net::SSLeay::ERR_get_error ();
            $data->{message} = Net::SSLeay::ERR_error_string
                ($data->{openssl_error});
          }

          if (defined $self->{starttls_done}) {
            (delete $self->{starttls_done})->[1]->($data);
          } else {
            my $rc = $self->{read_closed};
            $self->{read_closed} = 1;
            $self->{write_closed} = 1;
            AE::postpone {
              $self->{cb}->($self, 'writeeof', $data);
              $self->{cb}->($self, 'readeof',
                            {failed => 1, message => 'Closed by write error'})
                  unless $rc;
            };
          }
          $self->abort (message => 'TLS error');
          return;
        }

        unshift @{$self->{wq}}, $w;
        last;
      } else { # $r > 0
        $w = [$w->[0], $w->[1] - $r, $w->[2] + $r];
        if ($w->[1] > 0) { # more to write
          unshift @{$self->{wq}}, $w;
          redo;
        }
      }
    } elsif (@$w == 2) { # promise
      $w->[0]->();
    } else {
      die "Bad wq data (l = @{[0+@$w]})";
    }
  } # $w

  while (defined (my $read = Net::SSLeay::read ($self->{tls}))) {
    if (length $read) {
      AE::postpone { $self->{cb}->($self, 'readdata', \$read) };
    } else { # EOF
      if (defined $self->{starttls_done}) {
        (delete $self->{starttls_done})->[1]->({failed => 1, message => "TLS handshake failed"});
      } else {
        unless ($self->{read_closed}) {
          $self->{read_closed} = 1;
          AE::postpone { $self->{cb}->($self, 'readeof', {}) };
        }
      }
      last;
    }
  }
  {
    my $r = Net::SSLeay::get_error ($self->{tls}, -1); # -1 is not neccessarily correct, but Net::SSLeay doesn't tell us
    if ($r != ERROR_WANT_READ and
        $r != ERROR_WANT_WRITE and
        $r != ERROR_SYSCALL) {
      my $data = {failed => 1};
      if ($r == ERROR_SYSCALL) {
        $data->{errno} = 0+$!;
        $data->{message} = "$!";
      } else {
        $data->{openssl_error} = Net::SSLeay::ERR_get_error ();
        $data->{message} = Net::SSLeay::ERR_error_string
            ($data->{openssl_error});
      }

      if (defined $self->{starttls_done}) {
        (delete $self->{starttls_done})->[1]->($data);
      } else {
        my $wc = $self->{write_closed};
        $self->{read_closed} = 1;
        $self->{write_closed} = 1;
        AE::postpone {
          $self->{cb}->($self, 'readeof', $data);
          $self->{cb}->($self, 'writeeof',
                        {failed => 1, message => 'Closed by read error'})
              unless $wc;
        };
      }
      $self->abort (message => 'TLS error');
      return;
    }
  }

  unless ($self->{transport}->write_to_be_closed) {
    while (1){
      my $read = Net::SSLeay::BIO_read ($self->{_wbio});
      if (defined $read and length $read) {
        $self->{transport}->push_write (\$read);
        ($Web::Transport::TLSTransport::debug_read || sub { })->($self->{_wbio}, $read);
      } else {
        last;
      }
    }
  }

  if (defined $self->{starttls_done}) {
    if (Net::SSLeay::state ($self->{tls}) == Net::SSLeay::ST_OK ()) {
      my $data = $self->{starttls_data};
      $data->{tls_protocol} = Net::SSLeay::version ($self->{tls});
      #XXX session_id
      $data->{tls_session_resumed} = Net::SSLeay::session_reused ($self->{tls});
      $data->{tls_cipher} = Net::SSLeay::get_cipher ($self->{tls});
      $data->{tls_cipher_usekeysize} = Net::SSLeay::get_cipher_bits ($self->{tls});

      my $parser = Web::Transport::PKI::Parser->new;
      for my $depth (0..$#{$self->{_certs}}) {
        $self->{starttls_data}->{tls_cert_chain}->[$depth] = $parser->parse_pem ($self->{_certs}->[$depth])->[0]
            if defined $self->{_certs}->[$depth];
      }

      delete $self->{starttls_data};
      $self->{started} = 1;
      (delete $self->{starttls_done})->[0]->($self->{info} = $data);
    }
  }

  if (delete $self->{shutdown_after_tls}) {
    $self->{transport}->push_shutdown
        unless $self->{transport}->write_to_be_closed;
  }
  $self->_close if $self->{read_closed} and $self->{write_closed};
} # _tls

sub abort ($;%) {
  my ($self, %args) = @_;
  delete $self->{args};
  if (defined $self->{tls}) {
    Net::SSLeay::set_quiet_shutdown ($self->{tls}, 1);
    Net::SSLeay::shutdown ($self->{tls});
  }
  $self->{write_shutdown} = 1;
  if (defined $self->{transport}) {
    $self->{transport}->abort (%args);
  }
} # abort

sub _close ($$) {
  my $self = $_[0];
  if (defined $self->{transport}) {
    $self->{transport}->push_shutdown
        unless $self->{transport}->write_to_be_closed;
  }
  while (@{$self->{wq} || []}) {
    my $q = shift @{$self->{wq}};
    if (@$q == 2) { # promise
      $q->[1]->();
    }
  }
  delete $self->{wq};
  if (defined $self->{tls}) {
    Net::SSLeay::set_info_callback ($self->{tls}, undef);
    Net::SSLeay::set_verify ($self->{tls}, 0, undef);
    Net::SSLeay::free (delete $self->{tls});
  }
  delete $self->{_rbio};
  delete $self->{_wbio};
  delete $self->{tls_ctx};
  # $self->{cb} is not deleted by this method
} # _close

sub DESTROY ($) {
  $_[0]->abort (message => "Aborted by DESTROY of $_[0]");

  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;

} # DESTROY

1;

## This module partially derived from AnyEvent.
## <http://cpansearch.perl.org/src/MLEHMANN/AnyEvent-7.11/COPYING>
## > This module is licensed under the same terms as perl itself.

# XXX if destroy is called before establishment
# XXX Web compatibility of service identity check

=head1 LICENSE

Copyright 2016-2024 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
