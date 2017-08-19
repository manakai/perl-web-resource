package Web::Transport::BasicClient;
use strict;
use warnings;
our $VERSION = '2.0';
use ArrayBuffer;
use DataView;
use Promise;
use Promised::Flow;
use Web::DomainName::Canonicalize qw(canonicalize_url_host);
use Web::Transport::RequestConstructor;
use Web::Encoding;
use Web::Transport::Error;
use Web::Transport::TypeError;
use Web::Transport::ProtocolError;
use Web::Transport::Response;
use Web::URL::Scheme qw(get_default_port);
use Web::Transport::TCPStream;
use Web::Transport::TLSStream;
use Web::Transport::HTTPStream;

push our @CARP_NOT, qw(
  Web::Transport::ProtocolError Web::Transport::TypeError
);

use constant DEBUG => $ENV{WEBUA_DEBUG} || 0;

sub _te ($) {
  return Web::Transport::TypeError->new ($_[0]);
} # _te

sub _pe ($) {
  return Web::Transport::ProtocolError->new ($_[0]);
} # _pe

sub new_from_url ($$) {
  die _te "No URL is specified" unless defined $_[1];
  my $origin = $_[1]->get_origin;
  die _te "The URL does not have a tuple origin" if $origin->is_opaque;
  return bless {
    base_url => $_[1],
    path_prefix => $_[1]->path,
    origin => $origin,
    queue => Promise->resolve,
    parent_id => ($$ . '.' . ++$Web::Transport::NextID),
  }, $_[0];
} # new_from_url

sub new_from_host ($$) {
  my $host = $_[1];
  die _te "Not a valid host" unless defined $host;
  return $_[0]->new_from_url
      (Web::URL->parse_string ('https://' . $host->to_ascii));
} # new_from_host

sub origin ($) {
  return $_[0]->{origin};
} # origin

sub proxy_manager ($;$) {
  if (@_ > 1) {
    $_[0]->{proxy_manager} = $_[1];
  }
  return $_[0]->{proxy_manager} ||= do {
    require Web::Transport::ENVProxyManager;
    Web::Transport::ENVProxyManager->new;
  };
} # proxy_manager

sub resolver ($;$) {
  if (@_ > 1) {
    $_[0]->{resolver} = $_[1];
    return unless defined wantarray;
  }
  return $_[0]->{resolver} ||= do {
    require Web::Transport::PlatformResolver;
    require Web::Transport::CachedResolver;
    require Web::DateTime::Clock;
    Web::Transport::CachedResolver->new_from_resolver_and_clock
        (Web::Transport::PlatformResolver->new,
         Web::DateTime::Clock->monotonic_clock);
  };
} # resolver

sub protocol_clock ($;$) {
  if (@_ > 1) {
    $_[0]->{protocol_clock} = $_[1];
  }
  return $_[0]->{protocol_clock} ||= do {
    require Web::DateTime::Clock;
    Web::DateTime::Clock->realtime_clock;
  };
} # protocol_clock

sub tls_options ($;$) {
  if (@_ > 1) {
    $_[0]->{tls_options} = $_[1];
  }
  return $_[0]->{tls_options};
} # tls_options

sub max_size ($;$) {
  if (@_ > 1) {
    $_[0]->{max_size} = $_[1];
  }
  return defined $_[0]->{max_size} ? $_[0]->{max_size} : -1;
} # max_size

sub debug ($;$) {
  if (@_ > 1) {
    $_[0]->{debug} = $_[1];
  }
  return defined $_[0]->{debug} ? $_[0]->{debug} : DEBUG;
} # debug

our $LastResortTimeout;
$LastResortTimeout = 60*10 unless defined $LastResortTimeout;
sub last_resort_timeout ($;$) {
  if (@_ > 1) {
    $_[0]->{last_resort_timeout} = $_[1];
  }
  return defined $_[0]->{last_resort_timeout}
      ? $_[0]->{last_resort_timeout} : $LastResortTimeout;
} # last_resort_timeout

my $proxy_to_transport = sub {
  ## create a transport for a proxy configuration
  my ($tid, $proxy, $url_record, $resolver, $clock, $no_cache, $debug) = @_;

  ## 1. If $proxy->{protocol} is not supported, return null.

  if ($proxy->{protocol} eq 'tcp') {
    return $resolver->resolve ($url_record->host, no_cache => $no_cache, debug => $debug)->then (sub {
      my $addr = $_[0];
      die _pe "Can't resolve host |@{[$url_record->host->stringify]}|"
          unless defined $addr;

      my $port = $url_record->port;
      $port = get_default_port $url_record->scheme if not defined $port;
      die _te "No port specified" unless defined $port;

      $port = 0+$port;
      warn "$tid: TCP @{[$addr->stringify]}:$port...\n" if $debug;
      return [{
        class => 'Web::Transport::TCPStream',
        id => $tid,
        host => $addr, port => $port,
      }, 0];
    });
  } elsif ($proxy->{protocol} eq 'http' or $proxy->{protocol} eq 'https') {
    return $resolver->resolve ($proxy->{host}, debug => $debug)->then (sub {
      die _pe "Can't resolve proxy host |@{[$proxy->{host}->stringify]}|"
          unless defined $_[0];
      my $pport = 0+(defined $proxy->{port} ? $proxy->{port} : ($proxy->{protocol} eq 'https' ? 443 : 80));
      warn "$tid: TCP @{[$_[0]->stringify]}:$pport...\n" if $debug;
      my $tparams = {
        class => 'Web::Transport::TCPStream',
        id => $tid,
        host => $_[0], port => $pport,
      };
      if ($proxy->{protocol} eq 'https') {
        $tparams = {
          %{$proxy->{tls_options} or {}},
          class => 'Web::Transport::TLSStream',
          parent => $tparams,
          si_host => $proxy->{host},
          sni_host => $proxy->{host},
          protocol_clock => $clock,
        };
      }
      if ($url_record->scheme eq 'https') {
        # XXX HTTP version
        require Web::Transport::H1CONNECTStream;
        $tparams = {
          class => 'Web::Transport::H1CONNECTStream',
          parent => {
            parent => $tparams, debug => $debug || $proxy->{debug},
          },
          target => (encode_web_utf8 $url_record->hostport),
        };
        # XXX auth
        return [$tparams, 0];
      } else {
        return [$tparams, 1];
      }
    });
  } elsif ($proxy->{protocol} eq 'socks4') {
    return Promise->all ([
      $resolver->resolve ($url_record->host, no_cache => $no_cache, debug => $debug), # XXX force ipv4 option ?
      $resolver->resolve ($proxy->{host}, debug => $debug),
    ])->then (sub {
      my $addr = $_[0]->[0];
      die _pe "Can't resolve host |@{[$url_record->host->stringify]}|"
          unless defined $addr;
      die _pe "Can't resolve host |@{[$url_record->host->stringify]}| into an IPv4 address"
          unless $addr->is_ipv4;
      my $proxy_addr = $_[0]->[1];
      die _pe "Can't resolve proxy host |@{[$proxy->{host}->stringify]}|"
          unless defined $proxy_addr;

      my $port = $url_record->port;
      $port = get_default_port $url_record->scheme if not defined $port;
      die _te "No port specified" unless defined $port;

      my $pport = 0+(defined $proxy->{port} ? $proxy->{port} : 1080);
      warn "$tid: TCP @{[$proxy_addr->stringify]}:$pport...\n" if $debug;
      my $tparams = {
        class => 'Web::Transport::TCPStream',
        id => $tid,
        host => $proxy_addr, port => $pport,
      };
      require Web::Transport::SOCKS4Stream;
      return [{
        class => 'Web::Transport::SOCKS4Stream',
        parent => $tparams,
        host => $addr, port => 0+$port,
      }, 0];
    });
  } elsif ($proxy->{protocol} eq 'socks5') {
    return $resolver->resolve ($proxy->{host}, debug => $debug)->then (sub {
      die _pe "Can't resolve proxy host |@{[$proxy->{host}->stringify]}|"
          unless defined $_[0];

      my $port = $url_record->port;
      $port = get_default_port $url_record->scheme if not defined $port;
      die _te "No port specified" unless defined $port;

      my $pport = 0+(defined $proxy->{port} ? $proxy->{port} : 1080);
      warn "$tid: TCP @{[$_[0]->stringify]}:$pport...\n" if $debug;
      my $tparams = {
        class => 'Web::Transport::TCPStream',
        id => $tid,
        host => $_[0], port => $pport,
      };
      require Web::Transport::SOCKS5Stream;
      return [{
        class => 'Web::Transport::SOCKS5Stream',
        parent => $tparams,
        host => $url_record->host, port => 0+$port,
      }, 0];
    });
  } elsif ($proxy->{protocol} eq 'unix') {
    warn "$tid: Unix $proxy->{path}...\n" if $debug;
    require Web::Transport::UnixStream;
    return Promise->resolve ([{
      class => 'Web::Transport::UnixStream',
      id => $tid,
      path => $proxy->{path},
    }, 0]);
  } else {
    return Promise->reject
        (_te "Proxy protocol |$proxy->{protocol}| not supported");
  }
}; # $proxy_to_transport

sub _connect ($$) {
  my ($self, $url_record, %args) = @_;
  return Promise->reject ($self->{aborted}) if defined $self->{aborted};

  if ($self->{http} and $self->{http}->is_active) {
    return Promise->resolve;
  }

  my $http = delete $self->{http};
  delete $self->{connect_promise};
  $http->abort if defined $http;
  if ($self->debug) {
    if (defined $http) {
      warn "$self->{parent_id}: @{[__PACKAGE__]}: Current connection is no longer active @{[scalar gmtime]}\n";
    } else {
      warn "$self->{parent_id}: @{[__PACKAGE__]}: New connection @{[scalar gmtime]}\n";
    }
  }

  # XXX $self->abort should cancel ongoing connect
  return $self->{connect_promise} ||= do {
    ## Establish a transport

    my $parent_id = $self->{parent_id};
    my $debug = $self->debug;

    $self->proxy_manager->get_proxies_for_url ($url_record)->then (sub {
      my $proxies = [@{$_[0]}];
      my $resolver = $self->resolver;

      # XXX wait for other connections

      my $get; $get = sub {
        if (@$proxies) {
          my $proxy = shift @$proxies;
          my $tid = $parent_id . '.' . ++$self->{tid};
          return $proxy_to_transport->($tid, $proxy, $url_record, $resolver,
                                       $self->protocol_clock,
                                       $args{no_cache}, $debug)->catch (sub {
            if (@$proxies) {
              return $get->();
            } else {
              die $_[0];
            }
          });
        } else {
          return Promise->reject (_te "No proxy available");
        }
      }; # $get
      $get->()->then (sub {
        my ($tparams, $request_mode_is_http_proxy) = @{$_[0]};
        undef $get;
        if ($url_record->scheme eq 'https') {
          return [{
            %{$self->{tls_options} or {}},
            class => 'Web::Transport::TLSStream',
            parent => $tparams,
            si_host => $url_record->host,
            sni_host => $url_record->host,
            protocol_clock => $self->protocol_clock,
          }, 0];
        }
        return [$tparams, $request_mode_is_http_proxy];
      }, sub {
        undef $get;
        die $_[0];
      });
    })->then (sub {
      my ($tparams, $request_mode_is_http_proxy) = @{$_[0]};
      if (not $request_mode_is_http_proxy and
          not $url_record->scheme eq 'http' and
          not $url_record->scheme eq 'https' and
          not $url_record->scheme eq 'ftp') {
        die _te "Bad URL scheme |@{[$url_record->scheme]}|";
      }
      return Promise->reject ($self->{aborted}) if defined $self->{aborted};
      $self->{http} = Web::Transport::HTTPStream->new
          ({parent => $tparams, debug => $debug});
      $self->{request_mode_is_http_proxy} = 1 if $request_mode_is_http_proxy;
      return $self->{http}->ready;
    })->catch (sub {
      delete $self->{connect_promise};
      delete $self->{http};
      undef $self;
      die $_[0];
    });
  };
} # _connect

sub _request ($$$$$$$$$$) {
  my ($self, $method, $url_record, $headers,
      $body_ref, $body_reader, $no_cache, $is_ws, $need_readable_stream) = @_;
  if ($self->debug) {
    warn "$self->{parent_id}: @{[__PACKAGE__]}: Request <@{[$url_record->stringify]}> @{[scalar gmtime]}\n";
  }
  return $self->_connect ($url_record, no_cache => $no_cache)->then (sub {
    return _te "Bad input URL" unless defined $url_record->host;
    my $target;
    if ($self->{request_mode_is_http_proxy}) {
      $target = $url_record->originpathquery;
    } else {
      $target = $url_record->pathquery;
    }

    my $length;
    $headers = [
      ['Host', encode_web_utf8 $url_record->hostport],
      ['Connection', 'keep-alive'],
      grep {
        if ($_->[2] eq 'content-length') {
          if (not defined $length and $_->[1] =~ /\A[0-9]+\z/) {
            $length = $_->[1];
          } else {
            die _te "Bad |Content-Length:| header";
          }
          ();
        } else {
          $_;
        }
      } @$headers,
    ];

    my $http = $self->{http};
    my $timeout = $self->last_resort_timeout;
    my $timer;
    if ($timeout > 0) {
      $timer = AE::timer $timeout, 0, sub {
        $http->abort (_pe "Last-resort timeout ($timeout)");
        undef $timer;
      };
    }

    return promised_cleanup { undef $timer } $http->send_request ({
      method => $method,
      target => encode_web_utf8 ($target),
      headers => $headers,
      ws => $is_ws,
      length => $length,
    })->then (sub {
      my $stream = $_[0]->{stream};

      my $reqbody = $_[0]->{body};
      if (defined $body_ref and length $$body_ref) {
        if (defined $reqbody) {
          my $writer = $reqbody->get_writer;
          $writer->write
              (DataView->new (ArrayBuffer->new_from_scalarref ($body_ref)))->catch (sub { });
          $writer->close->catch (sub { });
        } else {
          my $error = _te 'Request body is not allowed';
          $stream->abort ($error);
          die $error;
        }
      } elsif (defined $body_reader) {
        if (defined $reqbody) {
          my $writer = $reqbody->get_writer;
          my $read; $read = sub {
            return $body_reader->read->then (sub {
              return if $_[0]->{done};
              return $writer->write ($_[0]->{value})->then ($read);
            });
          }; # $read
          promised_cleanup { undef $read } $read->()->then (sub {
            return $writer->close;
          })->catch (sub {
            $writer->abort ($_[0]);
          });
        } else {
          my $error = _te 'Request body is not allowed';
          $stream->abort ($error);
          die $error;
        }
      }

      return $stream->headers_received->then (sub {
        my $response = $_[0];

        if (not $self->{request_mode_is_http_proxy} and
            $_[0]->{status} == 407) {
          my $error = _pe "HTTP |407| response from non-proxy";
          $_[0]->{body}->cancel ($error);
          die $error;
        }

          #XXX
          #if ($http->transport->type eq 'TLS' and
          #    not $transport->has_alert) {
          #  # XXX HSTS, PKP
          #}
        # XXX $response->{ws_connection_established} = $_[3];

        bless $response, 'Web::Transport::Response';

        if ($is_ws) {
          if (defined $response->{messages}) { # established
            my $queue = Promise->resolve;
            $response->{ws_send_binary} = sub {
              my $v = \($_[0]);
              return $queue = $queue->then (sub {
                my $dv = DataView->new (ArrayBuffer->new_from_scalarref ($v)); # XXX can throw XXXlocation
                return $stream->send_ws_message ($dv->byte_length, 1)->then (sub {
                  my $writer = $_[0]->{body}->get_writer;
                  $writer->write ($dv);
                  return $writer->close;
                });
              })->catch (sub {
                $stream->abort ($_[0]);
                die $_[0];
              });
            }; # ws_send_binary
            $response->{ws_send_text} = sub {
              my $text = encode_web_utf8 $_[0];
              return $queue = $queue->then (sub {
                return $stream->send_ws_message ((length $text), 0);
              })->then (sub {
                my $writer = $_[0]->{body}->get_writer;
                $writer->write
                    (DataView->new (ArrayBuffer->new_from_scalarref (\$text)));
                return $writer->close;
              })->catch (sub {
                $stream->abort ($_[0]);
                die $_[0];
              });
            }; # ws_send_text
            $response->{ws_close} = sub {
              my ($x, $y) = @_;
              return $queue = $queue->then (sub {
                return $stream->send_ws_close ($x, $y);
              })->then (sub {
                $self->{closed} = 1;
                undef $stream;
                undef $self;
                return Web::Transport::Response->new_from_error ($_[0]);
              }, sub {
                $self->{closed} = 1;
                undef $stream;
                undef $self;
                return Web::Transport::Response->new_from_error ($_[0]);
              });
            }; # ws_close
            $response->{ws_closed} = $stream->closed;
            $stream->closed->then (sub {
              delete $response->{ws_send_binary};
              delete $response->{ws_send_text};
              delete $response->{ws_close};
            });
            return [$response, $stream->closed];
          } else { # non-WS response
            $response->{ws} = 2;
          }
        }

        my $readable = delete $response->{body};
        if ($need_readable_stream) {
          $response->{body_stream} = $readable;
        } elsif (defined $readable) {
          my $reader = $readable->get_reader ('byob');
          $response->{body} = [];
          my $body_length = 0;
          my $max = $self->max_size;
          my $read; $read = sub {
            return $reader->read (DataView->new (ArrayBuffer->new (1024*10)))->then (sub {
              return if $_[0]->{done};
              push @{$response->{body}}, \($_[0]->{value}->manakai_to_string);

              if ($max >= 0) {
                $body_length += length ${$response->{body}->[-1]};
                if ($body_length >= $max) {
                  $stream->abort (_pe "Response body is larger than max_size ($max)");
                }
              }

              return $read->();
            });
          }; # $read
          return (promised_cleanup { undef $read } $read->())->then (sub {
            return $stream->closed;
          })->then (sub {
            die $_[0] if Web::Transport::ProtocolError->is_error ($_[0]);
            return [$response, undef];
          });
        } # $readable

        return [$response, $stream->closed];
      });
    });
  });
} # _request

sub request ($%) {
  my ($self, %args) = @_;
  return Promise->reject (_te "Client closed") if $self->{closed};

  my $ready = $self->{queue};
  my $s_queue;
  ($self->{queue}, $s_queue) = promised_cv;
  return $ready->then (sub {
    $args{base_url} ||= $self->{base_url};
    $args{path_prefix} = $self->{path_prefix} if not defined $args{path_prefix};
    $args{protocol_clock} = $self->protocol_clock;
    my ($method, $url_record, $header_list, $body_ref, $body_reader)
        = Web::Transport::RequestConstructor->create (\%args);
    die _te $method->{message} if ref $method; # error

    die _te "Method |CONNECT| not supported" if $method eq 'CONNECT';

    die _te "|body| is utf8-flagged"
        if defined $body_ref and utf8::is_utf8 ($$body_ref);

    my $url_origin = $url_record->get_origin;
    die _te "Bad URL origin |@{[$url_origin->to_ascii]}| (|@{[$self->{origin}->to_ascii]}| expected)"
        unless $url_origin->same_origin_as ($self->{origin});

    my $scheme = $url_record->scheme;
    my $is_ws = $scheme eq 'wss' || $scheme eq 'ws';
    if ($is_ws) {
      my $v = $url_record->originpathquery;
      $v =~ s/^ws/http/;
      $url_record = Web::URL->parse_string ($v);
    }

    my $max = $self->max_size;
    my $no_cache = $args{superreload};
    return $self->_request (
      $method, $url_record, $header_list, $body_ref, $body_reader,
      $no_cache, $is_ws, $args{stream},
    )->catch (sub {
      return $self->_request (
        $method, $url_record, $header_list, $body_ref, $body_reader,
        $no_cache, $is_ws, $args{stream},
      ) if Web::Transport::ProtocolError->can_http_retry ($_[0]) and
           not defined $body_reader;
      die $_[0];
    })->then (sub {
      my ($return, $wait) = @{$_[0]};
      $s_queue->($wait);
      die $return if defined $return->{ws} and $return->{ws} == 2;
      return $return;
    });
  })->catch (sub {
    die $_[0] if UNIVERSAL::isa ($_[0], 'Web::Transport::Response');
    my $error = Web::Transport::Error->wrap ($_[0]);
    $s_queue->(undef);
    die Web::Transport::Response->new_from_error ($error);
  });
} # request

sub close ($) {
  my $self = $_[0];
  return $self->{queue} if $self->{closed};
  $self->{closed} = 1;
  return $self->{queue} = $self->{queue}->then (sub {
    return undef if defined $self->{aborted};
    #XXX send_ws_close
    return $self->{http}->close_after_current_stream->then (sub {
      delete $self->{http};
      delete $self->{connect_promise};
      return undef;
    }) if defined $self->{http};
    return undef;
  })->then (sub {
    warn "$self->{parent_id}: @{[__PACKAGE__]}: Closed @{[scalar gmtime]}\n"
        if $self->debug;
    return undef;
  });
} # close

sub abort ($;$) {
  my $self = $_[0];

  if (defined $self->{aborted}) {
    return $self->{http}->closed if defined $self->{http};
    return Promise->resolve;
  }

  my $error = Web::Transport::Error->wrap
      (defined $_[1] ? $_[1] : 'Client aborted');
  $self->{closed} = 1;
  $self->{aborted} = $error;
  return $self->{http}->abort ($error)->then (sub {
    delete $self->{http};
    delete $self->{connect_promise}; # XXX abort ongoing one
    warn "$self->{parent_id}: @{[__PACKAGE__]}: Aborted ($error) @{[scalar gmtime]}\n"
        if $self->debug;
  }) if defined $self->{http};
  return Promise->resolve;
} # abort

sub DESTROY ($) {
  $_[0]->abort ("Aborted by DESTROY of $_[0]") unless $_[0]->{closed};

  local $@;
  eval { die };
  warn "$$: Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

1;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
