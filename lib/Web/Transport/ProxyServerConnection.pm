package Web::Transport::ProxyServerConnection;
use strict;
use warnings;
our $VERSION = '4.0';
use Streams::_Common;
use Web::Transport::GenericServerConnection;
use Promised::Flow;
use Web::Transport::Error;
use Web::Transport::TypeError;
use Web::Transport::ProtocolError;
use Web::Transport::CustomStream;

push our @ISA, qw(Web::Transport::GenericServerConnection);
push our @CARP_NOT, qw(
  ReadableStreamDefaultReader
  ReadableStreamBYOBReader
  Web::Transport::TypeError
  Web::Transport::ProtocolError
  Web::Transport::RequestConstructor
  Web::Transport::HTTPStream
  Web::Transport::ProxyServerConnection::API
);

sub _te ($) {
  return Web::Transport::TypeError->new ($_[0]);
} # _te

sub _pe ($) {
  return Web::Transport::ProtocolError->new ($_[0]);
} # _pe

sub _handle_stream ($$$) {
  my ($server, $stream, $opts) = @_;
  my $client;
  my $reqbody;
  my $resbody;
  my @wait;

  my $client_opts = {%{$opts->{client} or {}},
                     parent_id => $stream->{id} . '.c'};
  $client_opts->{last_resort_timeout} = -1
      unless defined $client_opts->{last_resort_timeout};
  $client_opts->{debug} = $server->{debug}
      unless defined $client_opts->{debug};
  # XXX disallow connect to the proxy server itself (even as a
  # $client's proxy)
  my $api = bless {
    client_opts => $client_opts,
    clients => {},
    id => $stream->{id},
    debug => $server->{debug},
  }, __PACKAGE__ . '::API';

  my $mode = '';
  return $stream->headers_received->then (sub {
    my $req = $_[0];
    $reqbody = $req->{body}; # or undef

    my $req_headers = Web::Transport::RequestConstructor->filter_headers
        ($req->{headers}, proxy_removed => 1);
    my $request = {
      method => $req->{method},
      url => $req->{target_url},
      headers => $req_headers,
      length => $req->{length}, # or undef
      body_stream => (defined $req->{length} ? $req->{body} : undef),
      forwarding => 1,
    };

    return Promise->resolve ({
      info => $stream->{connection}->info, request => $request,
      api => $api,
    })->then ($opts->{handle_request} || sub {
      ## Default request handler.
      ##
      ## Return an error response if target hostport is same as the
      ## proxy server's hostport.  This is incomplete; the target host
      ## might be resolved into the proxy server's IP address; the
      ## proxy's HTTP client's proxy might be same as the proxy
      ## server's hostport; and so on.
      ##
      ## Any other |CONNECT| request is not modified by the handler.
      ## Therefore such request will result in an error response.
      my $args = $_[0];
      my $transport = $args->{info}->{parent};
      if ($transport->{type} eq 'TCP' and
          $transport->{local_host}->equals ($args->{request}->{url}->host) and
          $transport->{local_port} == $args->{request}->{url}->port) {
        return {error => _pe "Request target is the proxy server itself"};
      }
      return $args;
    })->then (sub {
      my $result = $_[0];
      if (defined $result and ref $result eq 'HASH' and
          (defined $result->{response} or
           defined $result->{request} or
           defined $result->{error})) {
        die _te "Bad |response|"
            if defined $result->{response} and
               not ref $result->{response} eq 'HASH';
        die _te "Bad |request|"
            if defined $result->{request} and
               not ref $result->{request} eq 'HASH';
      } else {
        die _te "|handle_request| does not return |request| or |response|";
      }
      return $result;
    })->catch (sub { # request handler failed
      return {error => $_[0]};
    });
  })->then (sub {
    my $result = $_[0];
    return $result if defined $result->{response} or defined $result->{error};
    my $request = $result->{request};

    ## The |TRACE| method is a security hole.  We don't support the
    ## method.  However, if a proxy application wants to support the
    ## method in some way, it can be implemented within the
    ## |handle_request| handler.
    if ($request->{method} eq 'TRACE') {
      return {
        unused_request_body_stream => $request->{body_stream}, # or undef
        error => _pe "HTTP |TRACE| method",
        response => {
          status => 405,
          headers => [['Content-Type', 'text/plain; charset=utf-8']],
          body => "405",
        },
      };
    }

    ## The |CONNECT| method can be handled in one of these ways:
    ##
    ##   a) By returning an error response and close the connection,
    ##      if the |handle_request| handler returns no |upstream|.
    ##
    ##        upstream => undef,
    ##
    ##     1. Response.  If there is no |response|, a 405 response is
    ##        returned.  Otherwise, a response created from |response|
    ##        is returned.  Note that the |response|'s status can't be
    ##        2xx.
    ##
    ##   b) By forwarding the |CONNECT| request to the upstream
    ##      server, if the |handle_request| handler returns |upstream|
    ##      whose |type| is |forward|.  XXX not implemented
    ##
    ##        upstream => {
    ##          type => 'forward',
    ##          XXX upstream proxy URL
    ##        },
    ##
    ##   c) By establishing a tunnel to the upstream server, if the
    ##      |handle_request| handler returns |upstream| whose |type|
    ##      is |direct|.  XXX not implemented
    ##
    ##        upstream => {
    ##          type => 'direct',
    ##        },
    ##
    ##     1. Upstream.  A transport connection to |request|'s |url|'s
    ##        origin is created, using the proxy server's client
    ##        options.  If failed, an error response is returned and
    ##        the stream is aborted.
    ##
    ##     2. Response.  If there is no |response|, a 200 response is
    ##        returned.  Otherwise, a response created from |response|
    ##        is returned.  Note that the |response|'s status must be
    ##        2xx.
    ##
    ##     3. The upstream connection is associated with the tunnel.
    ##
    ##   d) By establishing a tunnel to a custom handler, if the
    ##      |handle_request| handler returns |upstream| whose |type|
    ##      is |custom|.  XXX not implemented
    ##
    ##        upstream => {
    ##          type => 'custom',
    ##          XXX readable
    ##          XXX writable
    ##        },
    ##
    ##   e) By establishing a tunnel to an MITM HTTPS server, if
    ##      |handle_request| handler returns |upstream| whose |type|
    ##      is |mitm|.
    ##
    ##        upstream => {
    ##          type => 'mitm',
    ##          tls => {tls options},
    ##        },
    ##
    ##     1. Upstream.  If XXX not implemented flag is enabled, an
    ##        HTTPS connection to |request|'s |url|'s origin is
    ##        created, using the proxy server's client options.  If
    ##        failed, an error response is returned.
    ##
    ##     2. Response.  If there is no |response|, a 200 response is
    ##        returned.  Otherwise, a response created from |response|
    ##        is returned.  Note that the |response|'s status must be
    ##        2xx.
    ##
    ##     3. MITM HTTPS server.  An MITM HTTPS server is created
    ##        using |upstream|'s |tls| option over the tunnel.  Any
    ##        request to the MITM HTTPS server is handled in the
    ##        normal ways (e.g. the |handle_request| handler is
    ##        invoked).
    if ($request->{method} eq 'CONNECT') {
      if (defined $result->{upstream}) {
        my $type = $result->{upstream}->{type} || '';
        if ($type eq 'mitm') {
          # XXX preconnect $result->{upstream}

          $result->{response} = {
            status => 200,
          } unless defined $result->{response};
          # XXX if bad status
          $mode = 'mitm';
          return $result;
        } else { # b) c) d)
          die "Bad |upstream| |type|: |$type|";
        }
      } else { # a)
        return {
          unused_request_body_stream => $request->{body_stream}, # or undef
          response => {
            status => 405,
            headers => [['Content-Type', 'text/plain; charset=utf-8']],
            body => "405",
            close => 1,
          },
        };
      }
    } # CONNECT

    # XXX WS

    ## Normal request/response

    my $url = $request->{url} || $request->{base_url};
    unless (UNIVERSAL::isa ($url, 'Web::URL')) {
      return {
        unused_request_body_stream => $request->{body_stream}, # or undef
        error => _te "No |url| argument",
      };
    }
    my $allowed = $opts->{_allowed_scheme} || 'http';
    unless ($url->scheme eq $allowed) {
      return {
        unused_request_body_stream => $request->{body_stream}, # or undef
        error => _pe "Target URL scheme is not |$allowed|",
      };
    }

    $client = $api->client ($url, $result->{client_options});
    return $client->request (
      %$request,
      stream => 1,
    )->then (sub {
      my $res = $_[0];

      if ($res->status == 407) {
        return {
          unused_request_body_stream => $res->body_stream,
          error => _pe "Upstream server returns a 407 response",
        };
      } # 407

      my $res_headers = Web::Transport::RequestConstructor->filter_headers
          ($res->{headers}, proxy_removed => 1);
      my $response = {
        status => $res->{status},
        status_text => $res->{status_text},
        headers => $res_headers,
        body_stream => $resbody = $res->body_stream,
        length => $res->{length}, # or undef
        body_is_incomplete => sub { return $res->incomplete },
        forwarding => 1,
      };

      return Promise->resolve ({
        info => $stream->{connection}->info, response => $response,
        data => $result->{data},
        closed => $stream->closed,
        api => $api,
      })->then ($opts->{handle_response} || sub { return $_[0] })->then (sub {
        my $result = $_[0];
        if (defined $result and ref $result eq 'HASH' and
            (defined $result->{response} or
             defined $result->{error})) {
          die _te "Bad |response|"
              if defined $result->{response} and
                 not ref $result->{response} eq 'HASH';
        } else {
          die _te "|handle_response| does not return |response|";
        }
        return $result;
      })->catch (sub { # response handler failed
        return {error => $_[0]};
      });
    }, sub { # $client->request failed
      my $result = $_[0];
      my $error;
      if ((ref $result eq 'HASH' or
           ref $result eq 'Web::Transport::Response') and
          defined $result->{error}) {
        $error = $result->{error};
      } else {
        $error = Web::Transport::Error->wrap ($result);
      }
      $client->abort ($error);
      return {
        unused_request_body_stream => $request->{body_stream}, # or undef
        error => $error,
      };
    });
  })->then (sub {
    my $result = $_[0];
    my $response = $result->{response};

    my $reader;
    if (defined $response and
        defined $response->{body_stream}) {
      $reader = $response->{body_stream}->get_reader ('byob'); # or throw
    }

    if (defined $result->{error} and not defined $response) {
      my $error = Web::Transport::Error->wrap ($result->{error});
      if (defined $reqbody and not $reqbody->locked) {
        $reqbody->cancel ($error);
      }
      if (defined $resbody and not $resbody->locked) {
        $resbody->cancel ($error);
      }
      if (defined $result->{unused_request_body_stream} and
          not (defined $reqbody and $reqbody eq $result->{unused_request_body_stream}) and
          not $result->{unused_request_body_stream}->locked) {
        $result->{unused_request_body_stream}->cancel ($error);
      }

      my $status = 500;
      if ($error->name eq 'Protocol error' or
          $error->name eq 'Perl I/O error') {
        $status = 504;
      } elsif ($error->name eq 'HTTP parse error') {
        $status = 502;
      }

      push @wait, Promise->resolve->then (sub {
        return $server->onexception->($server, $error);
      })->catch (sub {
        warn $_[0];
      });

      $response = {
        status => $status,
        headers => [['content-type' => 'text/plain;charset=utf-8']],
        body => $status,
      };
    } else {
      if (defined $result->{error}) {
        my $error = Web::Transport::Error->wrap ($result->{error});
        push @wait, Promise->resolve->then (sub {
          return $server->onexception->($server, $error);
        })->catch (sub {
          warn $_[0];
        });
      }

      if (defined $reqbody and not $reqbody->locked) {
        my $reader = $reqbody->get_reader;
        # XXX pipeTo null
        push @wait, promised_until {
          return $reader->read->then (sub {
            return $_[0]->{done};
          });
        }; # $read
      }
    }

    return [$response, $reader, $result];
  })->catch (sub {
    my $error = Web::Transport::Error->wrap ($_[0]);

    push @wait, Promise->resolve->then (sub {
      return $server->onexception->($server, $error);
    })->catch (sub {
      warn $_[0];
    });

    my $status = 500;
    return [{
      status => $status,
      headers => [['content-type' => 'text/plain;charset=utf-8']],
      body => $status,
    }, undef];
  })->then (sub {
    my ($response, $reader, $result) = @{$_[0]};
    return Promise->resolve->then (sub {
      $response = Web::Transport::RequestConstructor->create_response ($response); # or throws
      push @{$response->{headers}},
          ['Server', $server->{server_header}, 'server']
              unless $response->{forwarding};
      return $stream->send_response ($response);
    })->then (sub {
      my $writer;
      if (defined $_[0]->{readable} and defined $_[0]->{writable}) { # CONNECT
        if ($mode eq 'mitm') {
          my $custom = {
            readable => $_[0]->{readable},
            writable => $_[0]->{writable},
            closed => $stream->closed,
            id => $stream->info->{id} . 'C',
            parent_layered_type => $stream->info->{parent}->{parent}->{layered_type},
            type => 'CONNECT',
            class => 'Web::Transport::CustomStream',
          };
          my $con = __PACKAGE__->_new_mitm_server ($custom, {
            %$opts,
            parent_id => undef,
            tls => $result->{upstream}->{tls} || {},
            _allowed_scheme => 'https',
          });
          $con->onexception ($server->onexception);
          return $con->completed;
        } else { # $mode ne 'mitm'
          $writer = $_[0]->{writable}->get_writer;
          my $reader = $_[0]->{readable}->get_reader;
          promised_until { # XXX pipeTo null
            return $reader->read->then (sub {
              return $_[0]->{done};
            });
          };
          $writer->closed->then (sub {
            return $reader->cancel;
          });
        }
      } else { # non-CONNECT response
        $writer = $_[0]->{body}->get_writer;
      }

      if (defined $reader) {
        # XXX pipeTo
        return ((promised_until {
          return $reader->read (DataView->new (ArrayBuffer->new ($Streams::_Common::DefaultBufferSize)))->then (sub {
            return 'done' if $_[0]->{done};
            return $writer->write ($_[0]->{value})->then (sub {
              return not 'done';
            });
          });
        })->then (sub {
          return 0 unless defined $response->{body_is_incomplete};
          return $response->{body_is_incomplete}->();
        })->then (sub {
          if ($_[0]) { # is incomplete
            return $writer->write (DataView->new (ArrayBuffer->new (0)))->then (sub {
              return $writer->abort (Web::Transport::ProtocolError->new ("Upstram connection truncated")); # XXX propagate upstream connection's exception
            });
          } else {
            return $writer->close;
          }
        })->catch (sub {
          my $error = Web::Transport::Error->wrap ($_[0]);
          $reader->cancel ($error)->catch (sub { });
          $writer->abort ($error);
          die $error;
        }));
      } # body_stream

      if (defined $response->{body}) {
        $writer->write
            (DataView->new (ArrayBuffer->new_from_scalarref (\($response->{body})))); # or throw
      } # body
      return $writer->close;
    })->catch (sub { # $stream->send_response failed
      my $error = Web::Transport::Error->wrap ($_[0]);
      $reader->cancel ($error) if defined $reader;
      $client->abort ($error) if defined $client;
      $stream->abort ($error);
      return $server->onexception->($server, $error);
    })->catch (sub {
      warn $_[0]; # onexception failure
    });
  })->then (sub {
    if (defined $resbody and not $resbody->locked) {
      # XXX pipeTo null
      my $reader = $resbody->get_reader;
      push @wait, promised_until {
        return $reader->read->then (sub {
          return $_[0]->{done};
        });
      };
    }
    push @wait, $api->_close; # XXX persist client
  })->then (sub {
    return Promise->all (\@wait);
  });
} # _handle_stream

package Web::Transport::ProxyServerConnection::API;
use Promise;
use Web::Encoding;
use Web::Transport::BasicClient;

push our @CARP_NOT, qw(
  Web::Transport::BasicClient
  Web::Transport::RequestConstructor
);

sub client ($$;$$) {
  my ($self, $url, $client_opts, $args) = @_;
  my $opts = {%{$self->{client_opts}}, %{$client_opts || {}}};

  # XXX connection pool
  my $key;
  if (defined $opts->{server_connection}) {
    $key = join $;,
        'server_connection',
        $opts->{server_connection}->{url}->get_origin->to_ascii,
        defined $args->{key} ? $args->{key} : '';
  } else {
    $key = join $;,
        'origin',
        $url->get_origin->to_ascii,
        defined $args->{key} ? $args->{key} : '';
  }
  # XXX parent_id uniqueness is broken
  $opts->{parent_id} .= $args->{key} if defined $args->{key};
  my $cons = $self->{clients}->{$key} ||= [];

  for (@$cons) {
    return $_;
  }
  push @$cons, Web::Transport::BasicClient->new_from_url ($url, $opts);
  return $cons->[-1];
} # client

sub _close ($) {
  my $self = $_[0];
  return Promise->all ([map {
    $_->close;
  } map { @$_ } values %{delete $self->{clients}}]);
} # _close

sub filter_headers ($$;%) {
  shift;
  return Web::Transport::RequestConstructor->filter_headers (@_);
} # filter_headers

sub note ($$;%) {
  my ($self, $message, %args) = @_;
  my $level = $args{level} || 0;
  warn encode_web_utf8 sprintf "%s: %s\n",
      $self->{id}, $message
          if $level <= $self->{debug};
  if ($args{error}) {
    # XXX error log hook
  }
} # note

sub DESTROY ($) {
  local $@;
  eval { die };
  warn "$$: Reference to $_[0] is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

# XXX CONNECT documentation
# XXX CONNECT request forwarded as is (CONNECT response)
# XXX CONNECT request forwarded as is (non-CONNECT response)
# XXX CONNECT request forwarded with modification (CONNECT response)
# XXX CONNECT request forwarded with modification (non-CONNECT response)
# XXX CONNECT request connects to specified TCP server
# XXX CONNECT request connects to another TCP server
# XXX CONNECT request responded with |response|, connected to application

# XXX WS request forwarded as is (WS response)
# XXX WS request forwarded as is (non-WS response)
# XXX WS request forwarded with modification (WS response)
# XXX WS request forwarded with modification (non-WS response)
# XXX WS request forwarded as non-WS
# XXX WS request responded with |response| (WS response)
# XXX WS request responded with |response| (non-WS response)
# XXX WS request responded with |error|
# XXX WS request rejected
# XXX WS message proxying
# XXX non-WS request forwarded as WS (WS response)
# XXX non-WS request forwarded as WS (non-WS response)

1;

=head1 LICENSE

Copyright 2016-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
