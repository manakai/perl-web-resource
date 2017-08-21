package Web::Transport::ProxyServerConnection;
use strict;
use warnings;
our $VERSION = '3.0';
use Web::Transport::GenericServerConnection;
use Promised::Flow;
use Web::Transport::Error;
use Web::Transport::TypeError;
use Web::Transport::ProtocolError;
use Web::Transport::BasicClient;

push our @ISA, qw(Web::Transport::GenericServerConnection);
push our @CARP_NOT, qw(
  Web::Transport::TypeError
  Web::Transport::ProtocolError
  Web::Transport::BasicClient
);

sub _te ($) {
  return Web::Transport::TypeError->new ($_[0]);
} # _te

sub _pe ($) {
  return Web::Transport::ProtocolError->new ($_[0]);
} # _pe

sub _headers_without_connection_specific ($) {
  my $return = {};
  # XXX move to _Defs
  my %remove = map { $_ => 1 } qw(
    host content-length transfer-encoding trailer te connection
    keep-alive proxy-connection upgrade proxy-authenticate proxy-authorization
  );
  for (@{$_[0]}) {
    if ($_->[2] eq 'connection') {
      for (split /,/, $_->[1]) {
        my $v = $_;
        $v =~ tr/A-Z/a-z/; ## ASCII case-insensitive.
        $v =~ s/\A[\x09\x0A\x0D\x20]+//;
        $v =~ s/[\x09\x0A\x0D\x20]+\z//;
        $remove{$v} = 1;
      }
    }
  }
  $return->{forwarded} = [map {
    if ($remove{$_->[2]}) {
      #push @{$return->{$_->[2]} ||= []}, $_->[1];
      ();
    } else {
      $_;
    }
  } @{$_[0]}];
  return $return;
} # _headers_without_connection_specific

sub _handle_stream ($$$) {
  my ($server, $stream, $opts) = @_;
  my $client;
  my $reqbody;
  my @wait;
  return $stream->headers_received->then (sub {
    my $req = $_[0];
    $reqbody = $req->{body}; # or undef

    my $req_headers = _headers_without_connection_specific $req->{headers};
    my $request = {
      method => $req->{method},
      url => $req->{target_url},
      headers => $req_headers->{forwarded},
      length => $req->{length}, # or undef
      body_stream => (defined $req->{length} ? $req->{body} : undef),
    };

    return Promise->resolve ({
      info => $stream->{connection}->info, request => $request,
    })->then ($opts->{handle_request} || sub {
      ## Default request handler - Return an error response if target
      ## hostport is same as the proxy server's hostport.  This is
      ## incomplete; the target host might be resolved into the proxy
      ## server's IP address; the proxy's HTTP client's proxy might be
      ## same as the proxy server's hostport; and so on.
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
    })->catch (sub {
      return {error => Web::Transport::Error->wrap ($_[0])};
    });
  })->then (sub {
    return $_[0] if defined $_[0]->{response} or defined $_[0]->{error};
    my $request = $_[0]->{request};

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

    # XXX $req->{method} eq 'CONNECT'
    if ($request->{method} eq 'CONNECT') { # XXX
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
    # XXX WS

    my $url = $request->{url} || $request->{base_url};
    unless (UNIVERSAL::isa ($url, 'Web::URL')) {
      return {
        unused_request_body_stream => $request->{body_stream}, # or undef
        error => _te "No |url| argument",
      };
    }
    unless ($url->scheme eq 'http') {
      return {
        unused_request_body_stream => $request->{body_stream}, # or undef
        error => _pe "Target URL scheme is not |http|",
      };
    }

    # XXX connection pool
    $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->{parent_id} = $stream->{id} . '.c';
    $client->proxy_manager ($opts->{client}->{proxy_manager});
    $client->resolver ($opts->{client}->{resolver});
    $client->tls_options ($opts->{client}->{tls_options});
    $client->last_resort_timeout ($opts->{client}->{last_resort_timeout});
    # XXX disallow connect to the proxy server itself (even as a
    # $client's proxy)

    return $client->request (
      %$request,
      _forwarding => 1,
      stream => 1,
    )->then (sub {
      my $res = $_[0];

      if ($res->status == 407) {
        return {
          unused_request_body_stream => $res->body_stream,
          error => _pe "Upstream server returns a 407 response",
        };
      } # 407

      my $res_headers = _headers_without_connection_specific $res->{headers};
      my $response = {
        status => $res->{status},
        status_text => $res->{status_text},
        headers => $res_headers->{forwarded},
        body_stream => $res->body_stream,
        body_is_incomplete => sub { return $res->incomplete },
      };

      # XXX response handler
      # XXX XXX->({response => $response})
      # XXX if failed, return 500 instead

      return {response => {
        %$response,
        forwarding => 1,
      }};
    }, sub { # $client->request failed
      my $result = $_[0];
      my $error = defined $result->{error}
          ? $result->{error} : Web::Transport::Error->wrap ($result);
      $client->abort ($error);
      return {
        unused_request_body_stream => $request->{body_stream}, # or undef
        error => $error,
      };
    });
  })->then (sub {
    my $result = $_[0];
    my $response = $result->{response};

    if (defined $result->{error} and not defined $response) {
      my $error = Web::Transport::ProtocolError->wrap ($result->{error});

      if (defined $reqbody and not $reqbody->locked) {
        $reqbody->cancel ($error);
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
        my $error = Web::Transport::ProtocolError->wrap ($result->{error});
        push @wait, Promise->resolve->then (sub {
          return $server->onexception->($server, $error);
        })->catch (sub {
          warn $_[0];
        });
      }

      if (defined $reqbody and not $reqbody->locked) {
        my $reader = $reqbody->get_reader;
        my $read; $read = sub {
          return $reader->read->then (sub {
            return if $_[0]->{done};
            return $read->();
          });
        }; # $read
        push @wait, promised_cleanup { undef $read } $read->();
      }
    }

    my $reader;
    if (defined $response->{body_stream}) {
      $reader = $response->{body_stream}->get_reader ('byob'); # or throw
      $reader->release_lock;
      $reader = $response->{body_stream}->get_reader;
    }

    return [$response, $reader];
  })->catch (sub {
    my $error = Web::Transport::ProtocolError->wrap ($_[0]);

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
    my ($response, $reader) = @{$_[0]};
    return $stream->send_response ($response)->then (sub {
      my $writer = $_[0]->{body}->get_writer;

      if (defined $reader) {
        my $read; $read = sub {
          return $reader->read->then (sub {
            return if $_[0]->{done};
            return $writer->write ($_[0]->{value})->then ($read);
          });
        }; # $read
        return promised_cleanup { undef $read } $read->()->then (sub {
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
        });
      } # body_stream

      if (defined $response->{body}) {
        $writer->write
            (DataView->new (ArrayBuffer->new_from_scalarref (\($response->{body})))); # or throw
      } # body
      return $writer->close;
    })->catch (sub { # $stream->send_response failed
      my $error = Web::Transport::Error->wrap ($_[0]);
      if (defined $response->{body_stream} and
          not $response->{body_stream}->locked) {
        $response->{body_stream}->cancel ($error);
      }
      $client->abort ($error) if defined $client;
      $stream->abort ($error);
      return $server->onexception->($server, $error);
    })->catch (sub {
      warn $_[0]; # onexception failure
    });
  })->then (sub {
    return $client->close if defined $client;
  })->then (sub {
    return Promise->all (\@wait);
  });
} # _handle_stream

# XXX test:
#  CONNECT
#  WS

1;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
