package Web::Transport::ProxyServerConnection;
use strict;
use warnings;
our $VERSION = '3.0';
use Web::Transport::GenericServerConnection;
use Promised::Flow;
use Web::Transport::Error;
use Web::Transport::TypeError;
use Web::Transport::ProtocolError;

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
      unless defined $server->{debug};
  # XXX disallow connect to the proxy server itself (even as a
  # $client's proxy)
  my $api = bless {
    client_opts => $client_opts,
    clients => {},
    id => $stream->{id},
    debug => $server->{debug},
  }, __PACKAGE__ . '::API';

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
    })->catch (sub { # request handler failed
      return {error => $_[0]};
    });
  })->then (sub {
    my $result = $_[0];
    return $result if defined $result->{response} or defined $result->{error};
    my $request = $result->{request};

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

    $client = $api->client ($url);
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
    }

    return [$response, $reader];
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
    my ($response, $reader) = @{$_[0]};
    return Promise->resolve->then (sub {
      $response = Web::Transport::RequestConstructor->create_response ($response); # or throws
      push @{$response->{headers}},
          ['Server', $server->{server_header}, 'server']
              unless $response->{forwarding};
      return $stream->send_response ($response);
    })->then (sub {
      my $writer = $_[0]->{body}->get_writer;

      if (defined $reader) {
        my $read; $read = sub {
          return $reader->read (DataView->new (ArrayBuffer->new (1024*1024)))->then (sub {
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
      $reader->cancel ($error) if defined $reader;
      $client->abort ($error) if defined $client;
      $stream->abort ($error);
      return $server->onexception->($server, $error);
    })->catch (sub {
      warn $_[0]; # onexception failure
    });
  })->then (sub {
    if (defined $resbody and not $resbody->locked) {
      my $reader = $resbody->get_reader;
      my $read; $read = sub {
        return $reader->read->then (sub {
          return if $_[0]->{done};
          return $read->();
        });
      }; # $read
      push @wait, promised_cleanup { undef $read } $read->();
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

sub client ($$) {
  my ($self, $url) = @_;
  # XXX connection pool
  my $cons = $self->{clients}->{$url->get_origin->to_ascii} ||= [];
  for (@$cons) {
    unless ($_->is_active) {
      return $_;
    }
  }
  push @$cons, Web::Transport::BasicClient->new_from_url
      ($url, $self->{client_opts});
  return $cons->[-1];
} # client

sub _close ($) {
  my $self = $_[0];
  return Promise->all ([map {
    $_->close;
  } map { @$_ } values %{$self->{clients}}]);
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

# XXX CONNECT request forwarded as is (CONNECT response)
# XXX CONNECT request forwarded as is (non-CONNECT response)
# XXX CONNECT request forwarded with modification (CONNECT response)
# XXX CONNECT request forwarded with modification (non-CONNECT response)
# XXX CONNECT request forwarded as non-CONNECT (non-2xx)
# XXX CONNECT request forwarded as non-CONNECT (2xx)
# XXX CONNECT request connects to specified TCP server
# XXX CONNECT request connects to another TCP server
# XXX CONNECT request responded with |response|, connected to application
# XXX CONNECT request responded with |response| (2xx with body)
# XXX CONNECT request responded with |response| (non-2xx)
# XXX CONNECT request responded with |error|
# XXX CONNECT request rejected
# XXX non-CONNECT request forwarded as CONNECT

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

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
