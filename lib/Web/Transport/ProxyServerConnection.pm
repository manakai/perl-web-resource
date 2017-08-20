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
  return $stream->headers_received->then (sub {
    my $req = $_[0];

    my $url = $req->{target_url};
    my $req_headers = _headers_without_connection_specific $req->{headers};
    my $request = {
      method => $req->{method},
      url => $url,
      _header_list => $req_headers->{forwarded},
      body_length => $req->{body_length}, # or undef
      body_stream => (defined $req->{body_length} ? $req->{body} : undef),
    };

    # XXX request handler
    # XXX XXX->({info => $info, request => $request});
    { # XXX default:
      my $info = $stream->{connection}->info;
      if ($info->{parent}->{type} eq 'TCP' and
          $info->{parent}->{local_host}->equals ($url->host) and
          $info->{parent}->{local_port} == $url->port) {
        return {
          status => 504,
          status_text => $Web::Transport::_Defs::ReasonPhrases->{504},
          headers => [['content-type' => 'text/plain;charset=utf-8']],
          body => \"504",
        };
      }
    }
    # XXX return response if requeset handler returns a response
    # XXX otherwise, continue with modified $request
    # XXX if failed, return 500

    # XXX proxy auth - 407

    # XXX reject TRACE ?
    if ($req->{method} eq 'CONNECT') {
      # XXX
      $req->{body}->cancel (405) if defined $req->{body};
      return {
        status => 405,
        status_text => $Web::Transport::_Defs::ReasonPhrases->{405},
        headers => [['Content-Type', 'text/plain; charset=utf-8']],
        body => \"405",
        close => 1,
      };
    }
    # XXX WS

    unless ($url->scheme eq 'http') {
      return {
        status => 504,
        status_text => $Web::Transport::_Defs::ReasonPhrases->{504},
        headers => [['content-type' => 'text/plain;charset=utf-8']],
        body => \"504",
      };
    }

    # XXX connection pool
    $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->{parent_id} = $stream->{id} . '.c';
    $client->proxy_manager ($opts->{client}->{proxy_manager});
    $client->resolver ($opts->{client}->{resolver});
    $client->tls_options ($opts->{client}->{tls_options});
    $client->last_resort_timeout ($opts->{client}->{last_resort_timeout});

    return $client->request (
      %$request,
      _forwarding => 1,
      stream => 1,
    )->then (sub {
      my $res = $_[0];

      if ($res->status == 407) {
        my $error = Web::Transport::ProtocolError->new
            ("Upstream server returns a 407 response");
        # XXX error log
        $res->body_stream->cancel ($error);

        return {
          status => 500,
          status_text => $Web::Transport::_Defs::ReasonPhrases->{500},
          headers => [['content-type' => 'text/plain;charset=utf-8']],
          body => \"500",
          body_is_incomplete => sub { 0 },
        };
      } # 407

      my $res_headers = _headers_without_connection_specific $res->{headers};
      my $response = {
        status => $res->{status},
        status_text => $res->{status_text},
        headers => $res_headers->{forwarded},
        body => $res->body_stream,
        body_is_incomplete => sub { return $res->incomplete },
      };

      # XXX response handler
      # XXX XXX->({response => $response})
      # XXX if failed, return 500 instead

      return {
        %$response,
        forwarding => 1,
      };
    }, sub { # $client->request failed
      my $result = $_[0];
      # XXX hook for logging $result
      warn $result;
      $client->abort ($result); # XXX cast to error object
      my $status = 503;
      my $error = '' . $result;
      if ($error =~ /^Network error: HTTP parse error/) {
        $status = 502;
      } elsif ($error =~ m{^Network error: (?:Protocol error|Perl I/O error)}) {
        $status = 504;
      }
      return {
        status => $status,
        status_text => $Web::Transport::_Defs::ReasonPhrases->{$status},
        headers => [['content-type' => 'text/plain;charset=utf-8']],
        body => \$status,
        body_is_incomplete => sub { 0 },
      };
    });
  })->then (sub {
    my $response = $_[0];
    return $stream->send_response ($response)->then (sub {
      my $writer = $_[0]->{body}->get_writer;
      if (ref $response->{body} eq 'SCALAR') {
        $writer->write
            (DataView->new (ArrayBuffer->new_from_scalarref ($response->{body})));
        return $writer->close;
      } else {
        my $reader = $response->{body}->get_reader;
        my $read; $read = sub {
          return $reader->read->then (sub {
            return if $_[0]->{done};
            return $writer->write ($_[0]->{value})->then ($read);
          });
        }; # $read
        return promised_cleanup { undef $read } $read->()->then (sub {
          if ($response->{body_is_incomplete}->()) {
            return $writer->write (DataView->new (ArrayBuffer->new (0)))->then (sub {
              return $writer->abort (Web::Transport::ProtocolError->new ("Upstram connection truncated")); # XXX propagate upstream connection's exception
            });
          } else {
            return $writer->close;
          }
        })->catch (sub {
          my $error = Web::Transport::Error->wrap ($_[0]);
          $reader->cancel ($error);
          die $error;
        });
      }
    })->catch (sub { # $stream->send_response failed
      my $error = Web::Transport::Error->wrap ($_[0]);
      if (not (ref $response->{body} eq 'SCALAR') and
          not $response->{body}->locked) {
        $response->{body}->cancel ($error);
      }
      return $client->abort ($error) if defined $client;
    });
  })->then (sub {
    return $client->close if defined $client;
  });
} # _handle_stream

1;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
