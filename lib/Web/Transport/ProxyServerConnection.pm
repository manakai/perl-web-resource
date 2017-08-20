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
  return $stream->headers_received->then (sub {
    my $req = $_[0];

    # XXX proxy auth - 407

    # XXX reject TRACE ?
    if ($req->{method} eq 'CONNECT') {
      # XXX
      return $stream->send_response ({
        status => 405,
        status_text => $Web::Transport::_Defs::ReasonPhrases->{405},
        headers => [['Content-Type', 'text/plain; charset=utf-8']],
        close => 1,
      })->then (sub {
        my $writer = $_[0]->{body}->get_writer;
        $writer->write
            (DataView->new (ArrayBuffer->new_from_scalarref (\"405")));
        return $writer->close;
      })->then (sub {
        $req->{body}->cancel (405) if defined $req->{body};
        return $stream->abort (405);
      });
    }
    # XXX WS

    my $url = $req->{target_url};
    unless ($url->scheme eq 'http') {
      return $stream->send_response ({
        status => 504,
        status_text => $Web::Transport::_Defs::ReasonPhrases->{504},
        headers => [['content-type' => 'text/plain;charset=utf-8']],
      })->then (sub {
        my $writer = $_[0]->{body}->get_writer;
        $writer->write
            (DataView->new (ArrayBuffer->new_from_scalarref (\504)));
        return $writer->close;
      });
    }

    # XXX url & request filter

    # XXX connection pool
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->{parent_id} = $stream->{id} . '.c';
    $client->proxy_manager ($opts->{client}->{proxy_manager});
    $client->resolver ($opts->{client}->{resolver});
    $client->tls_options ($opts->{client}->{tls_options});
    $client->last_resort_timeout ($opts->{client}->{last_resort_timeout});

    my $req_headers = _headers_without_connection_specific $req->{headers};
    return $client->request (
      method => $req->{method},
      url => $url,
      _header_list => $req_headers->{forwarded},
      _forwarding => 1,
      body_length => $req->{body_length}, # or undef
      body_stream => (defined $req->{body_length} ? $req->{body} : undef),
      stream => 1,
    )->then (sub {
      my $res = $_[0];

      if ($res->status == 407) {
        return $stream->send_response ({
          status => 500,
          status_text => $Web::Transport::_Defs::ReasonPhrases->{500},
          headers => [['content-type' => 'text/plain;charset=utf-8']],
        })->then (sub {
          my $writer = $_[0]->{body}->get_writer;
          # XXX error log
          $writer->write
              (DataView->new (ArrayBuffer->new_from_scalarref (\500)));
          return $writer->close;
        })->then (sub {
          my $error = Web::Transport::ProtocolError->new
              ("Upstream server returns a 407 response");
          $res->body_stream->cancel ($error);
          return $client->abort ($error);
        });
      }

      my $res_headers = _headers_without_connection_specific $res->{headers};
      return $stream->send_response ({
        status => $res->{status},
        status_text => $res->{status_text},
        headers => $res_headers->{forwarded},
        forwarding => 1,
      })->then (sub {
        my $writer = $_[0]->{body}->get_writer;
        # XXX response filter hook
        my $reader = $res->body_stream->get_reader;
        my $read; $read = sub {
          return $reader->read->then (sub {
            return if $_[0]->{done};
            return $writer->write ($_[0]->{value})->then ($read);
          });
        }; # $read
        return promised_cleanup { undef $read } $read->()->then (sub {
          if ($res->incomplete) {
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
      })->then (sub {
        return $client->close;
      }, sub {
        my $error = Web::Transport::Error->wrap ($_[0]);
        unless ($res->body_stream->locked) {
          $res->body_stream->cancel ($error);
        }
        return $client->abort ($error);
      });
    }, sub {
      my $result = $_[0];
      # XXX hook for logging $result
      warn $result;
      my $status = 503;
      my $error = '' . $result;
      if ($error =~ /^Network error: HTTP parse error/) {
        $status = 502;
      } elsif ($error =~ m{^Network error: (?:Protocol error|Perl I/O error)}) {
        $status = 504;
      }
      return $stream->send_response ({
        status => $status,
        status_text => $Web::Transport::_Defs::ReasonPhrases->{$status},
        headers => [['content-type' => 'text/plain;charset=utf-8']],
      })->then (sub {
        my $writer = $_[0]->{body}->get_writer;
        $writer->write
            (DataView->new (ArrayBuffer->new_from_scalarref (\$status)));
        return $writer->close;
      })->then (sub {
        return $client->abort ($error);
      });
    });
  }); # ready
} # _handle_stream

1;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
