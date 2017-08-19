package Web::Transport::ProxyServerConnection;
use strict;
use warnings;
our $VERSION = '2.0';
use Carp qw(croak);
use ArrayBuffer;
use DataView;
use AnyEvent;
use Promise;
use Promised::Flow;
use Web::Host;
use Web::Transport::_Defs;
use Web::Transport::TCPStream;
use Web::Transport::HTTPStream;
use Web::Transport::Error;
use Web::Transport::TypeError;
use Web::Transport::ProtocolError;
use Web::Transport::BasicClient;

push our @CARP_NOT, qw(
  ArrayBuffer
  Web::Transport::HTTPStream
  Web::Transport::HTTPStream::Stream
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

sub _handle_stream ($$) {
  my ($server, $stream) = @_;
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
    # XXX
    #$client->parent_id ($x->{parent_id});
    $client->proxy_manager ($server->{proxy_manager});
    #$client->resolver ($x->resolver);
    #$client->tls_options ($x->tls_options);
    $client->last_resort_timeout ($server->{last_resort_timeout});

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
        });
      })->then (sub {
        return $client->close;
      }, sub {
        return $client->abort ($_[0]);
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

sub new_from_ae_tcp_server_args ($$;%) {
  my ($class, $aeargs, %args) = @_;
  my $self = bless {}, $class;
  my $socket;
  if ($aeargs->[1] eq 'unix/') {
    require Web::Transport::UnixStream;
    $socket = {
      class => 'Web::Transport::UnixStream',
      server => 1, fh => $aeargs->[0],
      parent_id => $args{parent_id},
    };
  } else {
    $socket = {
      class => 'Web::Transport::TCPStream',
      server => 1, fh => $aeargs->[0],
      host => Web::Host->parse_string ($aeargs->[1]), port => $aeargs->[2],
      parent_id => $args{parent_id},
    };
  }
  $self->{connection} = Web::Transport::HTTPStream->new ({
    parent => $socket,
    server => 1,
    server_header => $args{server_header},
  });
  $self->{completed_cv} = AE::cv;
  $self->{completed_cv}->begin;
  my $reader = $self->{connection}->streams->get_reader;
  my $read; $read = sub {
    return $reader->read->then (sub {
      return if $_[0]->{done};
      _handle_stream $self, $_[0]->{value};
      return $read->();
    });
  }; # $read
  promised_cleanup { undef $read } $read->();
  $self->{connection}->closed->then (sub { $self->{completed_cv}->end });
  $self->{completed} = Promise->from_cv ($self->{completed_cv});
  return $self;
} # new_from_ae_tcp_server_args

sub id ($) {
  return $_[0]->{connection}->info->{id};
} # id

sub onexception ($;$) {
  if (@_ > 1) {
    $_[0]->{onexception} = $_[1];
  }
  return $_[0]->{onexception} || sub { warn $_[1] };
} # onexception

sub closed ($) {
  return $_[0]->{connection}->closed;
} # closed

sub completed ($) {
  return $_[0]->{completed};
} # completed

sub close_after_current_response ($;%) {
  my ($self, %args) = @_;
  my $timeout = $args{timeout};
  $timeout = 10 unless defined $timeout;
  $self->{connection}->close_after_current_stream;
  my $timer;
  if ($timeout > 0) {
    $timer = AE::timer $timeout, 0, sub {
      $self->{connection}->abort
          ("|close_after_current_response| timeout ($timeout)");
      undef $timer;
    };
  }
  return $self->completed->then (sub {
    undef $timer;
  });
} # close_after_current_response

sub DESTROY ($) {
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
