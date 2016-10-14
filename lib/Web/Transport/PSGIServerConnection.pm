package Web::Transport::PSGIServerConnection;
use strict;
use warnings;
our $VERSION = '1.0';
push our @CARP_NOT, qw(Web::Transport::PSGIServerConnection::Writer);
use Carp qw(croak);
use Web::Encoding;
use Web::URL::Encoding qw(percent_decode_b);
use Web::Host;
use Web::Transport::_Defs;
use Web::Transport::HTTPServerConnection;
use Web::Transport::TCPTransport;

sub _metavariables ($$) {
  my ($req, $transport) = @_;

  my $vars = {
    # CONTENT_LENGTH
    PATH_INFO => (percent_decode_b encode_web_utf8 $req->{target_url}->path),
    REQUEST_METHOD => $req->{method},
    SCRIPT_NAME => '',
    SERVER_PROTOCOL => {
      0.9, 'HTTP/0.9',
      1.0, 'HTTP/1.0',
      1.1, 'HTTP/1.1',
      2.0, 'HTTP/2.0',
    }->{$req->{version}},
    'psgi.url_scheme' => 'http',
  };

  if ($transport->type eq 'TLS') {
    if ($req->{target_url}->scheme eq 'https') {
      $vars->{HTTPS} = 'ON';
      $vars->{'psgi.url_scheme'} = 'https';
    }
    $transport = $transport->{transport};
  }

  if ($transport->type eq 'TCP') {
    my $info = $transport->info;
    $vars->{REMOTE_ADDR} = $info->{remote_host}->to_ascii;
    $vars->{SERVER_NAME} = $info->{local_host}->to_ascii;
    $vars->{SERVER_PORT} = ''.$info->{local_port};
  } else {
    $vars->{REMOTE_ADDR} = '127.0.0.1';
    $vars->{SERVER_NAME} = '127.0.0.1';
    $vars->{SERVER_PORT} = '0';
  }

  for my $header (@{$req->{headers} or []}) {
    my $name = $header->[0];
    if ($name =~ /\A[A-Za-z0-9-]+\z/) {
      $name =~ tr/a-z-/A-Z_/;
      my $key = $name eq 'CONTENT_TYPE' ? $name : 'HTTP_' . $name;
      if (defined $vars->{$key}) {
        $vars->{$key} .= ', ' . $header->[1];
      } else {
        $vars->{$key} = $header->[1];
      }
    }
  }
  delete $vars->{HTTP_CONTENT_LENGTH};

  my $query = $req->{target_url}->query;
  $vars->{QUERY_STRING} = $query if defined $query;

  if ($req->{target_url}->is_http_s and
      defined $vars->{HTTP_HOST} and
      $vars->{HTTP_HOST} eq $req->{target_url}->hostport) {
    $vars->{REQUEST_URI} = encode_web_utf8 $req->{target_url}->pathquery;
  } else {
    $vars->{REQUEST_URI} = encode_web_utf8 $req->{target_url}->stringify;
  }

  return $vars;
} # _metavariables

sub _status_and_headers ($) {
  my ($result) = @_;

  my $status = 0+$result->[0];
  if (100 <= $status and $status < 200) {
    die "PSGI application specified a bad status |$status|\n";
  }

  my $headers = $result->[1];
  if (defined $headers and ref $headers eq 'ARRAY' and not (@$headers % 2)) {
    #
  } else {
    die "PSGI application specified bad headers |@{[defined $headers ? $headers : '']}|\n";
  }
  $headers = [@$headers];
  my $h = [];
  while (@$headers) {
    my $name = shift @$headers;
    my $value = shift @$headers;
    push @$h, [$name, $value]; ## Errors will be thrown later
  }

  return ($status, $h);
} # _status_and_headers

my $cb = sub {
  my $server = shift;
  my $app = shift;
  my $env;
  my $method;
  my $status;
  my $canceled = 0;
  my $input = '';
  my $max = $server->max_request_body_length;
  
  return sub {
    my $self = $_[0];
    my $type = $_[1];
    if ($type eq 'headers') {
      my $req = $_[2];
      $env = _metavariables ($req, $self->{connection}->{transport});
      $env->{'psgi.version'} = [1, 1];
      $env->{'psgi.multithread'} = 0;
      $env->{'psgi.multiprocess'} = 0;
      $env->{'psgi.run_once'} = 0;
      $env->{'psgi.nonblocking'} = 1;
      $env->{'psgi.streaming'} = 1;
      $method = $env->{REQUEST_METHOD};
      if ($method eq 'CONNECT') {
        $self->send_response_headers
            ({status => 405,
              status_text => $Web::Transport::_Defs::ReasonPhrases->{405},
              headers => [['Content-Type', 'text/plain; charset=utf-8']]});
        $self->send_response_data (\q{405});
        $self->close_response;
        $canceled = 1;
      }
      if (defined $max and $self->{request}->{body_length} > $max) {
        $self->send_response_headers
            ({status => 413,
              status_text => $Web::Transport::_Defs::ReasonPhrases->{413},
              headers => [['Content-Type', 'text/plain; charset=utf-8']]},
             close => 1);
        $self->send_response_data (\q{413});
        $self->close_response;
        $canceled = 1;
      }
    } elsif ($type eq 'data' and not $canceled) {
      if (defined $max and (length $input) + (length $_[2]) > $max) {
        if (defined $self->{write_mode}) {
          $self->abort (message => "Request body too large ($max)");
        } else {
          $self->send_response_headers
              ({status => 413,
                status_text => $Web::Transport::_Defs::ReasonPhrases->{413},
                headers => [['Content-Type', 'text/plain; charset=utf-8']]},
               close => 1);
          $self->send_response_data (\q{413});
          $self->close_response;
        }
        $canceled = 1;
        return;
      }
      $input .= $_[2];
    } elsif ($type eq 'dataend' and not $canceled) {
      $env->{CONTENT_LENGTH} = length $input;
      open $env->{'psgi.input'}, '<', \$input;
      $server->_run ($self, $app, $env, $method, $status);
    }
  };
}; # $cb

sub new_from_app_and_ae_tcp_server_args ($$$;$$) {
  my $class = shift;
  my $app = shift;
  my $self = bless {
    max_request_body_length => 8_000_000,
  }, $class;
  my $socket;
  if ($_[1] eq 'unix/') {
    require Web::Transport::UNIXDomainSocketTransport;
    $socket = Web::Transport::UNIXDomainSocketTransport->new
        (server => 1, fh => $_[0]);
  } else {
    $socket = Web::Transport::TCPTransport->new
        (server => 1, fh => $_[0],
         host => Web::Host->parse_string ($_[1]), port => $_[2]);
  }
  $self->{connection} = Web::Transport::HTTPServerConnection->new (cb => sub {
    my ($sc, $type) = @_;
    if ($type eq 'startstream') {
      return $cb->($self, $app);
    }
  }, transport => $socket);
  $self->{completed} = $self->{connection}->closed;
  return $self;
} # new_from_app_and_ae_tcp_server_args

sub _run ($$$$$$) {
  my ($server, $stream, $app, $env, $method, $status) = @_;
  $env->{'psgix.exit_guard'} = AE::cv;
  $env->{'psgix.exit_guard'}->begin;
  my $guardended = 0;
  my $endguard = sub {
    $env->{'psgix.exit_guard'}->end unless $guardended++;
  };
  eval {
    $server->{completed} = $server->{completed}->then (sub {
      return Promise->from_cv ($env->{'psgix.exit_guard'});
    });

    my $result = $app->($env);
    if (defined $result and ref $result eq 'ARRAY' and @$result == 3) {
      my ($status, $headers) = _status_and_headers ($result);
      my $body = $result->[2];
      if (defined $body and ref $body eq 'ARRAY') {
        $stream->send_response_headers
            ({status => $status,
              status_text => $Web::Transport::_Defs::ReasonPhrases->{$status} || '',
              headers => $headers});
        my $writer = Web::Transport::PSGIServerConnection::Writer->_new
            ($stream, $method, $status, $endguard);
        for (@$body) {
          $writer->write ($_);
        }
        $writer->close;
      } else { ## Filehandles are not supported
        die "PSGI application specified bad response body\n";
      }
    } elsif (defined $result and ref $result eq 'CODE') {
      my $invoked = 0;
      my $ondestroy = bless sub {
        $server->_send_error ($stream, "$stream->{id}: PSGI application did not invoke the responder")
            unless $invoked;
        $endguard->();
      }, 'Web::Transport::PSGIServerConnection::DestroyCallback';
      my $onready = sub {
        $invoked = 1;
        undef $ondestroy;
        my $result = $_[0];
        unless (defined $result and ref $result eq 'ARRAY' and
                (@$result == 2 or @$result == 3)) {
          croak "PSGI application did not call the responder with a response";
        }

        my ($status, $headers) = _status_and_headers ($result);
        if (@$result == 3) {
          my $body = $result->[2];
          if (defined $body and ref $body eq 'ARRAY') {
            $stream->send_response_headers
                ({status => $status,
                  status_text => $Web::Transport::_Defs::ReasonPhrases->{$status} || '',
                  headers => $headers});
            my $writer = Web::Transport::PSGIServerConnection::Writer->_new
                ($stream, $method, $status, $endguard);
            for (@$body) {
              $writer->write ($_);
            }
            $writer->close;
            return undef;
          } else { ## Filehandles are not supported
            croak "PSGI application specified bad response body";
          }
        } else { # @$result == 2
          my $writer = Web::Transport::PSGIServerConnection::Writer->_new
              ($stream, $method, $status, $endguard);
          $stream->send_response_headers
              ({status => $status,
                status_text => $Web::Transport::_Defs::ReasonPhrases->{$status} || '',
                headers => $headers});
          return $writer;
        }
      }; # $onready
      $result->($onready);
    } else {
      die "PSGI application did not return a response\n";
    }
  };
  if ($@) {
    $server->_send_error ($stream, ref $@ ? $@ : "$stream->{id}: $@");
    $endguard->();
  }
} # _run

sub onerror ($;$) {
  if (@_ > 1) {
    $_[0]->{onerror} = $_[1];
  }
  return $_[0]->{onerror} || sub { warn $_[1] };
} # onerror

sub max_request_body_length ($;$) {
  if (@_ > 1) {
    $_[0]->{max_request_body_length} = $_[1];
  }
  return $_[0]->{max_request_body_length}; # or undef
} # max_request_body_length

sub _send_error ($$$) {
  my ($self, $stream, $error) = @_;
  my $p = Promise->all ([
    Promise->resolve->then (sub {
      return $self->onerror->($self, $error);
    })->catch (sub {
      warn $_[0];
    }),
    Promise->resolve->then (sub {
      $stream->send_response_headers
          ({status => 500,
            status_text => $Web::Transport::_Defs::ReasonPhrases->{500},
            headers => [['Content-Type', 'text/plain; charset=utf-8']]});
      $stream->send_response_data (\q{500});
      $stream->close_response;
    })->catch (sub {
      $stream->abort (message => "PSGI application throws an exception");
    }),
  ]);
  $self->{completed} = $self->{completed}->then (sub { return $p });
} # _send_error

sub closed ($) {
  return $_[0]->{connection}->closed;
} # closed

sub completed ($) {
  return $_[0]->{completed};
} # completed

sub DESTROY ($) {
  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

package Web::Transport::PSGIServerConnection::Writer;
push our @CARP_NOT, qw(Web::Transport::HTTPServerConnection::Stream);

sub _new ($$$$$) {
  my ($class, $stream, $method, $status, $cv) = @_;
  return bless [$stream,
                ($method eq 'HEAD' or $status == 204 or $status == 304),
                $cv],
               $class;
} # _new

sub write ($$) {
  $_[0]->[0]->send_response_data (\($_[1])) unless $_[0]->[1]; # or throw
} # write

sub close ($) {
  return if $_[0]->[3];
  $_[0]->[3] = 1;
  $_[0]->[0]->close_response;
  $_[0]->[2]->();
} # close

sub DESTROY ($) {
  unless ($_[0]->[3]) {
    $_[0]->[0]->abort (message => "PSGI application did not close the body");
    $_[0]->close;
  }

  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

package Web::Transport::PSGIServerConnection::DestroyCallback;

sub DESTROY ($) {
  $_[0]->();
} # DESTROY

# XXX documentation

1;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
