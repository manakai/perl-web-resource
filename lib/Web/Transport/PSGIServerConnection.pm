package Web::Transport::PSGIServerConnection;
use strict;
use warnings;
our $VERSION = '1.0';
push our @CARP_NOT, qw(Web::Transport::PSGIServerConnection::Writer);
use Carp qw(croak);
use Web::Encoding;
use Web::Host;
use Web::Transport::HTTPServerConnection;
use Web::Transport::TCPTransport;

#XXX
sub percent_decode_b ($) {
  my $s = $_[0];
  $s =~ s/%([0-9A-Fa-f]{2})/pack 'C', hex $1/ge;
  return $s;
} # percent_decode_b
sub metavariables ($$) {
  my ($req, $transport) = @_;

  # XXX tests
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
} # metavariables

sub status_and_headers ($) {
  my ($result) = @_;

  my $status = 0+$result->[0];
  if (100 <= $status and $status < 200) {
    die "PSGI application specified a bad status |$status|\n";
  }

  my $headers = $result->[1];
  if (defined $headers and ref $headers eq 'ARRAY' and not (@$headers % 2)) {
    #
  } else {
    die "PSGI application specified bad headers |$headers|\n";
  }
  $headers = [@$headers];
  my $h = [];
  while (@$headers) {
    my $name = shift @$headers;
    my $value = shift @$headers;
    push @$h, [$name, $value]; ## Errors will be thrown later
  }

  return ($status, $h);
} # status_and_headers

my $cb = sub {
  my $server = shift;
  my $app = shift;
  my $env;
  my $method;
  my $status;
  my $input = '';
  
  return sub {
    my $self = $_[0];
    my $type = $_[1];
    if ($type eq 'headers') {
      my $req = $_[2];
      $env = metavariables ($req, $self->{connection}->{transport});

      $env->{'psgi.version'} = [1, 1];
      $env->{'psgi.multithread'} = 0;
      $env->{'psgi.multiprocess'} = 0;
      $env->{'psgi.run_once'} = 0;
      $env->{'psgi.nonblocking'} = 1;
      $env->{'psgi.streaming'} = 1;
      $method = $env->{REQUEST_METHOD};
      if ($method eq 'CONNECT') {
        $self->send_response_headers
            ({status => 405, status_text => 'Method Not Allowed',
              headers => [['Content-Type', 'text/plain; charset=utf-8']]});
        $self->send_response_data (\q{405});
        $self->close_response;
      }
    } elsif ($type eq 'data') {
      # XXX If too large
      $input .= $_[2];
    } elsif ($type eq 'dataend' and not $method eq 'CONNECT') {
      $env->{CONTENT_LENGTH} = length $input;
      open $env->{'psgi.input'}, '<', \$input;
      $server->_run ($self, $app, $env, $method, $status);
    }
  };
}; # $cb

sub new_from_app_and_ae_tcp_server_args ($$$;$$) {
  my $class = shift;
  my $app = shift;
  my $self = bless {}, $class;
  # XXX UNIX
  my $tcp = Web::Transport::TCPTransport->new
      (server => 1, fh => $_[0],
       host => Web::Host->parse_string ($_[1]), port => $_[2]);
  $self->{connection} = Web::Transport::HTTPServerConnection->new (cb => sub {
    my ($sc, $type) = @_;
    if ($type eq 'startstream') {
      return $cb->($self, $app);
    }
  }, transport => $tcp);
  return $self;
} # new_from_app_and_ae_tcp_server_args

sub _run ($$$$$$) {
  my ($server, $stream, $app, $env, $method, $status) = @_;
  eval {
    $env->{'psgix.exit_guard'} = AE::cv;
    $env->{'psgix.exit_guard'}->cb (sub { warn "done!" }); # XXX
    $env->{'psgix.exit_guard'}->begin;

    my $result = $app->($env);
    if (defined $result and ref $result eq 'ARRAY' and @$result == 3) {
      my ($status, $headers) = status_and_headers ($result);
      my $body = $result->[2];
      if (defined $body and ref $body eq 'ARRAY') {
        my $status_text = $status; # XXX
        my $writer = Web::Transport::PSGIServerConnection::Writer->_new
            ($stream, $method, $status, $env->{'psgix.exit_guard'});
        $stream->send_response_headers
            ({status => $status, status_text => $status_text,
              headers => $headers});
        for (@$body) {
          $writer->write ($_);
        }
        $writer->close;
      } else { ## Filehandles are not supported
        die "PSGI application specified bad response body\n";
      }
    } elsif (defined $result and ref $result eq 'CODE') {
      my $onready = sub {
        my $result = $_[0];
        unless (defined $result and ref $result eq 'ARRAY' and
                (@$result == 2 or @$result == 3)) {
          croak "PSGI application did not call the responder with a response";
        }

        my ($status, $headers) = status_and_headers ($result);
        my $status_text = $status; # XXX
        my $writer = Web::Transport::PSGIServerConnection::Writer->_new
            ($stream, $method, $status, $env->{'psgix.exit_guard'});
        if (@$result == 3) {
          my $body = $result->[2];
          if (defined $body and ref $body eq 'ARRAY') {
            $stream->send_response_headers
                ({status => $status, status_text => $status_text,
                  headers => $headers});
            for (@$body) {
              $writer->write ($_);
            }
            $writer->close;
            return undef;
          } else { ## Filehandles are not supported
            croak "PSGI application specified bad response body";
          }
        } else { # @$result == 2
          $stream->send_response_headers
              ({status => $status, status_text => $status_text,
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
  }
} # _run

sub onerror ($;$) {
  if (@_ > 1) {
    $_[0]->{onerror} = $_[1];
  }
  return $_[0]->{onerror} || sub { warn $_[0] };
} # onerror

sub _send_error ($$$) {
  my ($self, $stream, $error) = @_;
  Promise->all ([
    Promise->resolve->then (sub {
      return $self->onerror->($self, $error);
    })->catch (sub {
      warn $_[0];
    }),
    Promise->resolve->then (sub {
      $stream->send_response_headers
          ({status => 500, status_text => 'Internal Server Error',
            headers => [['Content-Type', 'text/plain; charset=utf-8']]});
      $stream->send_response_data (\q{500});
      $stream->close_response;
    })->catch (sub {
      $stream->abort (message => "PSGI application throws an exception");
    }),
  ]);
  # XXX closed has to wait
} # _send_error

sub closed ($) {
  return $_[0]->{connection}->closed;
} # closed

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
  $_[0]->[0]->close_response;
  $_[0]->[2]->end;
} # close

# XXX DESTROY

# XXX documentation

1;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
