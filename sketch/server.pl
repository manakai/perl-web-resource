use strict;
use warnings;
use AnyEvent::Socket;
use Web::Host;
use Web::Transport::HTTPServerConnection;
use Web::Transport::TCPTransport;
use Data::Dumper;
use Promised::Flow;

my $host = 0;
my $port = 8522;

$Web::Transport::HTTPServerConnection::ReadTimeout = $ENV{SERVER_READ_TIMEOUT}
    if $ENV{SERVER_READ_TIMEOUT};

my $ended = 0;
my $cv = AE::cv;
$cv->begin;

{
  package Writer;

  sub _new ($$$$) {
    my ($class, $stream, $method, $status) = @_;
    return bless [$stream,
                  ($method eq 'HEAD' or $status == 204 or $status == 304)],
                 $class;
  } # _new

  sub write ($$) {
    $_[0]->[0]->send_response_data (\($_[1])) unless $_[0]->[1]; # or throw
  } # write

  sub close ($) {
    $_[0]->[0]->close_response;
  } # close
}

sub psgi_app ($) {
  my $env = $_[0];

  use Data::Dumper;
  warn Dumper $env;

  if ($env->{PATH_INFO} eq '/1') {
    return sub {
      my $c = $_[0];
      AE::postpone {
        $c->([200, [], ['<p>1!']]);
      };
    };
  } elsif ($env->{PATH_INFO} eq '/2') {
    return sub {
      my $c = $_[0];
      AE::postpone {
        my $w = $c->([200, []]);
        AE::postpone {
          $w->write ("<p>1!");
        };
        AE::postpone {
          $w->write ("<p>2!");
        };
        AE::postpone {
          $w->close;
        };
      };
    };
  }

  if ($env->{PATH_INFO} eq '/end') {
    if (not $ended) {
      $ended = 1;
      $cv->end;
    }

    return [200, [], [qq{<html>200 Goodbye!\x0D\x0A\x0D\x0A</html>}]];
  }

  return [200, [], ['200!']];
} # psgi_app

use Web::Encoding;
sub percent_decode_b ($) {
  my $s = $_[0];
  $s =~ s/%([0-9A-Fa-f]{2})/pack 'C', hex $1/ge;
  return $s;
} # percent_decode_b
sub metavariables ($$) {
  my ($req, $transport) = @_;

  my $vars = {
    CONTENT_LENGTH => ''.$req->{body_length},
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
  my $result = $_[0];

  my $status = 0+$result->[0];
  if (100 <= $status and $status < 200) {
    die "Bad status |$status|";
  }

  my $headers = $result->[1];
  if (defined $headers and ref $headers eq 'ARRAY' and not (@$headers % 2)) {
    #
  } else {
    die "Bad headers |$headers|";
  }
  $headers = [@$headers];
  my $h = [];
  while (@$headers) {
    my $name = shift @$headers;
    my $value = shift @$headers;
    push @$h, [$name, $value]; ## Errors will be thrown later
  }

  return ($status, $headers);
} # status_and_headers

my $cb = sub {
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
    } elsif ($type eq 'data') {
      $input .= ${$_[2]};
    } elsif ($type eq 'dataend') {
      if ($method eq 'CONNECT') {
        #XXX
      } else {
        open $env->{'psgi.input'}, '<', \$input;

        my $result = psgi_app ($env); # XXX if thrown
        if (defined $result and ref $result eq 'ARRAY' and
            @$result == 3) {
          my ($status, $headers) = status_and_headers ($result); # XXX if thrown
          my $status_text = $status; # XXX
          $self->send_response_headers
              ({status => $status, status_text => $status_text,
                headers => $headers}); # XXX or throw

          my $writer = Writer->_new ($self, $method, $status);

          my $body = $result->[2];
          if (defined $body and ref $body eq 'ARRAY') {
            for (@$body) {
              $writer->write ($_); # XXX or thrown
            }
            $writer->close;
          } else { ## Filehandles are not supported
            # XXX
          }
        } elsif (defined $result and ref $result eq 'CODE') {
          my $onready = sub {
            my $result = $_[0];

            unless (defined $result and ref $result eq 'ARRAY' and
                    (@$result == 2 or @$result == 3)) {
              # XXX
            }

            my ($status, $headers) = status_and_headers ($result); # XXX if thrown
            my $status_text = $status; # XXX
            $self->send_response_headers
                ({status => $status, status_text => $status_text,
                  headers => $headers}); # XXX or throw

            my $writer = Writer->_new ($self, $method, $status);

            if (@$result == 3) {
              my $body = $result->[2];
              if (defined $body and ref $body eq 'ARRAY') {
                for (@$body) {
                  $writer->write ($_); # XXX or thrown
                }
                $writer->close;
                return undef;
              } else { ## Filehandles are not supported
                # XXX
              }
            } else { # @$result == 2
              return $writer;
            }
          }; # $onready

          $result->($onready); # XXX or throw
        } else {
          #XXX
        }
      }
    }
  };
}; # $cb

my $con_cb = sub {
  my ($self, $type) = @_;
  if ($type eq 'startstream') {
    return $cb->();
  }
}; # $con_cb

my $server = tcp_server $host, $port, sub {
  $cv->begin;
  my $tcp = Web::Transport::TCPTransport->new
      (server => 1, fh => $_[0],
       host => Web::Host->parse_string ($_[1]), port => $_[2]);
  my $con = Web::Transport::HTTPServerConnection->new
      (transport => $tcp, cb => $con_cb);
  promised_cleanup { $cv->end } $con->closed;
};

$cv->recv;
