package Web::Transport::PSGIServerConnection;
use strict;
use warnings;
our $VERSION = '3.0';
use Web::Transport::RequestConstructor;
use Web::Transport::GenericServerConnection;
use Web::Transport::TypeError;
use AnyEvent;
use Promise;
use Promised::Flow;
use Web::Encoding;
use Web::URL::Encoding qw(percent_decode_b);

push our @ISA, qw(Web::Transport::GenericServerConnection);
push our @CARP_NOT, qw(
  Web::Transport::PSGIServerConnection::Writer
  Web::Transport::TypeError
);

sub _te ($) {
  return Web::Transport::TypeError->new ($_[0]);
} # _te

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

  if ($transport->{type} eq 'TLS') {
    if ($req->{target_url}->scheme eq 'https') {
      $vars->{HTTPS} = 'ON';
      $vars->{'psgi.url_scheme'} = 'https';
    }
    $transport = $transport->{parent};
  }

  if ($transport->{type} eq 'TCP') {
    $vars->{REMOTE_ADDR} = $transport->{remote_host}->to_ascii;
    $vars->{SERVER_NAME} = $transport->{local_host}->to_ascii;
    $vars->{SERVER_PORT} = ''.$transport->{local_port};
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

sub _handle_stream ($$$) {
  my ($server, $stream, $opts) = @_;
  return $stream->headers_received->then (sub {
    my $req = $_[0];
    my $env = _metavariables ($req, $server->{connection}->info->{parent});

    $env->{'psgi.version'} = [1, 1];
    $env->{'psgi.multithread'} = 0;
    $env->{'psgi.multiprocess'} = 0;
    $env->{'psgi.run_once'} = 0;
    $env->{'psgi.nonblocking'} = 1;
    $env->{'psgi.streaming'} = 1;
    $env->{'manakai.server.state'} = $opts->{state} if defined $opts->{state};

    my $method = $env->{REQUEST_METHOD};
    if ($method eq 'CONNECT') {
      return $stream->send_response (Web::Transport::RequestConstructor->create_response ({
        status => 405,
        headers => {
          Server => $server->{server_header},
          'Content-Type' => 'text/plain; charset=utf-8',
        },
        close => 1,
      }))->then (sub {
        my $writer = $_[0]->{body}->get_writer;
        $writer->write
            (DataView->new (ArrayBuffer->new_from_scalarref (\"405")));
        return $writer->close;
      })->then (sub {
        $req->{body}->cancel (405) if defined $req->{body};
        return $stream->abort (405);
      });
    }

    my $max = exists $opts->{max_request_body_length}
        ? $opts->{max_request_body_length}
        : 8_000_000;
    if (defined $max and $req->{length} > $max) {
      return $stream->send_response (Web::Transport::RequestConstructor->create_response ({
        status => 413,
        headers => {
          Server => $server->{server_header},
          'Content-Type' => 'text/plain; charset=utf-8',
        },
        close => 1,
      }))->then (sub {
        my $writer = $_[0]->{body}->get_writer;
        $writer->write
            (DataView->new (ArrayBuffer->new_from_scalarref (\"413")));
        return $writer->close;
      })->then (sub {
        $req->{body}->cancel (413) if defined $req->{body};
        return $stream->abort (413);
      });
    }

    my $input = '';
    my $reader = defined $_[0]->{body} ? $_[0]->{body}->get_reader ('byob') : undef;
    my $read; $read = defined $reader ? sub {
      my $dv = DataView->new (ArrayBuffer->new (1024*8));
      return $reader->read ($dv)->then (sub {
        return if $_[0]->{done};

        if (defined $max and
            (length $input) + $_[0]->{value}->byte_length > $max) {
          return $stream->send_response (Web::Transport::RequestConstructor->create_response ({
            status => 413,
            headers => {
              Server => $server->{server_header},
              'Content-Type' => 'text/plain; charset=utf-8',
            },
            close => 1,
          }))->then (sub {
            my $writer = $_[0]->{body}->get_writer;
            $writer->write
                (DataView->new (ArrayBuffer->new_from_scalarref (\"413")));
            return $writer->close;
          })->then (sub {
            $reader->cancel (413);
            return $stream->abort (413);
          });
        }

        $input .= $_[0]->{value}->manakai_to_string;
        return $read->();
      });
    } : sub { return Promise->resolve }; # $read
    return promised_cleanup { undef $read } $read->()->then (sub {
      $env->{CONTENT_LENGTH} = length $input;
      open $env->{'psgi.input'}, '<', \$input;
      return $server->_run ($stream, $opts->{psgi_app}, $env, $method);
    });
  }); # ready
} # _handle_stream

sub new_from_app_and_ae_tcp_server_args ($$$;%) {
  my ($class, $app, $aeargs, %args) = @_;
  return $class->new_from_aeargs_and_opts ($aeargs, {
    %args,
    psgi_app => $app,
  });
} # new_from_app_and_ae_tcp_server_args

sub _run ($$$$$) {
  my ($server, $stream, $app, $env, $method) = @_;
  my $xg_cv = $env->{'psgix.exit_guard'} = AE::cv;
  $server->{completed_cv}->begin;
  Promise->from_cv ($xg_cv)->then (sub {
    $server->{completed_cv}->end;
  });

  $xg_cv->begin;
  my $ondestroy2 = bless sub {
    $xg_cv->end;
  }, 'Web::Transport::PSGIServerConnection::DestroyCallback';

  my ($res_resolve, $res_reject);
  my $res_promise = Promise->new (sub { ($res_resolve, $res_reject) = @_ });
  my $invoked = 0;
  my $send_response_invoked = 0;
  my $ondestroy = bless sub {
    $res_reject->(_te "PSGI application did not invoke the responder")
        unless $invoked;
    $invoked = 1;
  }, 'Web::Transport::PSGIServerConnection::DestroyCallback';
  my $ondestroy_copy = $ondestroy;
  my $responder = sub {
    if ($invoked) {
      my $error = _te "PSGI application invoked the responder twice";
      $res_reject->($error);
      die $error;
    }
    $invoked = 1;
    undef $ondestroy;

    my $result = $_[0];
    unless (defined $result and ref $result eq 'ARRAY' and
            (@$result == 2 or @$result == 3)) {
      my $error = _te "PSGI application did not call the responder with a response";
      $res_reject->($error);
      die $error;
    }

    my $status = 0+$result->[0];
    if (100 <= $status and $status < 200) {
      my $error = _te "PSGI application specified a bad status |$status|";
      $res_reject->($error);
      die $error;
    }

    my $headers = $result->[1];
    if (defined $headers and ref $headers eq 'ARRAY' and not (@$headers % 2)) {
      $headers = [@$headers];
      my $h = [];
      push @$h, [Server => $server->{server_header}];
      while (@$headers) {
        my $name = shift @$headers;
        my $value = shift @$headers;
        if (utf8::is_utf8 $name) {
          my $error = _te "Bad header name |$name|";
          $res_reject->($error);
          die $error;
        }
        if (utf8::is_utf8 $value) {
          my $error = _te "Bad header value |$name: $value|";
          $res_reject->($error);
          die $error;
        }
        push @$h, [$name, $value]; ## More errors will be thrown later
      }
      $headers = $h;
    } else {
      my $error = _te "PSGI application specified bad headers |@{[defined $headers ? $headers : '']}|";
      $res_reject->($error);
      die $error;
    }

    if (@$result == 3) {
      my $body = $result->[2];
      if (defined $body and ref $body eq 'ARRAY') {
        my $length = 0;
        my $body = [map {
          my $l = length $_;
          if ($l) {
            $length += $l;
            DataView->new (ArrayBuffer->new_from_scalarref (\$_)); # or throw
          } else {
            ();
          }
        } @$body];
        undef $length if $status == 204 or $status == 205 or $status == 304 or
            $method eq 'HEAD';
        Promise->resolve->then (sub {
          return $stream->send_response (Web::Transport::RequestConstructor->create_response ({
            status => $status,
            headers => $headers,
            length => $length,
          }));
        })->then (sub {
          my $w = $_[0]->{body}->get_writer;
          $w->write ($_) for @$body;
          undef $ondestroy2;
          return $w->close;
        })->then ($res_resolve, $res_reject);
        $send_response_invoked = 1;
        return undef;
      } else { ## Filehandles are not supported
        my $error = _te "PSGI application specified bad response body";
        $res_reject->($error);
        die $error;
      }
    } else { # @$result == 2
      my $destroyed = 0;
      my ($r_writer, $s_writer) = promised_cv;
      my $writer = Web::Transport::PSGIServerConnection::Writer->_new
          ($r_writer, sub {
             return if $destroyed++;
             undef $ondestroy2;
           });
      Promise->resolve->then (sub {
        return $stream->send_response (Web::Transport::RequestConstructor->create_response ({
          status => $status,
          headers => $headers,
        }));
      })->then (sub {
        my $w = $_[0]->{body}->get_writer;
        $s_writer->($w);
      })->then ($res_resolve, $res_reject);
      $send_response_invoked = 1;
      return $writer;
    }
  }; # $responder

  Promise->resolve->then (sub {
    my $result = $app->($env); # or throw
    if (defined $result and ref $result eq 'ARRAY' and @$result == 3) {
      $responder->($result); # or throw
    } elsif (defined $result and ref $result eq 'CODE') {
      $result->($responder); # or throw
    } else {
      die _te "PSGI application did not return a response";
    }
  })->catch ($res_reject)->then (sub { undef $ondestroy_copy });

  return $res_promise->catch (sub {
    my $error = Web::Transport::Error->wrap ($_[0]);
    if ($send_response_invoked) {
      $stream->abort ($error, graceful => 1);
      return Promise->resolve->then (sub {
        return $server->onexception->($server, $error);
      })->catch (sub {
        warn $_[0];
      })->then (sub {
        undef $ondestroy2;
      });
    } else {
      return Promise->all ([
        Promise->resolve->then (sub {
          return $server->onexception->($server, $error);
        })->catch (sub {
          warn $_[0];
        }),
        $stream->send_response (Web::Transport::RequestConstructor->create_response ({
          status => 500,
          headers => {
            Server => $server->{server_header},
            'Content-Type' => 'text/plain; charset=utf-8',
          },
        }))->then (sub {
          my $writer = $_[0]->{body}->get_writer;
          $writer->write
              (DataView->new (ArrayBuffer->new_from_scalarref (\"500")));
          return $writer->close;
        })->catch (sub {
          return $stream->abort ($_[0], graceful => 1);
        }),
      ])->then (sub {
        undef $ondestroy2;
      });
    }
  });
} # _run

package Web::Transport::PSGIServerConnection::Writer;
use Carp qw(croak);
push our @CARP_NOT, qw(ArrayBuffer WritableStreamDefaultWriter);

sub _new ($$$) {
  my ($class, $r_writer, $ondestroy) = @_;
  return bless [$r_writer, $ondestroy, undef], $class;
} # _new

sub write ($$) {
  my $dv = DataView->new (ArrayBuffer->new_from_scalarref (\($_[1]))); # or throw
  croak "This writer is no longer writable" if $_[0]->[2];
  $_[0]->[0]->then (sub {
    return $_[0]->write ($dv);
  });
  return undef;
} # write

sub close ($) {
  return if $_[0]->[2];
  $_[0]->[2] = 1;
  $_[0]->[0]->then (sub { return $_[0]->close });
  return undef;
} # close

sub DESTROY ($) {
  unless ($_[0]->[2]) {
    $_[0]->[2] = 1;
    $_[0]->[0]->then (sub {
      my $writer = $_[0];
      $writer->write (DataView->new (ArrayBuffer->new (0)))->then (sub {
        return $writer->abort ("PSGI application did not close the body");
      });
    });
  }

  $_[0]->[1]->();

  local $@;
  eval { die };
  warn "$$: Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

package Web::Transport::PSGIServerConnection::DestroyCallback;

sub DESTROY ($) {
  $_[0]->();
} # DESTROY

1;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
