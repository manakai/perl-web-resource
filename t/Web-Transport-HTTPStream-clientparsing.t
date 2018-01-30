use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Test::HTCT::Parser;
use ArrayBuffer;
use DataView;
use Encode;
use JSON::PS;
use Web::Host;
use Web::Transport::TCPStream;
use Web::Transport::TLSStream;
use Web::Transport::HTTPStream;
use Promise;
use AnyEvent::Util qw(run_cmd);
use Test::Certificates;
use Promised::Flow;
use Promised::Command;

sub _a ($) {
  return encode 'utf-8', $_[0];
} # _a

{
  use Socket;
  my $EphemeralStart = 1024;
  my $EphemeralEnd = 5000;

  sub is_listenable_port ($) {
    my $port = $_[0];
    return 0 unless $port;
    
    my $proto = getprotobyname('tcp');
    socket(my $server, PF_INET, SOCK_STREAM, $proto) || die "socket: $!";
    setsockopt($server, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) || die "setsockopt: $!";
    bind($server, sockaddr_in($port, INADDR_ANY)) || return 0;
    listen($server, SOMAXCONN) || return 0;
    close($server);
    return 1;
  } # is_listenable_port

  my $using = {};
  sub find_listenable_port () {
    for (1..10000) {
      my $port = int rand($EphemeralEnd - $EphemeralStart);
      next if $using->{$port}++;
      return $port if is_listenable_port $port;
    }
    die "Listenable port not found";
  } # find_listenable_port
}

my @End;
my $server_pids = {};
END { kill 'KILL', $_ for keys %$server_pids }
sub server ($) {
  my $code = $_[0];

  my $port = find_listenable_port;
  my $host = (int rand 10000) . '.our.parsing.test';

  my $pid;
  my $server = {
    resultdata => [],
    stop => sub {
      kill 'TERM', $pid;
      delete $server_pids->{$pid};
    },
  };
  my $data = '';

  my ($r_ready, $s_ready) = promised_cv;

  my $cmd = Promised::Command->new ([
    'perl', path (__FILE__)->parent->parent->child ('t_deps/server.pl'),
    '127.0.0.1', $port,
  ]);
  $cmd->envs->{SERVER_HOST_NAME} = $host;
  $cmd->stdin (\$code);
  $cmd->stdout (sub {
    $data .= $_[0] if defined $_[0];
    if ($ENV{DUMP} and defined $_[0]) {
      warn "--- .parsing.t received. ---\n";
      warn "$_[0]\n";
      warn "--- ^parsing.t received^ ---\n";
    }
    while ($data =~ s/^\[data (.+)\]$//m) {
      push @{$server->{resultdata}}, json_bytes2perl $1;
    }
    if ($data =~ s/^\[server done\]$//m) {
      #
    }
    if ($data =~ /^\[server (.+) ([0-9]+)\]/m) {
      $server->{addr} = $1;
      $server->{port} = $2;
      $server->{host} = $host;
      $s_ready->($server);
    }
  }); # stdout
  push @End, $server->{closed} = $cmd->run->then (sub {
    $pid = $server->{pid} = $cmd->pid;
    $server_pids->{$pid} = 1;
    return $cmd->wait;
  })->then (sub {
    my $result = $_[0];
    warn "Server stopped ($result)" if $ENV{DUMP} or $result->is_error;
    $s_ready->(Promise->reject ($result)) if $result->is_error;
  });
  return $r_ready;
} # server

sub rsread ($$) {
  my $test = shift;
  my $rs = shift;
  return Promise->resolve (undef) unless defined $rs;
  my $r = $rs->get_reader ('byob');
  my $result = '';
  my $run; $run = sub {
    return $r->read (DataView->new (ArrayBuffer->new (1024)))->then (sub {
      return if $_[0]->{done};
      $result .= $_[0]->{value}->manakai_to_string;
      $result .= '(boundary)' if $test->{boundary};
      return $run->();
    });
  }; # $run
  return $run->()->then (sub { undef $run; return $result . '(close)' }, sub { undef $run; return "Error: $_[0]" });
} # rsread

sub rsread_text ($$) {
  my $test = shift;
  my $rs = shift;
  return Promise->resolve (undef) unless defined $rs;
  my $r = $rs->get_reader;
  my $result = '';
  my $run; $run = sub {
    return $r->read (DataView->new (ArrayBuffer->new (1024)))->then (sub {
      return if $_[0]->{done};
      $result .= ${$_[0]->{value}};
      $result .= '(boundary)' if $test->{boundary};
      return $run->();
    });
  }; # $run
  return $run->()->then (sub { undef $run; return $result . '(close)' }, sub { undef $run; return "Error: $_[0]" });
} # rsread_text

sub rsread_messages ($$) {
  my $test = shift;
  my $rs = shift;
  return Promise->resolve (undef) unless defined $rs;
  my $r = $rs->get_reader;
  my $result = '';
  my $run; $run = sub {
    return $r->read->then (sub {
      return if $_[0]->{done};
      my $v = $_[0]->{value};
      return (
        defined $v->{text_body}
            ? rsread_text ($test, $v->{text_body})
            : rsread ($test, $v->{body})
      )->then (sub {
        $result .= $_[0];
        return $run->();
      });
    });
  }; # $run
  return $run->()->then (sub { undef $run; return $result }, sub { undef $run; return "Error: $_[0]" });
} # rsread_messages

for my $path (map { path ($_) } glob path (__FILE__)->parent->parent->child ('t_deps/data/*.dat')) {
  next if $path =~ m{/h2}; # XXX not implemented yet
  for_each_test $path, {
    'tunnel-send' => {is_prefixed => 1, multiple => 1},
    '1xx' => {is_prefixed => 1, multiple => 1},
    headers => {is_prefixed => 1},
    body => {is_prefixed => 1},
    'ws-protocol' => {multiple => 1},
  }, sub {
    my $test = $_[0];
    return if defined $test->{name}->[0] and $test->{name}->[0] =~ /crash|2147483648/; # XXX not supported yet
    return if defined $test->{name}->[0] and
              $test->{name}->[0] eq 'TLS renegotiation (no client auth) 2';
    test {
      my $c = shift;
      server ($test->{data}->[0])->then (sub {
        my $server = $_[0];
        my $tparams = {
          class => 'Web::Transport::TCPStream',
          host => Web::Host->parse_string ($server->{addr}),
          port => $server->{port},
        };

        my $time = time + 60;
        if (defined $test->{time}) {
          $time += $test->{time}->[1]->[0];
        }

        if ($test->{tls}) {
          $tparams = {
            class => 'Web::Transport::TLSStream',
            parent => $tparams,
            ca_file => Test::Certificates->ca_path ('cert.pem'),
            sni_host => Web::Host->parse_string ($server->{host}),
            si_host => Web::Host->parse_string ($server->{host}),
            protocol_clock => sub { return $time },
          };
        }

        my $http = Web::Transport::HTTPStream->new ({parent => $tparams});
        my $test_type = $test->{'test-type'}->[1]->[0] || '';

        return promised_cleanup {
          $server->{stop}->();
          undef $server;
        } $http->ready->then (sub {
          if ($test_type eq 'ws') {
            return $http->send_request ({
              method => _a 'GET',
              target => _a $test->{url}->[1]->[0],
              ws => 1,
              ws_protocols => [map { _a $_->[0] } @{$test->{'ws-protocol'} or []}],
            })->then (sub {
              my $stream = $_[0]->{stream};
              my $result = {};
              return $stream->headers_received->then (sub {
                my $got = $_[0];
                $result->{response} = $got;
                if (defined $got->{messages}) {
                  $result->{ws_established} = 1;
                  if ($test->{'ws-send'}) {
                    $stream->send_ws_message (3, not 'binary')->then (sub {
                      my $writer = $_[0]->{body}->get_writer;
                      $writer->write
                          (DataView->new (ArrayBuffer->new_from_scalarref (\'stu')));
                      return $writer->close;
                    });
                  }
                  return rsread_messages ($test, $got->{messages});
                } else {
                  $stream->abort;
                  return rsread ($test, $got->{readable} || $got->{body});
                }
              })->then (sub {
                $result->{response_body} = $_[0];
              })->catch (sub {
                $result->{headers_received_error} = $_[0];
              })->then (sub {
                return $stream->closed;
              })->then (sub {
                $result->{exit} = $_[0];
                $server->{stop}->();
                return $server->{closed};
              })->then (sub {
                $result->{resultdata} = perl2json_bytes_for_record $server->{resultdata};
                return $result;
              });
            });
          } elsif ($test_type eq 'second' or
                   $test_type eq 'largerequest-second') {
            my $try_count = 0;
            my $result;
            return (promised_wait_until {
              unless ($http->is_active) {
                return $http->close_after_current_stream->then (sub {
                  $http = Web::Transport::HTTPStream->new ({parent => $tparams});
                  return $http->ready;
                })->then (sub {
                  return 0; # retry
                });
              } # is_active

              return $http->send_request ({
                method => _a $test->{method}->[1]->[0],
                target => _a $test->{url}->[1]->[0],
                length => ($test_type eq 'largerequest-second' ? 1024*1024 : undef),
              })->then (sub {
                my $stream = $_[0]->{stream};
                my $body = $_[0]->{body};
                $result = {};
                return $stream->headers_received->then (sub {
                  my $got = $_[0];
                  $result->{response} = $got;
                  my $writable = $got->{writable} || $body;
                  my $reqbody = defined $writable ? $writable->get_writer : undef;
                  if ($test_type eq 'largerequest-second' and defined $reqbody) {
                    $reqbody->write
                        (DataView->new (ArrayBuffer->new_from_scalarref
                                            (\('x' x (1024*1024)))));
                  }
                  if ($test->{method}->[1]->[0] eq 'CONNECT' and defined $reqbody) {
                    for (@{$test->{'tunnel-send'} or []}) {
                      $reqbody->write
                          (DataView->new
                               (ArrayBuffer->new_from_scalarref
                                    (\_a $_->[0])));
                    }
                    $reqbody->close;
                  } # CONNECT

                  return (
                    defined $got->{messages}
                      ? rsread_messages ($test, $got->{messages})
                      : defined $got->{readable}
                        ? rsread ($test, $got->{readable})
                        : rsread ($test, $got->{body})
                  );
                })->then (sub {
                  $result->{response_body} = $_[0];
                })->catch (sub {
                  $result->{headers_received_error} = $_[0];
                })->then (sub {
                  return $stream->closed;
                })->then (sub {
                  $result->{exit} = $_[0];

                  return 0 unless $try_count++;

                  for (@{$result->{response}->{headers} or []}) {
                    return 0 if $_->[2] eq 'x-test-retry' and $try_count < 10;
                  }
                  return 0 if $try_count < 10 and
                      UNIVERSAL::can ($result->{exit}, 'http_can_retry') and
                      $result->{exit}->http_can_retry;

                  return 1; # no retry
                });
              });
            } interval => 0.1, timeout => 30)->then (sub {
              return $result;
            });
          } else { # $test_type
            return $http->send_request ({
              method => _a $test->{method}->[1]->[0],
              target => _a $test->{url}->[1]->[0],
              length => ($test_type eq 'largerequest' ? 1024*1024 : undef),
            })->then (sub {
              my $stream = $_[0]->{stream};
              my $body = $_[0]->{body};
              my $result = {};
              return $stream->headers_received->then (sub {
                my $got = $_[0];
                $result->{response} = $got;
                my $writable = $body || $got->{writable};
                my $reqbody = defined $writable ? $writable->get_writer : undef;
                if ($test_type eq 'largerequest' and defined $reqbody) {
                  $reqbody->write
                      (DataView->new
                           (ArrayBuffer->new_from_scalarref (\('x' x 1024))))
                          for 1..1024;
                }
                if ($test->{method}->[1]->[0] eq 'CONNECT' and defined $reqbody) {
                  for (@{$test->{'tunnel-send'} or []}) {
                    $reqbody->write
                        (DataView->new
                             (ArrayBuffer->new_from_scalarref (\_a $_->[0])));
                  }
                  $reqbody->close;
                } # CONNECT
                return rsread ($test, $got->{body} || $got->{readable});
              })->then (sub {
                $result->{response_body} = $_[0];
              })->catch (sub {
                $result->{headers_received_error} = $_[0];
              })->then (sub {
                return $stream->closed;
              })->then (sub {
                $result->{exit} = $_[0];
                return $result;
              });
            });
          } # test type
        })->catch (sub {
          my $error = $_[0];
          my $result = {exit => $error};
          return $result;
        })->then (sub {
          my $result = $_[0];
          test {
            my $error_expected;
            if ($test_type eq 'ws') {
              $error_expected = !!$test->{'handshake-error'};
              is !$result->{ws_established}, $error_expected,
                 'is error (WS): ' . $result->{exit};
            } else {
              $error_expected = $test->{status}->[1]->[0] == 0 && !defined $test->{reason};
              is !!Web::Transport::ProtocolError->is_error ($result->{exit}),
                 $error_expected, 'is error: ' . $result->{exit};
            }

            if ($error_expected) {
              ok 1, 'response version (skipped)';
            } else {
              is $result->{response}->{version},
                 $test->{version} ? $test->{version}->[1]->[0] : '1.1',
                 'response version';
            }

            if ($error_expected) {
              ok 1, 'response status (skipped)';
              ok 1, 'response status text (skipped)';
            } elsif ($test_type eq 'ws') {
              my $actual_status = 1006;
              my $actual_reason = '';
              if (UNIVERSAL::can ($result->{exit}, 'ws_status')) {
                $actual_status = $result->{exit}->ws_status;
                $actual_reason = $result->{exit}->ws_reason;
                if ($actual_status == 1002) {
                  $actual_status = 1006;
                  $actual_reason = '';
                }
              }
              is $actual_status,
                 $test->{'ws-status'} ? $test->{'ws-status'}->[1]->[0] : undef,
                 'WebSocket status code';
              is $actual_reason,
                 $test->{'ws-reason'} ? $test->{'ws-reason'}->[0] : undef,
                 'WebSocket close reason';
            } else {
              is $result->{response}->{status}, $test->{status}->[1]->[0],
                 'response status';
              is $result->{response}->{status_text},
                 defined $test->{reason}->[1]->[0] ? $test->{reason}->[1]->[0] : defined $test->{reason}->[0] ? $test->{reason}->[0] : '',
                 'response status text';
            }

            if ($error_expected or $test_type eq 'ws') {
              ok 1, 'response headers (skipped)';
            } else {
              is join ("\x0A", map {
                $_->[0] . ': ' . $_->[1];
              } @{$result->{response}->{headers}}),
              defined $test->{headers}->[0] ? $test->{headers}->[0] : '',
              'response headers';
            }

            if ($error_expected) {
              ok 1, 'response body (skipped)';
              ok 1, 'response body incomplete (skipped)';
            } elsif ($test_type eq 'ws') {
              my $actual = $result->{response_body};
              $actual = '(close)' unless length $actual;
              if ($test->{'received-length'}) {
                is length $actual,
                   $test->{'received-length'}->[1]->[0] + length '(close)',
                   'response body length';
              } else {
                is $actual,
                 (defined $test->{received}->[0] ? $test->{received}->[0] : '') . '(close)',
                   'response body';
              }
              is !!(UNIVERSAL::can ($result->{exit}, 'ws_cleanly') and
                    $result->{exit}->ws_cleanly),
                 !!$test->{'ws-was-clean'}, 'WebSocket clean flag';
            } else {
              is $result->{response_body}, $test->{body}->[0], 'response body';
              is !!$result->{response}->{incomplete}, !!$test->{incomplete},
                 'response body incomplete';
            }

            if ($error_expected or not $test_type eq 'ws') {
              ok 1, 'WebSocket Close (skipped)';
            } else {
              my $expected = perl2json_bytes_for_record (json_bytes2perl (($test->{"result-data"} || ["[]"])->[0]));
              is $result->{resultdata}, $expected, 'WebSocket Close';
            }

            if (defined $result->{headers_received_error}) {
              is $result->{headers_received_error}, $result->{exit},
                 '|headers_received| rejection';
            } else {
              ok 1, '|headers_received| rejection (skipped)';
            }

            like $result->{exit}->name, qr{\A(?:HTTP parse error|WebSocket Close|OpenSSL error|Protocol error|Perl I/O error)\z}, 'error type';
          } $c;
          return $http->close_after_current_stream;
        });
      })->catch (sub {
        test {
          ok 0, 'No exception';
          is undef, $_[0], 'Exception';
        } $c;
      })->then (sub {
        done $c;
        undef $c;
      });
    } n => 10, name => [$path, $test->{name}->[0]], timeout => 120;
  };
} # $path

Test::Certificates->wait_create_cert;
run_tests;
Promise->all (\@End)->to_cv->recv;
@End = ();

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
