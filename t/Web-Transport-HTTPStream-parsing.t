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

my $server_pids = {};
END { kill 'KILL', $_ for keys %$server_pids }
sub server_as_cv ($) {
  my $code = $_[0];
  my $cv = AE::cv;
  my $started = 0;
  my $pid;
  my $data = '';
  my $port = find_listenable_port;
  my $host = (int rand 10000) . '.our.parsing.test';
  my $resultdata = [];
  my $after_server_close_cv = AE::cv;
  my $close_server = 0;
  local $ENV{SERVER_HOST_NAME} = $host;
  my $run_cv = run_cmd
      ['perl', path (__FILE__)->parent->parent->child ('t_deps/server.pl'), '127.0.0.1', $port],
      '<' => \$code,
      '>' => sub {
        $data .= $_[0] if defined $_[0];
        if ($ENV{DUMP} and defined $_[0]) {
          warn "--- .parsing.t received. ---\n";
          warn "$_[0]\n";
          warn "--- ^parsing.t received^ ---\n";
        }
        while ($data =~ s/^\[data (.+)\]$//m) {
          push @$resultdata, json_bytes2perl $1;
        }
        if ($data =~ s/^\[server done\]$//m) {
          #kill 'TERM', $pid if $close_server;
        }
        return if $started;
        if ($data =~ /^\[server (.+) ([0-9]+)\]/m) {
          $cv->send ({pid => $pid, addr => $1, port => $2, host => $host,
                      resultdata => $resultdata,
                      after_server_close_cv => $after_server_close_cv,
                      stop => sub {
                        kill 'TERM', $pid;
                        delete $server_pids->{$pid};
                      }});
          $started = 1;
        }
      },
      '$$' => \$pid;
  $server_pids->{$pid} = 1;
  $run_cv->cb (sub {
    my $result = $_[0]->recv;
    warn "Server stopped ($result)" if $ENV{DUMP};
    if ($result) {
      $after_server_close_cv->croak ("Server error: $result");
      $cv->croak ("Server error: $result") unless $started;
    } else {
      $after_server_close_cv->send;
    }
  });
  return $cv;
} # server_as_cv

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
      server_as_cv ($test->{data}->[0])->cb (sub {
        my $server = eval { $_[0]->recv };
        if ($@) {
          my $error = $@;
          test {
            is $error, undef, 'server_as_cv';
          } $c;
          done $c;
          undef $c;
          return;
        }
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

        $http->connect ()->then (sub {
          if ($test_type eq 'ws') {
            my $req = {
              method => _a 'GET',
              target => _a $test->{url}->[1]->[0],
              ws => 1,
            };
            return $http->send_request
                ($req,
                 ws => 1,
                 ws_protocols => [map { _a $_->[0] } @{$test->{'ws-protocol'} or []}])->then (sub {
              my $stream = $_[0]->{stream};
              my $closed = $_[0]->{closed};
              return $stream->headers_received->then (sub {
                my $got = $_[0];

                my $result = {};
                if ($got->{messages}) {
                  $result->{ws_established} = 1;
                  if ($test_type eq 'ws' and $test->{'ws-send'}) {
                    $stream->send_ws_message (3, not 'binary')->then (sub {
                      my $writer = $_[0]->{stream}->get_writer;
                      $writer->write (DataView->new (ArrayBuffer->new_from_scalarref (\'stu')));
                      return $writer->close;
                    });
                  }
                } else {
                  if ($test_type eq 'ws') {
                    Promise->resolve->then (sub { $http->abort });
                  }
                }
                $result->{response} = $stream->{response};
                return (
                  defined $got->{messages}
                    ? rsread_messages ($test, $got->{messages})
                    : rsread ($test, $got->{body})
                )->then (sub {
                  $result->{response_body} = $_[0];
                })->then (sub {
                  return $closed;
                })->then (sub {
                  $result->{error} = $_[0];
                }, sub {
                  $result->{error} = $_[0];
                })->then (sub {
                  return $result;
                });
              });
            });
          } elsif ($test_type eq 'second' or
                   $test_type eq 'largerequest-second') {
            my $try_count = 0;
            my $try; $try = sub {
              unless ($http->is_active) {
                return $http->close_after_current_stream->then (sub {
                  $tparams = {
                    class => 'Web::Transport::TCPStream',
                    host => Web::Host->parse_string ($server->{addr}),
                    port => $server->{port},
                  };
                  $http = Web::Transport::HTTPStream->new ({parent => $tparams});
                  return $http->connect;
                })->then (sub {
                  return $try->();
                });
              } # is_active
              my $req = {
                method => _a $test->{method}->[1]->[0],
                target => _a $test->{url}->[1]->[0],
              };
              return $http->send_request ($req, content_length => ($test_type eq 'largerequest-second' ? 1024*1024 : undef))->then (sub {
                my $stream = $_[0]->{stream};
                my $reqbody = $_[0]->{body}->get_writer;
                my $closed = $_[0]->{closed};
                my $result = {};
                return $stream->headers_received->then (sub {
                  my $got = $_[0];
                  if ($test_type eq 'largerequest-second') {
                    $reqbody->write
                        (DataView->new (ArrayBuffer->new_from_scalarref
                                            (\('x' x (1024*1024)))));
                  }
                  if ($req->{method} eq 'CONNECT') {
                    for (@{$test->{'tunnel-send'} or []}) {
                      $reqbody->write
                          (DataView->new
                               (ArrayBuffer->new_from_scalarref
                                    (\_a $_->[0])));
                    }
                    $reqbody->close;
                  }

                  $result->{response} = $stream->{response};
                  return (
                    defined $got->{messages}
                      ? rsread_messages ($test, $got->{messages})
                      : rsread ($test, $got->{body})
                  )->then (sub {
                    $result->{response_body} = $_[0];
                  })->then (sub {
                    return $closed;
                  });
                })->then (sub {
                  $result->{error} = $_[0];
                }, sub {
                  $result->{error} = $_[0];
                })->then (sub {
                  unless ($try_count++) {
                    return Promise->new (sub {
                      my $ok = $_[0];
                      my $timer; $timer = AE::timer 0.1, 0, sub {
                        undef $timer;
                        $ok->($try->());
                      };
                    });
                  }
                  for (@{$result->{response}->{headers}}) {
                    if ($_->[2] eq 'x-test-retry') {
                      return $try->() if $try_count < 10;
                    }
                  }
                  if (defined $result->{error} and
                      $result->{error}->{can_retry}) {
                    return $try->() if $try_count < 10;
                  }
                  return $result;
                });
              });
            }; # $try
            return promised_cleanup { undef $try } $try->();
          } else { # $test_type
            my $req = {
              method => _a $test->{method}->[1]->[0],
              target => _a $test->{url}->[1]->[0],
            };
            return $http->send_request ($req, content_length => ($test_type eq 'largerequest' ? 1024*1024 : undef))->then (sub {
              my $stream = $_[0]->{stream};
              my $closed = $_[0]->{closed};
              my $reqbody = $_[0]->{body}->get_writer;
              return $stream->headers_received->then (sub {
                my $got = $_[0];
                if ($test_type eq 'largerequest') {
                  $reqbody->write
                      (DataView->new
                           (ArrayBuffer->new_from_scalarref (\('x' x 1024))))
                          for 1..1024;
                }
                if ($req->{method} eq 'CONNECT') {
                  for (@{$test->{'tunnel-send'} or []}) {
                    $reqbody->write
                        (DataView->new
                             (ArrayBuffer->new_from_scalarref (\_a $_->[0])));
                  }
                  $reqbody->close;
                }
                my $result = {
                  response => $stream->{response},
                };
                return rsread ($test, $got->{body})->then (sub {
                  $result->{response_body} = $_[0];
                })->then (sub {
                  return $closed;
                })->then (sub {
                  $result->{error} = $_[0];
                }, sub {
                  $result->{error} = $_[0];
                })->then (sub {
                  return $result;
                });
              });
            });
          }
        })->then (sub {
          my $result = $_[0];
          my $res = $result->{response};
          return Promise->resolve->then (test {
            my $is_error;
            if ($test_type eq 'ws') {
              $is_error = !$result->{ws_established};
              is !!$is_error, !!$test->{'handshake-error'}, 'is error (ws)';
            } else {
              $is_error = $test->{status}->[1]->[0] == 0 && !defined $test->{reason};
              is !!($result->{error}->{failed}), !!$is_error, 'is error';
            }

            if ($is_error) {
              ok 1;
            } else {
              is $res->{version}, $test->{version} ? $test->{version}->[1]->[0] : '1.1', 'response version';
            }
            if ($test_type eq 'ws') {
              if ($is_error) {
                ok 1;
              } else {
                $result->{response_body} = '(close)' unless length $result->{response_body};
                if ($test->{'received-length'}) {
                  is length ($result->{response_body}), $test->{'received-length'}->[1]->[0] + length '(close)', 'received length';
                } else {
                  is $result->{response_body}, (defined $test->{received}->[0] ? $test->{received}->[0] : '') . '(close)', 'received';
                }
              }
              if (not $result->{ws_established}) {
                $result->{error}->{status} = 1006;
                $result->{error}->{reason} = '';
              } elsif (not defined $result->{error}->{status}) {
                $result->{error}->{status} = 1005;
                $result->{error}->{reason} = '';
              } elsif ($result->{error}->{status} == 1002) {
                $result->{error}->{status} = 1006;
                $result->{error}->{reason} = '';
              }
              is $result->{error}->{status}, $test->{'ws-status'} ? $test->{'ws-status'}->[1]->[0] : $test->{'handshake-error'} ? 1006 : undef, 'WS status code';
              is $result->{error}->{reason}, $test->{'ws-reason'} ? $test->{'ws-reason'}->[0] : $test->{'handshake-error'} ? '' : undef, 'WS reason';
              is !!$result->{error}->{cleanly}, !!$test->{'ws-was-clean'}, 'WS wasClean';
              ok 1, 'skip (ws)';

              return Promise->from_cv ($server->{after_server_close_cv})->then (sub {
                my $expected = perl2json_bytes_for_record (json_bytes2perl (($test->{"result-data"} || ["[]"])->[0]));
                my $actual = perl2json_bytes_for_record $server->{resultdata};
                test {
                  is $actual, $expected, 'resultdata';
                } $c;
              });
            } else {
              if ($is_error) {
                ok 1;
                ok 1;
                ok 1;
                ok 1;
                ok 1;
              } else {
                is $res->{status}, $test->{status}->[1]->[0];
                is $res->{reason}, defined $test->{reason}->[1]->[0] ? $test->{reason}->[1]->[0] : defined $test->{reason}->[0] ? $test->{reason}->[0] : '';
                is join ("\x0A", map {
                  $_->[0] . ': ' . $_->[1];
                } @{$res->{headers}}), defined $test->{headers}->[0] ? $test->{headers}->[0] : '';
                is $result->{response_body}, $test->{body}->[0], 'body';
                is !!$result->{response}->{incomplete}, !!$test->{incomplete}, 'incomplete message';
              }
            }
          } $c)->then (sub {
            return $http->close_after_current_stream;
          });
        }, sub { # connect failed
          my $error = $_[0]; # XXX
          test {
            # XXXX
            # XXX ws handshake error
            my $is_error = $test->{status} ? ($test->{status}->[1]->[0] == 0 && !defined $test->{reason}) : 1;
            is !!1, !!$is_error, 'is error';
            ok 1, 'response version (skipped)';
            is undef, $test->{status}->[1]->[0] || undef, 'status';
            if ($is_error) {
              ok 1, $error;
            } else {
              is $error, undef, 'no error';
            }
            ok 1, 'headers (skipped)';
            is '(close)', $test->{body}->[0] || '(close)', 'body';
            ok 1, 'incomplete (skipped)';
          } $c;
        })->then (sub {
          $server->{stop}->();
        })->catch (sub {
          warn "Error: $_[0]";
        })->then (sub {
          done $c;
          undef $c;
        });
      });
    } n => 7, name => [$path, $test->{name}->[0]], timeout => 120;
  };
} # $path

Test::Certificates->wait_create_cert;
run_tests;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
