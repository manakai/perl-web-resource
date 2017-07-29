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
          kill 'TERM', $pid if $close_server;
        }
        return if $started;
        if ($data =~ /^\[server (.+) ([0-9]+)\]/m) {
          $cv->send ({pid => $pid, addr => $1, port => $2, host => $host,
                      resultdata => $resultdata,
                      close_server_ref => \$close_server,
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
  return $run->()->then (sub { undef $run; return $result . '(close)' });
} # rsread

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

        my $req;
        my $req_results = {};
        my $onev = sub {
          my $req = shift;
          return sub {
            my ($http, $type, undef, $flag) = @_;
            #warn "$req $type";
            my $result = $req_results->{$req ? $req->{id} : ''} ||= {};
            if (not {requestsent => 1}->{$type}) {
              push @{$result->{r_events} ||= []}, $type;
            }
            if ({requestsent => 1, complete => 1}->{$type}) {
              push @{$result->{s_events} ||= []}, $type;
            }
            if ($type eq 'headers') {
              $result->{response} = $_[2];
              if ($flag) {
                $result->{ws_established} = 1;
                if ($test_type eq 'ws' and $test->{'ws-send'}) {
                  $http->send_text_header (3);
                  $http->send_data (\'stu');
                }
              } else {
                if ($test_type eq 'ws') {
                  AE::postpone { $http->abort };
                }
              }
            }
            if ($type eq 'data' or $type eq 'text') {
              $result->{body} = '' unless defined $result->{body};
              $result->{body} .= $_[2];
              $result->{body} .= '(boundary)' if $test->{boundary};
            }
            if ($type eq 'dataend' and
                $req->{method} eq 'CONNECT' and
                $result->{response}->{status} == 200) {
              AE::postpone { $http->close };
            }
            if ($type eq 'complete') {
              $result->{version} = $result->{response}
                  ? $result->{response}->{version} : '1.1';
              $result->{body} = '' unless defined $result->{body};
              $result->{body} .= '(close)';
              $result->{is_error} = 1 if $_[2]->{failed};
              $result->{can_retry} = 1 if $_[2]->{can_retry};
              if ($_[2]->{reset}) {
                $result->{body} = '';
                $result->{version} = '1.1';
              }
              if ($_[2]->{failed}) {
                delete $result->{response};
                $result->{body} = '(close)' unless defined $_[2]->{status};
              }
              $result->{exit} = $_[2];
              $req->{_ok}->();
            }
          };
        }; # $onev

        my $next_req_id = 1;
        my $get_req = sub {
          my $req = {
            @_,
            id => $next_req_id++,
          };
          $req->{done} = Promise->new (sub { $req->{_ok} = $_[0] });
          if ($test_type eq 'ws') {
            ${$server->{close_server_ref}} = 1;
            $req->{done} = $req->{done}->then (sub {
              return Promise->from_cv ($server->{after_server_close_cv});
            });
          }
          return $req;
        }; # $get_req

        $http->connect ()->then (sub {
          if ($test_type eq 'ws') {
            my $req = $get_req->(
              method => _a 'GET',
              target => _a $test->{url}->[1]->[0],
              ws => 1,
            );
            return $http->send_request
                ($req,
                 ws => 1,
                 ws_protocols => [map { _a $_->[0] } @{$test->{'ws-protocol'} or []}])->then (sub {
              my $stream = $_[0]->{stream};
              return $stream->headers_received->then (sub {
                my $got = $_[0];

                my $result = {};
                return $stream->closed->then (sub { # XXX
                  return $result;
                });
              });
            });
          } elsif ($test_type eq 'second' or
                   $test_type eq 'largerequest-second') {
            my $try_count = 0;
            my $try; $try = sub {
              unless ($http->is_active) {
                return $http->close->then (sub {
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
              }
              return $http->send_request ($req, cb => $onev->($req))->then (sub {
                my $stream = $_[0]->{stream};
                my $req = $get_req->(
                  method => _a $test->{method}->[1]->[0],
                  target => _a $test->{url}->[1]->[0],
                  headers => [['Content-Length' => $test_type eq 'largerequest-second' ? 1024*1024 : 0]],
                );
                my $reqbody = $_[0]->{body}->get_writer;
                return $stream->headers_received->then (sub {
                  my $got = $_[0];
                  if ($test_type eq 'largerequest-second') {
                    $reqbody->write
                        (DataView->new (ArrayBuffer->new_from_scalarref
                                            (\('x' x (1024*1024)))));
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

                  my $result = {
                    response => $stream->{response},
                  };
                  return rsread ($test, $got->{body})->then (sub {
                    $result->{response_body} = $_[0];
                  })->then (sub {
                    return $stream->closed;
                  })->catch (sub {
                    $result->{error} = $_[0];
                  })->then (sub {
                    return $req->{done};
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
              })->then (sub {
                undef $try;
                return $_[0];
              });
            };
            return $try->();
          } else { # $test_type
            my $req = $get_req->(
              method => _a $test->{method}->[1]->[0],
              target => _a $test->{url}->[1]->[0],
              headers => [['Content-Length' => $test_type eq 'largerequest' ? 1024*1024 : 0]],
            );
            return $http->send_request ($req, cb => $onev->($req))->then (sub {
              my $stream = $_[0]->{stream};
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
                  return $stream->closed;
                })->catch (sub {
                  $result->{error} = $_[0];
                })->then (sub {
                  return $req->{done};
                })->then (sub {
                  return $result;
                });              });
            });
          }
        })->then (sub {
          my $result = $_[0];
          my $res = $result->{response};
          test {
            my $is_error;
            if ($test_type eq 'ws') {
              $is_error = !$result->{ws_established};
              is !!$is_error, !!$test->{'handshake-error'}, 'is error (ws)';
            } else {
              $is_error = $test->{status}->[1]->[0] == 0 && !defined $test->{reason};
              is !!$result->{error}, !!$is_error, 'is error';
            }

            #my $expected_1xxes = $test->{'1xx'} || [];
            #my $actual_1xxes = $res->{'1xxes'} || [];
            #is 0+@$actual_1xxes, 0+@$expected_1xxes, '# of 1xx responses';
            #for my $i (0..$#$expected_1xxes) {
            #  my $expected = ($expected_1xxes->[$i] || [''])->[0];
            #  my $actual = $actual_1xxes->[$i] || {};
            #  for_each_test \$expected, {
            #    headers => {is_prefixed => 1},
            #  }, sub {
            #    my $t = $_[0];
            #    test {
            #      is $actual->{status}, $t->{status}->[1]->[0];
            #      is $actual->{reason}, $t->{reason}->[1]->[0] // $t->{reason}->[0] // '';
            #      is join ("\x0A", map {
            #        $_->[0] . ': ' . $_->[1];
            #      } @{$actual->{headers}}), $t->{headers}->[0] // '';
            #    } $c, name => $i;
            #  };
            #}

            if ($is_error) {
              ok 1;
            } else {
              is $res->{version}, $test->{version} ? $test->{version}->[1]->[0] : '1.1', 'response version';
            }
            if ($test_type eq 'ws') {
              if ($is_error) {
                ok 1;
              } else {
                if ($test->{'received-length'}) {
                  is length ($result->{response_body}), $test->{'received-length'}->[1]->[0] + length '(close)', 'received length';
                } else {
                  is $result->{response_body}, (defined $test->{received}->[0] ? $test->{received}->[0] : '') . '(close)', 'received';
                }
              }
              if (not $result->{ws_established}) {
                $result->{exit}->{status} = 1006;
                $result->{exit}->{reason} = '';
              } elsif (not defined $result->{exit}->{status}) {
                $result->{exit}->{status} = 1005;
                $result->{exit}->{reason} = '';
              } elsif ($result->{exit}->{status} == 1002) {
                $result->{exit}->{status} = 1006;
                $result->{exit}->{reason} = '';
              }
              is $result->{exit}->{status}, $test->{'ws-status'} ? $test->{'ws-status'}->[1]->[0] : $test->{'handshake-error'} ? 1006 : undef, 'WS status code';
              is $result->{exit}->{reason}, $test->{'ws-reason'} ? $test->{'ws-reason'}->[0] : $test->{'handshake-error'} ? '' : undef, 'WS reason';
              is !!$result->{exit}->{cleanly}, !!$test->{'ws-was-clean'}, 'WS wasClean';
              my $expected = perl2json_bytes_for_record (json_bytes2perl (($test->{"result-data"} || ["[]"])->[0]));
              my $actual = perl2json_bytes_for_record $server->{resultdata};
              is $actual, $expected, 'resultdata';
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
if (0) { # XXX
            if ($result->{exit}->{reset}) {
              is $result->{r_events}->[-1], 'complete', 'r_events';
              is $result->{s_events}->[-1], 'complete', 's_events';
            } else {
              my $r_events = join (',', @{$result->{r_events} || []});
              1 while $r_events =~ s/,data,data,/,data,/g;
              $r_events =~ s/,datastart,dataend,/,datastart,data,dataend,/g;
              $r_events =~ s/,textstart,textend,/,textstart,text,textend,/g;
              if ($test_type eq 'ws') {
                like $r_events, qr{^(?:
                  (?:
                    headers,
                    (?:datastart,data,dataend,|textstart,text,textend,|ping,)*
                    (?:closing,|)
                  |)
                  complete
                )$}x, 'r_events';
              } else {
                like $r_events, qr{^(?:headers,datastart,data,dataend,|)complete$}, 'r_events';
              }
              ## If server closes the connection before sending all
              ## data to the server, requestsent event might not be
              ## reported.
              like join (',', @{$result->{s_events} || []}),
                  qr{^(?:requestsent,|)complete$}, 's_events';
            }
}
          } $c;
          return $http->close;
        }, sub { # connect failed
          my $error = $_[0]; # XXX
          test {
            # XXXX
            # XXX ws handshake error
            my $is_error = $test->{status}->[1]->[0] == 0 && !defined $test->{reason};
            is !!1, !!$is_error, 'is error';
            ok 1, 'response version (skipped)';
            is undef, $test->{status}->[1]->[0], 'status';
            if ($is_error) {
              ok 1, $error;
            } else {
              is $error, undef, 'no error';
            }
            ok 1, 'headers (skipped)';
            is undef, $test->{body}->[0], 'body';
            ok 1, 'incomplete (skipped)';
#XXX
#            ok 1, 'r_events (skipped)';
#            ok 1, 's_events (skipped)';
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
    } n => 7 # + 1 + 3*@{$test->{'1xx'} || []}
      , name => [$path, $test->{name}->[0]],
        timeout => 120;
  };
} # $path

Test::Certificates->wait_create_cert;
run_tests;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
