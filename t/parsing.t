use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Test::HTCT::Parser;
use Encode;
use JSON::PS;
use Web::Host;
use Web::Transport::TCPTransport;
use Web::Transport::TLSTransport;
use Web::Transport::HTTPConnection;
use Promise;
use AnyEvent::Util qw(run_cmd);
use Test::Certificates;

sub _a ($) {
  return encode 'utf-8', $_[0];
} # _a

my $server_pids = {};
END { kill 'KILL', $_ for keys %$server_pids }
sub server_as_cv ($) {
  my $code = $_[0];
  my $cv = AE::cv;
  my $started;
  my $pid;
  my $data = '';
  my $port = int (rand 10000) + 1024;
  my $host = (int rand 10) . '.parsing.test';
  my $resultdata = [];
  my $after_server_close_cv;
  my $close_server = 0;
  local $ENV{SERVER_HOST_NAME} = $host;
  $after_server_close_cv = run_cmd
      ['perl', path (__FILE__)->parent->parent->child ('t_deps/server.pl'), '127.0.0.1', $port],
      '<' => \$code,
      '>' => sub {
        $data .= $_[0] if defined $_[0];
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
  return $cv;
} # server_as_cv

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
    test {
      my $c = shift;
      server_as_cv ($test->{data}->[0])->cb (sub {
        my $server = $_[0]->recv;
        my $transport = Web::Transport::TCPTransport->new
            (host => Web::Host->parse_string ($server->{addr}),
             port => $server->{port});

        my $time = time + 60;
        if (defined $test->{time}) {
          $time += $test->{time}->[1]->[0];
        }

        if ($test->{tls}) {
          $transport = Web::Transport::TLSTransport->new (
            transport => $transport,
            ca_file => Test::Certificates->ca_path ('cert.pem'),
            sni_host => Web::Host->parse_string ($server->{host}),
            si_host => Web::Host->parse_string ($server->{host}),
            clock => sub { return $time },
          );
        }

        my $http = Web::Transport::HTTPConnection->new
            (transport => $transport);
        my $test_type = $test->{'test-type'}->[1]->[0] || '';
        
        my $req_results = {};
        my $onev = sub {
          my ($http, $req, $type, undef, $flag) = @_;
          #warn "$req $type";
          my $result = $req_results->{$req->{id}} ||= {};
          if (not {requestsent => 1}->{$type}) {
            push @{$result->{r_events} ||= []}, $type;
          }
          if ({requestsent => 1, complete => 1}->{$type}) {
            push @{$result->{s_events} ||= []}, $type;
          }
          if ($type eq 'headers') {
            $result->{response} = $_[3];
            if ($req->{method} eq 'CONNECT') {
              $req->{_tunnel}->();
            }
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
            $result->{body} .= $_[3];
            $result->{body} .= '(boundary)' if $test->{boundary};
          }
          if ($type eq 'dataend' and
              $req->{method} eq 'CONNECT' and
              $result->{response}->{status} == 200) {
            AE::postpone { $http->close };
          }
          if ($type eq 'complete') {
            $result->{version} = $result->{response} ? $result->{response}->{version} : '1.1';
            $result->{body} = '' unless defined $result->{body};
            $result->{body} .= '(close)';
            $result->{is_error} = 1 if $_[3]->{failed};
            $result->{can_retry} = 1 if $_[3]->{can_retry};
            if ($_[3]->{reset}) {
              $result->{body} = '';
              $result->{version} = '1.1';
            }
            if ($_[3]->{failed}) {
              delete $result->{response};
              $result->{body} = '(close)' unless defined $_[3]->{status};
            }
            $result->{exit} = $_[3];
            $req->{_ok}->();
          }
        }; # $onev
        $http->onevent ($onev);

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
          $req->{tunnel} = Promise->new (sub { $req->{_tunnel} = $_[0] })
              if $req->{method} eq 'CONNECT';
          return $req;
        }; # $get_req

        $http->connect ()->then (sub {
          if ($test_type eq 'ws') {
            my $req = $get_req->(
              method => _a 'GET',
              target => _a $test->{url}->[1]->[0],
              ws => 1,
            );
            $http->send_request_headers
                ($req, ws => 1, ws_protocols => [map { _a $_->[0] } @{$test->{'ws-protocol'} or []}]);
            return $req->{done}->then (sub {
              return $req_results->{$req->{id}};
            });
          } elsif ($test_type eq 'second' or
                   $test_type eq 'largerequest-second') {
            my $try_count = 0;
            my $try; $try = sub {
              my $req = $get_req->(
                method => _a $test->{method}->[1]->[0],
                target => _a $test->{url}->[1]->[0],
                headers => [['Content-Length' => $test_type eq 'largerequest-second' ? 1024*1024 : 0]],
              );
              if ($test_type eq 'largerequest-second') {
                $req->{body} = 'x' x (1024*1024);
              }
              unless ($http->is_active) {
                return $http->close->then (sub {
                  $transport = Web::Transport::TCPTransport->new
                      (host => Web::Host->parse_string ($server->{addr}),
                       port => $server->{port});
                  $http = Web::Transport::HTTPConnection->new
                      (transport => $transport);
                  $http->onevent ($onev);
                  return $http->connect;
                })->then (sub {
                  return $try->();
                });
              }
              $http->send_request_headers ($req);
              $http->send_data (\('x' x (1024*1024))) if $test_type eq 'largerequest-second';
              if ($req->{method} eq 'CONNECT') {
                $req->{tunnel}->then (sub {
                  for (@{$test->{'tunnel-send'} or []}) {
                    $http->send_data (\_a $_->[0]);
                  }
                });
              }
              return $req->{done}->then (sub {
                unless ($try_count++) {
                  return Promise->new (sub {
                    my $ok = $_[0];
                    my $timer; $timer = AE::timer 0.1, 0, sub {
                      undef $timer;
                      $ok->($try->());
                    };
                  });
                }
                my $result = $req_results->{$req->{id}};
                for (@{$result->{response}->{headers}}) {
                  if ($_->[2] eq 'x-test-retry') {
                    return $try->() if $try_count < 10;
                  }
                }
                if ($result->{can_retry}) {
                  return $try->() if $try_count < 10;
                }
                return $result;
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
            $http->send_request_headers ($req);
            $http->send_data (\('x' x (1024*1024))) if $test_type eq 'largerequest';
            if ($req->{method} eq 'CONNECT') {
              $req->{tunnel}->then (sub {
                for (@{$test->{'tunnel-send'} or []}) {
                  $http->send_data (\_a $_->[0]);
                }
              });
            }
            return $req->{done}->then (sub {
              return $req_results->{$req->{id}};
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
              is !!$result->{is_error}, !!$is_error, 'is error';
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

            is $result->{version}, $test->{version} ? $test->{version}->[1]->[0] : '1.1', 'response version';
            if ($test_type eq 'ws') {
              if ($is_error) {
                ok 1;
              } else {
                if ($test->{'received-length'}) {
                  is length ($result->{body}), $test->{'received-length'}->[1]->[0] + length '(close)', 'received length';
                } else {
                  is $result->{body}, (defined $test->{received}->[0] ? $test->{received}->[0] : '') . '(close)', 'received';
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
              is $res->{status}, $is_error ? undef : $test->{status}->[1]->[0];
              is $res->{reason}, $is_error ? undef : defined $test->{reason}->[1]->[0] ? $test->{reason}->[1]->[0] : defined $test->{reason}->[0] ? $test->{reason}->[0] : '';
              is join ("\x0A", map {
                $_->[0] . ': ' . $_->[1];
              } @{$res->{headers}}), defined $test->{headers}->[0] ? $test->{headers}->[0] : '';
              is $result->{body}, $test->{body}->[0], 'body';
              is !!$result->{response}->{incomplete}, !!$test->{incomplete}, 'incomplete message';
            }
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
              is join (',', @{$result->{s_events} || []}), 'requestsent,complete', 's_events';
            }
          } $c;
          return $http->close;
        }, sub { # connect failed
          test {
            my $is_error = $test->{status}->[1]->[0] == 0 && !defined $test->{reason};
            is !!1, !!$is_error, 'is error';
            ok 1, 'response version (skipped)';
            is 0, $test->{status}->[1]->[0], 'status';
            ok 1, 'reason (skipped)';
            ok 1, 'headers (skipped)';
            is '(close)', $test->{body}->[0], 'body';
            ok 1, 'incomplete (skipped)';
            ok 1, 'r_events (skipped)';
            ok 1, 's_events (skipped)';
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
    } n => 9 # + 1 + 3*@{$test->{'1xx'} || []}
      , name => [$path, $test->{name}->[0]],
        timeout => (($test->{name}->[0] || '') =~ /length=/ ? 90 : 20);
  };
} # $path

Test::Certificates->wait_create_cert;
run_tests;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
