use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Test::HTCT::Parser;
use HTTP;
use Promise;
use AnyEvent::Util qw(run_cmd);

my $server_pids = {};
END { kill 'KILL', $_ for keys %$server_pids }
sub server_as_cv ($) {
  my $code = $_[0];
  my $cv = AE::cv;
  my $started;
  my $pid;
  my $data = '';
  my $port = int (rand 10000) + 1024;
  run_cmd
      ['perl', path (__FILE__)->parent->parent->child ('t_deps/server.pl'), '127.0.0.1', $port],
      '<' => \$code,
      '>' => sub {
        $data .= $_[0] if defined $_[0];
        return if $started;
        if ($data =~ /^\[server (.+) ([0-9]+)\]/m) {
          $cv->send ({pid => $pid, host => $1, port => $2,
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
  for_each_test $path, {
    'tunnel-send' => {is_prefixed => 1, multiple => 1},
    '1xx' => {is_prefixed => 1, multiple => 1},
    headers => {is_prefixed => 1},
    body => {is_prefixed => 1},
  }, sub {
    my $test = $_[0];
    test {
      my $c = shift;
      server_as_cv ($test->{data}->[0])->cb (sub {
        my $server = $_[0]->recv;
        my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
        
        my $req_results = {};
        my $onev = sub {
          my ($http, $req, $type) = @_;
          #warn "$req $type";
          my $result = $req_results->{$req->{id}} ||= {};
          push @{$result->{events} ||= []}, [$type];
          if ($type eq 'headers') {
            $result->{response} = $_[3];
            if ($req->{method} eq 'CONNECT') {
              $req->{_tunnel}->();
            }
          }
          if ($type eq 'data') {
            $result->{body} //= '';
            $result->{body} .= $_[3];
            $result->{body} .= '(boundary)' if $test->{boundary};
          }
          if ({
            complete => 1, abort => 1, reset => 1, cancel => 1,
            responseerror => 1,
          }->{$type}) {
            $result->{body} //= '';
            $result->{body} .= '(close)';
            $result->{is_error} = 1 unless $type eq 'complete';
            if ($type eq 'reset') {
              delete $result->{response};
              $result->{body} = '(close)';
            }
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
          $req->{tunnel} = Promise->new (sub { $req->{_tunnel} = $_[0] })
              if $req->{method} eq 'CONNECT';
          return $req;
        }; # $get_req

        my $test_type = $test->{'test-type'}->[1]->[0] // '';

        $http->connect->then (sub {
          if ($test_type eq 'second' or
              $test_type eq 'largerequest-second') {
            my $try_count = 0;
            my $try; $try = sub {
              my $req = $get_req->(
                method => $test->{method}->[1]->[0],
                target => $test->{url}->[1]->[0],
              );
              if ($test_type eq 'largerequest-second') {
                $req->{body} = 'x' x (1024*1024);
              }
              unless ($http->is_active) {
                return $http->close->then (sub {
                  $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
                  $http->onevent ($onev);
                  return $http->connect;
                })->then (sub {
                  return $try->();
                });
              }
              $http->send_request ($req);
              if ($req->{method} eq 'CONNECT') {
                $req->{tunnel}->then (sub {
                  for (@{$test->{'tunnel-send'} or []}) {
                    $http->send_through_tunnel ($_->[0]);
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
                return $result;
              })->then (sub {
                undef $try;
                return $_[0];
              });
            };
            return $try->();
          } else {
            my $req = $get_req->(
              method => $test->{method}->[1]->[0],
              target => $test->{url}->[1]->[0],
            );
            if ($test_type eq 'largerequest') {
              $req->{body_ref} = \('x' x (1024*1024));
            }
            $http->send_request ($req);
            if ($req->{method} eq 'CONNECT') {
              $req->{tunnel}->then (sub {
                for (@{$test->{'tunnel-send'} or []}) {
                  $http->send_through_tunnel ($_->[0]);
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
            my $is_error = $test->{status}->[1]->[0] == 0 && !defined $test->{reason};
            is !!$result->{is_error}, !!$is_error, 'is error';

            my $expected_1xxes = $test->{'1xx'} || [];
            my $actual_1xxes = $res->{'1xxes'} || [];
            is 0+@$actual_1xxes, 0+@$expected_1xxes, '# of 1xx responses';
            for my $i (0..$#$expected_1xxes) {
              my $expected = ($expected_1xxes->[$i] || [''])->[0];
              my $actual = $actual_1xxes->[$i] || {};
              for_each_test \$expected, {
                headers => {is_prefixed => 1},
              }, sub {
                my $t = $_[0];
                test {
                  is $actual->{status}, $t->{status}->[1]->[0];
                  is $actual->{reason}, $t->{reason}->[1]->[0] // $t->{reason}->[0] // '';
                  is join ("\x0A", map {
                    $_->[0] . ': ' . $_->[1];
                  } @{$actual->{headers}}), $t->{headers}->[0] // '';
                } $c, name => $i;
              };
            }

            is $res->{status}, $is_error ? undef : $test->{status}->[1]->[0];
            is $res->{reason}, $is_error ? undef : $test->{reason}->[1]->[0] // $test->{reason}->[0] // '';
            is join ("\x0A", map {
              $_->[0] . ': ' . $_->[1];
            } @{$res->{headers}}), $test->{headers}->[0] // '';
            is $result->{body}, $test->{body}->[0], 'body';
            is !!$result->{response}->{incomplete}, !!$test->{incomplete}, 'incomplete message';
          } $c;
          return $http->close;
        })->then (sub {
          $server->{stop}->();
        })->catch (sub {
          warn "Error: $_[0]";
        })->then (sub {
          done $c;
          undef $c;
        });
      });
    } n => 7 + 3*@{$test->{'1xx'} || []}, name => [$path, $test->{name}->[0]];
  };
} # $path

run_tests;
