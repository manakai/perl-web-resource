use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->parent->child ('t_deps/modules/*/lib');
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
      ['perl', path (__FILE__)->parent->parent->parent->child ('t_deps/server.pl'), '127.0.0.1', $port],
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

for my $path (map { path ($_) } glob path (__FILE__)->parent->parent->parent->child ('t_deps/data/*.dat')) {
  for_each_test $path, {
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
        my $res;
        my $data = '';
        $http->onresponsestart (sub {
          $res = $_[0];
        });
        $http->ondata (sub {
          $data .= $_[1];
          $data .= '(boundary)' if $test->{boundary};
        });
        $http->onclose (sub {
          $data .= '(close)';
          $data = '(close)',
          $res = {network_error => 1, error => $_[0]} if defined $_[0];
          test {
            my $is_error = $test->{status}->[1]->[0] == 0 && !defined $test->{reason};
            is !!$res->{network_error}, !!$is_error;

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
            is $data, $test->{body}->[0];

            $server->{stop}->();
            done $c;
            undef $c;
          } $c;
        });
        $http->connect->then (sub {
          return $http->send_request ({
            method => $test->{method}->[1]->[0],
            url => $test->{url}->[1]->[0],
            version => '1.0',
          });
        });
      });
    } n => 6 + 3*@{$test->{'1xx'} || []}, name => [$path, $test->{name}->[0]];
  };
} # $path

run_tests;
