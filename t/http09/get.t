use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Test::HTCT::Parser;
use HTTP;
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

for_each_test path (__FILE__)->parent->parent->parent->child ('t_deps/data/http09.dat'), {}, sub {
  my $test = $_[0];
  test {
    my $c = shift;
    server_as_cv ($test->{data}->[0])->cb (sub {
      my $server = $_[0]->recv;
      my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
      my $data = '';
      $http->ondata (sub {
        if (defined $_[0]) {
          $data .= $_[0];
          $data .= '(boundary)' if $test->{boundary};
        }
      });
      $http->onclose (sub {
        $data .= defined $_[0] ? '(error close)' : '(close)';
      });
      $http->connect_as_cv->cb (sub {
        test {
          my $status = $data eq '(close)' ? 0 : 200;
          is $status, $test->{status}->[1]->[0];
          is $data, $test->{body}->[0];
          $server->{stop}->();
          done $c;
          undef $c;
        } $c;
      });
    });
  } n => 2;
};

run_tests;
