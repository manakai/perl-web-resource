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

test {
  my $c = shift;
  my $http = HTTP->new_from_host_and_port ('localhost', rand);
  my $p = $http->send_request ({method => 'GET', target => '/'});
  isa_ok $p, 'Promise';
  $p->then (sub {
    test {
      ok 0;
    } $c;
  }, sub {
    my $e = $_[0];
    test {
      is $e, 'Connection has not been established';
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'not connected';

test {
  my $c = shift;
  server_as_cv (q{
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $p = $http->send_request ({method => 'GET', target => '/'});
      test {
        isa_ok $p, 'Promise';
      } $c;
      return $p->then (sub {
        test { ok 0 } $c;
      }, sub {
        my $e = $_[0];
        test {
          is $e, 'Connection is no longer in active';
        } $c;
      });
    })->then (sub{
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'connection already closed';

test {
  my $c = shift;
  server_as_cv (q{
    sleep 1
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    $http->connect->then (sub {
      my $p1 = $http->send_request ({method => 'GET', target => '/'});
      my $p = $http->send_request ({method => 'GET', target => '/'});
      test {
        isa_ok $p, 'Promise';
      } $c;
      return $p->then (sub {
        test { ok 0 } $c;
      }, sub {
        my $e = $_[0];
        test {
          is $e, 'Connection is busy';
        } $c;
      });
    })->then (sub{
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'connection already closed';

run_tests;
