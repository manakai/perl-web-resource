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
  server_as_cv (q{
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my @ev;
    my $ok;
    my $req2;
    $http->onevent (sub {
      my ($http, $req, $type) = @_;
      push @ev, [$req, $type];
      if ({
        complete => 1, abort => 1, reset => 1, cancel => 1,
        responseerror => 1,
      }->{$type}) {
        $ok->();
      }
    });
    $http->connect->then (sub {
      return Promise->new (sub {
        ($ok) = @_;
        $http->send_request ({
          method => 'GET',
          url => '/',
        });
      });
    })->then (sub {
      return Promise->new (sub {
        ($ok) = @_;
        $http->send_request ($req2 = {
          method => 'GET',
          url => '/',
        });
      });
    })->then (sub {
      test {
        @ev = grep { $_->[0] eq $req2 } @ev;
        is 0+@ev, 1;
        ok $ev[0]->[0];
        is $ev[0]->[1], 'cancel';
      } $c;
    })->then (sub {
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 3, name => 'immediately canceled as connection already closed';

test {
  my $c = shift;
  server_as_cv (q{
    receive "/req1"
    "HTTP/1.1 200 OK"CRLF
    "Content-Length: 1"CRLF
    CRLF
    "a"
    receive "/req2"
    "HTTP/1.1 200 OK"CRLF
    "Content-Length: 1"CRLF
    CRLF
    "b"
    receive "/req3"
    "HTTP/1.1 200 OK"CRLF
    "Content-Length: 1"CRLF
    CRLF
    "c"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my @ev;
    my $ok;
    my $req3;
    $http->onevent (sub {
      my ($http, $req, $type) = @_;
      push @ev, [$req, $type];
      if ({
        complete => 1, abort => 1, reset => 1, cancel => 1,
        responseerror => 1,
      }->{$type}) {
        $ok->();
      }
    });
    $http->connect->then (sub {
      return Promise->new (sub {
        ($ok) = @_;
        $http->send_request ({
          method => 'GET',
          url => '/req1',
        });
      });
    })->then (sub {
      return Promise->new (sub {
        ($ok) = @_;
        $http->send_request ({
          method => 'GET',
          url => '/req2',
        });
      });
    })->then (sub {
      return Promise->new (sub {
        ($ok) = @_;
        $http->send_request ($req3 = {
          method => 'GET',
          url => '/req3',
        });
      });
    })->then (sub {
      test {
        @ev = grep { $_->[0] eq $req3 } @ev;
        is @ev, 4, 'requestsent; headers; data; complete';
        ok grep { $_->[1] eq 'complete' } @ev;
      } $c;
    })->then (sub {
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'complete event -> send request';

run_tests;
