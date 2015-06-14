use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use AnyEvent;
use AnyEvent::HTTPD;
use AnyEvent::Util qw(run_cmd);
use Test::HTCT::Parser;

my $host = '0';
my $port = 4355;
my $test_port = int (rand 10000) + 1024;

my $server_pids = {};
END { kill 'KILL', $_ for keys %$server_pids }
sub server_as_cv ($) {
  my $code = $_[0];
  my $cv = AE::cv;
  my $started;
  my $pid;
  my $data = '';
  run_cmd
      ['perl', path (__FILE__)->parent->parent->child ('t_deps/server.pl'), 0, $test_port],
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

sub timer ($$) {
  my ($timeout, $code) = @_;
  my $timer; $timer = AE::timer $timeout, 0, sub {
    $code->();
    undef $timer;
  };
} # timer

my @test;
for (glob path (__FILE__)->parent->parent->child ('t_deps/data/*.dat')) {
  for_each_test $_, {}, sub {
    my $test = $_[0];
    push @test, $test;
  };
}

my $httpd = AnyEvent::HTTPD->new (host => $host, port => $port);
$httpd->reg_cb ('' => sub {
  my ($httpd, $req) = @_;
  my $host = $req->headers->{host} // $host;
  $host =~ s/\s+//g;
  $host =~ s/:[0-9]+$//;
  my $path = $req->url->path;
  if ($path eq '/') {
    server_as_cv (qq{
      "HTTP/1.0 200 OK"CRLF
      "Content-Type: text/html; charset=utf-8"CRLF
      CRLF
      "<link rel='shortcut icon' href=about:blank><body><script src=http://$host:$port/runner></script>"
      close
    })->cb (sub {
      my $server = $_[0]->recv;
      $req->respond ([302, 'Redirect', {
        'Location' => "http://$host:$test_port/?" . rand,
      }, '302 Redirect']);
      timer 10, sub { $server->{stop}->() };
    });
  } elsif ($path =~ m{^/start/([0-9]+)$}) {
    my $test_name = $1;
    my $test = $test[$test_name];
    if (defined $test) {
      server_as_cv ($test->{data}->[0])->cb (sub {
        my $server = $_[0]->recv;
        $req->respond ([200, 'OK', {
          'Access-Control-Allow-Origin' => '*',
        }, "http://$host:$test_port/?" . rand]);
        timer 10, sub { $server->{stop}->() };
      });
    } else {
      $req->respond ([404, 'Not found', {}, '404 Test not found']);
    }
  } elsif ($path eq '/runner') {
    $req->respond ([200, 'OK', {
      'Content-Type' => 'text/javascript; charset=utf-8',
    }, qq{
      var results = document.createElement ('table');
      document.body.appendChild (results);
      results = results.appendChild (document.createElement ('tbody'));

      function runTest (testName, then) {
        var xhr = new XMLHttpRequest ();
        xhr.open ('GET', 'http://$host:$port/start/' + encodeURIComponent (testName) + '?' + Math.random (), true);
        xhr.onreadystatechange = function () {
          if (xhr.readyState === 4 && xhr.status === 200) {
            var url = xhr.responseText;
            var x = new XMLHttpRequest;
            x.open ('GET', url, true);
            x.onreadystatechange = function () {
              if (x.readyState === 4) {
                var body = x.responseText;
                var tr = document.createElement ('tr');
                tr.appendChild (document.createElement ('th')).appendChild (document.createTextNode (testName));
                tr.appendChild (document.createElement ('td')).appendChild (document.createTextNode (x.status));
                tr.appendChild (document.createElement ('td')).appendChild (document.createTextNode (x.statusText));
                tr.appendChild (document.createElement ('td')).appendChild (document.createTextNode (body));
                results.appendChild (tr);
                then ();
              }
            };
            x.send (null);
          }
        };
        xhr.send (null);
      } // runTest

      var maxTest = @{[$#test]};
      var nextTest = 0;
      function runNext () { if (nextTest <= maxTest) runTest (nextTest++, runNext) }
      runNext ();
    }]);
  } else {
    $req->respond ([404, 'OK', {}, '404 Not Found']);
  }
});

warn "Listening $host:$port...";
warn "(Using $test_port)";

my $cv = AE::cv;
$cv->recv;
