use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use AnyEvent;
use AnyEvent::HTTPD;
use AnyEvent::Util qw(run_cmd);
use JSON::PS;
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
for my $file_name (glob path (__FILE__)->parent->parent->child ('t_deps/data/*.dat')) {
  for_each_test $file_name, {
    body => {is_prefixed => 1},
  }, sub {
    my $test = $_[0];
    $test->{_file_name} = $file_name;
    push @test, $test;
  };
}

my $httpd = AnyEvent::HTTPD->new (host => $host, port => $port);
my $cv = AE::cv;

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
      "<!DOCTYPE HTML><link rel='shortcut icon' href=about:blank><link rel=stylesheet href=http://$host:$port/css><body><script src=http://$host:$port/runner></script>"
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
    my $tests_json = perl2json_chars \@test;
    $req->respond ([200, 'OK', {
      'Content-Type' => 'text/javascript; charset=utf-8',
    }, qq{
      var link = document.createElement ('p');
      link.innerHTML = '<a href>Run again</a>';
      link.firstChild.href = 'http://$host:$port/';
      document.body.appendChild (link);

      var resultsContainer = document.createElement ('div');
      resultsContainer.innerHTML = '<table><thead><tr><th>#<th>Result<th><code>status</code><th><code>statusText</code><th><code>responseText</code><th>File<tbody></table>';
      var results = resultsContainer.firstChild;
      document.body.appendChild (resultsContainer);
      results = results.appendChild (document.createElement ('tbody'));

      function setResult (cell, result, actual, expected) {
        if (result) {
          cell.innerText = cell.textContent = '';
          cell.className = 'PASS';
        } else {
          cell.innerHTML = '<table><tr><th>Actual<td><code></code><tr><th>Expected<td><code></code></table>';
          var codes = cell.getElementsByTagName ('code');
          codes[0].innerText = codes[0].textContent = actual;
          codes[1].innerText = codes[1].textContent = expected;
          cell.className = 'FAIL';
        }
        return result;
      } // setResult

      function runTest (test, testName, then) {
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
                tr.className = 'FAIL';
                var failed = false;
                tr.appendChild (document.createElement ('th')).appendChild (document.createTextNode (testName));
                var resultCell = tr.appendChild (document.createElement ('th'));
                resultCell.textContent = 'FAIL';
                var cell = tr.appendChild (document.createElement ('td'));
                setResult (cell, x.status == test.status[1][0], x.status, test.status[1][0]) || (failed = true);
                var cell = tr.appendChild (document.createElement ('td'));
                var reason = (test.reason || ['', ['']])[1][0];
                setResult (cell, x.statusText == reason, x.statusText, reason) || (failed = true);
                var cell = tr.appendChild (document.createElement ('td'));
                var expected = test.body[0].replace (/\\(boundary\\)/g, '');
                setResult (cell, x.responseText + '(close)' == expected, x.responseText + '(close)', expected) || (failed = true);
                if (!failed) {
                  resultCell.textContent = 'PASS';
                  tr.className = 'PASS';
                }
                tr.appendChild (document.createElement ('td')).appendChild (document.createTextNode (test._file_name));
                results.appendChild (tr);
                then ();
              }
            };
            x.send (null);
          }
        };
        xhr.send (null);
      } // runTest

      var tests = $tests_json;
      var nextTest = 0;
      function runNext () {
        if (nextTest < tests.length) {
          runTest (tests[nextTest], nextTest++, runNext);
        } else {
          var xhr = new XMLHttpRequest;
          xhr.open ('GET', 'http://$host:$port/last?' + Math.random (), false);
          xhr.send (null);
        }
      }
      runNext ();
    }]);
  } elsif ($path eq '/css') {
    $req->respond ([200, 'OK', {'Content-Type' => 'text/css'}, q{
      .PASS { background-color: green; color: white }
      .FAIL { background-color: red; color: white }
      code:empty::after { content: "(empty)"; color: gray }
      td table th {
        text-align: right;
      }
    }]);
  } elsif ($path eq '/last') {
    $req->respond ([200, 'OK', {}, '']);
    $cv->send;
  } else {
    $req->respond ([404, 'OK', {}, '404 Not Found']);
  }
});

warn "Listening $host:$port...";
warn "(Using $test_port)";

$cv->recv;
