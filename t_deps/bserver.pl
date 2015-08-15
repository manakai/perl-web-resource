use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use AnyEvent;
use AnyEvent::HTTPD;
use AnyEvent::Util qw(run_cmd);
use Encode;
use JSON::PS;
use Test::HTCT::Parser;

my $host = '0';
my $port = 4355;
my $tlsport = 14355;
my $test_port = int (rand 10000) + 1024;

my $server_pids = {};
END { kill 'KILL', $_ for keys %$server_pids }
my $last_server;
sub server_as_cv ($) {
  my $code = $_[0];
  my $cv = AE::cv;
  my $start = sub {
    my $started;
    my $pid;
    my $data = '';
    my @after_stop;
    my $stopper = sub {
      if (kill 0, $pid) {
        kill 'TERM', $pid;
        delete $server_pids->{$pid};
        push @after_stop, $_[0] if $_[0];
      } else {
        $_[0]->() if $_[0];
      }
    }; # $stopper
    my $cmd_cv = run_cmd
        ['perl', path (__FILE__)->parent->parent->child ('t_deps/server.pl'), 0, $test_port],
        '<' => \$code,
        '>' => sub {
          $data .= $_[0] if defined $_[0];
          return if $started;
          if ($data =~ /^\[server (.+) ([0-9]+)\]/m) {
            $cv->send ({pid => $pid, host => $1, port => $2,
                        stop => $stopper});
            $started = 1;
          }
        },
        '$$' => \$pid;
    $server_pids->{$pid} = 1;
    $last_server = $stopper;
    $cmd_cv->cb (sub {
      for (@after_stop) {
        $_->();
      }
    });
  }; # $start
  if ($last_server) {
    $last_server->($start);
  } else {
    $start->();
  }
  return $cv;
} # server_as_cv

sub timer ($$) {
  my ($timeout, $code) = @_;
  my $timer; $timer = AE::timer $timeout, 0, sub {
    $code->();
    undef $timer;
  };
} # timer

my $filter = $ENV{TEST_METHOD} ? qr/$ENV{TEST_METHOD}/ : qr//;
my @test;
my @tlstest;
for my $file_name (glob path (__FILE__)->parent->parent->child ('t_deps/data/*.dat')) {
  for_each_test $file_name, {
    '1xx' => {is_prefixed => 1, multiple => 1},
    headers => {is_prefixed => 1},
    body => {is_prefixed => 1},
    'tunnel-send' => {is_prefixed => 1, multiple => 1},
  }, sub {
    my $test = $_[0];
    my $name = join ' - ', $file_name, $test->{name}->[0] // '';
    $name =~ /$filter/o or return;
    $test->{_file_name} = $file_name;
    if ($test->{tls}) {
      push @tlstest, $test;
    } else {
      push @test, $test;
    }
  };
}

my $root_path = path (__FILE__)->parent->parent->absolute;
my $cert_path = $root_path->child ('local/cert');
my $cn = $ENV{SERVER_HOST_NAME} // 'hoge.test';
my $httpd = AnyEvent::HTTPD->new (host => $host, port => $port);
my $tlshttpd = AnyEvent::HTTPD->new (host => $host, port => $tlsport, ssl => {
  ca_path => $cert_path->child ('ca-cert.pem'),
  cert_file => $cert_path->child ($cn . '-cert.pem'),
  key_file => $cert_path->child ($cn . '-key-pkcs1.pem'),
});
my $cv = AE::cv;

my $httpdcb = sub {
  my ($httpd, $req) = @_;
  my $host = $req->headers->{host} // $host;
  $host =~ s/\s+//g;
  $host =~ s/:[0-9]+$//;
  my $path = $req->url->path;
  if ($path eq '/') {
    server_as_cv ($httpd->port == $port ? qq{
      "HTTP/1.0 200 OK"CRLF
      "Content-Type: text/html; charset=utf-8"CRLF
      CRLF
      "<!DOCTYPE HTML><link rel='shortcut icon' href=https://test/favicon.ico><link rel=stylesheet href=http://$host:$port/css><body><script src=http://$host:$port/runner></script>"
      close
    } : qq{
      starttls
      receive "GET"
      "HTTP/1.0 200 OK"CRLF
      "Content-Type: text/html; charset=utf-8"CRLF
      CRLF
      "<!DOCTYPE HTML><link rel='shortcut icon' href=https://test/favicon.ico><link rel=stylesheet href=https://$host:$tlsport/css><body><script src=https://$host:$tlsport/runner></script>"
      close
    })->cb (sub {
      my $server = $_[0]->recv;
      my $scheme = $httpd->port == $port ? 'http' : 'https';
      $req->respond ([302, 'Redirect', {
        'Location' => "$scheme://$host:$test_port/?" . rand,
      }, '302 Redirect']);
      timer 10, sub { $server->{stop}->() };
    });
  } elsif ($path =~ m{^/start/([0-9]+)$}) {
    my $test_name = $1;
    #warn "start $test_name\n";
    my $test = $httpd->port == $port ? $test[$test_name] : $tlstest[$test_name];
    if (defined $test) {
      server_as_cv ($test->{data}->[0])->cb (sub {
        my $server = $_[0]->recv;
        my $ws = ($test->{'test-type'} || ['', ['']])->[1]->[0] eq 'ws';
        my $scheme = $httpd->port == $port ? 'http' : 'https';
        $scheme =~ s/http/ws/ if $ws;
        $req->respond ([200, 'OK', {
          'Access-Control-Allow-Origin' => '*',
        }, "$scheme://$host:$test_port/?" . rand]);
        timer 10, sub { $server->{stop}->() };
      });
    } else {
      $req->respond ([404, 'Not found', {}, '404 Test not found']);
    }
  } elsif ($path eq '/runner') {
    my $tests_json = perl2json_chars ($httpd->port == $port ? \@test : \@tlstest);
    $req->respond ([200, 'OK', {
      'Content-Type' => 'text/javascript; charset=utf-8',
    }, encode_utf8 qq{
      var link = document.createElement ('p');
      link.innerHTML = '<a href>Run http: tests</a> <a href>Run https: tests</a>';
      link.firstChild.href = 'http://$host:$port/';
      link.lastChild.href = 'https://$host:$tlsport/';
      document.body.appendChild (link);

      var resultsContainer = document.createElement ('div');
      resultsContainer.innerHTML = '<table><thead><tr><th>#<th>Result<th><code>status</code><th><code>statusText</code><th>Headers<th><code>responseText</code><th>File<th>Name<tbody></table>';
      var results = resultsContainer.firstChild;
      document.body.appendChild (resultsContainer);
      results = results.appendChild (document.createElement ('tbody'));

      var largeDataSize = 10*1024*1024;

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

      function compareResponse (test, testNumber, x) {
                var body = x.responseText;
                var tr = document.createElement ('tr');
                tr.className = 'FAIL';
                var failed = false;
                tr.appendChild (document.createElement ('th')).appendChild (document.createTextNode (testNumber));
                var resultCell = tr.appendChild (document.createElement ('th'));
                resultCell.textContent = 'FAIL';
                var cell = tr.appendChild (document.createElement ('td'));
                setResult (cell, x.status == test.status[1][0], x.status, test.status[1][0]) || (failed = true);
                var cell = tr.appendChild (document.createElement ('td'));
                var reason = test.reason || ['', ['']];
                reason = reason[1][0] || reason[0];
                if (reason === undefined) reason = '';
                setResult (cell, x.statusText == reason, x.statusText, reason) || (failed = true);
                var cell = tr.appendChild (document.createElement ('td'));
                var eHeaders = (test.headers || [''])[0];
                var aHeaderNames = x.getAllResponseHeaders ()
                    .split (/[\\u000D\\u000A]+/)
                    .filter (function (_) { return /:/.test (_); })
                    .map (function (_) { return _.split (/:/)[0]; });
                cell.title = x.getAllResponseHeaders () + "\\u000A\\u000A" + aHeaderNames;
                var aHeaders = aHeaderNames.map (function (name) {
                  try {
                    var value = x.getResponseHeader (name);
                    if (value === null) return '';
                    return name + ": " + value;
                  } catch (e) {
                    return '';
                  }
                }).filter (function (_) { return _.length }).join ("\\u000A");
                setResult (cell, aHeaders == eHeaders, aHeaders, eHeaders) || (failed = true);
                var cell = tr.appendChild (document.createElement ('td'));
                var expected = test.body[0].replace (/\\(boundary\\)/g, '');
                setResult (cell, x.responseText + '(close)' == expected, x.responseText + '(close)', expected) || (failed = true);
                if (!failed) {
                  resultCell.textContent = 'PASS';
                  tr.className = 'PASS';
                }
                tr.appendChild (document.createElement ('td')).appendChild (document.createTextNode (test._file_name));
                tr.appendChild (document.createElement ('td')).appendChild (document.createTextNode ((test.name || {})[0]));
                results.appendChild (tr);
      } // compareResponse

      function runTest (test, testNumber, then) {
        var xhr = new XMLHttpRequest ();
        if (location.protocol === "http:") {
          xhr.open ('GET', 'http://$host:$port/start/' + encodeURIComponent (testNumber) + '?' + Math.random (), true);
        } else {
          xhr.open ('GET', 'https://$host:$tlsport/start/' + encodeURIComponent (testNumber) + '?' + Math.random (), true);
        }
        xhr.onreadystatechange = function () {
          if (xhr.readyState === 4 && xhr.status === 200) {
            var url = xhr.responseText;

            var testType = (test['test-type'] || ['', ['']])[1][0];
            if (testType === 'ws') {
              var y = new WebSocket (url, (test['ws-protocol'] || [''])[0].split (/\\n/).filter (function (_) { return _.length }));
              var status = "noevent";
              var data = "";
              var events = [];
              y.onopen = function (ev) {
                if (status === "noevent") status = "open";
                y.send ("abc");
                events.push (ev.type);
              };
              y.onmessage = function (ev) {
                data += ev.data;
                y.close ();
                events.push (ev.type);
              };
              y.onerror = function (ev) {
                if (status === "noevent") status = "error";
                events.push (ev.type);
              };
              y.onclose = function (ev) {
                events.push (ev.type);
                var tr = document.createElement ('tr');
                tr.className = 'FAIL';
                var failed = false;
                tr.appendChild (document.createElement ('th')).appendChild (document.createTextNode (testNumber));
                var resultCell = tr.appendChild (document.createElement ('th'));
                resultCell.textContent = 'FAIL';

                var cell = tr.appendChild (document.createElement ('td'));
                var expected = test["handshake-error"] ? "error" : "open";
                setResult (cell, expected === status, status, expected) || (failed = true);
                cell.title = events;

                var cell = tr.appendChild (document.createElement ('td'));
                setResult (cell, true, "", "") || (failed = true);

                var cell = tr.appendChild (document.createElement ('td'));
                setResult (cell, true, "", "") || (failed = true);

                var cell = tr.appendChild (document.createElement ('td'));
                var expected = test["received"] ? test["received"][0] : "";
                setResult (cell, expected === data, data, expected) || (failed = true);

                if (!failed) {
                  resultCell.textContent = 'PASS';
                  tr.className = 'PASS';
                }
                tr.appendChild (document.createElement ('td')).appendChild (document.createTextNode (test._file_name));
                tr.appendChild (document.createElement ('td')).appendChild (document.createTextNode ((test.name || {})[0]));
                results.appendChild (tr);

                then ();
              };
            } else if (testType === 'second' || testType === 'largerequest-second') {
              var y = new XMLHttpRequest;
              y.open (test.method[1][0], url, true);
              y.onreadystatechange = function () {
                if (y.readyState === 4) {
                  var tryCount = 0;
                  var tryReq = function () {
                    var x = new XMLHttpRequest;
                    x.open (test.method[1][0], url + ';' + tryCount, true);
                    x.onreadystatechange = function () {
                      if (x.readyState === 4) {
                        if (x.getResponseHeader ('x-test-retry') && tryCount++ < 10) {
                          tryReq ();
                        } else {
                          compareResponse (test, testNumber, x);
                          then ();
                        }
                      }
                    };
                    x.send (null);
                  };
                  tryReq ();
                }
              };
              if (testType === 'largerequest-second') {
                var data = '';
                for (var i = 0; i < largeDataSize; i++) data += "x";
                y.send (data);
              } else {
                y.send (null);
              }
            } else { // testType
              var x = new XMLHttpRequest;
              x.open (test.method[1][0], url, true);
              x.onreadystatechange = function () {
                if (x.readyState === 4) {
                  compareResponse (test, testNumber, x);
                  then ();
                }
              };
              if (testType === 'largerequest') {
                var data = '';
                for (var i = 0; i < largeDataSize; i++) data += "x";
                x.send (data);
              } else {
                x.send (null);
              }
            }
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
          if (location.protocol === "http:") {
            xhr.open ('GET', 'http://$host:$port/last?' + Math.random (), true);
          } else {
            xhr.open ('GET', 'https://$host:$tlsport/last?' + Math.random (), true);
          }
          xhr.send (null);
        }
      }
      runNext ();
    }]);
  } elsif ($path eq '/css') {
    $req->respond ([200, 'OK', {'Content-Type' => 'text/css'}, q{
      .PASS { background-color: green; color: white }
      .FAIL { background-color: red; color: white }
      code { white-space: pre }
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
}; # $httpdcb
$httpd->reg_cb ('' => $httpdcb);
$tlshttpd->reg_cb ('' => $httpdcb);

warn "Listening http://$host:$port & https://$host:$tlsport ...";
warn "(Using $test_port)";

$cv->recv;
