use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Promise;
use Promised::Flow;
use Test::X1;
use Test::More;
use AnyEvent::Socket;
use AnyEvent::Util qw(run_cmd);
use Web::URL;
use Web::Transport::BasicClient;
use Web::Transport::ConstProxyManager;
use Web::Transport::ProxyServerConnection;
use Web::Transport::PSGIServerConnection;
use Web::Transport::TCPTransport;

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

sub psgi_server ($$;%) {
  my $app = shift;
  my $cb = shift;
  my %args = @_;
  my $onexception = $args{onexception};
  return Promise->new (sub {
    my ($ok, $ng) = @_;
    my $cv = AE::cv;
    $cv->begin;
    my $host = '127.0.0.1';
    my $port = find_listenable_port;
    my $con;
    my $server = tcp_server $host, $port, sub {
      $cv->begin;
      $con = Web::Transport::PSGIServerConnection->new_from_aeargs_and_opts ([@_], {
        psgi_app => $app,
        parent_id => $args{parent_id},
        server_header => $args{server_header},
      });
      $con->onexception ($onexception) if defined $onexception;
      promised_cleanup { $cv->end } $con->completed;
    };
    $cv->cb ($ok);
    my $origin = Web::URL->parse_string ("http://$host:$port");
    my $close = sub { undef $server; $cv->end };
    $cb->($origin, $close, \$con);
  });
} # psgi_server

my $server_pids = {};
END { kill 'KILL', $_ for keys %$server_pids }
sub _server_as_cv ($$$$) {
  my ($host, $addr, $port, $code) = @_;
  my $cv = AE::cv;
  my $started;
  my $pid;
  my $data = '';
  local $ENV{SERVER_HOST_NAME} = $host;
  run_cmd
      ['perl', path (__FILE__)->parent->parent->child ('t_deps/server.pl'), $addr, $port],
      '<' => \$code,
      '>' => sub {
        $data .= $_[0] if defined $_[0];
        return if $started;
        if ($data =~ /^\[server (\S+) (\S+)\]/m) {
          $cv->send ({pid => $pid, host => $host, addr => $1, port => $2,
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
} # _server_as_cv

sub rawclient ($$$) {
  my ($host, $port, $input) = @_;
  my $tcp = Web::Transport::TCPTransport->new (host => $host, port => $port);
  my $data = '';
  my $p = Promise->new (sub {
    my $ok = $_[0];
    $tcp->start (sub {
      my ($self, $type) = @_;
      if ($type eq 'readdata') {
        $data .= ${$_[2]};
      } elsif ($type eq 'readeof') {
        $tcp->push_shutdown;
      } elsif ($type eq 'close') {
        $ok->($data);
      }
    })->then (sub {
      return $tcp->push_write (\$input);
    });
  });
  return $p;
} # rawclient

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $server_name,
        handle_request => sub {
          my $args = $_[0];
          return {response => {
            status => 567,
            status_text => "abc",
            headers => [["Foo-" => "ab c"]],
            body => "aa bb cc",
          }};
        },
      });
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 567;
        is $res->status_text, 'abc';
        is $res->header ('Foo-'), 'ab c';
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $res->body_bytes, 'aa bb cc';
        is $server_invoked, 0;
      } $c;
    });
  });
} n => 7, name => 'handle_request returns a response';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_request => sub {
          my $args = $_[0];
          return Promise->resolve ({response => {
            status => 567,
            status_text => "abc",
            headers => [["Foo-" => "ab c"]],
            body => "aa bb cc",
          }});
        },
      });
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 567;
        is $res->status_text, 'abc';
        is $res->header ('Foo-'), 'ab c';
        is $res->body_bytes, 'aa bb cc';
        is $server_invoked, 0;
      } $c;
    });
  });
} n => 5, name => 'handle_request returns a response (promise)';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_request => sub {
          my $args = $_[0];
          return {response => {
            status => 567,
            status_text => "abc",
            headers => [["Foo-" => "ab c"]],
            body => "aa bb cc",
          }};
        },
      });
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    my $body = "aagegteae" x 1000 x 10;
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url, body => $body)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 567;
        is $res->status_text, 'abc';
        is $res->header ('Foo-'), 'ab c';
        is $res->body_bytes, 'aa bb cc';
        is $server_invoked, 0;
      } $c;
    });
  });
} n => 5, name => 'handle_request returns a response, request body not used';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $server_name,
        handle_request => sub {
          my $args = $_[0];
          my $rs = ReadableStream->new ({
            type => 'bytes',
            start => sub {
              my $rc = $_[1];
              $rc->enqueue (DataView->new (ArrayBuffer->new_from_scalarref (\"aa bb cc")));
              $rc->close;
            },
          });
          return {response => {
            status => 567,
            status_text => "abc",
            headers => [["Foo-" => "ab c"]],
            body_stream => $rs,
          }};
        },
      });
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 567;
        is $res->status_text, 'abc';
        is $res->header ('Foo-'), 'ab c';
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $res->body_bytes, 'aa bb cc';
        is $server_invoked, 0;
      } $c;
    });
  });
} n => 7, name => 'handle_request returns a response with readablestream';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $server_name,
        handle_request => sub {
          my $args = $_[0];
          my $rs = ReadableStream->new ({
            start => sub {
              my $rc = $_[1];
              $rc->enqueue (DataView->new (ArrayBuffer->new_from_scalarref (\"aa bb cc")));
              $rc->close;
            },
          });
          return {response => {
            status => 567,
            status_text => "abc",
            headers => [["Foo-" => "ab c"]],
            body_stream => $rs,
          }};
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'TypeError', $x;
          is $x->message, 'ReadableStream is not a byte stream';
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->status_text, 'Internal Server Error';
        is $res->header ('Foo-'), undef;
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $res->body_bytes, '500';
        is $server_invoked, 0;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 13, name => 'handle_request returns a response with readablestream not bytes';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $server_name,
        handle_request => sub {
          my $args = $_[0];
          my $rs = ReadableStream->new ({
            type => 'bytes',
            start => sub {
              my $rc = $_[1];
              $rc->error;
            },
          });
          return {response => {
            status => 567,
            status_text => "abc",
            headers => [["Foo-" => "ab c"]],
            body_stream => $rs,
          }};
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'Error', $x;
          is $x->message, "Something's wrong";
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    }; # $server
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 567;
        is $res->status_text, 'abc';
        is $res->header ('Foo-'), 'ab c';
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        ok $res->incomplete;
        is $server_invoked, 0;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 13, name => 'handle_request returns a response with readablestream aborted soon';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $server_name,
        handle_request => sub {
          my $args = $_[0];
          my $rs = ReadableStream->new ({
            type => 'bytes',
            pull => sub {
              my $rc = $_[1];
              $rc->error;
            },
          });
          return {response => {
            status => 567,
            status_text => "abc",
            headers => [["Foo-" => "ab c"]],
            body_stream => $rs,
          }};
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'Error', $x;
          is $x->message, "Something's wrong";
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    }; # $server
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 567;
        is $res->status_text, 'abc';
        is $res->header ('Foo-'), 'ab c';
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        ok $res->incomplete;
        is $server_invoked, 0;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 13, name => 'handle_request returns a response with readablestream aborted later';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $server_name,
        handle_request => sub {
          return {};
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'TypeError', $x;
          is $x->message, "|handle_request| does not return |request| or |response|";
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    }; # $server
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->status_text, 'Internal Server Error';
        is $res->header ('Foo-'), undef;
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $res->body_bytes, '500';
        ok ! $res->incomplete;
        is $server_invoked, 0;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 14, name => 'handle_request returns a bad hashref';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $server_name,
        handle_request => sub {
          return {request => "abc"};
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'TypeError', $x;
          is $x->message, "Bad |request|";
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    }; # $server
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->status_text, 'Internal Server Error';
        is $res->header ('Foo-'), undef;
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $res->body_bytes, '500';
        ok ! $res->incomplete;
        is $server_invoked, 0;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 14, name => 'handle_request returns a bad request';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $server_name,
        handle_request => sub {
          return {response => "abc"};
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'TypeError', $x;
          is $x->message, "Bad |response|";
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    }; # $server
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->status_text, 'Internal Server Error';
        is $res->header ('Foo-'), undef;
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $res->body_bytes, '500';
        ok ! $res->incomplete;
        is $server_invoked, 0;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 14, name => 'handle_request returns a bad response';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $server_name,
        handle_request => sub {
          die "abcde";
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'Error', $x;
          like $x->message, qr{^abcde at \Q@{[__FILE__]}\E line \Q@{[__LINE__-9]}\E};
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    }; # $server
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->status_text, 'Internal Server Error';
        is $res->header ('Foo-'), undef;
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $res->body_bytes, '500';
        ok ! $res->incomplete;
        is $server_invoked, 0;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 14, name => 'handle_request throws';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $server_name,
        handle_request => sub {
          return Promise->resolve->then (sub { die "abcde" });
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'Error', $x;
          like $x->message, qr{^abcde at \Q@{[__FILE__]}\E line \Q@{[__LINE__-9]}\E};
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    }; # $server
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->status_text, 'Internal Server Error';
        is $res->header ('Foo-'), undef;
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $res->body_bytes, '500';
        ok ! $res->incomplete;
        is $server_invoked, 0;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 14, name => 'handle_request rejects';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $server_name,
        handle_request => sub {
          return {response => {}};
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'TypeError', $x;
          is $x->message, 'Bad |status|';
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    }; # $server
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->catch (sub {
      my $result = $_[0];
      test {
        ok $result->is_network_error, $result;
        is $result->network_error_message, 'Connection closed without response';
        is $server_invoked, 0;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 9, name => 'handle_request returned response is broken';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_request => sub {
          my $args = $_[0];
          return {response => {
            status => 407,
            status_text => "abc",
            headers => [["Proxy-authenticate" => "ab c"]],
            body => "aa bb cc",
          }};
        },
      });
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    my $body = "aagegteae" x 1000 x 10;
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url, body => $body)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 407;
        is $res->status_text, 'abc';
        is $res->header ('Proxy-Authenticate'), 'ab c';
        is $res->body_bytes, 'aa bb cc';
        is $server_invoked, 0;
      } $c;
    });
  });
} n => 5, name => 'handle_request returns a 407 response';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_request => sub {
          my $args = $_[0];
          return {response => {
            status => 407,
            status_text => "abc",
            headers => [["Proxy-authenticate" => "ab c"]],
            body => "aa bb cc\x{500}",
          }};
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'TypeError', $x;
          is $x->message, 'The argument is a utf8-flaged string';
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    my $body = "aagegteae" x 1000 x 10;
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url, body => $body)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 407;
        is $res->status_text, 'abc';
        is $res->header ('Proxy-Authenticate'), 'ab c';
        ok $res->incomplete;
        is $server_invoked, 0;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 11, name => 'handle_request returns a response body with utf8 flag';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_request => sub {
          my $args = $_[0];
          $args->{request}->{headers} = {Foo => "ab", "ABC" => "de"};
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        $exception_invoked++;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    test {
      is $env->{HTTP_FOO}, 'ab';
      is $env->{HTTP_ABC}, 'de';
    } $c;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->body_bytes, '200!';
        is $server_invoked, 1;
        is $exception_invoked, 0;
      } $c;
    });
  });
} n => 6, name => 'handle_request returns a request';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_request => sub {
          my $args = $_[0];
          delete $args->{request}->{body_stream};
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        $exception_invoked++;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    test {
      is $env->{CONTENT_LENGTH}, 0;
    } $c;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    my $data = 'abceagtee' x 1000;
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url, body => $data)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->body_bytes, '200!';
        is $server_invoked, 1;
        is $exception_invoked, 0;
      } $c;
    });
  });
} n => 5, name => 'handle_request returns a request, request body unused';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $new_data = 't3watahwa' x 10000;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_request => sub {
          my $args = $_[0];
          delete $args->{request}->{body_stream};
          $args->{request}->{body} = $new_data;
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        $exception_invoked++;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    test {
      is $env->{CONTENT_LENGTH}, length $new_data;
      my $got = '';
      read $env->{'psgi.input'}, $got, $env->{CONTENT_LENGTH};
      is $got, $new_data;
    } $c;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    my $data = 'abceagtee' x 10000;
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url, body => $data)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->body_bytes, '200!';
        is $server_invoked, 1;
        is $exception_invoked, 0;
      } $c;
    });
  });
} n => 6, name => 'handle_request returns a request, request body string';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $new_data = 't3watahwa' x 10000;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_request => sub {
          my $args = $_[0];
          my $rs = ReadableStream->new ({
            type => 'bytes',
            start => sub {
              my $rc = $_[1];
              $rc->enqueue (DataView->new (ArrayBuffer->new_from_scalarref (\$new_data)));
              $rc->close;
            },
          });
          $args->{request}->{body_stream} = $rs;
          $args->{request}->{length} = length $new_data;
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        $exception_invoked++;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    test {
      is $env->{CONTENT_LENGTH}, length $new_data;
      my $got = '';
      read $env->{'psgi.input'}, $got, $env->{CONTENT_LENGTH};
      is $got, $new_data;
    } $c;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    my $data = 'abceagtee' x 10000;
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url, body => $data)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->body_bytes, '200!';
        is $server_invoked, 1;
        is $exception_invoked, 0;
      } $c;
    });
  });
} n => 6, name => 'handle_request returns a request, request body stream';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $new_data = 't3watahwa';
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $server_name,
        handle_request => sub {
          my $args = $_[0];
          my $rs = ReadableStream->new ({
            start => sub {
              my $rc = $_[1];
              $rc->enqueue (DataView->new (ArrayBuffer->new_from_scalarref (\$new_data)));
              $rc->close;
            },
          });
          $args->{request}->{body_stream} = $rs;
          $args->{request}->{length} = length $new_data;
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'TypeError', $x;
          is $x->message, 'ReadableStream is not a byte stream';
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    test {
      is $env->{CONTENT_LENGTH}, length $new_data;
      my $got = '';
      read $env->{'psgi.input'}, $got, $env->{CONTENT_LENGTH};
      is $got, $new_data;
    } $c;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $res->body_bytes, '500';
        is $server_invoked, 0;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 11, name => 'handle_request returns a request, request body bad stream';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $new_data = 't3watahwa';
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $server_name,
        handle_request => sub {
          return {request => {}};
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'TypeError', $x;
          is $x->message, 'No |url| argument';
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->status_text, 'Internal Server Error';
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $res->body_bytes, '500';
        is $server_invoked, 0;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 12, name => 'handle_request returns a bad request';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $new_data = 't3watahwa';
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $server_name,
        handle_request => sub {
          my $args = $_[0];
          $args->{request}->{headers} = [{ab => 4}];
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'TypeError', $x;
          is $x->message, 'Bad headers';
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->status_text, 'Internal Server Error';
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $res->body_bytes, '500';
        is $server_invoked, 0;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 12, name => 'handle_request returns a bad request headers';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $server_url;
  my $close_server;
  my $exception_invoked = 0;
  my $new_data = 't3watahwa' x 10000;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_request => sub {
          my $args = $_[0];
          $args->{request}->{url} = $server_url;
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        $exception_invoked++;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    $server_url = Web::URL->parse_string (q</abc?d>, $origin);
    my $url = Web::URL->parse_string (q<http://hoge.fuga.test/agaeweeee>);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->body_bytes, '200!';
        is $server_invoked, 1;
        is $exception_invoked, 0;
      } $c;
    });
  });
} n => 4, name => 'handle_request custom request URL';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_request => sub {
          my $args = $_[0];
          delete $args->{request}->{forwarding};
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        $exception_invoked++;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, ['User-agent', $env->{HTTP_USER_AGENT},
                  'accept-language', $env->{HTTP_ACCEPT_LANGUAGE},
                  'Accept', $env->{HTTP_ACCEPT}], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        ok $res->header ('User-Agent');
        is $res->header ('accept'), '*/*';
        is $res->header ('accept-language'), 'en-US';
      } $c;
    });
  });
} n => 4, name => 'handle_request not forwarding';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $server_url;
  my $close_server;
  my $exception_invoked = 0;
  my $new_data = 't3watahwa' x 10000;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_request => sub {
          my $args = $_[0];

          my $api = $args->{api};
          test {
            isa_ok $api, 'Web::Transport::ProxyServerConnection::API';
          } $c;

          $api->note ("API note method");

          my $url2 = Web::URL->parse_string ($server_url->scheme . "://" . $server_url->host->to_ascii . ":" . ($server_url->port + 1) . "/test");
          my $client = $api->client ($server_url);
          my $client2 = $api->client ($server_url, {}, {key => 'b'});
          my $client3 = $api->client ($url2, {}, {key => 'b'});
          test {
            isa_ok $client, 'Web::Transport::BasicClient';
            is $api->client ($server_url, {}, {key => undef}), $client;
            is $api->client ($server_url, {}, {key => ''}), $client;
            isa_ok $client2, 'Web::Transport::BasicClient';
            isnt $client2, $client, 'different keys';
            is $api->client ($server_url, {}, {key => 'b'}), $client2;
            isnt $client3, $client2, 'different origin';
          } $c;

          return $client->request (%{$args->{request}}, url => $server_url)->then (sub {
            my $res = $_[0];
            $args->{response} = {
              status => $res->status + 1,
              body => "[[" . $res->body_bytes . "]]",
            };
            return $args;
          });
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        $exception_invoked++;
        warn $_[1];
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    $server_url = Web::URL->parse_string (q</abc?d>, $origin);
    my $url = Web::URL->parse_string (q<http://hoge.fuga.test/agaeweeee>);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 202;
        is $res->body_bytes, '[[200!]]';
        is $server_invoked, 1;
        is $exception_invoked, 0;
      } $c;
    });
  });
} n => 12, name => 'handle_request custom client fetch';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_response => sub {
          my $args = $_[0];
          test {
            is $args->{info}->{parent}->{type}, 'TCP';
            is $args->{response}->{status}, 201;
            is $args->{response}->{status_text}, 'Created';
            isa_ok $args->{response}->{body_stream}, 'ReadableStream';
            is $args->{response}->{length}, undef;
            is ref $args->{response}->{body_is_incomplete}, 'CODE';
            ok ! $args->{response}->{body_is_incomplete}->();
          } $c;
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        $exception_invoked++;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->body_bytes, '200!';
        is $res->header ('Transfer-Encoding'), 'chunked';
        is $res->header ('Content-Length'), undef;
        is $server_invoked, 1;
        is $exception_invoked, 0;
      } $c;
    });
  });
} n => 13, name => 'handle_response (no response Content-Length)';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_response => sub {
          my $args = $_[0];
          test {
            is $args->{info}->{parent}->{type}, 'TCP';
            is $args->{response}->{status}, 201;
            is $args->{response}->{status_text}, 'Created';
            isa_ok $args->{response}->{body_stream}, 'ReadableStream';
            is $args->{response}->{length}, 4;
            is ref $args->{response}->{body_is_incomplete}, 'CODE';
            ok ! $args->{response}->{body_is_incomplete}->();
          } $c;
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        $exception_invoked++;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->header ('Transfer-Encoding'), undef;
        is $res->header ('Content-Length'), '4';
        is $res->body_bytes, '200!';
        is $server_invoked, 1;
        is $exception_invoked, 0;
      } $c;
    });
  });
} n => 13, name => 'handle_response (with response Content-Length)';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_response => sub {
          my $args = $_[0];
          delete $args->{response}->{body_stream};
          $args->{response}->{body} = "abcde";
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        $exception_invoked++;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->body_bytes, 'abcde';
        is $res->header ('Transfer-Encoding'), 'chunked';
        is $res->header ('Content-Length'), undef;
        is $server_invoked, 1;
        is $exception_invoked, 0;
      } $c;
    });
  });
} n => 6, name => 'handle_response response body string (body_stream unused)';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_response => sub {
          my $args = $_[0];
          my $rs = ReadableStream->new ({
            type => 'bytes',
            start => sub {
              my $rc = $_[1];
              $rc->enqueue (DataView->new (ArrayBuffer->new_from_scalarref (\"abcd1355")));
              $rc->close;
            },
          });
          $args->{response}->{body_stream} = $rs;
          $args->{response}->{length} = 8;
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        $exception_invoked++;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->body_bytes, 'abcd1355';
        is $res->header ('Transfer-Encoding'), undef;
        is $res->header ('Content-Length'), '8';
        is $server_invoked, 1;
        is $exception_invoked, 0;
      } $c;
    });
  });
} n => 6, name => 'handle_response response body stream (original body_stream unused)';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $reader;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_response => sub {
          my $args = $_[0];
          $reader = $args->{response}->{body_stream}->get_reader; # lock
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'TypeError', $x;
          is $x->message, 'ReadableStream is locked';
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    $reader->cancel;
    undef $reader;
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->status_text, 'Internal Server Error';
        is $res->body_bytes, '500';
        is $res->header ('Transfer-Encoding'), 'chunked';
        is $res->header ('Content-Length'), undef;
        is $server_invoked, 1;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 12, name => 'handle_response response body stream locked';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_response => sub {
          my $args = $_[0];
          my $rs = ReadableStream->new ({
            start => sub {
              my $rc = $_[1];
              $rc->enqueue (DataView->new (ArrayBuffer->new_from_scalarref (\"abcd1355")));
              $rc->close;
            },
          });
          $args->{response}->{body_stream} = $rs;
          $args->{response}->{length} = 8;
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'TypeError', $x;
          is $x->message, 'ReadableStream is not a byte stream';
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, '500';
        is $res->header ('Transfer-Encoding'), 'chunked';
        is $res->header ('Content-Length'), undef;
        is $server_invoked, 1;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 11, name => 'handle_response response body stream not bytes';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_response => sub {
          my $args = $_[0];
          my $rs = ReadableStream->new ({
            type => 'bytes',
            start => sub {
              my $rc = $_[1];
              $rc->error (Web::Transport::Error->new ("abc"));
            },
          });
          $args->{response}->{body_stream} = $rs;
          $args->{response}->{length} = 8;
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'Error', $x;
          is $x->message, "abc";
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-16;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->catch (sub {
      my $result = $_[0];
      test {
        ok $result->is_network_error, $result;
        is $result->network_error_message, 'Connection truncated';
        is $server_invoked, 1;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 9, name => 'handle_response response body stream aborted';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_response => sub {
          my $args = $_[0];
          $args->{response}->{status_text} = "21\x0D";
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'TypeError', $x;
          is $x->message, 'Bad |status_text|';
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->catch (sub {
      my $result = $_[0];
      test {
        ok $result->is_network_error;
        is $result->network_error_message, 'Connection closed without response';
        is $server_invoked, 1;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 9, name => 'handle_response response broken (bad status_text)';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_response => sub {
          my $args = $_[0];
          $args->{response}->{status_text} = "21\x{4020}";
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'TypeError', $x;
          is $x->message, 'Bad |status_text| (utf8-flagged)';
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->catch (sub {
      my $result = $_[0];
      test {
        ok $result->is_network_error;
        is $result->network_error_message, 'Connection closed without response';
        is $server_invoked, 1;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 9, name => 'handle_response response broken (bad |status_text| - utf8)';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_response => sub {
          return {};
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'TypeError', $x;
          is $x->message, '|handle_response| does not return |response|';
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, '500';
        is $res->header ('Transfer-Encoding'), 'chunked';
        is $res->header ('Content-Length'), undef;
        is $server_invoked, 1;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 11, name => 'handle_response no response';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_response => sub {
          return undef;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'TypeError', $x;
          is $x->message, '|handle_response| does not return |response|';
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, '500';
        is $res->header ('Transfer-Encoding'), 'chunked';
        is $res->header ('Content-Length'), undef;
        is $server_invoked, 1;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 11, name => 'handle_response bad return';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_response => sub {
          die "#abcd";
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'Error', $x;
          like $x->message, qr{^#abcd at \Q@{[__FILE__]}\E line @{[__LINE__-9]}};
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, '500';
        is $res->header ('Transfer-Encoding'), 'chunked';
        is $res->header ('Content-Length'), undef;
        is $server_invoked, 1;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 11, name => 'handle_response throws';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_response => sub {
          return Promise->resolve->then (sub { die "#abcd" });
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'Error', $x;
          like $x->message, qr{^#abcd at \Q@{[__FILE__]}\E line @{[__LINE__-9]}};
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, '500';
        is $res->header ('Transfer-Encoding'), 'chunked';
        is $res->header ('Content-Length'), undef;
        is $server_invoked, 1;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 11, name => 'handle_response rejects';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_response => sub {
          my $args = $_[0];
          return Promise->resolve->then (sub { $args });
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        $exception_invoked++;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->body_bytes, '200!';
        is $res->header ('Transfer-Encoding'), 'chunked';
        is $res->header ('Content-Length'), undef;
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $server_invoked, 1;
        is $exception_invoked, 0;
      } $c;
    });
  }, server_header => $server_name);
} n => 8, name => 'handle_response fulfilled';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $server_name = rand;
  my $proxy_server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_response => sub {
          my $args = $_[0];
          delete $args->{response}->{forwarding};
          return Promise->resolve->then (sub { $args });
        },
        server_header => $proxy_server_name,
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        $exception_invoked++;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->body_bytes, '200!';
        is $res->header ('Transfer-Encoding'), 'chunked';
        is $res->header ('Content-Length'), undef;
        is $res->header ('Server'), $server_name . ', ' . $proxy_server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $server_invoked, 1;
        is $exception_invoked, 0;
      } $c;
    });
  }, server_header => $server_name);
} n => 8, name => 'handle_response no forwarding flag';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $proxy_server_name = rand;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $proxy_server_name,
        handle_response => sub {
          return {response => {
            status => 205,
            status_text => "AABc",
          }};
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        $exception_invoked++;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 205;
        is $res->status_text, "AABc";
        is $res->body_bytes, '';
        is $res->header ('Transfer-Encoding'), 'chunked';
        is $res->header ('Content-Length'), undef;
        is $res->header ('Server'), $proxy_server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $server_invoked, 1;
        is $exception_invoked, 0;
      } $c;
    });
  });
} n => 9, name => 'handle_response custom response';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $proxy_server_name = rand;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $proxy_server_name,
        handle_response => sub {
          my $args = $_[0];
          test {
            is $args->{data}, undef;
          } $c;
          return {response => {
            status => 205,
            status_text => "AABc",
            forwarding => 1,
          }};
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        $exception_invoked++;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 205;
        is $res->status_text, "AABc";
        is $res->body_bytes, '';
        is $res->header ('Transfer-Encoding'), 'chunked';
        is $res->header ('Content-Length'), undef;
        is $res->header ('Server'), undef;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $server_invoked, 1;
        is $exception_invoked, 0;
      } $c;
    });
  });
} n => 10, name => 'handle_response custom response forwarding flagged';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $proxy_server_name = rand;
  my $exception_invoked = 0;
  my $data = {};
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $proxy_server_name,
        handle_request => sub {
          my $args = $_[0];
          test {
            is $args->{data}, undef;
          } $c;
          $args->{data} = $data;
          return $args;
        },
        handle_response => sub {
          my $args = $_[0];
          test {
            is $args->{data}, $data;
          } $c;
          return {response => {
            status => 205,
            status_text => "AABc",
            forwarding => 1,
          }};
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        $exception_invoked++;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 205;
        is $server_invoked, 1;
        is $exception_invoked, 0;
      } $c;
    });
  });
} n => 5, name => 'handle_response data';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $proxy_server_name = rand;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $proxy_server_name,
        handle_response => sub {
          die Web::Transport::ProtocolError->new ("ABC");
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'Protocol error', $x;
          is $x->message, "ABC";
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-11;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 504;
        is $res->status_text, "Gateway Timeout";
        is $res->body_bytes, '504';
        is $res->header ('Server'), $proxy_server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $server_invoked, 1;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 12, name => 'handle_response throws Protocol error';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $proxy_server_name = rand;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $proxy_server_name,
        handle_response => sub {
          return {error => Web::Transport::ProtocolError->new ("ABC")};
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'Protocol error', $x;
          is $x->message, "ABC";
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-11;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 504;
        is $res->status_text, "Gateway Timeout";
        is $res->body_bytes, '504';
        is $res->header ('Server'), $proxy_server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $server_invoked, 1;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 12, name => 'handle_response error Protocol error';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $proxy_server_name = rand;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $proxy_server_name,
        handle_response => sub {
          return {error => "abcd"};
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'Error', $x;
          is $x->message, "abcd";
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->status_text, "Internal Server Error";
        is $res->body_bytes, '500';
        is $res->header ('Server'), $proxy_server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $server_invoked, 1;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 12, name => 'handle_response error non error';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $proxy_server_name = rand;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $proxy_server_name,
        handle_response => sub {
          my $args = $_[0];
          $args->{response}->{body_is_incomplete} = sub { 1 };
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        $exception_invoked++;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->body_bytes, '200!';
        ok $res->incomplete;
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $server_invoked, 1;
        is $exception_invoked, 0;
      } $c;
    });
  }, server_header => $server_name);
} n => 7, name => 'handle_response body_is_incomplete 1';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $proxy_server_name = rand;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $proxy_server_name,
        handle_response => sub {
          my $args = $_[0];
          $args->{response}->{body_is_incomplete} = sub { Promise->resolve (0) };
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        $exception_invoked++;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->body_bytes, '200!';
        ok ! $res->incomplete;
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $server_invoked, 1;
        is $exception_invoked, 0;
      } $c;
    });
  }, server_header => $server_name);
} n => 7, name => 'handle_response body_is_incomplete fulfilled 0';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $proxy_server_name = rand;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $proxy_server_name,
        handle_response => sub {
          my $args = $_[0];
          $args->{response}->{body_is_incomplete} = sub { die "abc" };
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'Error', $x;
          like $x->message, qr{^abc at \Q@{[__FILE__]}\E line @{[__LINE__-10]}};
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->body_bytes, '200!';
        ok $res->incomplete;
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $server_invoked, 1;
        is $exception_invoked, 1;
      } $c;
    });
  }, server_header => $server_name);
} n => 12, name => 'handle_response body_is_incomplete throws';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $closed;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_response => sub {
          my $args = $_[0];
          $args->{closed}->then (sub {
            $closed = 1;
          });
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        ok $closed;
      } $c;
    });
  });
} n => 1, name => 'handle_response closed promise';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $closed;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_response => sub {
          my $args = $_[0];
          test {
            isa_ok $args->{api}, 'Web::Transport::ProxyServerConnection::API';
          } $c;
          $args->{api}->note ("response API note method");
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    return sub {
      my $writer = $_[0]->([201, []]);
      $writer->write ('200!');
      $writer->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url);
  });
} n => 1, name => 'handle_response api';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $server_url;
  my $real_server_url;
  my $close_server;
  my $exception_invoked = 0;
  my $new_data = 't3watahwa' x 10000;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_request => sub {
          my $args = $_[0];

          $args->{request}->{url} = $server_url;
          $args->{client_options} = {
            server_connection => {url => $real_server_url},
          };

          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        $exception_invoked++;
        warn $_[1];
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    $real_server_url = Web::URL->parse_string (q</abc?d>, $origin);
    $server_url = Web::URL->parse_string (q</abc?d>, Web::URL->parse_string ("http://proxied.test"));
    my $url = Web::URL->parse_string (q<http://hoge.fuga.test/agaeweeee>);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->body_bytes, '200!';
        is $server_invoked, 1;
        is $exception_invoked, 0;
      } $c;
    });
  });
} n => 4, name => 'handle_request server_connection url';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $server_url;
  my $real_server_url;
  my $close_server;
  my $exception_invoked = 0;
  my $new_data = 't3watahwa' x 10000;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_request => sub {
          my $args = $_[0];

          my $api = $args->{api};
          test {
            isa_ok $api, 'Web::Transport::ProxyServerConnection::API';
          } $c;

          my $client = $api->client ($server_url, {
            server_connection => {url => $real_server_url},
          });
          my $client2 = $api->client ($server_url, {
            server_connection => {url => $real_server_url},
          }, {key => 'b'});
          my $client3 = $api->client ($real_server_url, {}, {});
          my $client4 = $api->client ($real_server_url, {}, {key => 'b'});
          test {
            isa_ok $client, 'Web::Transport::BasicClient';
            isnt $client2, $client, 'different keys';
            isnt $client3, $client, 'different origin';
            isnt $client4, $client2, 'different origin and key';
          } $c;

          return $client->request (%{$args->{request}}, url => $server_url)->then (sub {
            my $res = $_[0];
            $args->{response} = {
              status => $res->status + 1,
              body => "[[" . $res->body_bytes . "]]",
            };
            return $args;
          });
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        $exception_invoked++;
        warn $_[1];
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    $real_server_url = Web::URL->parse_string (q</abc?d>, $origin);
    $server_url = Web::URL->parse_string (q</abc?d>, Web::URL->parse_string ("http://proxied.test"));
    my $url = Web::URL->parse_string (q<http://hoge.fuga.test/agaeweeee>);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 202;
        is $res->body_bytes, '[[200!]]';
        is $server_invoked, 1;
        is $exception_invoked, 0;
      } $c;
    });
  });
} n => 9, name => 'handle_request custom client fetch with server_connection url';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $server_url;
  my $close_server;
  my $exception_invoked = 0;
  my ($r_2, $s_2) = promised_cv;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_request => sub {
          my $args = $_[0];

          my $api = $args->{api};
          my $client = $api->client ($server_url, {}, {key => "[2]"});
          $client->request (url => Web::URL->parse_string (q</2>, $server_url))->then (sub {
            my $res = $_[0];
            $s_2->($res->body_bytes);
          });

          $args->{request}->{url} = $server_url;
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        $exception_invoked++;
        warn $_[1];
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    return sub {
      my $x = $_[0];
      if ($env->{PATH_INFO} eq '/2') {
        promised_sleep (2)->then (sub {
          my $writer = $x->([202, []]);
          $writer->write ('/2');
          $writer->close;
        });
      } else {
        my $writer = $x->([201, []]);
        $writer->write ('200!');
        $writer->close;
      }
    };
  }, sub {
    my ($origin, $close) = @_;
    $server_url = Web::URL->parse_string (q</1>, $origin);
    my $url = Web::URL->parse_string (q<http://hoge.fuga.test/agaeweeee>);
    my $proxy_client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close->();
    } promised_cleanup {
      $close_server->();
      undef $s_2;
    } $proxy_client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->body_bytes, '200!';
      } $c;
      return $proxy_client->abort;
    })->then (sub {
      return $r_2;
    })->then (sub {
      my $got = $_[0];
      test {
        is $got, '/2';
        is $exception_invoked, 0;
      } $c;
    });
  });
} n => 4, name => 'handle_request custom client fetch non-default client not discarded after stream closure';

run_tests;

=head1 LICENSE

Copyright 2016-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
