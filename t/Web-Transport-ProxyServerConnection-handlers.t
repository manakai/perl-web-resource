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
      $con = Web::Transport::PSGIServerConnection->new_from_app_and_ae_tcp_server_args
          ($app, [@_], parent_id => $args{parent_id});
      $con->{connection}->{server_header} = $args{server_name};
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

sub rawserver ($) {
  return Promise->from_cv (_server_as_cv ('localhost', '127.0.0.1', find_listenable_port, $_[0]));
} # rawserver

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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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
          #is $x->file_name, __FILE__; XXXlocation
          #is $x->line_number, __LINE__;
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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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
} n => 11, name => 'handle_request returns a response with readablestream not bytes';

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
          #is $x->file_name, __FILE__; XXXlocation
          #is $x->line_number, __LINE__;
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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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
} n => 11, name => 'handle_request returns a response with readablestream aborted soon';

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
          #is $x->file_name, __FILE__; XXXlocation
          #is $x->line_number, __LINE__;
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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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
} n => 11, name => 'handle_request returns a response with readablestream aborted later';

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
          #is $x->file_name, __FILE__; XXXlocation
          #is $x->line_number, __LINE__;
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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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
} n => 12, name => 'handle_request returns a bad hashref';

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
          #is $x->file_name, __FILE__; XXXlocation
          #is $x->line_number, __LINE__;
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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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
} n => 12, name => 'handle_request returns a bad request';

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
          #is $x->file_name, __FILE__; XXXlocation
          #is $x->line_number, __LINE__;
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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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
} n => 12, name => 'handle_request returns a bad response';

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
          #is $x->file_name, __FILE__; XXXlocation
          #is $x->line_number, __LINE__;
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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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
} n => 12, name => 'handle_request throws';

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
          #is $x->file_name, __FILE__; XXXlocation
          #is $x->line_number, __LINE__;
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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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
} n => 12, name => 'handle_request rejects';

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
          #is $x->file_name, __FILE__; XXXlocation
          #is $x->line_number, __LINE__;
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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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
} n => 7, name => 'handle_request returned response is broken';

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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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
          #is $x->file_name, __FILE__; XXXlocation
          #is $x->line_number, __LINE__;
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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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
} n => 9, name => 'handle_request returns a response body with utf8 flag';

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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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
          $args->{request}->{body_length} = length $new_data;
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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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
          $args->{request}->{body_length} = length $new_data;
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
          #is $x->file_name, __FILE__; XXXlocation
          #is $x->line_number, __LINE__;
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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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
} n => 9, name => 'handle_request returns a request, request body bad stream';

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
          #is $x->file_name, __FILE__; XXXlocation
          #is $x->line_number, __LINE__;
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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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
} n => 10, name => 'handle_request returns a bad request';

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
          is $x->message, 'Bad |headers|';
          #is $x->file_name, __FILE__; XXXlocation
          #is $x->line_number, __LINE__;
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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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
} n => 10, name => 'handle_request returns a bad request headers';

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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
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

# XXX handle_response

run_tests;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
