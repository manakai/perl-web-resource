use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Test::HTCT::Parser;
use Test::Certificates;
use Web::Host;
use Web::Transport::TCPStream;
use Web::Transport::UnixStream;
use Web::Transport::TLSStream;
use Web::Transport::H1CONNECTTransport; # XXX
use Web::Transport::HTTPStream;
use Promise;
use AnyEvent::Util qw(run_cmd);
use ArrayBuffer;
use DataView;

sub d ($) {
  return DataView->new (ArrayBuffer->new_from_scalarref (\($_[0])));
} # d

sub rsread ($) {
  my $rs = shift;
  return Promise->resolve (undef) unless defined $rs;
  my $r = $rs->get_reader;
  my $run; $run = sub {
    return $r->read->then (sub {
      return if $_[0]->{done};
      if (ref $_[0]->{value} eq 'HASH' and
          defined $_[0]->{value}->{data_stream}) {
        rsread ($_[0]->{value}->{data_stream});
      }
      return $run->();
    });
  }; # $run
  return $run->()->then (sub { undef $run }, sub { undef $run });
} # rsread

sub read_rbs ($) {
  my $rs = shift;
  return Promise->resolve (undef) unless defined $rs;
  my $r = $rs->get_reader ('byob');
  my $result = '';
  my $run; $run = sub {
    return $r->read (d "x" x 100)->then (sub {
      return if $_[0]->{done};
      $result .= $_[0]->{value}->manakai_to_string;
      return $run->();
    });
  }; # $run
  return $run->()->then (sub { undef $run; return $result }, sub { undef $run });
} # read_rbs

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

my $server_pids = {};
END { kill 'KILL', $_ for keys %$server_pids }
sub _server_as_cv ($$$) {
  my ($host, $port, $code) = @_;
  my $cv = AE::cv;
  my $started;
  my $pid;
  my $data = '';
  my $run_cv = run_cmd
      ['perl', path (__FILE__)->parent->parent->child ('t_deps/server.pl'), $host, $port],
      '<' => \$code,
      '>' => sub {
        $data .= $_[0] if defined $_[0];
        return if $started;
        if ($data =~ /^\[server (\S+) (\S+)\]/m) {
          $cv->send ({pid => $pid, addr => $1, port => $2,
                      stop => sub {
                        kill 'TERM', $pid;
                        delete $server_pids->{$pid};
                      }});
          $started = 1;
        }
      },
      '$$' => \$pid;
  $server_pids->{$pid} = 1;
  $run_cv->cb (sub {
    my $result = $_[0]->recv;
    if ($result) {
      $cv->croak ("Server error: $result") unless $started;
    }
  });
  return $cv;
} # _server_as_cv

sub server_as_cv ($) {
  return _server_as_cv ('127.0.0.1', find_listenable_port, $_[0]);
} # server_as_cv

my $test_path = path (__FILE__)->parent->parent->child ('local/test')->absolute;
$test_path->mkpath;

sub unix_server_as_cv ($) {
  return _server_as_cv ('unix/', $test_path->child (int (rand 10000) + 1024), $_[0]);
} # unix_server_as_cv

test {
  my $c = shift;
  my $http = Web::Transport::HTTPStream->new ({parent => {
    class => 'Web::Transport::TCPStream',
    host => Web::Host->parse_string ('127.0.53.53'), port => rand,
  }});
  my $p = $http->send_request ({method => 'GET', target => '/'});
  isa_ok $p, 'Promise';
  $p->then (sub {
    test {
      ok 0;
    } $c;
  }, sub {
    my $e = $_[0];
    test {
      like $e, qr{^TypeError: Connection is not ready at \Q@{[__FILE__]}\E line @{[__LINE__-9]}};
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
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $stream = $_[0]->{stream};
      return $stream->headers_received;
    })->catch (sub {
      my $p = $http->send_request ({method => 'GET', target => '/'});
      test {
        isa_ok $p, 'Promise';
      } $c;
      return $p->then (sub {
        test { ok 0 } $c;
      }, sub {
        my $e = $_[0];
        test {
          like $e, qr{^TypeError: Connection is closed at \Q@{[__FILE__]}\E line @{[__LINE__-9]}};
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
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
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
          like $e, qr{^TypeError: Connection is busy at \Q@{[__FILE__]}\E line @{[__LINE__-9]}};
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
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->connect->then (sub {
      my @p;
      for my $subtest (
        [['' => 'abc']],
        [['[]' => 'abc']],
        [["\x{100}" => 'abc']],
        [['Hoge' => "abc \x0A"]],
        [['Hoge' => "abc \x0Db"]],
        [['Hoge' => "\x0D\x0A"]],
        [['Hoge' => "\x{4000}"]],
      ) {
        push @p, Promise->resolve->then (sub {
          return $http->send_request
              ({method => 'GET', target => '/',
                headers => $subtest});
        })->catch (sub {
          my $error = $_[0];
          test {
            like $error, qr{Bad header };
          } $c;
        });
      }
      return Promise->all (\@p);
    })->then (sub{
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 7, name => 'send_request_headers with bad headers';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 203 ok"CRLF
    "X-hoge: Foo bar"CRLF
    CRLF
    "abc"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    my $closed;
    my $closed_fulfilled;
    my $closed_rejected;
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $stream = $_[0]->{stream};
      $closed = $_[0]->{closed};
      $closed->then (sub { $closed_fulfilled = 1 }, sub { $closed_rejected = 1 });
      test {
        isa_ok $stream, 'Web::Transport::HTTPStream::Stream';
      } $c;
      return $stream->headers_received;
    })->then (sub {
      my $got = $_[0];
      test {
        is $got->{failed}, undef;
        is $got->{message}, undef;
        isa_ok $got->{received}, 'ReadableStream';
        is $got->{received_messages}, undef;
        is $got->{version}, '1.1';
        is $got->{status}, 203;
        is $got->{reason}, 'ok';
        is $got->{headers}->[0]->[0], 'X-hoge';
        is $got->{headers}->[0]->[1], 'Foo bar';
        ok ! $got->{incomplete};
        ok ! $closed_fulfilled;
        ok ! $closed_rejected;
      } $c;
      return read_rbs ($got->{received})->then (sub {
        my $bytes = $_[0];
        test {
          is $bytes, "abc";
          ok ! $got->{incomplete};
        } $c;
      });
    })->then (sub{
      return $closed;
    })->then (sub {
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 15, name => 'send_request gets a response';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 203 ok"CRLF
    "X-hoge: Foo bar"CRLF
    "content-length: 10"CRLF
    CRLF
    "abc"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    my $closed;
    my $closed_fulfilled;
    my $closed_rejected;
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $stream = $_[0]->{stream};
      $closed = $_[0]->{closed};
      $closed->then (sub { $closed_fulfilled = 1 }, sub { $closed_rejected = 1 });
      test {
        isa_ok $stream, 'Web::Transport::HTTPStream::Stream';
      } $c;
      return $stream->headers_received;
    })->then (sub {
      my $got = $_[0];
      test {
        is $got->{failed}, undef;
        is $got->{message}, undef;
        isa_ok $got->{received}, 'ReadableStream';
        is $got->{received_messages}, undef;
        is $got->{version}, '1.1';
        is $got->{status}, 203;
        is $got->{reason}, 'ok';
        is $got->{headers}->[0]->[0], 'X-hoge';
        is $got->{headers}->[0]->[1], 'Foo bar';
        is $got->{headers}->[1]->[0], 'content-length';
        is $got->{headers}->[1]->[1], '10';
        ok ! $got->{incomplete};
        ok ! $closed_fulfilled;
        ok ! $closed_rejected;
      } $c;
      return read_rbs ($got->{received})->then (sub {
        my $bytes = $_[0];
        test {
          is $bytes, "abc";
          ok $got->{incomplete};
        } $c;
      });
    })->then (sub {
      return $closed;
    })->catch (sub{
      my $error = $_[0];
      # XXX
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 17, name => 'send_request gets an incomplete response';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "abcdefg"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    my $error;
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $stream = $_[0]->{stream};
      test {
        isa_ok $stream, 'Web::Transport::HTTPStream::Stream';
      } $c;
      return $stream->headers_received;
    })->then (sub {
      my $got = $_[0];
      test {
        is $got->{failed}, undef;
        is $got->{message}, undef;
        isa_ok $got->{received}, 'ReadableStream';
        is $got->{received_messages}, undef;
        is $got->{version}, '0.9';
        is $got->{status}, 200;
        is $got->{reason}, 'OK';
        is 0+@{$got->{headers}}, 0;
        ok ! $got->{incomplete};
      } $c;
      return read_rbs ($got->{received})->then (sub {
        my $bytes = $_[0];
        test {
          is $bytes, "abcdefg";
          ok ! $got->{incomplete};
        } $c;
      });
    })->then (sub{
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 12, name => 'send_request HTTP/0.9 response';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 212 ok"CRLF
    "content-length: 2"CRLF
    "content-length: 3"CRLF
    CRLF
    "abcdefg"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    my $closed;
    my $closed_fulfilled;
    my $closed_rejected;
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $stream = $_[0]->{stream};
      $closed = $_[0]->{closed};
      $closed->then (sub { $closed_fulfilled = 1 }, sub { $closed_rejected = 1 });
      test {
        isa_ok $stream, 'Web::Transport::HTTPStream::Stream';
      } $c;
      return $stream->headers_received;
    })->then (sub {
      test { ok 0 } $c;
    }, sub {
      my $got = $_[0];
      test {
        ok $got->{failed};
        is $got->{message}, 'Inconsistent content-length values';
        is $got->{received}, undef;
        is $got->{received_messages}, undef;
        is $got->{version}, undef;
        is $got->{status}, undef;
        is $got->{reason}, undef;
        is $got->{headers}, undef;
        is $got->{incomplete}, undef;
        ok ! $closed_fulfilled;
        ok $closed_rejected;
      } $c;
    })->then (sub{
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 12, name => 'send_request response error';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 203 ok"CRLF
    "X-hoge: Foo bar"CRLF
    "content-length: 3"CRLF
    CRLF
    "abc"
    receive "GET"
    "HTTP/1.1 207 foo"CRLF
    "content-length: 7"CRLF
    CRLF
    "abcdefg"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    my $closed;
    my $closed_fulfilled;
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $stream = $_[0]->{stream};
      $closed = $_[0]->{closed};
      $closed->then (sub { $closed_fulfilled = 1 });
      test {
        isa_ok $stream, 'Web::Transport::HTTPStream::Stream';
      } $c;
      return $stream->headers_received;
    })->then (sub {
      my $got = $_[0];
      test {
        is $got->{failed}, undef;
        is $got->{message}, undef;
        isa_ok $got->{received}, 'ReadableStream';
        is $got->{received_messages}, undef;
        is $got->{version}, '1.1';
        is $got->{status}, 203;
        is $got->{reason}, 'ok';
        is $got->{headers}->[0]->[0], 'X-hoge';
        is $got->{headers}->[0]->[1], 'Foo bar';
        ok ! $got->{incomplete};
      } $c;
      return read_rbs ($got->{received})->then (sub {
        my $bytes = $_[0];
        test {
          is $bytes, "abc";
          ok ! $got->{incomplete};
          ok $closed_fulfilled;
        } $c;
        return $http->send_request ({method => 'GET', target => '/'});
      });
    })->then (sub {
      my $stream = $_[0]->{stream};
      test {
        isa_ok $stream, 'Web::Transport::HTTPStream::Stream';
      } $c;
      return $stream->headers_received;
    })->then (sub {
      my $got = $_[0];
      test {
        is $got->{failed}, undef;
        is $got->{message}, undef;
        isa_ok $got->{received}, 'ReadableStream';
        is $got->{received_messages}, undef;
        is $got->{version}, '1.1';
        is $got->{status}, 207;
        is $got->{reason}, 'foo';
        is $got->{headers}->[0]->[0], 'content-length';
        is $got->{headers}->[0]->[1], '7';
        ok ! $got->{incomplete};
      } $c;
      return read_rbs ($got->{received})->then (sub {
        my $bytes = $_[0];
        test {
          is $bytes, "abcdefg";
          ok ! $got->{incomplete};
        } $c;
      });
    })->then (sub{
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 27, name => 'send_request two times';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 203 ok"CRLF
    "X-hoge: Foo bar"CRLF
    "content-length: 3"CRLF
    CRLF
    "abc"
    receive "GET"
    "HTTP/1.1 207 foo"CRLF
    "content-length: 7"CRLF
    CRLF
    "abcdefg"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    my $error;
    $http->connect->then (sub {
      my $p = $http->send_request ({method => 'GET', target => '/'});
      my $q = $http->send_request ({method => 'GET', target => '/'});
      return $q->catch (sub {
        my $error = $_[0];
        test {
          is $error->name, 'TypeError';
          is $error->message, 'Connection is busy';
          is $error->file_name, __FILE__;
          is $error->line_number, __LINE__-7;
        } $c;
        return $p;
      })->then (sub {
        my $stream = $_[0]->{stream};
        test {
          isa_ok $stream, 'Web::Transport::HTTPStream::Stream';
        } $c;
        return $stream->headers_received->then (sub {
          my $got = $_[0];
          test {
            is $got->{failed}, undef;
            isa_ok $got->{received}, 'ReadableStream';
            is $got->{status}, 203;
          } $c;
          return read_rbs ($got->{received});
        });
      });
    })->then (sub{
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 8, name => 'send_request connection in use';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 203 ok"CRLF
    "X-hoge: Foo bar"CRLF
    "content-length: 3"CRLF
    CRLF
    "abc"
    receive "GET"
    "HTTP/1.1 207 foo"CRLF
    "content-length: 7"CRLF
    CRLF
    "abcdefg"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    my $error;
    $http->connect->then (sub {
      return $http->close;
    })->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->catch (sub {
      my $error = $_[0];
      test {
        is $error->name, 'TypeError';
        is $error->message, 'Connection is closed';
        is $error->file_name, __FILE__;
        is $error->line_number, __LINE__-7;
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 4, name => 'send_request after close';

test {
  my $c = shift;
  my $http = Web::Transport::HTTPStream->new ({parent => {
    class => 'Web::Transport::TCPStream',
    host => Web::Host->parse_string ('127.0.0.1'),
    port => 5323322,
  }});
  $http->send_request ({method => 'GET', target => '/'})->catch (sub {
    my $error = $_[0];
    test {
      is $error->name, 'TypeError';
      is $error->message, 'Connection is not ready';
      is $error->file_name, __FILE__;
      is $error->line_number, __LINE__+5;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 4, name => 'send_request before connect';

test {
  my $c = shift;
  server_as_cv (q{
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    my $error;
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'}, cb => sub {
#XXXXXXXXXXXXXXXX
        my ($http, $type, $data) = @_;
        $error = $data if $type eq 'complete';
      });
    })->then (sub {
      test {
        ok $error;
        ok not $error->{can_retry};
      } $c;
    })->then (sub{
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'first empty response';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 200 OK"CRLF
    "Content-Length: 0"CRLF
    CRLF
    receive "GET"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    my $error1;
    my $error2;
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'}, cb => sub {
#XXXXXXXXXXXXX
        my ($http, $type, $data) = @_;
        $error1 = $data if $type eq 'complete';
      });
    })->then (sub {
      return $_[0]->{stream}->headers_received;
    })->then (sub {
      return $http->send_request ({method => 'GET', target => '/'}, cb => sub {
# XXXX
        my ($http, $type, $data) = @_;
        $error2 = $data if $type eq 'complete';
      });
    })->then (sub {
      test {
        ok $error2;
        ok $error2->{can_retry};
      } $c;
    })->then (sub{
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'second empty response';

for my $is_binary (0, 1) {
  test {
    my $c = shift;
    server_as_cv (q{
      receive "GET"
      "HTTP/1.1 200 OK"CRLF
      "Content-Length: 0"CRLF
      CRLF
      receive "GET"
      close
    })->cb (sub {
      my $server = $_[0]->recv;
      my $http = Web::Transport::HTTPStream->new ({parent => {
        class => 'Web::Transport::TCPStream',
        host => Web::Host->parse_string ($server->{addr}),
        port => $server->{port},
      }});
      my $error;
      $http->connect->then (sub {
        return $http->send_request ({method => 'GET', target => '/'}, ws => 1, cb => sub {
#XXXXX
          my ($http, $type, $data) = @_;
          $error = $data->{reason} if $type eq 'complete';
        });
      })->then (sub {
        my $stream = $_[0]->{stream};
        return Promise->resolve->then (sub {
          return $stream->send_ws_message (3, $is_binary);
        })->then (sub {
          test { ok 0 } $c;
        }, sub {
          my $error = $_[0];
          test {
            like $error, qr{^TypeError: Stream is busy at \Q@{[__FILE__]}\E line \Q@{[__LINE__-6]}\E};
          } $c;
        })->then (sub{
#XXXX
          return $http->close;
        });
      })->then (sub {
        done $c;
        undef $c;
      });
    });
  } n => 2, name => ['send_ws_message after bad handshake', $is_binary];

  test {
    my $c = shift;
    server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=1 length=3
"xyz"
close
    })->cb (sub {
      my $server = $_[0]->recv;
      my $http = Web::Transport::HTTPStream->new ({parent => {
        class => 'Web::Transport::TCPStream',
        host => Web::Host->parse_string ($server->{addr}),
        port => $server->{port},
      }});
      $http->connect->then (sub {
        return $http->send_request ({method => 'GET', target => '/'}, ws => 1);
      })->then (sub {
        my $stream = $_[0]->{stream};
        return $stream->headers_received->then (sub {
          rsread $_[0]->{received_messages};
          return $stream->send_ws_message (3, $is_binary);
        })->then (sub {
          my $writer = $_[0]->{stream}->get_writer;
          $writer->write (d 'abc');
          return $writer->close;
        })->then (sub {
          return $stream->send_ws_close;
        });
      })->catch (sub {
        my $error = $_[0];
        test {
#XXX
          ok $error->{ws};
          is $error->{status}, 1006;
        } $c;
      })->then (sub {
        done $c;
        undef $c;
      });
    });
  } n => 2, name => ['send_ws_message ok', $is_binary];

my $tbmethod;
test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
sleep 1
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $error = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->$tbmethod (2);
          eval {
            $http->send_data (\'abc');
          } or do {
            test {
              like $@, qr{^Data too large};
            } $c;
            $error++;
          }
        }
      });
    })->then (sub{
      test {
        is $error, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => ['send_ws_message data too large', $tbmethod];

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
sleep 1
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $error = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->$tbmethod (2);
          eval {
            $http->send_data (\"\x{100}");
          } or do {
            test {
              like $@, qr{^Data is utf8-flagged};
            } $c;
            $error++;
          }
        }
      });
    })->then (sub{
      test {
        is $error, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => ['send_ws_message data utf8 flagged', $tbmethod];

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
sleep 1
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $error = 0;
    my @p;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->$tbmethod (3);
          $http->send_data (\'ab');
          for my $code (
            sub { $http->send_text_header (4); },
            sub { $http->send_binary_header (4); },
            sub { $http->send_ping },
            sub { $http->send_ping (pong => 1) },
            sub { $http->close },
          ) {
            push @p,
            Promise->resolve->then ($code)->then (sub { test { ok 0 } $c }, sub {
              my $err = $_[0];
              test {
                like $err, qr{^(?:Bad state|Body is not sent)};
              } $c;
              $error++;
            });
          }
        }
      });
    })->then (sub{
      test {
        is $error, 5;
      } $c;
      return Promise->all (\@p);
    })->then (sub {
      return $http->abort;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => ['send_ws_message then bad method', $tbmethod];

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-header
ws-receive-data
ws-receive-header
ws-send-header opcode=1 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->$tbmethod (0);
          $http->$tbmethod (3);
          $http->send_data (\'a');
          $http->send_data (\'bc');
          $http->$tbmethod (0);
          $sent++;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => ['send_ws_message zero length', $tbmethod];

}

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=1 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->close;
          $sent++;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'ws close ok no args';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=1 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->close (status => 1234);
          $sent++;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'ws close ok with status';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=1 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->close (status => 1234, reason => 'av c');
          $sent++;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'ws close ok with status and reason';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=1 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->close (status => 0x10000, reason => 'av c')->then (sub {
            test { ok 0 } $c;
          }, sub {
            my $err = $_[0];
            test {
              like $err, qr{^Bad status};
            } $c;
          })->then (sub { return $http->close });
          $sent++;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'ws close with bad status';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=1 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->close (status => 1234, reason => "\x{105}")->then (sub {
            test { ok 0 } $c;
          }, sub {
            my $err = $_[0];
            test {
              like $err, qr{^Reason is utf8-flagged};
            } $c;
          })->then (sub { return $http->close });
          $sent++;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'ws close with bad reason';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=1 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->close (status => 1234, reason => 'x' x 126)->then (sub {
            test { ok 0 } $c;
          }, sub {
            my $err = $_[0];
            test {
              like $err, qr{^Reason is too long};
            } $c;
          })->then (sub { return $http->close });
          $sent++;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'ws close with long reason';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 200 OK"CRLF
CRLF
"abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          AE::postpone {
            $http->abort;
            $sent++;
          };
        }
      });
    })->then (sub{
      test {
        is $sent, 1, "abort called";
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    }, sub {
      warn $_[0];
    });
  });
} n => 1, name => 'headers then abort';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          AE::postpone {
            $http->abort;
            $sent++;
          };
        }
      });
    })->then (sub{
      test {
        is $sent, 1, "abort called";
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    }, sub {
      warn $_[0];
    });
  });
} n => 1, name => 'ws then abort';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=10 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    my $pong = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->send_ping;
          $sent++;
        } elsif ($type eq 'ping') {
          $pong++;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
        is $pong, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'ws ping';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=10 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->send_ping (pong => 1);
          $sent++;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'ws ping pong';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=10 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->send_ping (data => "ab c");
          $sent++;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'ws ping data';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=10 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $error = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          eval {
            $http->send_ping (data => "ab c\x{500}");
          } or do {
            test {
              like $@, qr{^Data is utf8-flagged};
              $error++;
            } $c;
          };
          $http->close;
        }
      });
    })->then (sub{
      test {
        is $error, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'ws ping utf8 data';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=10 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $error = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          eval {
            $http->send_ping (data => 'x' x 126);
          } or do {
            test {
              like $@, qr{^Data too large};
              $error++;
            } $c;
          };
          $http->close;
        }
      });
    })->then (sub{
      test {
        is $error, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'ws ping long data';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=10 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $error = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->close->then (sub {
            $http->send_ping (data => 'x');
          })->then (sub {
            test { ok 0 } $c;
          }, sub {
            my $err = $_[0];
            test {
              like $err, qr{^Bad state}, 'error text';
              $error++;
            } $c;
          });
        }
      });
    })->then (sub{
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'ws ping after closed';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
sleep 21
ws-send-header opcode=9 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $ping = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->close;
        } elsif ($type eq 'ping') {
          $ping++;
        }
      });
    })->then (sub{
      return $http->close;
    })->then (sub {
      test {
        is $ping, 0, 'ping not received';
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'ws ping received after closed';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=10 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $error = 0;
    $http->connect->then (sub {
      return $http->send_ping;
    })->then (sub{
      test { ok 0 } $c;
    }, sub {
      my $err = $_[0];
      test {
        like $err, qr{^Bad state}, 'error text';
        $error++;
      } $c;
    })->then (sub {
      test {
        is $error, 1, 'error count';
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'ws ping bad context';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    my $received = '';
    my @ev;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'CONNECT', target => 'test'}, cb => sub {
        my ($http, $type, $data) = @_;
        push @ev, $type if $type eq 'complete';
        if ($type eq 'headers') {
          AE::postpone {
            test {
              $http->send_data (\'abc');
              $http->close;
              $sent++;
            } $c;
          };
        } elsif ($type eq 'data') {
          $received .= $data;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
        is $received, 'xyz';
        is $ev[-1], 'complete';
        pop @ev;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 3, name => 'connect';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    my $received = '';
    my @ev;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'CONNECT', target => 'test'}, cb => sub {
        my ($http, $type, $data) = @_;
        push @ev, $type if $type eq 'complete';
        if ($type eq 'headers') {
          AE::postpone {
            test {
              eval {
                $http->send_data (\"\x{5000}");
              };
              like $@, qr{^Data is utf8-flagged};
            } $c;
          };
          AE::postpone {
            test {
              $http->send_data (\'abc');
              $http->close;
              $sent++;
            } $c;
          };
        } elsif ($type eq 'data') {
          $received .= $data;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
        is $received, 'xyz';
        is $ev[-1], 'complete';
        pop @ev;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 4, name => 'connect send_data utf8';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    my $received = '';
    my @ev;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'CONNECT', target => 'test'}, cb => sub {
        my ($http, $type, $data) = @_;
        push @ev, $type if $type eq 'complete';
        if ($type eq 'headers') {
          AE::postpone {
            test {
              $http->send_data (\'');
              $http->close;
              $sent++;
            } $c;
          };
        } elsif ($type eq 'data') {
          $received .= $data;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
        is $received, 'xyz';
        is $ev[-1], 'complete';
        pop @ev;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 3, name => 'connect send_data empty';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $error = 0;
    my $x;
    my $p = Promise->new (sub { $x = $_[0] });
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'CONNECT', target => 'test'}, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          AE::postpone {
            $http->close->then (sub {
              $http->send_data (\'abc');
            })->then (sub {
              test { ok 0 } $c;
            }, sub {
              my $err = $_[0];
              test {
                like $err, qr{^Bad state};
                $x->();
              } $c;
            });
          };
        }
      });
    })->then (sub{
      return $p;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'connect data after close';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
show "sleep"
sleep 1
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $received = '';
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'CONNECT', target => 'test'}, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $received .= '(headers)';
          AE::postpone {
            $http->close;
          };
        } elsif ($type eq 'data') {
          $received .= $data;
        }
      });
    })->then (sub{
      test {
        is $received, '(headers)xyz';
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'connect received after send-shutdown';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'CONNECT', target => 'test'}, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          my $timer; $timer = AE::timer 1, 0, sub {
            $http->send_data (\'abc');
            AE::postpone {
              $http->close;
            };
            undef $timer;
          };
        }
      });
    })->then (sub{
      test {
        ok 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'connect sending after EOF';

test {
  my $c = shift;
  server_as_cv (q{
receive "hoge"
"HTTP/1.1 200 OK"CRLF
"Content-Length: 2"CRLF
CRLF
"OK"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    $http->connect->then (sub {
      my $p = $http->send_request_headers
          ({method => 'GET', target => 'test',
            headers => [['Content-Length' => 4]]}, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'data') {
          test {
            is $data, 'OK';
          } $c;
        }
      });
      $http->send_data (\"hoge");
      return $p;
    })->then (sub {
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'with request body';

test {
  my $c = shift;
  server_as_cv (q{
receive "hoge"
"HTTP/1.1 200 OK"CRLF
"Content-Length: 2"CRLF
CRLF
"NG"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    $http->connect->then (sub {
      my $p = $http->send_request_headers
          ({method => 'GET', target => 'test',
            headers => [['Content-Length' => 4]]},
           cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'data') {
          test {
            ok 0;
          } $c;
        }
      });
      test {
        eval {
          $http->send_data (\"hoge!");
        } or do {
          like $@, qr/^Data too large/;
          $http->abort;
        };
      } $c;
      return $p;
    })->then (sub {
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'with request body - too long 1';

test {
  my $c = shift;
  server_as_cv (q{
receive "hoge"
"HTTP/1.1 200 OK"CRLF
"Content-Length: 2"CRLF
CRLF
"NG"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    $http->connect->then (sub {
      my $p = $http->send_request_headers
          ({method => 'GET', target => 'test',
            headers => [['Content-Length' => 4]]}, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'data') {
          test {
            ok 0;
          } $c;
        }
      });
      $http->send_data (\"ho");
      test {
        eval {
          $http->send_data (\"ge!");
        } or do {
          like $@, qr/^Data too large/;
          $http->abort;
        };
      } $c;
      return $p;
    })->then (sub {
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'with request body - too long 2';

test {
  my $c = shift;
  server_as_cv (q{
receive "hoge"
"HTTP/1.1 200 OK"CRLF
"Content-Length: 2"CRLF
CRLF
"NG"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    $http->connect->then (sub {
      my $p = $http->send_request_headers
          ({method => 'GET', target => 'test',
            headers => [['Content-Length' => 0]]}, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'data') {
          test {
            ok 0;
          } $c;
        }
      });
      test {
        eval {
          $http->send_data (\"hoge");
        } or do {
          like $@, qr/^Bad state/;
          $http->abort;
        };
      } $c;
      return $p;
    })->then (sub {
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'with request body - not allowed';

test {
  my $c = shift;
  server_as_cv (q{
receive "hoge"
"HTTP/1.1 200 OK"CRLF
"Content-Length: 0"CRLF
CRLF
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    $http->connect->then (sub {
      my $p = $http->send_request_headers
          ({method => 'GET', target => 'test',
            headers => [['Content-Length' => 4]]},
           cb => sub {});
      return $http->close->catch (sub {
        my $err = $_[0];
        test {
          like $err, qr{^Body is not sent};
        } $c;
        return $http->send_data (\'hoge');
      })->then (sub { return $p });
    })->then (sub {
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'with request body - closed without body';

test {
  my $c = shift;
  server_as_cv (q{
receive "hoge"
"HTTP/1.1 200 OK"CRLF
"Content-Length: 2"CRLF
CRLF
"NG"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    $http->connect->then (sub {
      my $p = $http->send_request_headers
          ({method => 'GET', target => 'test',
            headers => [['Content-Length' => 4]]},
           cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'data') {
          test {
            ok 0;
          } $c;
        }
      });
      test {
        eval {
          $http->send_data (\"ge\x{500}");
        } or do {
          like $@, qr/^Data is utf8-flagged/;
          $http->abort;
        };
      } $c;
      return $p;
    })->then (sub {
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'with request body - utf8';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
starttls
receive "GET"
"HTTP/1.1 200 OK"CRLF
"Content-Length: 3"CRLF
CRLF
"abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $proxy = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $connect = Web::Transport::H1CONNECTTransport->new
        (http => $proxy, target => 'hoge.test');
    my $tls = Web::Transport::TLSTransport->new
        (transport => $connect,
         sni_host_name => Web::Host->parse_string ('hoge.test'),
         si_host_name => Web::Host->parse_string (Test::Certificates->cert_name),
         ca_file => Test::Certificates->ca_path ('cert.pem'));
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tls);
    my $d = '';
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET',
                                           target => '/test'}, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'data') {
          $d .= $data;
        }
      });
    })->then (sub {
      test {
        is $d, 'abc';
      } $c;
      return $http->close;
    })->catch (sub {
      my $error = $_[0];
      test {
        is defined $error ? $error : '(undef)', undef;
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'CONNECT https';

test {
  my $c = shift;
  {
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ('127.0.53.53'), port => int rand);
    my $proxy = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $connect = Web::Transport::H1CONNECTTransport->new
        (http => $proxy, target => 'hoge.test');
    my $tls = Web::Transport::TLSTransport->new
        (transport => $connect,
         sni_host_name => Web::Host->parse_string ('hoge.test'),
         si_host_name => Web::Host->parse_string (Test::Certificates->cert_name),
         ca_file => Test::Certificates->ca_path ('cert.pem'));
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tls);
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET',
                                           target => '/test'}, cb => sub { });
    })->then (sub { test { ok 0 } $c }, sub {
      test {
        ok 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  }
} n => 1, name => 'CONNECT https bad TCP host';

test {
  my $c = shift;
  {
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ('127.0.53.53'), port => int rand);
    my $proxy = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $connect = Web::Transport::H1CONNECTTransport->new
        (http => $proxy, target => 'hoge.test');
    my $http = Web::Transport::HTTPClientConnection->new (transport => $connect);
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET',
                                           target => '/test'}, cb => sub { });
    })->then (sub { test { ok 0 } $c }, sub {
      test {
        ok 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  }
} n => 1, name => 'CONNECT http bad TCP host';

test {
  my $c = shift;
  unix_server_as_cv (q{
receive "GET"
"HTTP/1.1 200 OK"CRLF
"Content-Length: 3"CRLF
CRLF
"xyz"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $unix = Web::Transport::UNIXDomainSocketTransport->new
        (path => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $unix);
    my $d = '';
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'data') {
          $d .= $data;
        }
      });
    })->then (sub {
      test {
        is $d, 'xyz';
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'UNIX domain socket';

Test::Certificates->wait_create_cert;
run_tests;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
