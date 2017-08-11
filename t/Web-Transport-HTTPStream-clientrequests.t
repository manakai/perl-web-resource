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
use Web::Transport::H1CONNECTStream;
use Web::Transport::HTTPStream;
use Promise;
use Promised::Flow;
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
          defined $_[0]->{value}->{body}) {
        rsread ($_[0]->{value}->{body});
      }
      if (ref $_[0]->{value} eq 'HASH' and
          defined $_[0]->{value}->{text_body}) {
        rsread ($_[0]->{value}->{text_body});
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
  return $run->()->then (sub { undef $run; return $result }, sub { undef $run; die $_[0] });
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
    $http->ready->then (sub {
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
      return $http->close_after_current_stream;
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
    $http->ready->then (sub {
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
      return $http->close_after_current_stream;
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
    $http->ready->then (sub {
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
      return $http->close_after_current_stream;
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
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $stream = $_[0]->{stream};
      $closed = $stream->closed;
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
        isa_ok $got->{body}, 'ReadableStream';
        is $got->{messages}, undef;
        is $got->{version}, '1.1';
        is $got->{status}, 203;
        is $got->{status_text}, 'ok';
        is $got->{headers}->[0]->[0], 'X-hoge';
        is $got->{headers}->[0]->[1], 'Foo bar';
        ok ! $got->{incomplete};
        ok ! $closed_fulfilled;
        ok ! $closed_rejected;
      } $c;
      return read_rbs ($got->{body})->then (sub {
        my $bytes = $_[0];
        test {
          is $bytes, "abc";
          ok ! $got->{incomplete};
        } $c;
      });
    })->then (sub{
      return $closed;
    })->then (sub {
      return $http->close_after_current_stream;
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
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $stream = $_[0]->{stream};
      $closed = $stream->closed;
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
        isa_ok $got->{body}, 'ReadableStream';
        is $got->{messages}, undef;
        is $got->{version}, '1.1';
        is $got->{status}, 203;
        is $got->{status_text}, 'ok';
        is $got->{headers}->[0]->[0], 'X-hoge';
        is $got->{headers}->[0]->[1], 'Foo bar';
        is $got->{headers}->[1]->[0], 'content-length';
        is $got->{headers}->[1]->[1], '10';
        ok ! $got->{incomplete};
        ok ! $closed_fulfilled;
        ok ! $closed_rejected;
      } $c;
      return read_rbs ($got->{body})->then (sub {
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
      return $http->close_after_current_stream;
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
    $http->ready->then (sub {
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
        isa_ok $got->{body}, 'ReadableStream';
        is $got->{messages}, undef;
        is $got->{version}, '0.9';
        is $got->{status}, 200;
        is $got->{status_text}, 'OK';
        is 0+@{$got->{headers}}, 0;
        ok ! $got->{incomplete};
      } $c;
      return read_rbs ($got->{body})->then (sub {
        my $bytes = $_[0];
        test {
          is $bytes, "abcdefg";
          ok ! $got->{incomplete};
        } $c;
      });
    })->then (sub{
      return $http->close_after_current_stream;
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
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $stream = $_[0]->{stream};
      $stream->closed->then (sub { $closed = $_[0] });
      test {
        isa_ok $stream, 'Web::Transport::HTTPStream::Stream';
      } $c;
      return $stream->headers_received;
    })->then (sub {
      test { ok 0 } $c;
    }, sub {
      my $got = $_[0];
      test {
        is $got, $closed;
        isa_ok $got, 'Web::Transport::ProtocolError::HTTPParseError';
        is $got->name, 'HTTP parse error';
        is $got->message, 'Inconsistent content-length values';
        # XXXlocation
        ok $got->http_fatal;
        ok ! $got->http_can_retry;
      } $c;
    })->then (sub {
      return $http->close_after_current_stream;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 7, name => 'send_request response error';

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
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $stream = $_[0]->{stream};
      $closed = $stream->closed;
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
        isa_ok $got->{body}, 'ReadableStream';
        is $got->{messages}, undef;
        is $got->{version}, '1.1';
        is $got->{status}, 203;
        is $got->{status_text}, 'ok';
        is $got->{headers}->[0]->[0], 'X-hoge';
        is $got->{headers}->[0]->[1], 'Foo bar';
        ok ! $got->{incomplete};
      } $c;
      return read_rbs ($got->{body})->then (sub {
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
        isa_ok $got->{body}, 'ReadableStream';
        is $got->{messages}, undef;
        is $got->{version}, '1.1';
        is $got->{status}, 207;
        is $got->{status_text}, 'foo';
        is $got->{headers}->[0]->[0], 'content-length';
        is $got->{headers}->[0]->[1], '7';
        ok ! $got->{incomplete};
      } $c;
      return read_rbs ($got->{body})->then (sub {
        my $bytes = $_[0];
        test {
          is $bytes, "abcdefg";
          ok ! $got->{incomplete};
        } $c;
      });
    })->then (sub{
      return $http->close_after_current_stream;
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
    $http->ready->then (sub {
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
            isa_ok $got->{body}, 'ReadableStream';
            is $got->{status}, 203;
          } $c;
          return read_rbs ($got->{body});
        });
      });
    })->then (sub{
      return $http->close_after_current_stream;
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
    $http->ready->then (sub {
      return $http->close_after_current_stream;
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
    receive "Content-Length: 0"
    "HTTP/1.1 203 ok"CRLF
    "X-hoge: Foo bar"CRLF
    "content-length: 3"CRLF
    CRLF
    "abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'PUT', target => '/', length => 0});
    })->then (sub {
      my $got = $_[0];
      my $stream = $got->{stream};
      test {
        isa_ok $got->{body}, 'WritableStream';
        my $writer = $got->{body}->get_writer;
        $writer->close;
      } $c;
      return $stream->headers_received;
    })->then (sub {
      my $got = $_[0];
      test {
        is $got->{failed}, undef;
        is $got->{message}, undef;
        isa_ok $got->{body}, 'ReadableStream';
        is $got->{messages}, undef;
        is $got->{version}, '1.1';
        is $got->{status}, 203;
        is $got->{status_text}, 'ok';
        is $got->{headers}->[0]->[0], 'X-hoge';
        is $got->{headers}->[0]->[1], 'Foo bar';
        ok ! $got->{incomplete};
      } $c;
      return read_rbs ($got->{body})->then (sub {
        my $bytes = $_[0];
        test {
          is $bytes, "abc";
          ok ! $got->{incomplete};
        } $c;
      });
    })->then (sub{
      return $http->close_after_current_stream;
    })->catch (sub {
      my $error = $_[0];
      test {
        ok 0, $error;
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 13, name => 'send_request with PUT 0 body';

test {
  my $c = shift;
  server_as_cv (q{
    receive "Content-Length: 0"
    "HTTP/1.1 203 ok"CRLF
    "X-hoge: Foo bar"CRLF
    "content-length: 3"CRLF
    CRLF
    "abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'POST', target => '/', length => 0});
    })->then (sub {
      my $got = $_[0];
      my $stream = $got->{stream};
      test {
        isa_ok $got->{body}, 'WritableStream';
        my $writer = $got->{body}->get_writer;
        $writer->close;
      } $c;
      return $stream->headers_received;
    })->then (sub {
      my $got = $_[0];
      test {
        is $got->{failed}, undef;
        is $got->{message}, undef;
        isa_ok $got->{body}, 'ReadableStream';
        is $got->{messages}, undef;
        is $got->{version}, '1.1';
        is $got->{status}, 203;
        is $got->{status_text}, 'ok';
        is $got->{headers}->[0]->[0], 'X-hoge';
        is $got->{headers}->[0]->[1], 'Foo bar';
        ok ! $got->{incomplete};
      } $c;
      return read_rbs ($got->{body})->then (sub {
        my $bytes = $_[0];
        test {
          is $bytes, "abc";
          ok ! $got->{incomplete};
        } $c;
      });
    })->then (sub{
      return $http->close_after_current_stream;
    })->catch (sub {
      my $error = $_[0];
      test {
        ok 0, $error;
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 13, name => 'send_request with POST 0 body';

test {
  my $c = shift;
  server_as_cv (q{
    receive "Content-Length: 5"
    "HTTP/1.1 203 ok"CRLF
    "X-hoge: Foo bar"CRLF
    "content-length: 3"CRLF
    CRLF
    "abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', length => 5});
    })->then (sub {
      my $got = $_[0];
      my $stream = $got->{stream};
      test {
        isa_ok $got->{body}, 'WritableStream';
        my $writer = $got->{body}->get_writer;
        $writer->write (d "12345");
        $writer->close;
      } $c;
      return $stream->headers_received;
    })->then (sub {
      my $got = $_[0];
      test {
        is $got->{failed}, undef;
        is $got->{message}, undef;
        isa_ok $got->{body}, 'ReadableStream';
        is $got->{messages}, undef;
        is $got->{version}, '1.1';
        is $got->{status}, 203;
        is $got->{status_text}, 'ok';
        is $got->{headers}->[0]->[0], 'X-hoge';
        is $got->{headers}->[0]->[1], 'Foo bar';
        ok ! $got->{incomplete};
      } $c;
      return read_rbs ($got->{body})->then (sub {
        my $bytes = $_[0];
        test {
          is $bytes, "abc";
          ok ! $got->{incomplete};
        } $c;
      });
    })->then (sub{
      return $http->close_after_current_stream;
    })->catch (sub {
      my $error = $_[0];
      test {
        ok 0, $error;
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 13, name => 'send_request with body';

test {
  my $c = shift;
  server_as_cv (q{
    receive "Content-Length: 5"
    "HTTP/1.1 203 ok"CRLF
    "X-hoge: Foo bar"CRLF
    "content-length: 3"CRLF
    CRLF
    "abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', length => 5});
    })->then (sub {
      my $got = $_[0];
      my $stream = $got->{stream};
      my $writer = $got->{body}->get_writer;
      test {
        isa_ok $got->{body}, 'WritableStream';
        $writer->write (d "1234");
      } $c;
      return $writer->close->catch (sub {
        my $error = $_[0];
        test {
          is $error->name, 'TypeError';
          is $error->message, 'Closed before bytes (n = 1) are sent';
          #is $error->file_name, __FILE__; # XXX location
          #is $error->line_number, __LINE__;
        } $c;
        return $stream->headers_received;
      })->catch (sub {
        my $error = $_[0];
        test {
          is $error->name, 'TypeError';
          is $error->message, 'Closed before bytes (n = 1) are sent';
          #is $error->file_name, __FILE__; # XXX
          #is $error->line_number, __LINE__;
        } $c;
      });
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'send_request with body closed early';

test {
  my $c = shift;
  server_as_cv (q{
    receive "Content-Length: 5"
    "HTTP/1.1 203 ok"CRLF
    "X-hoge: Foo bar"CRLF
    "content-length: 3"CRLF
    CRLF
    "abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', length => 5});
    })->then (sub {
      my $got = $_[0];
      my $stream = $got->{stream};
      my $writer = $got->{body}->get_writer;
      test {
        isa_ok $got->{body}, 'WritableStream';
      } $c;
      return $writer->write (d "123456")->catch (sub {
        my $error = $_[0];
        test {
          is $error->name, 'TypeError';
          is $error->message, 'Byte length 6 is greater than expected length 5';
          #is $error->file_name, __FILE__; # XXX location
          #is $error->line_number, __LINE__;
        } $c;
        return $stream->headers_received;
      })->catch (sub {
        my $error = $_[0];
        test {
          is $error->name, 'TypeError';
          is $error->message, 'Byte length 6 is greater than expected length 5';
          #is $error->file_name, __FILE__; # XXX
          #is $error->line_number, __LINE__;
        } $c;
      });
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'send_request with body written too much 1';

test {
  my $c = shift;
  server_as_cv (q{
    receive "Content-Length: 5"
    "HTTP/1.1 203 ok"CRLF
    "X-hoge: Foo bar"CRLF
    "content-length: 3"CRLF
    CRLF
    "abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', length => 5});
    })->then (sub {
      my $got = $_[0];
      my $stream = $got->{stream};
      my $writer = $got->{body}->get_writer;
      test {
        isa_ok $got->{body}, 'WritableStream';
      } $c;
      $writer->write (d "12345");
      return $writer->write (d "6")->catch (sub {
        my $error = $_[0];
        test {
          is $error->name, 'TypeError';
          is $error->message, 'Byte length 1 is greater than expected length 0';
          #is $error->file_name, __FILE__; # XXX location
          #is $error->line_number, __LINE__;
        } $c;
        return $stream->headers_received;
      })->catch (sub {
        my $error = $_[0];
        test {
          is $error->name, 'TypeError';
          is $error->message, 'Byte length 1 is greater than expected length 0';
          #is $error->file_name, __FILE__; # XXX
          #is $error->line_number, __LINE__;
        } $c;
      });
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'send_request with body written too much 2';

test {
  my $c = shift;
  server_as_cv (q{
    receive "Content-Length: 5"
    "HTTP/1.1 203 ok"CRLF
    "X-hoge: Foo bar"CRLF
    "content-length: 3"CRLF
    CRLF
    "abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', length => 5});
    })->then (sub {
      my $got = $_[0];
      my $stream = $got->{stream};
      my $writer = $got->{body}->get_writer;
      test {
        isa_ok $got->{body}, 'WritableStream';
      } $c;
      return $writer->write ("12345")->catch (sub {
        my $error = $_[0];
        test {
          is $error->name, 'TypeError';
          is $error->message, 'The argument is not an ArrayBufferView';
          #is $error->file_name, __FILE__; # XXX location
          #is $error->line_number, __LINE__;
        } $c;
        return $stream->headers_received;
      })->catch (sub {
        my $error = $_[0];
        test {
          is $error->name, 'TypeError';
          is $error->message, 'The argument is not an ArrayBufferView';
          #is $error->file_name, __FILE__; # XXX
          #is $error->line_number, __LINE__;
        } $c;
      });
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'send_request with body bad written data';

test {
  my $c = shift;
  server_as_cv (q{
    receive "Content-Length: 5"
    "HTTP/1.1 203 ok"CRLF
    "X-hoge: Foo bar"CRLF
    "content-length: 3"CRLF
    CRLF
    "abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', length => 5});
    })->then (sub {
      my $got = $_[0];
      my $stream = $got->{stream};
      my $writer = $got->{body}->get_writer;
      test {
        isa_ok $got->{body}, 'WritableStream';
      } $c;
      $writer->write (d "12345");
      return $http->send_request ({method => 'GET', target => '/'})->catch (sub {
        my $error = $_[0];
        test {
          is $error->name, 'TypeError';
          is $error->message, 'Connection is busy';
          is $error->file_name, __FILE__;
          is $error->line_number, __LINE__+20;
        } $c;
        return $writer->write (d "6");
      })->catch (sub {
        my $error = $_[0];
        test {
          is $error->name, 'TypeError';
          is $error->message, 'Byte length 1 is greater than expected length 0';
          #is $error->file_name, __FILE__; # XXX location
          #is $error->line_number, __LINE__;
        } $c;
        return $stream->headers_received;
      })->catch (sub {
        my $error = $_[0];
        test {
          is $error->name, 'TypeError';
          is $error->message, 'Byte length 1 is greater than expected length 0';
          #is $error->file_name, __FILE__; # XXX
          #is $error->line_number, __LINE__;
        } $c;
      });
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 9, name => 'send_request with body written too much 3';

test {
  my $c = shift;
  server_as_cv (q{
    receive "Content-Length: 5"
    "HTTP/1.1 203 ok"CRLF
    "X-hoge: Foo bar"CRLF
    "content-length: 3"CRLF
    CRLF
    "abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', length => 5});
    })->then (sub {
      my $got = $_[0];
      my $stream = $got->{stream};
      my $writer = $got->{body}->get_writer;
      test {
        isa_ok $got->{body}, 'WritableStream';
      } $c;
      $writer->write (d "1234");
      my $thrown = Web::DOM::TypeError->new;
      $writer->abort ($thrown);
      return $stream->closed->then (sub {
        my $error = $_[0];
        test {
          is $error, $thrown;
        } $c;
      });
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'send_request with body aborted 1';

test {
  my $c = shift;
  server_as_cv (q{
    receive "Content-Length: 5"
    "HTTP/1.1 203 ok"CRLF
    "X-hoge: Foo bar"CRLF
    "content-length: 3"CRLF
    CRLF
    "abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', length => 5});
    })->then (sub {
      my $got = $_[0];
      my $stream = $got->{stream};
      my $writer = $got->{body}->get_writer;
      test {
        isa_ok $got->{body}, 'WritableStream';
      } $c;
      $writer->write (d "1234");
      $writer->abort;
      return $stream->closed->then (sub {
        my $error = $_[0];
        test {
          is $error->name, 'Error';
          is $error->message, "Something's wrong";
          is $error->file_name, __FILE__;
          is $error->line_number, __LINE__-7;
        } $c;
      });
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'send_request with body aborted 2';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 203 ok"CRLF
    "X-hoge: Foo bar"CRLF
    CRLF
    "abc"
    "def"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    my $response;
    my $closed;
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $got = $_[0];
      my $stream = $got->{stream};
      $closed = $stream->closed;
      return $stream->headers_received;
    })->then (sub {
      $response = my $got = $_[0];
      test {
        isa_ok $got->{body}, 'ReadableStream';
        is $got->{messages}, undef;
      } $c;
      my $reader = $got->{body}->get_reader ('byob');
      my $result = '';
      my $run; $run = sub {
        return $reader->read (d 'x' x 6)->then (sub {
          return if $_[0]->{done};
          $result .= $_[0]->{value}->manakai_to_string;
          $http->abort if $result =~ /abcdef/;
          return $run->();
        });
      };
      return $run->()->then (sub { undef $run });
    })->then (sub {
      test {
        ok ! $http->is_active;
      } $c;
      return $closed;
    })->then (sub {
      test {
        ok $response->{incomplete}, 'response aborted';
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 4, name => 'send_request response body HTTP aborted';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 203 ok"CRLF
    "X-hoge: Foo bar"CRLF
    CRLF
    "abc"
    "def"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    my $response;
    my $closed;
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $got = $_[0];
      my $stream = $got->{stream};
      $closed = $stream->closed;
      return $stream->headers_received;
    })->then (sub {
      $response = my $got = $_[0];
      test {
        isa_ok $got->{body}, 'ReadableStream';
        is $got->{closing}, undef;
        is $got->{messages}, undef;
      } $c;
      my $reader = $got->{body}->get_reader ('byob');
      my $result = '';
      my $run; $run = sub {
        return $reader->read (d 'x' x 6)->then (sub {
          return if $_[0]->{done};
          $result .= $_[0]->{value}->manakai_to_string;
          $reader->cancel if $result =~ /abcdef/;
          return $run->();
        });
      };
      return $run->()->then (sub { undef $run });
    })->then (sub {
      test {
        ok ! $http->is_active;
      } $c;
      return $closed;
    })->then (sub {
      my $error = $_[0];
      test {
        ok $response->{incomplete}, 'response aborted';
        # XXX
        ok $error;
        #is $error->name, 'Error';
        #is $error->message, "Something's wrong";
        #is $error->file_name, __FILE__;
        #is $error->line_number, __LINE__-17;
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => 'send_request response body aborted';

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
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $got = $_[0];
      my $stream = $got->{stream};
      my $writer = $got->{body}->get_writer;
      $closed = $stream->closed;
      return $stream->headers_received->then (sub {
        my $got = $_[0];
        return (read_rbs $got->{body});
      })->then (sub {
        my $received = $_[0];
        test {
          is $received, "abc";
        } $c;
        return $writer->write (d 'xyz')->catch (sub {
          my $error = $_[0];
          test {
            is $error->name, 'TypeError';
            is $error->message, 'Byte length 3 is greater than expected length 0';
            # XXX location
          } $c;
        });
      });
    })->then (sub {
      test {
        ok ! $http->is_active;
      } $c;
      return $closed;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 4, name => 'send_request request body write (should fail) after response closed';

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
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $got = $_[0];
      my $stream = $got->{stream};
      my $writer = $got->{body}->get_writer;
      $closed = $stream->closed;
      return $stream->headers_received->then (sub {
        my $got = $_[0];
        return (read_rbs $got->{body});
      })->then (sub {
        my $received = $_[0];
        test {
          is $received, "abc";
        } $c;
        return $writer->close;
      });
    })->then (sub {
      test {
        ok ! $http->is_active;
      } $c;
      return $closed;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'send_request request body close after response closed';

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
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', length => 3});
    })->then (sub {
      my $got = $_[0];
      my $stream = $got->{stream};
      my $writer = $got->{body}->get_writer;
      $closed = $stream->closed;
      return $stream->headers_received->then (sub {
        my $got = $_[0];
        return (read_rbs $got->{body});
      })->then (sub {
        my $received = $_[0];
        test {
          is $received, "abc";
        } $c;
        return $writer->write (d 'xyz');
      });
    })->then (sub {
      test {
        ok ! $http->is_active;
      } $c;
      return $closed;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'send_request request body write after response closed';

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
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', length => 3});
    })->then (sub {
      my $got = $_[0];
      my $stream = $got->{stream};
      my $writer = $got->{body}->get_writer;
      $closed = $stream->closed;
      return $stream->headers_received->then (sub {
        my $got = $_[0];
        return (read_rbs $got->{body});
      })->then (sub {
        my $received = $_[0];
        test {
          is $received, "abc";
        } $c;
        $writer->write (d 'xyz');
        return $writer->close;
      });
    })->then (sub {
      test {
        ok ! $http->is_active;
      } $c;
      return $closed;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'send_request request body write after response closed';

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
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $got = $_[0];
      return $got->{stream}->closed;
    })->then (sub {
      my $error = $_[0];
      test {
        is $error->name, 'HTTP parse error';
        is $error->message, 'Connection closed without response';
        ok $error->http_fatal;
        ok ! $error->http_can_retry;
      } $c;
    })->then (sub{
      return $http->close_after_current_stream;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 4, name => 'first empty response';

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
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $stream = $_[0]->{stream};
      return $stream->headers_received->then (sub {
        return $http->send_request ({method => 'GET', target => '/'});
      })->then (sub {
        return $_[0]->{stream}->closed;
      });
    })->then (sub {
      my $error = $_[0];
      test {
        is $error->name, 'HTTP parse error';
        is $error->message, 'Connection closed without response (can retry)';
        ok $error->http_fatal;
        ok $error->http_can_retry;
      } $c;
    })->then (sub{
      return $http->close_after_current_stream;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 4, name => 'second empty response';

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
      $http->ready->then (sub {
        return $http->send_request ({method => 'GET', target => '/', ws => 1});
      })->then (sub {
        my $stream = $_[0]->{stream};
        my $closed = $stream->closed;
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
          return $http->close_after_current_stream;
        })->then (sub {
          return $closed;
        })->then (sub {
          test {
            ok 1;
          } $c;
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
      $http->ready->then (sub {
        return $http->send_request ({method => 'GET', target => '/', ws => 1});
      })->then (sub {
        my $stream = $_[0]->{stream};
        my $closed = $stream->closed;
        return $stream->headers_received->then (sub {
          rsread $_[0]->{messages};
          return $stream->send_ws_message (3, $is_binary);
        })->then (sub {
          my $writer = $_[0]->{body}->get_writer;
          $writer->write (d 'abc');
          return $writer->close;
        })->then (sub {
          return $stream->send_ws_close;
        })->then (sub {
          return $closed;
        });
      })->then (sub {
        my $error = $_[0];
        test {
          is $error->name, 'WebSocket Close';
          is $error->ws_status, 1006;
        } $c;
      })->then (sub {
        done $c;
        undef $c;
      });
    });
  } n => 2, name => ['send_ws_message ok', $is_binary];

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
      my $http = Web::Transport::HTTPStream->new ({parent => {
        class => 'Web::Transport::TCPStream',
        host => Web::Host->parse_string ($server->{addr}),
        port => $server->{port},
      }});
      $http->ready->then (sub {
        return $http->send_request ({method => 'GET', target => '/', ws => 1});
      })->then (sub {
        my $stream = $_[0]->{stream};
        return $stream->headers_received->then (sub {
          return $stream->send_ws_message (2, $is_binary);
        })->then (sub {
          my $writer = $_[0]->{body}->get_writer;
          return $writer->write (d 'abc');
        })->catch (sub {
          my $error = $_[0];
          test {
            is $error->name, 'TypeError', $error;
            is $error->message, 'Byte length 3 is greater than expected length 2';
            # XXX location
          } $c;
        });
      })->then (sub{
        return $http->close_after_current_stream;
      })->then (sub {
        done $c;
        undef $c;
      });
    });
  } n => 2, name => ['send_ws_message data too large', $is_binary];

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
      my $http = Web::Transport::HTTPStream->new ({parent => {
        class => 'Web::Transport::TCPStream',
        host => Web::Host->parse_string ($server->{addr}),
        port => $server->{port},
      }});
      my @p;
      $http->ready->then (sub {
        return $http->send_request ({method => 'GET', target => '/', ws => 1});
      })->then (sub {
        my $stream = $_[0]->{stream};
        return $stream->headers_received->then (sub {
          return $stream->send_ws_message (3, $is_binary);
        })->then (sub {
          my $writer = $_[0]->{body}->get_writer;
          $writer->write (d "ab");
          for my $code (
            sub { $stream->send_ws_message (4, 0); },
            sub { $stream->send_ws_message (4, 1); },
            sub { $stream->send_ping },
            sub { $stream->send_ping (pong => 1) },
            sub { $stream->send_ws_close },
          ) {
            push @p,
            Promise->resolve->then ($code)->then (sub { test { ok 0 } $c }, sub {
              my $err = $_[0];
              test {
                is $err->name, 'TypeError', 'error name';
                is $err->message, 'Stream is busy';
                is $err->file_name, __FILE__, $err;
                ok __LINE__-13 <= $err->line_number && $err->line_number <= __LINE__-6, $err->line_number;
              } $c;
            });
          }
        });
      })->then (sub{
        return Promise->all (\@p);
      })->then (sub {
        return $http->abort;
      })->then (sub {
        done $c;
        undef $c;
      });
    });
  } n => 5*4, name => ['send_ws_message then bad method', $is_binary];

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
      my $http = Web::Transport::HTTPStream->new ({parent => {
        class => 'Web::Transport::TCPStream',
        host => Web::Host->parse_string ($server->{addr}),
        port => $server->{port},
      }});
      my @p;
      $http->ready->then (sub {
        return $http->send_request ({method => 'GET', target => '/', ws => 1});
      })->then (sub {
        my $stream = $_[0]->{stream};
        return $stream->headers_received->then (sub {
          return $stream->send_ws_message (3, $is_binary);
        })->then (sub {
          my $writer = $_[0]->{body}->get_writer;
          $writer->write (d "ab");
          return $writer->abort;
        })->then (sub {
          return $stream->closed;
        })->then (sub {
          my $error = $_[0];
          test {
            is $error->name, 'WebSocket Close';
            is $error->message, "(1006 ) Something's wrong";
            is $error->ws_status, 1006;
            is $error->file_name, __FILE__;
            is $error->line_number, __LINE__-10;
          } $c;
        });
      })->then (sub{
        return Promise->all (\@p);
      })->then (sub {
        done $c;
        undef $c;
      });
    });
  } n => 5, name => ['send_ws_message writer abort', $is_binary];

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
      my $http = Web::Transport::HTTPStream->new ({parent => {
        class => 'Web::Transport::TCPStream',
        host => Web::Host->parse_string ($server->{addr}),
        port => $server->{port},
      }});
      $http->ready->then (sub {
        return $http->send_request ({method => 'GET', target => '/', ws => 1});
      })->then (sub {
        my $stream = $_[0]->{stream};
        return $stream->headers_received->then (sub {
          rsread $_[0]->{messages};
          return $stream->send_ws_message (0, $is_binary);
        })->then (sub {
          return $stream->send_ws_message (3, $is_binary);
        })->then (sub {
          my $writer = $_[0]->{body}->get_writer;
          $writer->write (d 'a');
          $writer->write (d 'bc');
        })->then (sub {
          return $stream->send_ws_message (0, $is_binary);
        })->then (sub {
          return $stream->send_ws_close;
        })->then (sub {
          my $error = $_[0];
          test {
            isa_ok $error, 'Web::Transport::ProtocolError::WebSocketClose';
            is $error->name, 'WebSocket Close';
            is $error->message, '(1006 ) Connection truncated';
            is $error->ws_status, 1006;
            is $error->ws_reason, '';
            ok ! $error->ws_cleanly;
          } $c;
        });
      })->then (sub{
        return $http->closed;
      })->then (sub {
        test {
          ok 1;
        } $c;
        done $c;
        undef $c;
      });
    });
  } n => 7, name => ['send_ws_message zero length', $is_binary];
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
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    my $closing;
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', ws => 1});
    })->then (sub {
      my $stream = $_[0]->{stream};
      my @ev;
      my $closed = $stream->closed;
      return $stream->headers_received->then (sub {
        $_[0]->{closing}->then (sub { push @ev, 'closing' });
        $stream->closed->then (sub { push @ev, 'closed' });
        rsread $_[0]->{messages};
        return $stream->send_ws_close;
      })->then (sub {
        return $closed;
      })->then (sub {
        my $error = $_[0];
        test {
          isa_ok $error, 'Web::Transport::ProtocolError::WebSocketClose', $error;
          is $error->name, 'WebSocket Close';
          is $error->message, '(1006 ) Connection truncated';
          #XXXlocation
          is $error->ws_status, 1006;
          is $error->ws_reason, '';
          ok ! $error->ws_cleanly;
          is join (';', @ev), 'closing;closed';
        } $c;
      });
    })->then (sub{
      return $http->close_after_current_stream;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 7, name => 'ws close ok no args (no close response)';

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
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', ws => 1});
    })->then (sub {
      my $stream = $_[0]->{stream};
      return $stream->headers_received->then (sub {
        rsread $_[0]->{messages};
        return $stream->send_ws_close (1234);
      })->then (sub {
        my $error = $_[0];
        test {
          is $error->name, 'WebSocket Close';
          is $error->message, '(1006 ) Connection truncated';
          is $error->ws_status, 1006;
          is $error->ws_reason, '';
        } $c;
      });
    })->then (sub{
      return $http->closed;
    })->then (sub {
      test {
        ok 1;
      } $c;
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'ws close ok with status';

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
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', ws => 1});
    })->then (sub {
      my $stream = $_[0]->{stream};
      return $stream->headers_received->then (sub {
        rsread $_[0]->{messages};
        return $stream->send_ws_close (1234, 'av c');
      })->then (sub {
        my $error = $_[0];
        test {
          is $error->name, 'WebSocket Close';
          is $error->message, '(1006 ) Connection truncated';
          is $error->ws_status, 1006;
          is $error->ws_reason, '';
        } $c;
      });
    })->then (sub{
      test {
        ok 1;
      } $c;
      return $http->close_after_current_stream;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'ws close ok with status and reason';

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
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', ws => 1});
    })->then (sub {
      my $stream = $_[0]->{stream};
      return $stream->headers_received->then (sub {
        rsread $_[0]->{messages};
        return $stream->send_ws_close (0x10000, 'av c');
      })->catch (sub {
        my $err = $_[0];
        test {
          like $err, qr{^Bad status};
        } $c;
      })->then (sub {
        return $stream->send_ws_close;
      })->then (sub {
        my $error = $_[0];
        test {
          is $error->name, 'WebSocket Close';
          is $error->message, '(1006 ) Connection truncated';
          is $error->ws_status, 1006;
          is $error->ws_reason, '';
        } $c;
      });
    })->then (sub{
      return $http->close_after_current_stream;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'ws close with bad status';

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
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', ws => 1});
    })->then (sub {
      my $stream = $_[0]->{stream};
      return $stream->headers_received->then (sub {
        rsread $_[0]->{messages};
        return $stream->send_ws_close (1234, "\x{105}");
      })->catch (sub {
        my $err = $_[0];
        test {
          like $err, qr{^Status text is utf8-flagged};
        } $c;
      })->then (sub {
        return $stream->send_ws_close;
      })->then (sub {
        my $error = $_[0];
        test {
          is $error->name, 'WebSocket Close';
          is $error->message, '(1006 ) Connection truncated';
          is $error->ws_status, 1006;
          is $error->ws_reason, '';
        } $c;
      });
    })->then (sub{
      return $http->close_after_current_stream;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'ws close with bad reason';

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
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', ws => 1});
    })->then (sub {
      my $stream = $_[0]->{stream};
      return $stream->headers_received->then (sub {
        rsread $_[0]->{messages};
        return $stream->send_ws_close (1234, 'x' x 126);
      })->catch (sub {
        my $err = $_[0];
        test {
          like $err, qr{^Status text is too long};
        } $c;
      })->then (sub {
        return $stream->send_ws_close;
      })->then (sub {
        my $error = $_[0];
        test {
          is $error->name, 'WebSocket Close';
          is $error->message, '(1006 ) Connection truncated';
          is $error->ws_status, 1006;
          is $error->ws_reason, '';
        } $c;
      });
    })->then (sub {
      return $http->closed;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'ws close with long reason';

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
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', ws => 1});
    })->then (sub {
      my $stream = $_[0]->{stream};
      return $stream->send_ws_close (1234, 'x')->catch (sub {
        my $error = $_[0];
        test {
          is $error->name, 'TypeError';
          is $error->message, 'Stream is busy';
          is $error->file_name, __FILE__;
          is $error->line_number, __LINE__+3;
        } $c;
        return $http->abort;
      });
    })->then (sub {
      return $http->closed;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 4, name => 'ws close ws_status CONNECTING';

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
ws-send-header opcode=8
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', ws => 1});
    })->then (sub {
      my $stream = $_[0]->{stream};
      return $stream->headers_received->then (sub {
        $stream->send_ws_close;
        return $stream->send_ws_close (1234, 'x');
      });
    })->then (sub {
      test {
        ok ! $http->is_active;
      } $c;
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'ws close ws_status CLOSING';

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
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    my $body;
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      return $_[0]->{stream}->headers_received;
    })->then (sub {
      $http->abort;
      $body = $_[0]->{body};
    })->then (sub {
      return $http->closed;
    })->then (sub {
      return read_rbs ($body)->catch (sub { });
    })->then (sub {
      my $received = $_[0];
      test {
        ok 1;
      } $c;
    })->then (sub {
      done $c;
      undef $c;
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
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', ws => 1});
    })->then (sub {
      my $stream = $_[0]->{stream};
      return $stream->headers_received->then (sub {
        return $http->abort;
      });
    })->then (sub {
      test {
        ok 1;
      } $c;
      done $c;
      undef $c;
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
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', ws => 1});
    })->then (sub {
      my $stream = $_[0]->{stream};
      return $stream->headers_received->then (sub {
        rsread $_[0]->{messages};
        $stream->send_ping;
      });
    })->then (sub{
      test {
        ok 1;
      } $c;
      return $http->close_after_current_stream;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'ws ping';

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
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', ws => 1});
    })->then (sub {
      my $stream = $_[0]->{stream};
      return $stream->headers_received->then (sub {
        $stream->send_ping (pong => 1);
      });
    })->then (sub{
      test {
        ok 1;
      } $c;
      return $http->close_after_current_stream;
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
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', ws => 1});
    })->then (sub {
      my $stream = $_[0]->{stream};
      return $stream->headers_received->then (sub {
        $stream->send_ping (data => "ab c");
      });
    })->then (sub{
      test {
        ok 1;
      } $c;
      return $http->close_after_current_stream;
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
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', ws => 1});
    })->then (sub {
      my $stream = $_[0]->{stream};
      return $stream->headers_received->then (sub {
        $stream->send_ping (data => "ab c\x{500}");
      })->catch (sub {
        my $error = $_[0];
        test {
          like $error, qr{^Data is utf8-flagged};
        } $c;
      })->then (sub {
        return $stream->send_ws_close;
      })->then (sub {
        my $error = $_[0];
        test {
          is $error->name, 'WebSocket Close';
          is $error->message, '(1006 ) Connection truncated';
          is $error->ws_status, 1006;
          is $error->ws_reason, '';
        } $c;
      });
    })->then (sub{
      return $http->close_after_current_stream;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'ws ping utf8 data';

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
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', ws => 1});
    })->then (sub {
      my $stream = $_[0]->{stream};
      return $stream->headers_received->then (sub {
        $stream->send_ping (data => 'x' x 126);
      })->catch (sub {
        my $error = $_[0];
        test {
          like $error, qr{^Data too large};
        } $c;
        return $stream->send_ws_close;
      })->then (sub {
        my $error = $_[0];
        test {
          is $error->name, 'WebSocket Close';
          is $error->message, '(1006 ) Connection truncated';
          is $error->ws_status, 1006;
          is $error->ws_reason, '';
        } $c;
      });
    })->then (sub{
      return $http->close_after_current_stream;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'ws ping long data';

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
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', ws => 1});
    })->then (sub {
      my $stream = $_[0]->{stream};
      return $stream->headers_received->then (sub {
        return $stream->send_ws_close->catch (sub { });
      })->then (sub {
        $stream->send_ping (data => 'x');
      })->catch (sub {
        my $err = $_[0];
        test {
          like $err, qr{^TypeError: Stream is busy at }, 'error text';
        } $c;
      });
    })->then (sub{
      return $http->close_after_current_stream;
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
show "sleep (20)..."
sleep 21
  # WS timeout = 20
show "awake!"
ws-send-header opcode=9 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', ws => 1});
    })->then (sub {
      my $stream = $_[0]->{stream};
      return $stream->headers_received->then (sub {
        return $stream->send_ws_close;
      });
    })->then (sub{
      return $http->close_after_current_stream;
    })->then (sub {
      test {
        ok 1;
      } $c;
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'ws ping received after closed (not received)';

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
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    my $error = Web::DOM::Error->new ("Custom error");
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', ws => 1});
    })->then (sub {
      my $stream = $_[0]->{stream};
      my $closed = $stream->closed;
      return $stream->headers_received->then (sub {
        $_[0]->{messages}->cancel ($error);
        return $closed;
      })->then (sub {
        my $error = $_[0];
        test {
          is $error->name, 'WebSocket Close';
          is $error->message, '(1006 ) Custom error';
          is $error->ws_status, 1006;
          is $error->ws_reason, '';
          is $error->file_name, __FILE__;
          is $error->line_number, __LINE__-17;
        } $c;
      });
    })->then (sub{
      return $http->close_after_current_stream;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => 'ws messages cancel';

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
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    my $error = Web::DOM::Error->new ("Custom error");
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', ws => 1});
    })->then (sub {
      my $stream = $_[0]->{stream};
      my $closed = $stream->closed;
      return $stream->headers_received->then (sub {
        $stream->send_ws_close;
        $_[0]->{messages}->cancel ($error);
        return $closed;
      })->then (sub {
        my $error = $_[0];
        test {
          is $error->name, 'WebSocket Close';
          is $error->message, '(1006 ) Custom error';
          is $error->ws_status, 1006;
          is $error->ws_reason, '';
          is $error->file_name, __FILE__;
          is $error->line_number, __LINE__-18;
        } $c;
      });
    })->then (sub{
      return $http->close_after_current_stream;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => 'ws messages cancel';

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
ws-send-header opcode=1 length=3
"xyz"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    my $error = Web::DOM::Error->new ("Custom error");
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', ws => 1});
    })->then (sub {
      my $stream = $_[0]->{stream};
      my $closed = $stream->closed;
      return $stream->headers_received->then (sub {
        $stream->send_ws_close;
        my $reader = $_[0]->{messages}->get_reader;
        return $reader->read->then (sub {
          my $msg = $_[0]->{value};
          my $reader = $msg->{text_body}->get_reader;
          $reader->cancel ($error);
          return $closed;
        });
      })->then (sub {
        my $error = $_[0];
        test {
          is $error->name, 'WebSocket Close';
          is $error->message, '(1006 ) Custom error';
          is $error->ws_status, 1006;
          is $error->ws_reason, '';
          is $error->file_name, __FILE__;
          is $error->line_number, __LINE__-23;
        } $c;
      });
    })->then (sub{
      return $http->close_after_current_stream;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => 'ws messages text cancel';

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
ws-send-header opcode=2 length=3
"xyz"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    my $error = Web::DOM::Error->new ("Custom error");
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', ws => 1});
    })->then (sub {
      my $stream = $_[0]->{stream};
      my $closed = $stream->closed;
      return $stream->headers_received->then (sub {
        $stream->send_ws_close;
        my $reader = $_[0]->{messages}->get_reader;
        return $reader->read->then (sub {
          my $msg = $_[0]->{value};
          my $reader = $msg->{body}->get_reader;
          $reader->cancel ($error);
          return $closed;
        });
      })->then (sub {
        my $error = $_[0];
        test {
          is $error->name, 'WebSocket Close';
          is $error->message, '(1006 ) Custom error';
          is $error->ws_status, 1006;
          is $error->ws_reason, '';
          is $error->file_name, __FILE__;
          is $error->line_number, __LINE__-23;
        } $c;
      });
    })->then (sub{
      return $http->close_after_current_stream;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => 'ws messages binary cancel';

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
ws-send-header opcode=8
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    my $error;
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', ws => 1});
    })->then (sub {
      my $stream = $_[0]->{stream};
      my $closed = $stream->closed;
      return $stream->headers_received->then (sub {
        $stream->send_ping;
        return $stream->send_ws_message (2, 'binary')->then (sub {
          my $writer = $_[0]->{body}->get_writer;
          return promised_sleep (1)->then (sub {
            $writer->write (d "ab")->catch (sub { $error = $_[0] });
            return $closed;
          });
        });
      })->then (sub {
        my $e = $_[0];
        test {
          is $e->name, 'WebSocket Close';
          is $e->message, '(1005 ) WebSocket closed cleanly';
          is $e->ws_status, 1005;
          is $e->ws_reason, '';
          ok $e->ws_cleanly;
          is $error, undef;
        } $c;
      });
    })->then (sub{
      return $http->close_after_current_stream;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => 'ws messages write after close received';

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
ws-send-header opcode=9
show "ping sent"
ws-receive-header
ws-receive-data
show "something received"
ws-send-header opcode=8
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    my $error;
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/', ws => 1});
    })->then (sub {
      my $stream = $_[0]->{stream};
      my $closed = $stream->closed;
      return $stream->headers_received->then (sub {
        $stream->send_ping;
        return $stream->send_ws_message (2, 'binary')->then (sub {
          my $writer = $_[0]->{body}->get_writer;
          return promised_sleep (1)->then (sub {
            $writer->write (d "ab")->catch (sub { $error = $_[0] });
          });
        })->then (sub {
          return $stream->send_ws_message (3, 'binary');
        })->then (sub {
          my $writer = $_[0]->{body}->get_writer;
          $writer->write (d "123");
          return $closed;
        });
      })->then (sub {
        my $e = $_[0];
        test {
          is $e->name, 'WebSocket Close';
          is $e->message, '(1005 ) WebSocket closed cleanly';
          is $e->ws_status, 1005;
          is $e->ws_reason, '';
          ok $e->ws_cleanly;
        } $c;
      });
    })->then (sub{
      return $http->close_after_current_stream;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'ws messages write after ping received';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
receive "abc"
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'CONNECT', target => 'test'});
    })->then (sub {
      my $got = $_[0];
      test {
        isa_ok $got->{stream}, 'Web::Transport::HTTPStream::Stream';
        is $got->{body}, undef;
      } $c;
      my $stream = $got->{stream};
      return $stream->headers_received->then (sub {
        my $got = $_[0];
        test {
          isa_ok $got->{readable}, 'ReadableStream';
          isa_ok $got->{writable}, 'WritableStream';
          is $got->{body}, undef;
          is $got->{messages}, undef;
          is $got->{closing}, undef;
        } $c;
        my $writer = $got->{writable}->get_writer;
        $writer->write (d 'abc');
        $writer->close;
        return read_rbs $got->{readable};
      })->then (sub {
        my $received = $_[0];
        test {
          is $received, 'xyz';
        } $c;
      });
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 8, name => 'connect';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
receive "abc"
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'CONNECT', target => 'test', length => 12});
    })->catch (sub {
      my $error = $_[0];
      test {
        is $error->name, 'TypeError';
        is $error->message, 'Bad byte length 12';
        is $error->file_name, __FILE__;
        is $error->line_number, __LINE__-7;
        ok $http->is_active;
      } $c;
      return $http->close_after_current_stream;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'connect with content_length';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
receive "abc"
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'CONNECT', target => 'test', length => 0});
    })->catch (sub {
      my $error = $_[0];
      test {
        is $error->name, 'TypeError';
        is $error->message, 'Bad byte length 0';
        is $error->file_name, __FILE__;
        is $error->line_number, __LINE__-7;
        ok $http->is_active;
      } $c;
      return $http->close_after_current_stream;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'connect with content_length';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
receive "abc"
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'CONNECT', target => 'test'});
    })->then (sub {
      my $got = $_[0];
      my $stream = $got->{stream};
      return $stream->headers_received->then (sub {
        my $got = $_[0];
        my $writer = $got->{writable}->get_writer;
        $writer->write (d 'ab');
        $writer->write (d '');
        $writer->write (d 'c');
        $writer->close;
        return read_rbs $got->{readable};
      })->then (sub {
        my $received = $_[0];
        test {
          is $received, 'xyz';
        } $c;
      });
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'connect empty';

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
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'CONNECT', target => 'test'});
    })->then (sub {
      my $got = $_[0];
      my $stream = $got->{stream};
      return $stream->headers_received->then (sub {
        my $writer = $_[0]->{writable}->get_writer;
        $writer->close;
        return read_rbs $_[0]->{readable};
      })->then (sub {
        my $received = $_[0];
        test {
          is $received, 'xyz';
        } $c;
      });
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
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'CONNECT', target => 'test'});
    })->then (sub{
      my $got = $_[0];
      my $stream = $got->{stream};
      my $closed = $stream->closed;
      return $stream->headers_received->then (sub {
        my $got = $_[0];
        my $writer = $got->{writable}->get_writer;
        return read_rbs ($got->{readable})->then (sub {
          my $received = $_[0];
          test {
            is $received, '';
          } $c;
          $writer->write (d 'abc');
          $writer->close;
          return $closed;
        });
      });
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'connect sending after EOF';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'CONNECT', target => 'test'});
    })->then (sub{
      my $got = $_[0];
      my $stream = $got->{stream};
      my $closed = $stream->closed;
      return $stream->headers_received->then (sub {
        my $got = $_[0];
        my $writer = $got->{writable}->get_writer;
        return read_rbs ($got->{readable})->then (sub {
          my $received = $_[0];
          test {
            is $received, '';
          } $c;
          return promised_sleep 1;
        })->then (sub {
          $writer->write (d 'abc');
          Promise->resolve->then (sub { $writer->close });
          return $closed;
        });
      });
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
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request
          ({method => 'GET', target => 'test', length => 4});
    })->then (sub {
      my $got = $_[0];
      my $writer = $got->{body}->get_writer;
      $writer->write (d 'hoge');
      $writer->close;
      return $got->{stream}->headers_received;
    })->then (sub {
      my $got = $_[0];
      return read_rbs $got->{body};
    })->then (sub {
      my $received = $_[0];
      test {
        is $received, 'OK';
      } $c;
      return $http->close_after_current_stream;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'with request body';

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
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TLSStream',
      parent => {
        class => 'Web::Transport::H1CONNECTStream',
        target => 'hoge.test',
        parent => {
          parent => {
            class => 'Web::Transport::TCPStream',
            host => Web::Host->parse_string ($server->{addr}),
            port => $server->{port},
          },
        },
      },
      sni_host => Web::Host->parse_string ('hoge.test'),
      si_host => Web::Host->parse_string (Test::Certificates->cert_name),
      ca_file => Test::Certificates->ca_path ('cert.pem'),
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/test'});
    })->then (sub {
      return $_[0]->{stream}->headers_received;
    })->then (sub {
      return read_rbs $_[0]->{body};
    })->then (sub {
      my $received = $_[0];
      test {
        is $received, 'abc';
      } $c;
      return $http->close_after_current_stream;
    })->catch (sub {
      my $error = $_[0];
      test {
        ok 0, $error;
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'H1CONNECT https';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
receive "GET"
"HTTP/1.1 200 OK"CRLF
"Content-Length: 3"CRLF
CRLF
"abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::H1CONNECTStream',
      target => 'hoge.test',
      parent => {
        parent => {
          class => 'Web::Transport::TCPStream',
          host => Web::Host->parse_string ($server->{addr}),
          port => $server->{port},
        },
      },
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/test'});
    })->then (sub {
      return $_[0]->{stream}->headers_received;
    })->then (sub {
      return read_rbs $_[0]->{body};
    })->then (sub {
      my $received = $_[0];
      test {
        is $received, 'abc';
      } $c;
      return $http->close_after_current_stream;
    })->catch (sub {
      my $error = $_[0];
      test {
        ok 0, $error;
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'H1CONNECT http';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
receive "GET"
"HTTP/1.1 200 OK"CRLF
"Content-Length: 3"CRLF
CRLF
"abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::H1CONNECTStream',
      target => 'hoge.test',
      parent => {
        parent => {
          class => 'Web::Transport::H1CONNECTStream',
          target => 'hoge.test',
          parent => {
            parent => {
              class => 'Web::Transport::TCPStream',
              host => Web::Host->parse_string ($server->{addr}),
              port => $server->{port},
            },
          },
        },
      },
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/test'});
    })->then (sub {
      return $_[0]->{stream}->headers_received;
    })->then (sub {
      return read_rbs $_[0]->{body};
    })->then (sub {
      my $received = $_[0];
      test {
        is $received, 'abc';
      } $c;
      return $http->close_after_current_stream;
    })->catch (sub {
      my $error = $_[0];
      test {
        ok 0, $error;
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'H1CONNECT over H1CONNECT http';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 300 OK"CRLF
CRLF
receive "GET"
"HTTP/1.1 200 OK"CRLF
"Content-Length: 3"CRLF
CRLF
"abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::H1CONNECTStream',
      target => 'hoge.test',
      parent => {
        parent => {
          class => 'Web::Transport::TCPStream',
          host => Web::Host->parse_string ($server->{addr}),
          port => $server->{port},
        },
      },
    }});
    $http->ready->catch (sub {
      my $error = $_[0];
      test {
        is $error->name, 'HTTP parse error', $error;
        is $error->message, 'HTTP |300| response';
        # XXXlocation
      } $c;
      return $http->closed->then (sub {
        my $e = $_[0];
        test {
          is $e, undef;
        } $c;
      });
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 3, name => 'H1CONNECT http non-200 response to CONNECT';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
receive "CONNECT"
"HTTP/1.1 300 OK"CRLF
CRLF
"abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::H1CONNECTStream',
      target => 'hoge.test',
      parent => {
        parent => {
          class => 'Web::Transport::H1CONNECTStream',
          target => 'hoge.test',
          parent => {
            parent => {
              class => 'Web::Transport::TCPStream',
              host => Web::Host->parse_string ($server->{addr}),
              port => $server->{port},
            },
          },
        },
      },
    }});
    $http->ready->catch (sub {
      my $error = $_[0];
      test {
        is $error->name, 'HTTP parse error', $error;
        is $error->message, 'HTTP |300| response';
        # XXXlocation
      } $c;
      return $http->closed->then (sub {
        my $e = $_[0];
        test {
          is $e, undef;
        } $c;
      });
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 3, name => 'H1CONNECT over H1CONNECT http non-200';

test {
  my $c = shift;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TLSStream',
      parent => {
        class => 'Web::Transport::H1CONNECTStream',
        target => 'hoge.test',
        parent => {
          parent => {
            class => 'Web::Transport::TCPStream',
            host => Web::Host->parse_string ('127.0.53.53'),
            port => int rand,
          },
        },
      },
      sni_host => Web::Host->parse_string ('hoge.test'),
      si_host => Web::Host->parse_string (Test::Certificates->cert_name),
      ca_file => Test::Certificates->ca_path ('cert.pem'),
    }});
  $http->ready->catch (sub {
    my $error = $_[0];
    test {
      is $error->name, 'Protocol error', $error;
      is $error->message, 'ICANN_NAME_COLLISION';
      is $error->file_name, __FILE__;
      is $error->line_number, __LINE__-23;
    } $c;
    return $http->closed->then (sub {
      my $e = $_[0];
      test {
        is $e, undef;
      } $c;
    });
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 5, name => 'H1CONNECT https bad TCP host';

test {
  my $c = shift;
  my $http = Web::Transport::HTTPStream->new ({parent => {
    class => 'Web::Transport::H1CONNECTStream',
    parent => {
      parent => {
        class => 'Web::Transport::TCPStream',
        host => Web::Host->parse_string ('127.0.53.53'),
        port => int rand,
      },
    },
    target => 'hoge.test',
  }});
  $http->ready->catch (sub {
    my $error = $_[0];
    test {
      is $error->name, 'Protocol error', $error;
      is $error->message, 'ICANN_NAME_COLLISION';
      is $error->file_name, __FILE__;
      is $error->line_number, __LINE__-17;
    } $c;
    return $http->closed->then (sub {
      my $e = $_[0];
      test {
        is $e, undef;
      } $c;
    });
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 5, name => 'H1CONNECT http bad TCP host';

test {
  my $c = shift;
  my $http = Web::Transport::HTTPStream->new ({parent => {
    class => 'Web::Transport::H1CONNECTStream',
    parent => {
      parent => {
        class => 'Web::Transport::TCPStream',
        host => Web::Host->parse_string ('127.0.51.54'),
        port => int rand,
      },
    },
    target => 'hoge.test',
  }});
  $http->ready->catch (sub {
    my $error = $_[0];
    test {
      is $error->name, 'Perl I/O error', $error;
      ok $error->message;
      #is $error->file_name, __FILE__; # XXXlocation
      #is $error->line_number, __LINE__-17;
    } $c;
    return $http->closed->then (sub {
      my $e = $_[0];
      test {
        is $e, undef;
      } $c;
    });
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 3, name => 'H1CONNECT http bad TCP host';

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
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::UnixStream',
      path => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      return $_[0]->{stream}->headers_received;
    })->then (sub {
      return read_rbs $_[0]->{body};
    })->then (sub {
      my $received = $_[0];
      test {
        is $received, 'xyz';
      } $c;
      return $http->close_after_current_stream;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'UNIX domain socket';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 203 ok"CRLF
    "X-hoge: Foo bar"CRLF
    "content-length: 3"CRLF
    CRLF
    "abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $stream = $_[0]->{stream};
      $http->close_after_current_stream;
      return $stream->headers_received;
    })->then (sub {
      my $got = $_[0];
      test {
        is $got->{failed}, undef;
        is $got->{message}, undef;
        isa_ok $got->{body}, 'ReadableStream';
        is $got->{messages}, undef;
        is $got->{version}, '1.1';
        is $got->{status}, 203;
        is $got->{status_text}, 'ok';
        is $got->{headers}->[0]->[0], 'X-hoge';
        is $got->{headers}->[0]->[1], 'Foo bar';
        ok ! $got->{incomplete};
      } $c;
      return read_rbs ($got->{body})->then (sub {
        my $bytes = $_[0];
        test {
          is $bytes, "abc";
          ok ! $got->{incomplete};
        } $c;
      });
    })->then (sub{
      test {
        ok ! $http->is_active;
      } $c;
      return $http->closed;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 13, name => 'close_after_current_stream after send_request';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 203 ok"CRLF
    "X-hoge: Foo bar"CRLF
    "content-length: 3"CRLF
    CRLF
    "abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $stream = $_[0]->{stream};
      return $stream->headers_received;
    })->then (sub {
      my $got = $_[0];
      test {
        is $got->{failed}, undef;
        is $got->{message}, undef;
        isa_ok $got->{body}, 'ReadableStream';
        is $got->{messages}, undef;
        is $got->{version}, '1.1';
        is $got->{status}, 203;
        is $got->{status_text}, 'ok';
        is $got->{headers}->[0]->[0], 'X-hoge';
        is $got->{headers}->[0]->[1], 'Foo bar';
        ok ! $got->{incomplete};
      } $c;
      $http->close_after_current_stream;
      return read_rbs ($got->{body})->then (sub {
        my $bytes = $_[0];
        test {
          is $bytes, "abc";
          ok ! $got->{incomplete};
        } $c;
      });
    })->then (sub{
      test {
        ok ! $http->is_active;
      } $c;
      return $http->closed;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 13, name => 'close_after_current_stream after headers_received';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 203 ok"CRLF
    "X-hoge: Foo bar"CRLF
    "content-length: 3"CRLF
    CRLF
    "abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->close_after_current_stream;
    })->then (sub{
      test {
        ok ! $http->is_active;
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'close_after_current_stream before request';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 203 ok"CRLF
    "X-hoge: Foo bar"CRLF
    "content-length: 3"CRLF
    CRLF
    "abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $stream = $_[0]->{stream};
      $http->close_after_current_stream;
      return $stream->headers_received;
    })->then (sub {
      my $got = $_[0];
      $http->close_after_current_stream;
      test {
        is $got->{failed}, undef;
        is $got->{message}, undef;
        isa_ok $got->{body}, 'ReadableStream';
        is $got->{messages}, undef;
        is $got->{version}, '1.1';
        is $got->{status}, 203;
        is $got->{status_text}, 'ok';
        is $got->{headers}->[0]->[0], 'X-hoge';
        is $got->{headers}->[0]->[1], 'Foo bar';
        ok ! $got->{incomplete};
      } $c;
      return read_rbs ($got->{body})->then (sub {
        my $bytes = $_[0];
        test {
          is $bytes, "abc";
          ok ! $got->{incomplete};
        } $c;
      });
    })->then (sub{
      test {
        ok ! $http->is_active;
      } $c;
      return $http->close_after_current_stream;
    })->then (sub {
      return $http->closed;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 13, name => 'close_after_current_stream duplicate invocations';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
receive "abc"
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'CONNECT', target => 'test'});
    })->then (sub {
      my $got = $_[0];
      my $stream = $got->{stream};
      return $stream->headers_received->then (sub {
        my $got = $_[0];
        my $writer = $got->{writable}->get_writer;
        $http->close_after_current_stream;
        $writer->write (d 'abc');
        $writer->close;
        return read_rbs $got->{readable};
      })->then (sub {
        my $received = $_[0];
        test {
          is $received, 'xyz';
        } $c;
      });
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'close_after_current_stream connect';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET"
"HTTP/1.1 200 OK"CRLF
CRLF
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = Web::Transport::HTTPStream->new ({parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ($server->{addr}),
      port => $server->{port},
    }});
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => 'test', length => 3});
    })->then (sub {
      my $got = $_[0];
      my $stream = $got->{stream};
      my $writer = $got->{body}->get_writer;
      my $error;
      return $stream->headers_received->then (sub {
        my $got = $_[0];
        $stream->send_response ({}, content_length => 0)->catch (sub {
          $error = $_[0];
          $writer->write (d 'abc');
          $writer->close;
          return read_rbs $got->{body};
        });
      })->then (sub {
        my $received = $_[0];
        test {
          is $received, 'xyz';
          is $error->name, 'TypeError';
          is $error->message, 'Response is not allowed';
          is $error->file_name, __FILE__;
          is $error->line_number, __LINE__-8;
        } $c;
      });
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'send_response';

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
    $http->ready;
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $stream = $_[0]->{stream};
      $closed = $stream->closed;
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
        isa_ok $got->{body}, 'ReadableStream';
        is $got->{messages}, undef;
        is $got->{version}, '1.1';
        is $got->{status}, 203;
        is $got->{status_text}, 'ok';
        is $got->{headers}->[0]->[0], 'X-hoge';
        is $got->{headers}->[0]->[1], 'Foo bar';
        ok ! $got->{incomplete};
        ok ! $closed_fulfilled;
        ok ! $closed_rejected;
      } $c;
      return read_rbs ($got->{body})->then (sub {
        my $bytes = $_[0];
        test {
          is $bytes, "abc";
          ok ! $got->{incomplete};
        } $c;
      });
    })->then (sub{
      return $closed;
    })->then (sub {
      return $http->close_after_current_stream;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 15, name => 'ready promise';

test {
  my $c = shift;
  my $http = Web::Transport::HTTPStream->new ({parent => {
    class => 'Web::Transport::TCPStream',
  }});
  $http->ready->then (sub {
    test {
      ok 0;
    } $c;
  }, sub {
    my $error = $_[0];
    test {
      ok $error;
    } $c;
    return $http->closed;
  })->then (sub {
    test {
      ok 1;
    } $c;
    done $c;
    undef $c;
  });
} n => 2, name => 'ready promise';

test {
  my $c = shift;
  my $http = Web::Transport::HTTPStream->new ({parent => {
    class => 'Web::Transport::TCPStream',
  }});
  $http->close_after_current_stream->then (sub {
    test {
      ok 0;
    } $c;
  }, sub {
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
} n => 4, name => 'close_after_current_stream when no connection';

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

    my $ss = $http->streams;
    test {
      isa_ok $ss, 'ReadableStream';
    } $c;

    return $http->ready->then (sub {
      return $http->close_after_current_stream;
    })->then (sub {
      my $reader = $ss->get_reader;
      return $reader->read->then (sub {
        my $v = $_[0];
        test {
          ok $v->{done};
        } $c;
        return $reader->closed;
      });
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'streams readable stream';

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

    my $ss = $http->streams;
    my $reason = {};

    return $http->ready->then (sub {
      return $ss->cancel ($reason);
    })->then (sub {
      return $http->closed;
    })->then (sub {
      test {
        ok 1;
      } $c;
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'streams readable stream cancel';

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
    my $reason = Web::DOM::Error->new;
    $http->ready->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $stream = $_[0]->{stream};
      return $stream->headers_received;
    })->then (sub {
      my $got = $_[0];
      test {
        is $got->{status}, 203;
        rsread $got->{body};
      } $c;
      return $http->abort ($reason);
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'abort';

Test::Certificates->wait_create_cert;
run_tests;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
