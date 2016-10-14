use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use AnyEvent;
use Promised::Flow;
use Test::X1;
use Test::More;
use AnyEvent::Socket;
use Web::URL;
use Web::Transport::ConnectionClient;
use Web::Transport::WSClient;
use Web::Transport::PSGIServerConnection;

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

sub server ($$;$%) {
  my $app = shift;
  my $cb = shift;
  my $onerror = shift;
  my %args = @_;
  return Promise->new (sub {
    my ($ok, $ng) = @_;
    my $cv = AE::cv;
    $cv->begin;
    my $host = '127.0.0.1';
    my $port = find_listenable_port;
    my $con;
    my $server = tcp_server $host, $port, sub {
      $cv->begin;
      $con = Web::Transport::PSGIServerConnection->new_from_app_and_ae_tcp_server_args ($app, @_);
      $con->onerror ($onerror) if defined $onerror;
      if (exists $args{max}) {
        $con->max_request_body_length ($args{max});
      }
      promised_cleanup { $cv->end } $con->closed;
    };
    $cv->cb ($ok);
    my $origin = Web::URL->parse_string ("http://$host:$port");
    my $close = sub { undef $server; $cv->end };
    $cb->($origin, $close, \$con);
  });
} # server

my $UnixParentPath = path (__FILE__)->parent->parent->child
    ('local/test/')->absolute;
$UnixParentPath->mkpath;

sub unix_server ($$;$) {
  my $app = shift;
  my $cb = shift;
  my $onerror = shift;
  return Promise->new (sub {
    my ($ok, $ng) = @_;
    my $cv = AE::cv;
    $cv->begin;
    my $unix_path = $UnixParentPath->child (rand);
    my $server = tcp_server 'unix/', $unix_path, sub {
      $cv->begin;
      my $con = Web::Transport::PSGIServerConnection->new_from_app_and_ae_tcp_server_args ($app, @_);
      $con->onerror ($onerror) if defined $onerror;
      promised_cleanup { $cv->end } $con->closed;
    };
    $cv->cb ($ok);
    my $close = sub { undef $server; $cv->end };
    $cb->($unix_path, $close);
  });
} # unix_server

test {
  my $c = shift;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    my $env = $_[0];
    return [200, ['Hoge', 'foo'], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 200;
        is $res->header ('Hoge'), 'foo';
        is $res->body_bytes, "200!";
      } $c;
    });
  });
} n => 3, name => 'normal non-streamed response';

test {
  my $c = shift;
  my $n = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    my $env = $_[0];
    return [200, ['Hoge', 'foo'], [++$n]];
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 200;
        is $res->header ('Hoge'), 'foo';
        is $res->body_bytes, "1";
      } $c;
      return $client->request (url => $origin);
    })->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 200;
        is $res->header ('Hoge'), 'foo';
        is $res->body_bytes, "2";
      } $c;
    });
  });
} n => 6, name => 'normal non-streamed responses';

test {
  my $c = shift;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    my $env = $_[0];
    return sub {
      my $c = $_[0];
      $c->([209, ['Hoge', 'foo'], ['200', '!']]);
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 209;
        is $res->header ('Hoge'), 'foo';
        is $res->body_bytes, "200!";
      } $c;
    });
  });
} n => 3, name => 'code response';

test {
  my $c = shift;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    my $env = $_[0];
    return sub {
      my $c = $_[0];
      $c->([204, ['Hoge', 'foo'], ['200', '!']]);
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 204;
        is $res->header ('Hoge'), 'foo';
        is $res->body_bytes, "";
      } $c;
    });
  });
} n => 3, name => '204 response';

test {
  my $c = shift;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    my $env = $_[0];
    return sub {
      my $c = $_[0];
      $c->([205, ['Hoge', 'foo'], ['200', '!']]);
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 205;
        is $res->header ('Hoge'), 'foo';
        is $res->body_bytes, "";
      } $c;
    });
  });
} n => 3, name => '205 response';

test {
  my $c = shift;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    my $env = $_[0];
    return [304, ['Hoge', 'foo'], ['200', '!']];
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 304;
        is $res->header ('Hoge'), 'foo';
        is $res->body_bytes, "";
      } $c;
    });
  });
} n => 3, name => '304 response';

test {
  my $c = shift;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    my $env = $_[0];
    return [403, ['Hoge', 'foo'], ['200', '!']];
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin, method => 'HEAD')->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 403;
        is $res->header ('Hoge'), 'foo';
        is $res->body_bytes, "";
      } $c;
    });
  });
} n => 3, name => 'HEAD response';

test {
  my $c = shift;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    my $env = $_[0];
    return [403, ['Hoge', 'foo'], []];
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin, method => 'HEAD')->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 403;
        is $res->header ('Hoge'), 'foo';
        is $res->body_bytes, "";
      } $c;
    });
  });
} n => 3, name => 'HEAD response';

test {
  my $c = shift;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    my $env = $_[0];
    return sub {
      my $c = shift;
      my $writer = $c->([200, ['Hoge', 'foo']]);
      AE::postpone {
        $writer->write ('abc');
      };
      AE::postpone {
        $writer->write ('xyz');
      };
      AE::postpone {
        $writer->close;
      };
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 200;
        is $res->header ('Hoge'), 'foo';
        is $res->body_bytes, "abcxyz";
      } $c;
    });
  });
} n => 3, name => 'stream response';

test {
  my $c = shift;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    my $env = $_[0];
    return sub {
      my $c = shift;
      my $writer = $c->([200, ['Hoge', 'foo']]);
      AE::postpone {
        $writer->close;
      };
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 200;
        is $res->header ('Hoge'), 'foo';
        is $res->body_bytes, "";
      } $c;
    });
  });
} n => 3, name => 'stream response';

test {
  my $c = shift;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    die "Thrown by app";
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->status_text, 'Internal Server Error';
        is $res->header ('Content-Type'), 'text/plain; charset=utf-8';
        is $res->body_bytes, "500";
      } $c;
    });
  });
} n => 4, name => 'app throws, no onerror';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    die "Thrown by app";
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->status_text, 'Internal Server Error';
        is $res->header ('Content-Type'), 'text/plain; charset=utf-8';
        is $res->body_bytes, "500";
        is $error_invoked, 1;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{Thrown by app at \Q@{[__FILE__]}\E line @{[__LINE__-20]}};
    } $c;
  });
} n => 6, name => 'app throws';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return undef;
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->status_text, 'Internal Server Error';
        is $res->header ('Content-Type'), 'text/plain; charset=utf-8';
        is $res->body_bytes, "500";
        is $error_invoked, 1;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{PSGI application did not return a response};
    } $c;
  });
} n => 6, name => 'app returns bad value';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return [];
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->status_text, 'Internal Server Error';
        is $res->header ('Content-Type'), 'text/plain; charset=utf-8';
        is $res->body_bytes, "500";
        is $error_invoked, 1;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{PSGI application did not return a response};
    } $c;
  });
} n => 6, name => 'app returns bad value';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return [200, []];
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->status_text, 'Internal Server Error';
        is $res->header ('Content-Type'), 'text/plain; charset=utf-8';
        is $res->body_bytes, "500";
        is $error_invoked, 1;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{PSGI application did not return a response};
    } $c;
  });
} n => 6, name => 'app returns bad value';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return [200, [], [], "abc"];
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->status_text, 'Internal Server Error';
        is $res->header ('Content-Type'), 'text/plain; charset=utf-8';
        is $res->body_bytes, "500";
        is $error_invoked, 1;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{PSGI application did not return a response};
    } $c;
  });
} n => 6, name => 'app returns bad value';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return [40, [], ["abv"]];
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 40;
        is $res->body_bytes, "abv";
        is $error_invoked, 0;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      ok 0;
    } $c;
  });
} n => 3, name => 'Bad status code';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      $_[0]->([40, [], ["abv"]]);
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 40;
        is $res->body_bytes, "abv";
        is $error_invoked, 0;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      ok 0;
    } $c;
  });
} n => 3, name => 'Bad status code';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return [101, [], ["abv"]];
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, "500";
        is $error_invoked, 1;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{PSGI application specified a bad status \|101\|};
    } $c;
  });
} n => 4, name => 'Bad status code';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      $_[0]->([101, [], ["abv"]]);
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, "500";
        is $error_invoked, 1;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{PSGI application specified a bad status \|101\|};
    } $c;
  });
} n => 4, name => 'Bad status code';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      $_[0]->(["abc", [], ["abv"]]);
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 0;
        is $res->body_bytes, "abv";
        is $error_invoked, 0;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      ok 0;
    } $c;
  });
} n => 3, name => 'Bad status code';

for my $headers (
  undef,
  ["Hoge"],
  {},
  "abcd",
  ["Foo", "bar", "abc"],
) {
test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return [201, $headers, ["abv"]];
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, "500";
        is $error_invoked, 1;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{PSGI application specified bad headers};
    } $c;
  });
} n => 4, name => 'Bad headers';
test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      $_[0]->([201, $headers, ["abv"]]);
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, "500";
        is $error_invoked, 1;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{PSGI application specified bad headers};
    } $c;
  });
} n => 4, name => 'Bad headers';}

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      $_[0]->([320, ["", "aa"], ["abv"]]);
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, "500";
        is $error_invoked, 1;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{Bad header name \|\|};
    } $c;
  });
} n => 4, name => 'Bad header name';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return [320, ["\x{504}", "aa"], ["abv"]];
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, "500";
        is $error_invoked, 1;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{Bad header name \|\\x504\|};
    } $c;
  });
} n => 4, name => 'Bad header name';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      $_[0]->([320, ["\x{504}", "aa"], ["abv"]]);
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, "500";
        is $error_invoked, 1;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{Bad header name \|\\x504\|};
    } $c;
  });
} n => 4, name => 'Bad header name';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      $_[0]->([320, ["a", "\x{504}"], ["abv"]]);
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, "500";
        is $error_invoked, 1;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{Bad header value \|a: \\x504\|};
    } $c;
  });
} n => 4, name => 'Bad header value';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      $_[0]->([320, ["a", "\x0A"], ["abv"]]);
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, "500";
        is $error_invoked, 1;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{Bad header value \|a: \\x0A\|};
    } $c;
  });
} n => 4, name => 'Bad header value';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return [320, ["a", "\x0A"], ["abv"]];
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, "500";
        is $error_invoked, 1;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{Bad header value \|a: \\x0A\|};
    } $c;
  });
} n => 4, name => 'Bad header value';

{
  sub pp ($) {
    return bless $_[0], 'proxymanager';
  } # pp

  package proxymanager;
  use Promise;

  sub get_proxies_for_url ($$) {
    for (@{$_[0]}) {
      if (defined $_->{host} and not ref $_->{host}) {
        $_->{host} = Web::Host->parse_string ($_->{host});
      }
    }
    return Promise->resolve ($_[0]);
  } # get_proxies_for_url
}

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return [200, [], ["abv"]];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string ("https://" . $origin->hostport);
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->proxy_manager (pp [{protocol => 'http',
                                 host => $origin->host,
                                 port => $origin->port}]);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        is $error_invoked, 0;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      ok 0;
    } $c;
  });
} n => 2, name => 'CONNECT request';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return [200, [], ["abv"]];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string ("ws://" . $origin->hostport);
    promised_cleanup {
      $close->();
    } Web::Transport::WSClient->new (
      url => $url,
      cb => sub {
        test {
          ok 0;
        } $c;
      },
    )->then (sub {
      my $result = $_[0];
      test {
        is $result->status, 200;
        like ''.$result, qr{^WS handshake error: 200};
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      ok 0;
    } $c;
  });
} n => 2, name => 'WS request';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return [101, [], ["abv"]];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string ("ws://" . $origin->hostport);
    promised_cleanup {
      $close->();
    } Web::Transport::WSClient->new (
      url => $url,
      cb => sub {
        test {
          ok 0;
        } $c;
      },
    )->then (sub {
      my $result = $_[0];
      test {
        is $result->status, 500;
        like ''.$result, qr{^WS handshake error: 500};
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{PSGI application specified a bad status \|101\|};
    } $c;
  });
} n => 3, name => 'WS request';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return [320, [], ["abv\x{5000}"]];
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        is $res->network_error_message, 'Connection closed without response';
        is $error_invoked, 1;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{Data is utf8-flagged}, $error;
    } $c;
  });
} n => 4, name => 'Bad body';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      $_[0]->([320, [], ["abv\x{5000}"]]);
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        is $res->network_error_message, 'Connection closed without response';
        is $error_invoked, 1;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{Data is utf8-flagged}, $error;
    } $c;
  });
} n => 4, name => 'Bad body';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return [320, [], "abc"];
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, "500";
        is $error_invoked, 1;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{PSGI application specified bad response body}, $error;
    } $c;
  });
} n => 4, name => 'Bad body';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      $_[0]->([320, [], "abc"]);
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, "500";
        is $error_invoked, 1;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{PSGI application specified bad response body at \Q@{[__FILE__]}\E line @{[__LINE__-19]}}, $error;
    } $c;
  });
} n => 4, name => 'Bad body';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      die "Thrown!";
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, "500";
        is $error_invoked, 2;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{: Thrown! at \Q@{[__FILE__]}\E line @{[__LINE__-19]}|PSGI application did not invoke the responder}, $error;
    } $c;
  });
} n => 5, name => 'Response callback throws';

test {
  my $c = shift;
  my $error_invoked = 0;
  my $hoge = {};
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      die $hoge;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, "500";
        is $error_invoked, 2;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      if (ref $error) {
        ok ref $hoge;
        is $error, $hoge;
      }
    } $c;
  });
} n => 5, name => 'Response callback throws';

test {
  my $c = shift;
  my $error_invoked = 0;
  my $after_thrown = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      my $responder = $_[0];
      $responder->();
      $after_thrown++;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, "500";
        is $error_invoked, 1;
        is $after_thrown, 0;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{: PSGI application did not call the responder with a response at \Q@{[__FILE__]}\E line @{[__LINE__-21]}}, $error;
    } $c;
  });
} n => 5, name => 'Responder bad args';

test {
  my $c = shift;
  my $error_invoked = 0;
  my $after_thrown = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      my $responder = $_[0];
      $responder->([200]);
      $after_thrown++;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, "500";
        is $error_invoked, 1;
        is $after_thrown, 0;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{: PSGI application did not call the responder with a response at \Q@{[__FILE__]}\E line @{[__LINE__-21]}}, $error;
    } $c;
  });
} n => 5, name => 'Responder bad args';

test {
  my $c = shift;
  my $error_invoked = 0;
  my $after_thrown = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      my $responder = $_[0];
      $responder->([200, [], [], 1]);
      $after_thrown++;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, "500";
        is $error_invoked, 1;
        is $after_thrown, 0;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{: PSGI application did not call the responder with a response at \Q@{[__FILE__]}\E line @{[__LINE__-21]}}, $error;
    } $c;
  });
} n => 5, name => 'Responder bad args';

test {
  my $c = shift;
  my $error_invoked = 0;
  my $after_thrown = 0;
  my $return = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      my $responder = $_[0];
      $return = $responder->([200, [], []]);
      $after_thrown++;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 200;
        is $res->body_bytes, "";
        is $return, undef;
        is $error_invoked, 0;
        is $after_thrown, 1;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      ok 0;
    } $c;
  });
} n => 5, name => 'Responder return';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      my $responder = $_[0];
      my $return = $responder->([200, ['Foo', 5]]);
      $return->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 200;
        is $res->header ('Foo'), '5';
        is $res->body_bytes, "";
        is $error_invoked, 0;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      ok 0;
    } $c;
  });
} n => 4, name => 'Writer';

test {
  my $c = shift;
  my $error_invoked = 0;
  my $after_thrown = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      my $responder = $_[0];
      my $return = $responder->([200, ['Foo', 5]]);
      $return->write ("a");
      $return->write ("\x{5000}");
      $after_thrown++;
      $return->close;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        is $res->network_error_message, 'Connection closed without response';
        is $error_invoked, 1;
        is $after_thrown, 0;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{Data is utf8-flagged at \Q@{[__FILE__]}\E line @{[__LINE__-22]}}, $error;
    } $c;
  });
} n => 5, name => 'Writer';

test {
  my $c = shift;
  my $error_invoked = 0;
  my $after_thrown = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      my $responder = $_[0];
      my $return = $responder->([200, ['Foo', 5]]);
      $return->write ("a");
      $return->close;
      $return->write ("b");
      $after_thrown++;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 200;
        is $res->body_bytes, "a";
        is $error_invoked, 1;
        is $after_thrown, 0;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{Not writable for now at \Q@{[__FILE__]}\E line @{[__LINE__-21]}}, $error;
    } $c;
  });
} n => 5, name => 'Writer';

test {
  my $c = shift;
  my $error_invoked = 0;
  my $after_thrown = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      my $responder = $_[0];
      my $return = $responder->([200, ['Foo', 5]]);
      $return->write ("a");
      $return->close;
      $return->close;
      $after_thrown++;
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 200;
        is $res->body_bytes, "a";
        is $error_invoked, 0;
        is $after_thrown, 1;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      ok 0, $error;
    } $c;
  });
} n => 4, name => 'Writer';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      my $responder = $_[0];
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 500;
        is $res->body_bytes, "500";
        is $error_invoked, 1;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      like $error, qr{PSGI application did not invoke the responder};
    } $c;
  });
} n => 4, name => 'Responder not called';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      my $responder = $_[0];
      my $return = $responder->([200, ['Foo', 5]]);
      $return->write ("a");
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        is $res->network_error_message, 'Connection closed without response';
        is $error_invoked, 0;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      ok 0, $error;
    } $c;
  });
} n => 3, name => 'Writer no close';

test {
  my $c = shift;
  my $error_invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    return sub {
      my $responder = $_[0];
      my $return = $responder->([200, ['Foo', 5]]);
      AE::postpone { $return->write ("a") };
      AE::postpone { undef $return };
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        is $res->network_error_message, 'Connection closed without response';
        is $error_invoked, 0;
      } $c;
    });
  }, sub {
    my $error = $_[1];
    test {
      $error_invoked++;
      ok 0, $error;
    } $c;
  });
} n => 3, name => 'Writer no close';

test {
  my $c = shift;
  my $error_invoked = 0;
  my $envs = {};
  my $origin;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    my $env = $_[0];
    $envs = {%$env};
    return [200, [], []];
  }, sub {
    my $close;
    ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin);
  })->then (sub {
    test {
      is $envs->{SERVER_PROTOCOL}, 'HTTP/1.1';
      is $envs->{REMOTE_ADDR}, '127.0.0.1';
      is $envs->{REMOTE_HOST}, undef;
      is $envs->{CONTENT_LENGTH}, '0';
      is $envs->{REQUEST_METHOD}, 'GET';
      is $envs->{SERVER_NAME}, $origin->host->to_ascii;
      is $envs->{SERVER_PORT}, $origin->port;
      is $envs->{SCRIPT_NAME}, '';
      is $envs->{PATH_INFO}, '/';
      is $envs->{REQUEST_URI}, '/';
      is $envs->{QUERY_STRING}, undef;
      is $envs->{'psgi.url_scheme'}, 'http';
      is $envs->{HTTPS}, undef;
      is $envs->{HTTP_HOST}, $origin->hostport;
      is $envs->{CONTENT_TYPE}, undef;
    } $c;
  });
} n => 15, name => 'env';

test {
  my $c = shift;
  my $error_invoked = 0;
  my $envs = {};
  my $origin;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    my $env = $_[0];
    $envs = {%$env};
    return [200, [], []];
  }, sub {
    my $close;
    ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => Web::URL->parse_string (q</hoge/fu%2Fga?ab%23%4acd>, $origin), headers => {
      hoge => ['foo', 'bar'],
    }, method => 'PUT', body => "abcde");
  })->then (sub {
    test {
      is $envs->{SERVER_PROTOCOL}, 'HTTP/1.1';
      is $envs->{REMOTE_ADDR}, '127.0.0.1';
      is $envs->{REMOTE_HOST}, undef;
      is $envs->{CONTENT_LENGTH}, '5';
      is $envs->{REQUEST_METHOD}, 'PUT';
      is $envs->{SERVER_NAME}, $origin->host->to_ascii;
      is $envs->{SERVER_PORT}, $origin->port;
      is $envs->{SCRIPT_NAME}, '';
      is $envs->{PATH_INFO}, '/hoge/fu/ga';
      is $envs->{REQUEST_URI}, '/hoge/fu%2Fga?ab%23%4acd';
      is $envs->{QUERY_STRING}, 'ab%23%4acd';
      is $envs->{'psgi.url_scheme'}, 'http';
      is $envs->{HTTPS}, undef;
      is $envs->{HTTP_HOST}, $origin->hostport;
      is $envs->{CONTENT_TYPE}, undef;
      is $envs->{HTTP_HOGE}, 'foo, bar';
    } $c;
  });
} n => 16, name => 'env';

test {
  my $c = shift;
  my $error_invoked = 0;
  my $envs = {};
  my $url;
  my $unix_path;
  promised_cleanup { done $c; undef $c } unix_server (sub ($) {
    my $env = $_[0];
    $envs = {%$env};
    return [200, [], []];
  }, sub {
    my $close;
    ($unix_path, $close) = @_;
    $url = Web::URL->parse_string ('http://foo/hoge/fu%2Fga?ab%23%4acd');
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->proxy_manager (pp [{protocol => 'unix', path => $unix_path}]);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $url, headers => {
      hoge => ['foo', 'bar'],
    }, method => 'PUT', body => "abcde");
  })->then (sub {
    test {
      is $envs->{SERVER_PROTOCOL}, 'HTTP/1.1';
      is $envs->{REMOTE_ADDR}, '127.0.0.1';
      is $envs->{REMOTE_HOST}, undef;
      is $envs->{CONTENT_LENGTH}, '5';
      is $envs->{REQUEST_METHOD}, 'PUT';
      is $envs->{SERVER_NAME}, '127.0.0.1';
      is $envs->{SERVER_PORT}, '0';
      is $envs->{SCRIPT_NAME}, '';
      is $envs->{PATH_INFO}, '/hoge/fu/ga';
      is $envs->{REQUEST_URI}, '/hoge/fu%2Fga?ab%23%4acd';
      is $envs->{QUERY_STRING}, 'ab%23%4acd';
      is $envs->{'psgi.url_scheme'}, 'http';
      is $envs->{HTTPS}, undef;
      is $envs->{HTTP_HOST}, $url->hostport;
      is $envs->{CONTENT_TYPE}, undef;
      is $envs->{HTTP_HOGE}, 'foo, bar';
    } $c;
  });
} n => 16, name => 'env UNIX';

test {
  my $c = shift;
  my $invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    my $env = $_[0];
    $invoked++;
    return [200, [], []];
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin, body => "abcde")->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 413;
        is $res->status_text, 'Payload Too Large';
        is $res->body_bytes, '413';
      } $c;
    });
  }, undef, max => 4)->then (sub {
    test {
      is $invoked, 0;
    } $c;
  });
} n => 4, name => 'max_request_body_length';

test {
  my $c = shift;
  my $invoked = 0;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    my $env = $_[0];
    $invoked++;
    return sub {
      my $w = $_[0]->([200, []]);
      $w->write ("abcdeF");
    };
  }, sub {
    my ($origin, $close) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $client->close->then ($close);
    } $client->request (url => $origin)->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        is $res->network_error_message, 'Connection closed without response';
      } $c;
    });
  }, undef, max => 0)->then (sub {
    test {
      is $invoked, 1;
    } $c;
  });
} n => 3, name => 'max_request_body_length';

test {
  my $c = shift;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    my $env = $_[0];
    return sub {
      my $w = $_[0]->([200, [], []]);
    };
  }, sub {
    my ($origin, $close, $conref) = @_;
    my @event;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $close->();
      undef $conref;
    } $client->request (url => $origin)->then (sub {
      return $client->close;
    })->then (sub {
      return Promise->all ([
        $$conref->closed->then (sub {
          push @event, 'closed';
        }),
        $$conref->completed->then (sub {
          push @event, 'completed';
        }),
      ]);
    })->then (sub {
      test {
        is join (',', @event), 'closed,completed';
      } $c;
    });
  });
} n => 1, name => 'closed / completed';

test {
  my $c = shift;
  my @event;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    my $env = $_[0];
    return sub {
      my $w = $_[0]->([200, []]);
      AE::postpone {
        $w->close;
        push @event, 'writerclose';
      };
    };
  }, sub {
    my ($origin, $close, $conref) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $close->();
      undef $conref;
    } $client->request (url => $origin)->then (sub {
      return $client->close;
    })->then (sub {
      return Promise->all ([
        $$conref->closed->then (sub {
          push @event, 'closed';
        }),
        $$conref->completed->then (sub {
          push @event, 'completed';
        }),
      ]);
    })->then (sub {
      test {
        is join (',', @event), 'writerclose,closed,completed';
      } $c;
    });
  });
} n => 1, name => 'closed / completed';

test {
  my $c = shift;
  my @event;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    my $env = $_[0];
    return 0;
  }, sub {
    my ($origin, $close, $conref) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $close->();
      undef $conref;
    } $client->request (url => $origin)->then (sub {
      return $client->close;
    })->then (sub {
      return Promise->all ([
        $$conref->closed->then (sub {
          push @event, 'closed';
        }),
        $$conref->completed->then (sub {
          push @event, 'completed';
        }),
      ]);
    })->then (sub {
      test {
        is join (',', @event), 'error,closed,completed';
      } $c;
    });
  }, sub {
    push @event, 'error';
  });
} n => 1, name => 'closed / completed - onerror invoked';

test {
  my $c = shift;
  my @event;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    my $env = $_[0];
    return 0;
  }, sub {
    my ($origin, $close, $conref) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $close->();
      undef $conref;
    } $client->request (url => $origin)->then (sub {
      return $client->close;
    })->then (sub {
      return Promise->all ([
        $$conref->closed->then (sub {
          push @event, 'closed';
        }),
        $$conref->completed->then (sub {
          push @event, 'completed';
        }),
      ]);
    })->then (sub {
      test {
        is join (',', @event), 'error,closed,aftererror,completed';
      } $c;
    });
  }, sub {
    push @event, 'error';
    return promised_sleep (1)->then (sub { push @event, 'aftererror' });
  });
} n => 1, name => 'closed / completed - onerror invoked';

test {
  my $c = shift;
  my @event;
  promised_cleanup { done $c; undef $c } server (sub ($) {
    my $env = $_[0];
    $env->{'psgix.exit_guard'}->begin;
    promised_sleep (1)->then (sub {
      push @event, 'aftersleep';
      $env->{'psgix.exit_guard'}->end;
    });
    return [200, [], []];
  }, sub {
    my ($origin, $close, $conref) = @_;
    my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
    promised_cleanup {
      $close->();
      undef $conref;
    } $client->request (url => $origin)->then (sub {
      return $client->close;
    })->then (sub {
      return Promise->all ([
        $$conref->closed->then (sub {
          push @event, 'closed';
        }),
        $$conref->completed->then (sub {
          push @event, 'completed';
        }),
      ]);
    })->then (sub {
      test {
        is join (',', @event), 'closed,aftersleep,completed';
      } $c;
    });
  });
} n => 1, name => 'closed / completed - psgix.exit_guard';

run_tests;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
