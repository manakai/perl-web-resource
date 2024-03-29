use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Test::Certificates;
use Promise;
use Promised::Flow;
use AnyEvent::Util qw(run_cmd);
use Web::Transport::ConnectionClient;
use Web::Host;
use Web::URL;
use Web::Transport::ConstProxyManager;
use Web::Transport::FindPort;

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

sub server_as_cv ($) {
  return _server_as_cv ('localhost', '127.0.0.1', find_listenable_port, $_[0]);
} # server_as_cv

sub pp ($) {
  return Web::Transport::ConstProxyManager->new_from_arrayref ($_[0]);
} # pp

{
  no warnings 'once';
  $Web::Transport::SOCKS5Transport::HandshakeTimeout = 5;
}

test {
  my $c = shift;
  server_as_cv (q{
    5
    0x00

    5
    0x00
    0x00

    0x01
    0x00
    0x00
    0x00
    0x00

    0x00
    0x00

    receive "GET /foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://hoge.test/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->proxy_manager (pp [{protocol => 'socks5', host => $server->{host},
                                 port => $server->{port}}]);
    return $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->network_error_message, undef;
        is $res->status, 203, $res;
        is $res->body_bytes, 'abcdef';
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 3, name => 'socks5 proxy';

test {
  my $c = shift;
  server_as_cv (q{
    5
    0x00

    5
    0x00
    0x00

    0x01
    0x00
    0x00
    0x00
    0x00

    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://hoge.test/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->proxy_manager (pp [{protocol => 'socks5', host => $server->{host},
                                 port => $server->{port}}]);
    return $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->network_error_message, q{SOCKS5 server does not return a valid reply: |\x05\x00\x05\x00\x00\x01\x00\x00\x00\x00| (EOF received)}, $res;
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'socks5 proxy incomplete close';

test {
  my $c = shift;
  server_as_cv (q{
    5
    0x00

    5
    0x00
    0x00

    0x01
    0x00
    0x00
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://hoge.test/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->proxy_manager (pp [{protocol => 'socks5', host => $server->{host},
                                 port => $server->{port}}]);
    return $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->network_error_message, q{SOCKS5 timeout (5)}, $res;
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'socks5 proxy incomplete timeout';

test {
  my $c = shift;
  server_as_cv (q{
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://hoge.test/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->proxy_manager (pp [{protocol => 'socks5', host => $server->{host},
                                 port => $server->{port}}]);
    return $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->network_error_message, q{SOCKS5 server does not return a valid reply: || (EOF received)};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'socks5 proxy empty close';

test {
  my $c = shift;
  server_as_cv (q{
    0x00
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://hoge.test/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->proxy_manager (pp [{protocol => 'socks5', host => $server->{host},
                                 port => $server->{port}}]);
    return $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->network_error_message, q{SOCKS5 server does not return a valid reply: |\x00| (EOF received)};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'socks5 proxy bad';

test {
  my $c = shift;
  server_as_cv (q{
    6
    0x00

    5
    0x00
    0x00
    0x00
    0x00
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://hoge.test/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->proxy_manager (pp [{protocol => 'socks5', host => $server->{host},
                                 port => $server->{port}}]);
    return $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        like $res->network_error_message,
            qr{^\QSOCKS5 server does not return a valid reply: |\x06\x00\E.*\|};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'socks5 proxy bad';

test {
  my $c = shift;
  server_as_cv (q{
    5
    0x00

    10
    0x00
    0x00
    0x00
    0x00
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://hoge.test/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->proxy_manager (pp [{protocol => 'socks5', host => $server->{host},
                                 port => $server->{port}}]);
    return $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->network_error_message, q{SOCKS5 server does not return a valid reply: |\x05\x00\x0A\x00\x00\x00\x00|}, $res;
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'socks5 proxy bad';

run_tests;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
