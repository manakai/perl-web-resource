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

test {
  my $c = shift;
  server_as_cv (q{
    0x00
    90

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
    my $url = Web::URL->parse_string (qq{http://$server->{host}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->proxy_manager (pp [{protocol => 'socks4', host => $server->{host},
                        port => $server->{port}}]);
    return $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
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
} n => 2, name => 'socks4 proxy';

test {
  my $c = shift;
  server_as_cv (q{
    0x00
    90

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
    my $url = Web::URL->parse_string (qq{http://badhost.test/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->proxy_manager (pp [{protocol => 'socks4', host => $server->{host},
                        port => $server->{port}}]);
    return $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        is $res->network_error_message, "Can't resolve host |badhost.test|";
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'socks4 proxy not resolvable';

test {
  my $c = shift;
  server_as_cv (q{
    0x00
    90

    0x00
    0x00
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->proxy_manager (pp [{protocol => 'socks4', host => $server->{host},
                        port => $server->{port}}]);
    return promised_cleanup {
      done $c;
      undef $c;
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        is $res->network_error_message, 'SOCKS4 server does not return a valid reply (result code 90)';
      } $c;
    }, sub {
      my $error = $_[0];
      test {
        ok 0;
        is $error, undef;
      } $c;
    })->then (sub {
      return $client->close;
    });
  });
} n => 2, name => 'socks4 proxy incomplete';

test {
  my $c = shift;
  server_as_cv (q{
    0x00
    95

    0x00
    0x00
    0x00
    0x00
    0x00
    0x00
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->proxy_manager (pp [{protocol => 'socks4', host => $server->{host},
                        port => $server->{port}}]);
    return promised_cleanup {
      done $c;
      undef $c;
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        is $res->network_error_message, 'SOCKS4 server does not return a valid reply (result code 95)';
      } $c;
    }, sub {
      my $error = $_[0];
      test {
        ok 0;
        is $error, undef;
      } $c;
    })->then (sub {
      return $client->close;
    });
  });
} n => 2, name => 'socks4 proxy error';

{
  no warnings 'once';
  $Web::Transport::SOCKS4Transport::HandshakeTimeout = 5;
}

test {
  my $c = shift;
  server_as_cv (q{
    0x00
    95
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->proxy_manager (pp [{protocol => 'socks4', host => $server->{host},
                        port => $server->{port}}]);
    return promised_cleanup {
      done $c;
      undef $c;
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        is $res->network_error_message, 'SOCKS4 timeout (5)';
      } $c;
    }, sub {
      my $error = $_[0];
      test {
        ok 0;
        is $error, undef;
      } $c;
    })->then (sub {
      return $client->close;
    });
  });
} n => 2, name => 'socks4 proxy error incomplete';

test {
  my $c = shift;
  server_as_cv (q{
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->proxy_manager (pp [{protocol => 'socks4', host => $server->{host},
                                 port => $server->{port}}]);
    return promised_cleanup {
      done $c;
      undef $c;
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        is $res->network_error_message, 'SOCKS4 server does not return a valid reply (empty)';
      } $c;
    }, sub {
      my $error = $_[0];
      test {
        ok 0;
        is $error, undef;
      } $c;
    })->then (sub {
      return $client->close;
    });
  });
} n => 2, name => 'socks4 proxy empty closed';

run_tests;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
