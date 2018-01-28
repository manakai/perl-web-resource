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
use AnyEvent::Socket;
use Web::Transport::BasicClient;
use Web::Host;
use Web::URL;
use Web::Transport::ConstProxyManager;
use Web::Transport::PSGIServerConnection;
use Time::Local qw(timegm_nocheck);

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

Test::Certificates->generate_ca_cert;

test {
  my $c = shift;
  my $url1 = Web::URL->parse_string ('http://test/');
  my $client = Web::Transport::BasicClient->new_from_url ($url1);
  my $err = rand;
  $client->abort ($err)->catch (sub { });
  $client->request (url => $url1)->then (sub {
    test { ok 0 } $c;
  }, sub {
    my $result = $_[0];
    test {
      ok $result->is_network_error;
      is $result->network_error_message, "Client closed";
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'abort then connect by request';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('255.0.0.1');

  my $url1 = Web::URL->parse_string ("http://".$host->to_ascii.":$port/");
  my $client = Web::Transport::BasicClient->new_from_url ($url1);

  promised_sleep (1)->then (sub {
    return $client->abort;
  })->catch (sub { });

  $client->request (url => $url1)->then (sub {
    test { ok 0 } $c;
  }, sub {
    my $result = $_[0];
    test {
      ok $result->is_network_error;
      is $result->network_error_message, "Aborted";
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request abort';

test {
  my $c = shift;

  my $url1 = Web::URL->parse_string ("http://hoge.test/");
  my $pm = bless {}, 'test::pm1';
  my $client = Web::Transport::BasicClient->new_from_url ($url1, {
    proxy_manager => $pm,
  });
  $pm->{client} = $client;

  {
    package test::pm1;
    sub get_proxies_for_url {
      my ($self, $url, %args) = @_;
      return Promise->new (sub {
        my ($ok, $ng) = @_;
        if ($args{signal}->aborted) {
          return $ng->($args{signal}->manakai_error);
        } else {
          $args{signal}->manakai_onabort (sub {
            $ng->($args{signal}->manakai_error);
          });
        }
        Promise->resolve->then (sub { $self->{client}->abort })->catch (sub { });
      });
    }
  }

  $client->request (url => $url1)->then (sub {
    test { ok 0 } $c;
  }, sub {
    my $result = $_[0];
    test {
      ok $result->is_network_error;
      is $result->network_error_message, "Aborted";
    } $c;
  })->then (sub {
    done $c;
    undef $c;
    delete $pm->{client};
  });
} n => 2, name => 'proxy manager abort';

test {
  my $c = shift;

  my $url1 = Web::URL->parse_string ("http://hoge.test/");
  my $pm = bless {}, 'test::resolver1';
  my $client = Web::Transport::BasicClient->new_from_url ($url1, {
    resolver => $pm,
    proxy_manager => Web::Transport::ConstProxyManager->new_from_arrayref ([
      {protocol => 'tcp'},
    ]),
  });
  $pm->{client} = $client;

  {
    package test::resolver1;
    sub resolve {
      my ($self, $host, %args) = @_;
      return Promise->new (sub {
        my ($ok, $ng) = @_;
        if ($args{signal}->aborted) {
          return $ng->($args{signal}->manakai_error);
        } else {
          $args{signal}->manakai_onabort (sub {
            $ng->($args{signal}->manakai_error);
          });
        }
        Promise->resolve->then (sub { $self->{client}->abort })->catch (sub { });
      });
    }
  }

  $client->request (url => $url1)->then (sub {
    test { ok 0 } $c;
  }, sub {
    my $result = $_[0];
    test {
      ok $result->is_network_error;
      is $result->network_error_message, "Aborted";
    } $c;
  })->then (sub {
    done $c;
    undef $c;
    delete $pm->{client};
  });
} n => 2, name => 'tcp resolver abort';

test {
  my $c = shift;

  my $url1 = Web::URL->parse_string ("http://hoge.test/");
  my $pm = bless {}, 'test::resolver1';
  my $client = Web::Transport::BasicClient->new_from_url ($url1, {
    resolver => $pm,
    proxy_manager => Web::Transport::ConstProxyManager->new_from_arrayref ([
      {protocol => 'http', host => Web::Host->parse_string ('foo.test'), port => 1},
    ]),
  });
  $pm->{client} = $client;

  $client->request (url => $url1)->then (sub {
    test { ok 0 } $c;
  }, sub {
    my $result = $_[0];
    test {
      ok $result->is_network_error;
      is $result->network_error_message, "Aborted";
    } $c;
  })->then (sub {
    done $c;
    undef $c;
    delete $pm->{client};
  });
} n => 2, name => 'http proxy resolver abort';

test {
  my $c = shift;

  my $url1 = Web::URL->parse_string ("http://hoge.test/");
  my $pm = bless {}, 'test::resolver1';
  my $client = Web::Transport::BasicClient->new_from_url ($url1, {
    resolver => $pm,
    proxy_manager => Web::Transport::ConstProxyManager->new_from_arrayref ([
      {protocol => 'socks5', host => Web::Host->parse_string ('foo.test'), port => 1},
    ]),
  });
  $pm->{client} = $client;

  $client->request (url => $url1)->then (sub {
    test { ok 0 } $c;
  }, sub {
    my $result = $_[0];
    test {
      ok $result->is_network_error;
      is $result->network_error_message, "Aborted";
    } $c;
  })->then (sub {
    done $c;
    undef $c;
    delete $pm->{client};
  });
} n => 2, name => 'socks5 proxy resolver abort';

test {
  my $c = shift;

  my $url1 = Web::URL->parse_string ("http://host.test/");
  my $pm = bless {}, 'test::resolver2';
  my $client = Web::Transport::BasicClient->new_from_url ($url1, {
    resolver => $pm,
    proxy_manager => Web::Transport::ConstProxyManager->new_from_arrayref ([
      {protocol => 'socks4', host => Web::Host->parse_string ('proxy.test'), port => 1},
    ]),
  });
  $pm->{client} = $client;

  {
    package test::resolver2;
    sub resolve {
      my ($self, $host, %args) = @_;
      return Web::Host->parse_string ('10.4.1.1')
          if $host->to_ascii eq 'host.test';
      return Promise->new (sub {
        my ($ok, $ng) = @_;
        if ($args{signal}->aborted) {
          return $ng->($args{signal}->manakai_error);
        } else {
          $args{signal}->manakai_onabort (sub {
            $ng->($args{signal}->manakai_error);
          });
        }
        Promise->resolve->then (sub { $self->{client}->abort })->catch (sub { });
      });
    }
  }

  $client->request (url => $url1)->then (sub {
    test { ok 0 } $c;
  }, sub {
    my $result = $_[0];
    test {
      ok $result->is_network_error;
      is $result->network_error_message, "Aborted";
    } $c;
  })->then (sub {
    done $c;
    undef $c;
    delete $pm->{client};
  });
} n => 2, name => 'socks4 proxy resolver abort';

test {
  my $c = shift;

  my $url1 = Web::URL->parse_string ("http://host.test/");
  my $pm = bless {}, 'test::resolver3';
  my $client = Web::Transport::BasicClient->new_from_url ($url1, {
    resolver => $pm,
    proxy_manager => Web::Transport::ConstProxyManager->new_from_arrayref ([
      {protocol => 'socks4', host => Web::Host->parse_string ('proxy.test'), port => 1},
    ]),
  });
  $pm->{client} = $client;

  {
    package test::resolver3;
    sub resolve {
      my ($self, $host, %args) = @_;
      return Web::Host->parse_string ('10.4.1.1')
          if $host->to_ascii eq 'proxy.test';
      return Promise->new (sub {
        my ($ok, $ng) = @_;
        if ($args{signal}->aborted) {
          return $ng->($args{signal}->manakai_error);
        } else {
          $args{signal}->manakai_onabort (sub {
            $ng->($args{signal}->manakai_error);
          });
        }
        Promise->resolve->then (sub { $self->{client}->abort })->catch (sub { });
      });
    }
  }

  $client->request (url => $url1)->then (sub {
    test { ok 0 } $c;
  }, sub {
    my $result = $_[0];
    test {
      ok $result->is_network_error;
      is $result->network_error_message, "Aborted";
    } $c;
  })->then (sub {
    done $c;
    undef $c;
    delete $pm->{client};
  });
} n => 2, name => 'socks4 resolver abort';

Test::Certificates->wait_create_cert;
run_tests;

=head1 LICENSE

Copyright 2016-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
