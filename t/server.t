use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Web::URL;
use Web::Transport::ConnectionClient;
use Test::X1;
use Test::More;

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

my $Origin;
my $HandleRequestHeaders = {};
{
  use AnyEvent::Socket;
  use Web::Transport::HTTPServerConnection;
  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  $Origin = Web::URL->parse_string ("http://$host:$port");

  my $cb = sub {
    my $self = $_[0];
    my $type = $_[1];
    if ($type eq 'requestheaders') {
      my $req = $_[2];
      my $handler = $HandleRequestHeaders->{$req->{target}};
      if (defined $handler) {
        $handler->($self, $req);
      } else {
        die "No handler for |$req->{target}|";
      }
    }
  }; # $cb

  our $server = tcp_server $host, $port, sub {
    Web::Transport::HTTPServerConnection->new_from_fh_and_host_and_port_and_cb
        ($_[0], $_[1], $_[2], $cb);
  };
}

test {
  my $c = shift;
  $HandleRequestHeaders->{'/hoge'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga'],
        ]}, close => 1);
    $req->_response_done;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => ['hoge'])->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 201;
      is $res->status_text, 'OK';
      is $res->header ('Hoge'), 'Fuga';
      is $res->header ('Connection'), 'close';
      is $res->body_bytes, '';
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 5, name => 'no Content-Length, no body';

run_tests;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
