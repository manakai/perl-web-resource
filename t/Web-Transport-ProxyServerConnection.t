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
use Web::URL;
use Web::Transport::ConnectionClient;
use Web::Transport::ConstProxyManager;
use Web::Transport::ProxyServerConnection;
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

sub psgi_server ($$;$%) {
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
      $con->{connection}->server_header ($args{server_name});
      $con->onexception ($onexception) if defined $onexception;
      if (exists $args{max}) {
        $con->max_request_body_length ($args{max});
      }
      promised_cleanup { $cv->end } $con->completed;
    };
    $cv->cb ($ok);
    my $origin = Web::URL->parse_string ("http://$host:$port");
    my $close = sub { undef $server; $cv->end };
    $cb->($origin, $close, \$con);
  });
} # psgi_server

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_ae_tcp_server_args ([@_]);
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  promised_cleanup {
    done $c; undef $c;
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    return [412, ['Hoge', 'foo', 'Fuga', $env->{HTTP_FUGA},
                  'Request-URL', $env->{REQUEST_URI},
                  'Request-Via', $env->{HTTP_VIA},
                  'Request-Method', $env->{REQUEST_METHOD},
                  'Request-Connection', $env->{HTTP_CONNECTION}], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->proxy_manager ($pm);
    promised_cleanup {
      $close_server->();
      $client->close->then ($close);
    } $client->request (url => $url, headers => {'Fuga' => 'a b'})->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 412;
        is $res->status_text, 'Precondition Failed';
        is $res->header ('Hoge'), 'foo';
        is $res->header ('Fuga'), 'a b';
        is $res->header ('Request-URL'), '/abc?d';
        is $res->header ('Via'), undef;
        is $res->header ('Request-Via'), '';
        is $res->header ('Request-Method'), 'GET';
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $res->header ('Connection'), undef;
        is $res->header ('Request-Connection'), 'keep-alive';
        is $res->header ('Transfer-Encoding'), 'chunked';
        is $res->body_bytes, '200!';
      } $c;
    });
  }, server_name => $server_name);
} n => 14, name => 'Basic request and response forwarding';

# XXX remote host not found
# XXX remote host timeout
# XXX remote host broken
# XXX request body forwarding
# XXX client aborting
# XXX remote server aborting
# XXX server-level preprocessing hook
# XXX proxy authentication
# XXX request-target URL scheme restrictions
# XXX CONNECT support
# XXX WS proxying
# XXX option accessors

run_tests;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
