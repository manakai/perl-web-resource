use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Time::Local qw(timegm_nocheck);
use Promise;
use Promised::Flow;
use AnyEvent::Socket;
use Web::Transport::ConnectionClient;
use Web::URL;
use Web::Transport::ConstProxyManager;
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
      $con->{connection}->{server_header} = $args{server_name};
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
  promised_cleanup {
    done $c; undef $c;
  } psgi_server (sub ($) {
    my $env = $_[0];
    return [412, ['request-authorization', $env->{HTTP_AUTHORIZATION}], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
        ([{protocol => 'http', host => $origin->host, port => $origin->port}]);
    ## Test data from <http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html>
    my $url = Web::URL->parse_string (q<http://examplebucket.s3.amazonaws.com>);
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->proxy_manager ($pm);
    my $access_key_id = 'AKIAIOSFODNN7EXAMPLE';
    my $secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    my $region = 'us-east-1';
    my $service = 's3';
    promised_cleanup {
      return $client->close->then ($close);
    } promised_for {
      my $test = shift;
      $client->protocol_clock
          (sub { return timegm_nocheck (0, 0, 0, 24, 5-1, 2013) });
      return $client->request (
        method => $test->{method},
        path => $test->{path},
        (defined $test->{target} ? (url => Web::URL->parse_string ($test->{target}, $url)) : ()),
        aws4 => [$access_key_id, $secret_access_key, $region, $service],
        aws4_signed_headers => {RANGE => 1, date => 1},
        headers => $test->{headers},
        body => $test->{body},
      )->then (sub {
        my $res = $_[0];
        test {
          is $res->header ('Request-Authorization'), $test->{expected};
        } $c;
      });
    } [
      {path => ['test.txt'], headers => {Range => 'bytes=0-9'},
       expected => 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41'},
      {method => 'PUT', path => ['test$file.text'],
       headers => {'x-amz-storage-class' => 'REDUCED_REDUNDANCY',
                   DaTE => 'Fri, 24 May 2013 00:00:00 GMT'},
       body => 'Welcome to Amazon S3.',
       expected => 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd'},
      {target => q</?lifecycle>,
       expected => 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543'},
    ];
  });
} n => 1 * 3;

test {
  my $c = shift;
  my $url = Web::URL->parse_string (q<https://test/>);
  my $client = Web::Transport::ConnectionClient->new_from_url ($url);
  $client->request (url => $url, body => "\x{5000}", aws4 => ['a', 'n', '&&', 'a'])->then (sub {
    test {
      ok 0;
    } $c;
  }, sub {
    my $res = $_[0];
    test {
      ok $res->is_network_error;
      is $res->network_error_message, '|body| is utf8-flagged';
    } $c;
    done $c;
    undef $c;
  });
} n => 2, name => 'utf8 body';

run_tests;

=head1 LICENSE

Copyright 2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
