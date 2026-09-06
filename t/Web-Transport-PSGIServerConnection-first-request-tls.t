use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use IO::Socket::INET ();
use AnyEvent;
use AnyEvent::Socket qw(tcp_server);
use Test::More;
use Test::Certificates;
use Promise;
use Web::Host;
use Web::URL;
use Web::Transport::BasicClient;
use Web::Transport::PSGIServerConnection;

Test::Certificates->wait_create_cert ({});

my $reservation = IO::Socket::INET->new (
  LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 1,
) or die $!;
my $port = $reservation->sockport;
close $reservation;
my ($upstream, $closing);
my (@received, @errors);
my $server = tcp_server '127.0.0.1', $port, sub {
  $upstream = Web::Transport::PSGIServerConnection->new_from_aeargs_and_opts ([ @_ ], {
    tls => {
      cert_file => Test::Certificates->cert_path ('cert-chained.pem'),
      key_file => Test::Certificates->cert_path ('key.pem'),
    },
    psgi_app => sub {
      my $env = shift;
      my $body = do { local $/; readline $env->{'psgi.input'} } // '';
      push @received, $body;
      return [200, ['Content-Length' => length $body], [$body]];
    },
  });
  $upstream->onexception (sub { push @errors, "$_[1]" });
  $upstream->{connection}->ready->then (sub {
    $closing = $upstream->close_after_current_response (
      timeout => 1, wait_for_first_request => 1,
    );
  });
};
my $client = Web::Transport::BasicClient->new_from_url (
  Web::URL->parse_string ('https://' . Test::Certificates->cert_name . ":$port/"), {
    resolver => bless ({}, 'FirstRequestTLSResolver'),
    tls_options => {ca_file => Test::Certificates->ca_path ('cert.pem')},
  },
);
my $guard = AE::timer 8, 0, sub { die "TLS first-request probe timed out\n" };
my $response = $client->request (
  path => [], method => 'POST', body => 'tls-single-delivery',
)->catch (sub { return $_[0] })->to_cv->recv;
ok !$response->is_network_error, 'the single request has no network error';
is $response->status, 200, 'ready TLS connection drains its accepted request';
is $response->body_bytes, 'tls-single-delivery', 'the complete response arrives';
is_deeply \@received, ['tls-single-delivery'], 'the POST is dispatched once';
is_deeply \@errors, [], 'the application can still write its response';
is lc ($response->header ('Connection') // ''), 'close', 'the connection is not reusable';
$client->close->to_cv->recv;
$closing->to_cv->recv if $closing;
undef $upstream;
undef $server;
undef $guard;
done_testing;

package FirstRequestTLSResolver;
sub resolve {
  return Promise->resolve (Web::Host->parse_string ('127.0.0.1'));
}
