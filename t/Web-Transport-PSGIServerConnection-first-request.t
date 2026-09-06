use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use IO::Socket::INET ();
use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::Socket qw(tcp_server);
use Time::HiRes qw(time);
use Test::More;
use Promise;
use Promised::Flow;
use Web::URL;
use Web::Transport::BasicClient;
use Web::Transport::PSGIServerConnection;
use Web::Transport::ProxyServerConnection;

sub port {
  my $socket = IO::Socket::INET->new (LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 1) or die $!;
  return $socket->sockport;
}
sub await_condition (&) {
  my $condition = shift;
  (promised_wait_until { $condition->() } timeout => 5, interval => 0.001)->to_cv->recv;
}

for my $case (qw(fresh partial_line headers body response pipeline default
                 default_timeout false_option idle_timeout reused
                 zero_timeout negative_timeout)) {
  subtest $case => sub {
    my $port = port;
    my ($server, $respond);
    my (@bodies, @errors);
    my $listener = tcp_server '127.0.0.1', $port, sub {
      $server = Web::Transport::PSGIServerConnection->new_from_aeargs_and_opts ([ @_ ], {
        psgi_app => sub {
          my $env = shift;
          my $body = do { local $/; readline $env->{'psgi.input'} } // '';
          push @bodies, $body;
          return sub { $respond = shift } if $case eq 'response';
          return [200, ['Content-Length' => length $body], [$body]];
        },
      });
      $server->onexception (sub { push @errors, "$_[1]" });
    };
    my $socket = IO::Socket::INET->new (PeerAddr => '127.0.0.1', PeerPort => $port) or die $!;
    my $eof = AE::cv;
    my $raw = '';
    my $handle = AnyEvent::Handle->new (
      fh => $socket,
      on_read => sub { $raw .= delete $_[0]->{rbuf} },
      on_eof => sub { $_[0]->destroy; $eof->send },
      on_error => sub { $_[0]->destroy; $eof->send },
    );
    my $guard = AE::timer 8, 0, sub { die "Probe timed out: $case\n" };
    await_condition { $server && defined $server->{connection}->{state} };
    my $request = "POST /probe HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nabc";
    my $prefix = {
      partial_line => 'POST /pr',
      headers => "POST /probe HTTP/1.1\r\nHost:",
      body => "POST /probe HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\na",
      response => $request,
      reused => $request,
    }->{$case} // '';
    $handle->push_write ($prefix) if length $prefix;
    my $expected_state = {
      partial_line => 'before request-line', headers => 'before request header',
      body => 'request body', reused => 'waiting',
    }->{$case};
    await_condition { $server->{connection}->{state} eq $expected_state } if $expected_state;
    await_condition { $respond } if $case eq 'response';
    await_condition { $raw =~ /abc\z/ } if $case eq 'reused';
    my $is_default = $case eq 'default' || $case eq 'false_option';
    my $is_idle = $case eq 'idle_timeout';
    my $is_zero = $case eq 'zero_timeout';
    my $is_negative = $case eq 'negative_timeout';
    my $is_immediate = $is_default || $is_zero || $is_negative;
    my $started = time;
    my $closed = $server->close_after_current_response (
      ($case eq 'default_timeout' ? () : (
        timeout => $is_zero ? 0 : $is_negative ? -1 : $is_idle ? 0.05 : 1,
      )),
      ($case eq 'default' ? () : (
        wait_for_first_request => $case eq 'false_option' ? 0 : 1,
      )),
    );
    if ($case eq 'reused' || $is_immediate) {
      ok !defined $server->{connection}->{writer}, 'default/reused/unbounded close still closes output immediately';
    }
    if ($case eq 'response') {
      $respond->([200, ['Content-Length' => 3], ['abc']]);
      undef $respond;
    } elsif (!$is_idle && $case ne 'reused') {
      $handle->push_write (substr $request, length $prefix);
      $handle->push_write ($request) if $case eq 'pipeline';
    }
    $eof->recv;
    $closed->to_cv->recv;
    if ($is_idle) {
      is scalar @bodies, 0, 'a silent accepted socket never invokes the app';
      cmp_ok time - $started, '>=', 0.04, 'the existing positive shutdown deadline bounds the wait';
      unlike $raw, qr{HTTP/1\.[01] 200}, 'no fabricated success response';
    } elsif ($is_immediate) {
      unlike $raw, qr{HTTP/1\.[01] 200}, 'the non-opt-in contract is unchanged';
      diag 'app calls after immediate close=' . scalar @bodies;
    } else {
      like $raw, qr{\AHTTP/1\.[01] 200}, 'accepted request receives success';
      like $raw, qr{\r\n\r\nabc\z}, 'complete response body arrives';
      is_deeply \@bodies, ['abc'], 'POST body is processed exactly once';
      is_deeply \@errors, [], 'no response-after-close exception';
      like $raw, qr{\r\nConnection: close\r\n}i, 'the drained connection is not reusable'
          unless $case eq 'reused';
    }
    $handle->destroy;
    undef $listener;
    undef $server;
    undef $guard;
    done_testing;
  };
}

subtest 'proxy POST at fresh-connection shutdown' => sub {
  my $upstream_port = port;
  my $proxy_port = port;
  my ($upstream, $closing);
  my (@received, @errors, @proxies);
  my $server = tcp_server '127.0.0.1', $upstream_port, sub {
    $upstream = Web::Transport::PSGIServerConnection->new_from_aeargs_and_opts ([ @_ ], {
      psgi_app => sub {
        my $env = shift;
        my $body = do { local $/; readline $env->{'psgi.input'} } // '';
        push @received, $body;
        return [200, ['Content-Length' => length $body], [$body]];
      },
    });
    $upstream->onexception (sub { push @errors, "$_[1]" });
    $upstream->{connection}->ready->then (sub {
      $closing = $upstream->close_after_current_response (timeout => 1, wait_for_first_request => 1);
    });
  };
  my $proxy = tcp_server '127.0.0.1', $proxy_port, sub {
    push @proxies, Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([ @_ ], {});
  };
  my $client = Web::Transport::BasicClient->new_from_url (
    Web::URL->parse_string ("http://127.0.0.1:$upstream_port/"), {
      proxy_manager => bless ({port => $proxy_port}, 'LocalDrainProxy'),
    },
  );
  my $guard = AE::timer 8, 0, sub { die "Proxy probe timed out\n" };
  my $response = $client->request (path => [], method => 'POST', body => 'single-delivery')->to_cv->recv;
  is $response->status, 200, 'real proxy returns 200 rather than 502';
  is $response->body_bytes, 'single-delivery', 'proxy receives complete response';
  is_deeply \@received, ['single-delivery'], 'proxy does not replay the POST';
  is_deeply \@errors, [], 'upstream response remains writable';
  $client->close->to_cv->recv;
  $closing->to_cv->recv if $closing;
  Promise->all ([map { $_->completed } @proxies])->to_cv->recv;
  undef $proxy;
  undef $server;
  undef $upstream;
  @proxies = ();
  undef $guard;
  done_testing;
};
done_testing;

package LocalDrainProxy;
sub get_proxies_for_url {
  return Promise->resolve ([{
    protocol => 'http', host => Web::URL->parse_string ('http://127.0.0.1/')->host,
    port => $_[0]->{port},
  }]);
}
