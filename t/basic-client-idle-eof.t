use strict;
use FindBin;
use lib glob "$FindBin::Bin/../modules/*/lib";
use lib glob "$FindBin::Bin/../t_deps/modules/*/lib";
use lib "$FindBin::Bin/../lib";
use warnings;
use Test::More;
use AnyEvent;
use AnyEvent::Socket qw(tcp_server);
use IO::Socket::INET;
use Promise;
use Promised::Flow;
use Web::URL;
use Web::Transport::BasicClient;
use Web::Transport::ConstProxyManager;
use Web::Transport::PSGIServerConnection;

alarm 45;
for my $transport (qw(tcp http-proxy)) {
for my $mode (qw(graceful timeout)) {
for my $length (0, 2, 131072) {
  subtest "$transport $mode idle EOF after $length-byte response" => sub {
    local $Web::Transport::HTTPStream::ServerConnection::ReadTimeout = 60;
    my $reservation = IO::Socket::INET->new (LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 1) or die $!;
    my $port = $reservation->sockport;
    close $reservation;
    my (@connections, @requests);
    my $listener = tcp_server '127.0.0.1', $port, sub {
      my $number = @connections + 1;
      push @connections, Web::Transport::PSGIServerConnection->new_from_aeargs_and_opts ([@_], {
        psgi_app => sub {
          my $env = $_[0];
          my $body = do { local $/; readline $env->{'psgi.input'} } // '';
          push @requests, [$number, $env->{REQUEST_METHOD}, $body];
          # Expire the used connection, not initial request delivery.
          $Web::Transport::HTTPStream::ServerConnection::ReadTimeout = 0.05
              if $mode eq 'timeout' && $number == 1;
          return [200, ['Content-Length' => $length], ['x' x $length]];
        },
      });
    };
    my $client = Web::Transport::BasicClient->new_from_url (
      Web::URL->parse_string ($transport eq 'tcp' ? "http://127.0.0.1:$port" : 'http://origin.invalid'),
      $transport eq 'tcp' ? {} : {
        proxy_manager => Web::Transport::ConstProxyManager->new_from_arrayref ([
          {protocol => 'http', host => '127.0.0.1', port => $port},
        ]),
      },
    );
    my $first = $client->request (method => 'GET', path => ['probe'])->to_cv->recv;
    is $first->status, 200, 'first response succeeds';
    $connections[0]->close_after_current_response (timeout => 1)->to_cv->recv if $mode eq 'graceful';
    $connections[0]->completed->to_cv->recv;
    # Replacement connections retain the normal request deadline.
    $Web::Transport::HTTPStream::ServerConnection::ReadTimeout = 60;
    diag 'idle state=' . ($client->{http}->{state} // 'undef') . ' read_running=' . ($client->{http}->{read_running} // 0);
    my ($second, $error);
    eval { $second = $client->request (method => 'POST', path => ['probe'], body => 'once')->to_cv->recv; 1 } or $error = $@;
    is $error, undef, 'POST succeeds without caller retry';
    is $second && $second->status, 200, 'POST response arrives';
    is_deeply \@requests, [[1, 'GET', ''], [2, 'POST', 'once']], 'POST is sent on a fresh connection and processed exactly once';
    $client->close->to_cv->recv;
    $_->close_after_current_response (timeout => 1)->to_cv->recv for @connections;
    undef $listener;
    done_testing;
  };
}
}
}
done_testing;
