use strict;
use FindBin;
use lib glob "$FindBin::Bin/../modules/*/lib";
use lib glob "$FindBin::Bin/../t_deps/modules/*/lib";
use lib "$FindBin::Bin/../lib";
use warnings;
use Test::More;
use IO::Socket::INET;
use Socket qw(SOL_SOCKET SO_LINGER);
use POSIX ();
use Time::HiRes ();
use Promise;
use Promised::Flow;
use Web::URL;
use Web::Transport::BasicClient;
use Web::Transport::ConstProxyManager;

alarm 50;
for my $transport (qw(tcp http-proxy)) {
for my $reset (0, 1) {
for my $block (0, 1) {
  subtest "$transport reset=$reset block=$block" => sub {
    my $server = IO::Socket::INET->new (LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 4) or die $!;
    my $port = $server->sockport;
    pipe my $report_reader, my $report_writer or die $!;
    my $pid = fork;
    die $! unless defined $pid;
    if (!$pid) {
      close $report_reader;
      $report_writer->autoflush (1);
      my $handle_request = sub {
        my ($socket, $connection) = @_;
        my $request = '';
        while ($request !~ /\r\n\r\n/) {
          my $length = sysread $socket, my $byte, 1;
          die "No complete request\n" unless $length;
          $request .= $byte;
        }
        my ($method) = $request =~ /\A([A-Z]+) /;
        my ($length) = $request =~ /\r\nContent-Length: ([0-9]+)/i;
        my $body = '';
        while (length $body < ($length // 0)) {
          my $n = sysread $socket, my $chunk, $length - length $body;
          die "No complete body\n" unless $n;
          $body .= $chunk;
        }
        print $report_writer "$connection $method $body\n";
        print $socket "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: keep-alive\r\n\r\nx";
      };
      eval {
        local $SIG{ALRM} = sub { die "No second connection\n" };
        alarm 4;
        my $first = $server->accept or die $!;
        $first->autoflush (1);
        $handle_request->($first, 1);
        Time::HiRes::sleep (0.05);
        setsockopt $first, SOL_SOCKET, SO_LINGER, pack ('ii', 1, 0) if $reset;
        close $first;
        my $second = $server->accept or die $!;
        $second->autoflush (1);
        $handle_request->($second, 2);
        close $second;
        1;
      };
      close $report_writer;
      POSIX::_exit (0);
    }
    close $server;
    close $report_writer;
    my $client = Web::Transport::BasicClient->new_from_url (
      Web::URL->parse_string ($transport eq 'tcp' ? "http://127.0.0.1:$port" : 'http://origin.invalid'),
      $transport eq 'tcp' ? {} : {
        proxy_manager => Web::Transport::ConstProxyManager->new_from_arrayref ([
          {protocol => 'http', host => '127.0.0.1', port => $port},
        ]),
      },
    );
    my $first = $client->request (method => 'GET', path => ['probe'])->to_cv->recv;
    is $first->status, 200, 'first request succeeds';
    if ($block) {
      # Deliberately starve this client event loop while the separate server closes.
      Time::HiRes::sleep (0.15);
    } else {
      promised_sleep (0.15)->to_cv->recv;
    }
    diag 'before POST state=' . ($client->{http}->{state} // 'undef');
    my ($second, $error);
    eval { $second = $client->request (method => 'POST', path => ['probe'], body => 'once')->to_cv->recv; 1 } or $error = $@;
    is $error, undef, 'one caller POST has no network error';
    is $second && $second->status, 200, 'POST response is successful';
    $client->close->to_cv->recv;
    my @received = <$report_reader>;
    close $report_reader;
    waitpid $pid, 0;
    is_deeply \@received, ["1 GET \n", "2 POST once\n"], 'POST is processed once on a fresh connection';
    done_testing;
  };
}
}
}
done_testing;
