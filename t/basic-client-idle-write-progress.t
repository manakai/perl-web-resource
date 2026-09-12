use strict;
use FindBin;
use lib glob "$FindBin::Bin/../modules/*/lib";
use lib glob "$FindBin::Bin/../t_deps/modules/*/lib";
use lib "$FindBin::Bin/../lib";
use warnings;
use Test::More;
use IO::Socket::INET;
use Socket qw(SOL_SOCKET SO_LINGER MSG_PEEK);
use POSIX ();
use Promise;
use Web::URL;
use Web::Transport::BasicClient;
use Web::Transport::ConstProxyManager;
use ArrayBuffer;
use ReadableStream;
use DataView;

alarm 60;
for my $body_mode (qw(bytes stream)) {
for my $proxy (0, 1) {
for my $partial (0, 1) {
  subtest "$body_mode peer reset at first header write proxy=$proxy partial=$partial" => sub {
    my $listener = IO::Socket::INET->new (
      LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 2,
    ) or die $!;
    my $port = $listener->sockport;
    pipe my $control_r, my $control_w or die $!;
    pipe my $ack_r, my $ack_w or die $!;
    pipe my $report_r, my $report_w or die $!;
    my $pid = fork;
    die $! unless defined $pid;
    if (!$pid) {
      close $control_w; close $ack_r; close $report_r;
      $report_w->autoflush (1);
      eval {
        alarm 5;
        my $socket = $listener->accept or die $!;
        $socket->autoflush (1);
        my $headers = '';
        until ($headers =~ /\r\n\r\n/) {
          sysread ($socket, my $byte, 1) or die 'incomplete GET';
          $headers .= $byte;
        }
        print $report_w "GET\n";
        print $socket "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: keep-alive\r\n\r\nx";
        sysread ($control_r, my $signal, 1) or die 'missing close signal';
        setsockopt $socket, SOL_SOCKET, SO_LINGER, pack ('ii', 1, 0) or die $!;
        close $socket;
        syswrite ($ack_w, 'x') or die $!;
        if (!$partial) {
          my $second = $listener->accept or die $!;
          $second->autoflush (1);
          my $request = '';
          until ($request =~ /\r\n\r\n/) {
            sysread ($second, my $byte, 1) or die 'incomplete POST';
            $request .= $byte;
          }
          my ($length) = $request =~ /\r\nContent-Length: ([0-9]+)/i;
          my $body = '';
          while (length $body < ($length // 0)) {
            sysread ($second, my $bytes, $length - length $body) or die 'incomplete body';
            $body .= $bytes;
          }
          print $report_w "POST $body\n";
          print $second "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx";
          close $second;
        }
        1;
      } or print $report_w "SETUP_ERROR\n";
      close $report_w;
      POSIX::_exit (0);
    }
    close $listener; close $control_r; close $ack_w; close $report_w;
    my $client = Web::Transport::BasicClient->new_from_url (
      Web::URL->parse_string ($proxy ? 'http://origin.invalid' : "http://127.0.0.1:$port"),
      $proxy ? {proxy_manager => Web::Transport::ConstProxyManager->new_from_arrayref ([
        {protocol => 'http', host => '127.0.0.1', port => $port},
      ])} : {},
    );
    is $client->request (method => 'GET', path => ['probe'])->to_cv->recv->status,
       200, 'initial GET succeeds';
    my $original = \&ArrayBuffer::manakai_syswrite;
    my ($writes, $bytes, $intercepted) = (0, 0, 0);
    my ($response, $error);
    my $connections = 0;
    my $original_connect = \&Web::Transport::TCPStream::create;
    my $body_pulls = 0;
    my %body = (body => 'once');
    if ($body_mode eq 'stream') {
      delete $body{body};
      $body{length} = 4;
      $body{body_stream} = ReadableStream->new ({
        type => 'bytes',
        pull => sub {
          $body_pulls++;
          my $bytes = 'once';
          $_[1]->enqueue (DataView->new (ArrayBuffer->new_from_scalarref (\$bytes)));
          $_[1]->close;
        },
      });
    }
    {
      no warnings 'redefine';
      local *Web::Transport::TCPStream::create = sub {
        $connections++;
        return $original_connect->(@_);
      };
      local *ArrayBuffer::manakai_syswrite = sub {
        return $original->(@_) unless $_[2];
        if (!$intercepted++) {
          if ($partial) {
            my $written = $original->($_[0], $_[1], 1, $_[3]);
            $writes++;
            $bytes += $written;
            syswrite ($control_w, 'x') or die $!;
            sysread ($ack_r, my $ack, 1) or die 'missing close acknowledgement';
            return $written;
          }
          syswrite ($control_w, 'x') or die $!;
          sysread ($ack_r, my $ack, 1) or die 'missing close acknowledgement';
        }
        $writes++;
        my $written = $original->(@_);
        $bytes += $written;
        return $written;
      };
      eval { $response = $client->request (method => 'POST', path => ['probe'],
                                         %body)->to_cv->recv; 1 } or $error = $@;
    }
    ok $intercepted, 'peer reset after idle checks, immediately before syscall';
    if (!$partial) {
      is $error, undef, 'zero-byte failed dispatch is recovered';
      is $response && $response->status, 200, 'one POST returns success';
    } else {
      is $bytes, $partial, 'only the controlled number of bytes were accepted';
      ok $error && $error->is_network_error, 'transport error stays visible';
      ok !defined $response, 'no successful response fabricated';
    }
    is $connections, ($partial ? 0 : 1),
        'only a zero-byte failure creates one replacement connection';
    $client->close->to_cv->recv;
    close $control_w; close $ack_r;
    my @report = <$report_r>;
    close $report_r;
    waitpid $pid, 0;
    is_deeply \@report, ["GET\n", (!$partial ? "POST once\n" : ())],
        'peer processes POST once only when no earlier bytes were sent';
    if ($body_mode eq 'stream') {
      if (!$partial) {
        is $body_pulls, 1, 'successful POST pulls the streamed body exactly once';
      } else {
        cmp_ok $body_pulls, '<=', 1, 'failed POST never pulls the streamed body twice';
      }
    }
    diag "write_calls=$writes accepted_post_bytes=$bytes";
    done_testing;
  };
}
}
}
done_testing;
