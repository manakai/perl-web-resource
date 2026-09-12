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
use Scalar::Util qw(weaken);
use Promise;
use ReadableStream;
use ArrayBuffer;
use DataView;
use Web::URL;
use Web::Transport::BasicClient;
use Web::Transport::HTTPStream;
use Web::Transport::ConstProxyManager;

alarm 45;
for my $body_mode (qw(bytes stream)) {
for my $phase (qw(before_dispatch before_processed after_post)) {
for my $transport (qw(tcp http-proxy)) {
for my $reset (0, 1) {
  next if $phase eq 'after_post' && !$reset;
  subtest "$body_mode $transport $phase reset=$reset" => sub {
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
      close $control_w;
      close $ack_r;
      close $report_r;
      $report_w->autoflush (1);
      my $handle = sub {
        my ($socket, $connection, $no_response) = @_;
        $socket->autoflush (1);
        my $headers = '';
        until ($headers =~ /\r\n\r\n/) {
          sysread ($socket, my $byte, 1) or die "incomplete headers";
          $headers .= $byte;
        }
        my ($method) = $headers =~ /\A([A-Z]+) /;
        my ($length) = $headers =~ /\r\nContent-Length: ([0-9]+)/i;
        my $body = '';
        while (length $body < ($length // 0)) {
          sysread ($socket, my $bytes, $length - length $body) or die "incomplete body";
          $body .= $bytes;
        }
        print $report_w "$connection $method $body\n";
        print $socket "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: keep-alive\r\n\r\nx"
            unless $no_response;
      };
      eval {
        local $SIG{ALRM} = sub { die "deadline" };
        alarm 5;
        my $first = $listener->accept or die $!;
        $handle->($first, 1);
        if ($phase ne 'after_post') {
          sysread ($control_r, my $signal, 1) or die "missing close signal";
        } else {
          $handle->($first, 1, 1);
        }
        setsockopt $first, SOL_SOCKET, SO_LINGER, pack ('ii', 1, 0) if $reset;
        close $first;
        syswrite ($ack_w, 'x') if $phase ne 'after_post';
        alarm 1 if $phase eq 'after_post';
        my $second = $listener->accept or die $!;
        $handle->($second, 2);
        close $second;
        1;
      };
      close $report_w;
      POSIX::_exit (0);
    }
    close $listener;
    close $control_r;
    close $ack_w;
    close $report_w;
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
    my $initial_http = $client->{http};
    weaken $initial_http;
    my $original = \&Web::Transport::HTTPStream::_check_send_request;
    my $closed_after_check = 0;
    my ($second, $error);
    my $body_pulls = 0;
    my $pulls_at_close;
    my %body = (body => 'once');
    # Forward proxies expose even a buffered caller POST as a body stream.
    if ($body_mode eq 'stream') {
      $body{body_stream} = ReadableStream->new ({
        type => 'bytes',
        pull => sub {
          $body_pulls++;
          my $bytes = 'once';
          $_[1]->enqueue (DataView->new (ArrayBuffer->new_from_scalarref (\$bytes)));
          $_[1]->close;
        },
      });
      delete $body{body};
      $body{length} = 4;
    }
    {
      no warnings 'redefine';
      local *Web::Transport::HTTPStream::_check_send_request = sub {
        my $http = $_[0];
        return $original->(@_)->then (sub {
          if ($phase ne 'after_post' && defined $initial_http &&
              $http == $initial_http && !$closed_after_check++) {
            $pulls_at_close = $body_pulls;
            syswrite ($control_w, 'x');
            sysread ($ack_r, my $ack, 1) or die "missing close acknowledgement";
            my $check = $http->{info}->{parent}->{read_eof_pending};
            my $deadline = Time::HiRes::time + 1;
            until ($check->()) {
              die "close not readable" if Time::HiRes::time > $deadline;
              Time::HiRes::sleep (0.001);
            }
            if ($phase eq 'before_processed') {
              $http->_read;
              return $http->closed->then (sub {
                ok $http->{to_be_closed}, 'the idle close is processed before dispatch';
                return undef;
              });
            }
          }
          return undef;
        });
      };
      eval {
        $second = $client->request (method => 'POST', path => ['probe'], %body)->to_cv->recv;
        1;
      } or $error = $@;
    }
    if ($phase ne 'after_post') {
      is $closed_after_check, 1, 'peer closes after successful check, before request dispatch';
      is $pulls_at_close, 0, 'streamed body has not been read at the idle close'
          if $body_mode eq 'stream';
      is $error, undef, 'one caller POST completes without a transport error';
      is $second && $second->status, 200, 'POST receives a successful response';
    } else {
      is $closed_after_check, 0, 'peer closes only after receiving the complete POST';
      ok $error && $error->is_network_error, 'an error after POST remains visible';
      ok !defined $second, 'no successful response is fabricated';
    }
    $client->close->to_cv->recv;
    close $control_w;
    close $ack_r;
    my @requests = <$report_r>;
    close $report_r;
    waitpid $pid, 0;
    is_deeply \@requests, ["1 GET \n", ($phase ne 'after_post' ? 2 : 1)." POST once\n"],
        'server processes POST exactly once';
    is $body_pulls, 1, 'streamed body is read once' if $body_mode eq 'stream';
    done_testing;
  };
}
}
}
}
subtest 'direct HTTP stream callers retain the closed-connection error' => sub {
  my $http = bless {
    state => 'waiting', to_be_closed => 1,
    info => {layered_type => 'HTTP/TCP'},
  }, 'Web::Transport::HTTPStream';
  my ($result, $error);
  eval {
    $result = $http->send_request ({
      method => 'POST', target => '/probe', headers => [], length => 4,
    })->to_cv->recv;
    1;
  } or $error = $@;
  isa_ok $error, 'Web::Transport::TypeError';
  ok !Web::Transport::ProtocolError->can_http_retry ($error),
      'retry is not enabled without the existing opt-in';
  ok !defined $result, 'no request body writer is returned';
  done_testing;
};
done_testing;
