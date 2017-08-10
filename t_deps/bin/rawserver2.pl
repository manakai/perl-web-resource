use strict;
use warnings;
use AnyEvent;
use AnyEvent::Socket;
use Promise;
use Promised::Flow;
use ArrayBuffer;
use DataView;
use Web::Transport::TCPStream;
use Web::Transport::HTTPStream;

my $host = shift;
my $port = shift or die;

my $server;
my @server_closed;

$Web::Transport::HTTPStream::ServerConnection::ReadTimeout
    = $ENV{TEST_SERVER_READ_TIMEOUT} if $ENV{TEST_SERVER_READ_TIMEOUT};

my ($r_end, $s_end) = promised_cv;

my $process_stream = sub {
  my $stream = $_[0];

  $stream->headers_received->then (sub {
    my $req = $_[0];
    warn sprintf "> headers version=%.1f method=%s target=%s\n",
        $req->{version}, $req->{method}, $req->{target_url}->stringify;
    for (@{$req->{headers}}) {
      warn ">  + $_->[0]: $_->[1]\n";
    }

    my $r = $req->{body} || $req->{readable};
    if (defined $r) {
      my $reader = $r->get_reader;
      my $read; $read = sub {
        return $reader->read->then (sub {
          return if $_[0]->{done};
          my $view = $_[0]->{value};
          my $d = $view->manakai_to_string;
          if (length $d > 100) {
            $d = substr $d, 0, 100;
            $d =~ s/([^\x21-\x24\x26-\x7E])/sprintf '%%%02X', ord $1/ge;
            warn "> data |$d|... (length=@{[length $_[2]]})\n";
          } else {
            $d =~ s/([^\x21-\x24\x26-\x7E])/sprintf '%%%02X', ord $1/ge;
            warn "> data |$d| (length=@{[length $_[2]]})\n";
          }
          return $read->();
        });
      }; # $read
      promised_cleanup { undef $read } $read->();
    }

    if ($req->{target_url}->path eq '/end') {
      return $stream->send_response ({status => 200, status_text => 'OK', headers => []})->then (sub {
        my $writer = $_[0]->{body}->get_writer;
        $writer->write (DataView->new (ArrayBuffer->new_from_scalarref (\qq{<html>200 Goodbye!\x0D\x0A\x0D\x0A</html>
})));
        $s_end->();
        return $writer->close;
      });
    } elsif ($req->{method} eq 'GET' or $req->{method} eq 'POST') {
      my $data = qq{<html>...404 Not Found\x0D\x0A\x0D\x0A</html>
};
      return $stream->send_response ({status => 404, status_text => 'Not Found', headers => [], length => length $data})->then (sub {
        my $writer = $_[0]->{body}->get_writer;
        $writer->write (DataView->new (ArrayBuffer->new_from_scalarref (\$data)));
        return $writer->close;
      });
    } elsif ($req->{method} eq 'HEAD') {
      return $stream->send_response ({status => 404, status_text => 'Not Found', headers => []});
    } else {
      my $data = qq{<html>...405 Not Allowed (@{[$req->{method}]})</html>
};
      return $stream->send_response ({status => 405, status_text => 'Not Allowed', headers => [], length => length $data})->then (sub {
        my $writer = $_[0]->{body}->get_writer;
        $writer->write (DataView->new (ArrayBuffer->new_from_scalarref (\$data)));
        return $writer->close;
      });
    }
  });

  return $stream->closed->then (sub {
    my $error = $_[0];
    warn "> complete $error\n";
  });
}; # $process_stream

$server = tcp_server $host, $port, sub {
  my $con = Web::Transport::HTTPStream->new ({parent => {
    class => 'Web::Transport::TCPStream',
    fh => $_[0],
    host => Web::Host->parse_string ($_[1]), port => $_[2],
  }, server => 1});
  my $reader = $con->streams->get_reader;
  my $run; $run = sub {
    return $reader->read->then (sub {
      return if $_[0]->{done};
      $process_stream->($_[0]->{value});
      return $run->();
    });
  }; # $run
  promised_cleanup { undef $run } $run->();
  push @server_closed, $con->closed;
}; # $server

$r_end->to_cv->recv;
undef $server;
Promise->all (\@server_closed)->to_cv->recv;

syswrite STDOUT, "\x0A[[rawserver end]]\x0A";

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
