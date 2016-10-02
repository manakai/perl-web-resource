use strict;
use warnings;
use AnyEvent::Socket;
use Web::Host;
use Web::Transport::HTTPServerConnection;
use Web::Transport::TCPTransport;
use Data::Dumper;
use Promised::Flow;

my $host = 0;
my $port = 8522;

$Web::Transport::HTTPServerConnection::ReadTimeout = $ENV{SERVER_READ_TIMEOUT}
    if $ENV{SERVER_READ_TIMEOUT};

my $cv = AE::cv;
$cv->begin;

my $end = 0;
my $ended = 0;
my $cb = sub {
  my $self = $_[0];
  my $type = $_[1];
  if ($type eq 'headers') {
    my $req = $_[2];
    if ($req->{target_url}->path eq '/end') {
      $self->send_response_headers
          ({status => 200, status_text => 'OK', headers => []}); # XXX
      $self->send_response_data (\qq{<html>200 Goodbye!\x0D\x0A\x0D\x0A</html>
});
      $self->close_response;
      $end++;
    } elsif ($req->{method} eq 'GET' or
             $req->{method} eq 'POST') {
      $self->send_response_headers
          ({status => 404, status_text => 'Not Found', headers => []}); # XXX
      $self->send_response_data (\qq{<html>...404 Not Found\x0D\x0A\x0D\x0A</html>
});
      $self->close_response;
    } elsif ($req->{method} eq 'HEAD') {
      $self->send_response_headers
          ({status => 404, status_text => 'Not Found', headers => []}); # XXX
      $self->close_response;
    } else {
      $self->send_response_headers
          ({status => 405, status_text => 'Not Allowed', headers => []}); # XXX
      $self->send_response_data (\qq{<html>...405 Not Allowed (@{[$req->{method}]})</html>
});
      $self->close_response;
    }
  } elsif ($type eq 'complete') {
    if ($end and not $ended) {
      $ended = 1;
      $cv->end;
    }
  }
}; # $cb

my $con_cb = sub {
  my ($self, $type) = @_;
  if ($type eq 'startstream') {
    return $cb;
  }
}; # $con_cb

my $server = tcp_server $host, $port, sub {
  $cv->begin;
  my $tcp = Web::Transport::TCPTransport->new
      (server => 1, fh => $_[0],
       host => Web::Host->parse_string ($_[1]), port => $_[2]);
  my $con = Web::Transport::HTTPServerConnection->new
      (transport => $tcp, cb => $con_cb);
  promised_cleanup { $cv->end } $con->closed;
};

$cv->recv;
