use strict;
use warnings;
use AnyEvent::Socket;
use Web::Host;
use Web::Transport::TCPTransport;
use Web::Transport::HTTPServerConnection;
use Data::Dumper;

my $host = 0;
my $port = 8522;

$Web::Transport::HTTPServerConnection::ReadTimeout = $ENV{SERVER_READ_TIMEOUT}
    if $ENV{SERVER_READ_TIMEOUT};

my $cb = sub {
  my $self = $_[0];
  my $type = $_[1];
  if ($type eq 'headers') {
    my $req = $_[2];
    warn sprintf "> headers version=%.1f method=%s target=%s\n",
        $req->{version}, $req->{method}, $req->{target_url}->stringify;
    for (@{$req->{headers}}) {
      warn ">  + $_->[0]: $_->[1]\n";
    }

    if ($req->{target_url}->path eq '/end') {
      $self->send_response_headers
          ({status => 200, status_text => 'OK', headers => []});
      $self->send_response_data (\qq{<html>200 Goodbye!\x0D\x0A\x0D\x0A</html>
});
      AE::postpone { exit };
    } elsif ($self->{write_closed}) {
      #
    } elsif ($req->{method} eq 'GET' or
             $req->{method} eq 'POST') {
      my $data = qq{<html>...404 Not Found\x0D\x0A\x0D\x0A</html>
};
      $self->send_response_headers
          ({status => 404, status_text => 'Not Found', headers => []},
           content_length => length $data);
      eval {
        $self->send_response_data (\$data);
      };
    } elsif ($req->{method} eq 'HEAD') {
      $self->send_response_headers
          ({status => 404, status_text => 'Not Found', headers => []});
    } else {
      my $data = qq{<html>...405 Not Allowed (@{[$req->{method}]})</html>
};
      $self->send_response_headers
          ({status => 405, status_text => 'Not Allowed', headers => []},
           content_length => length $data);
      eval {
        $self->send_response_data (\$data);
      };
    }

    $self->close_response;
  } elsif ($type eq 'data') {
    my $d = $_[2];
    if (length $d > 100) {
      $d = substr $d, 0, 100;
      $d =~ s/([^\x21-\x24\x26-\x7E])/sprintf '%%%02X', ord $1/ge;
      warn "> data |$d|... (length=@{[length $_[2]]})\n";
    } else {
      $d =~ s/([^\x21-\x24\x26-\x7E])/sprintf '%%%02X', ord $1/ge;
      warn "> data |$d| (length=@{[length $_[2]]})\n";
    }
  } elsif ($type eq 'complete') {
    warn "> complete " . join ' ', %{$_[2]}, "\n";
  } else {
    warn "> $type\n";
  }
}; # $cb

my $server = tcp_server $host, $port, sub {
  my $socket = Web::Transport::TCPTransport->new
      (server => 1, fh => $_[0],
       host => Web::Host->parse_string ($_[1]), port => $_[2]);
  my $con = Web::Transport::HTTPServerConnection->new (cb => sub {
    my ($sc, $type) = @_;
    if ($type eq 'startstream') {
      return $cb;
    }
  }, transport => $socket);
};

AE::cv->recv;
