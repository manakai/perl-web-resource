package Web::Transport::ProxyServerConnection;
use strict;
use warnings;
our $VERSION = '1.0';
use Carp qw(croak);
use AnyEvent;
use Promise;
use Web::Host;
use Web::Transport::_Defs;
use Web::Transport::HTTPServerConnection;
use Web::Transport::TCPTransport;
use Web::Transport::ConnectionClient;

sub headers_without_connection_specific ($) {
  my %remove = map { $_ => 1 } qw(
    host content-length transfer-encoding trailer te connection
    keep-alive proxy-connection upgrade proxy-authenticate proxy-authorization
  );
  for (@{$_[0]}) {
    if ($_->[2] eq 'connection') {
      for (split /,/, $_->[1]) {
        my $v = $_;
        $v =~ tr/A-Z/a-z/; ## ASCII case-insensitive.
        $v =~ s/\A[\x09\x0A\x0D\x20]+//;
        $v =~ s/[\x09\x0A\x0D\x20]+\z//;
        $remove{$v} = 1;
      }
    }
  }
  return [map {
    if ($remove{$_->[2]}) {
      ();
    } else {
      $_;
    }
  } @{$_[0]}];
} # headers_without_connection_specific

my $cb = sub {
  my $env;
  my $method;
  my $status;
  my $input = '';
  my $con;
  
  return sub {
    my $self = $_[0];
    my $type = $_[1];
    if ($type eq 'headers') {
      my $req = $_[2];

      my $header_sent;
      my $url = $req->{target_url};
      my $con = Web::Transport::ClientBareConnection->new_from_url ($url);

      my $x = Web::Transport::ConnectionClient->new_from_url ($url);
      $con->parent_id ($x->{parent_id});
      $con->proxy_manager ($x->proxy_manager);
      $con->resolver ($x->resolver);
      $con->tls_options ($x->tls_options);

      my $headers = headers_without_connection_specific $req->{headers};
      $con->request ($req->{method}, $url, $headers, undef, ! 'nocache', ! 'ws', sub {
        unless ($header_sent) {
          my $res = $_[1];
          my $headers = headers_without_connection_specific $res->{headers};
          $self->send_response_headers
              ({status => $res->{status},
                status_text => $res->{reason},
                headers => $headers},
               proxying => 1); # XXX or throw
          $header_sent = 1;
        }
        if (defined $_[2]) {
          $self->send_response_data (\($_[2]));
        } else {
          $self->close_response;
        }
      });

    } elsif ($type eq 'data') {
      # XXX If too large
      $input .= $_[2];
    } elsif ($type eq 'dataend') {

    }
  };
}; # $cb

sub new_from_ae_tcp_server_args ($$$;%) {
  my ($class, $aeargs, %args) = @_;
  my $self = bless {
  }, $class;
  my $socket;
  if ($aeargs->[1] eq 'unix/') {
    require Web::Transport::UNIXDomainSocketTransport;
    $socket = Web::Transport::UNIXDomainSocketTransport->new
        (server => 1, fh => $aeargs->[0], parent_id => $args{parent_id});
  } else {
    $socket = Web::Transport::TCPTransport->new
        (server => 1, fh => $aeargs->[0],
         host => Web::Host->parse_string ($aeargs->[1]), port => $aeargs->[2],
         parent_id => $args{parent_id});
  }
  $self->{connection} = Web::Transport::HTTPServerConnection->new (cb => sub {
    my ($sc, $type) = @_;
    if ($type eq 'startstream') {
      return $cb->($self);
    }
  }, transport => $socket);
  $self->{completed_cv} = AE::cv;
  $self->{completed_cv}->begin;
  $self->{connection}->closed->then (sub { $self->{completed_cv}->end });
  $self->{completed} = Promise->from_cv ($self->{completed_cv});
  return $self;
} # new_from_ae_tcp_server_args

sub id ($) {
  return $_[0]->{connection}->id;
} # id

sub onexception ($;$) {
  if (@_ > 1) {
    $_[0]->{onexception} = $_[1];
  }
  return $_[0]->{onexception} || sub { warn $_[1] };
} # onexception

sub _send_error ($$$) {
  my ($self, $stream, $error) = @_;
  my $p = Promise->all ([
    Promise->resolve->then (sub {
      return $self->onexception->($self, $error);
    })->catch (sub {
      warn $_[0];
    }),
    Promise->resolve->then (sub {
      $stream->send_response_headers
          ({status => 500,
            status_text => $Web::Transport::_Defs::ReasonPhrases->{500},
            headers => [['Content-Type', 'text/plain; charset=utf-8']]});
      $stream->send_response_data (\q{500});
      $stream->close_response;
    })->catch (sub {
      $stream->abort (message => "PSGI application throws an exception");
    }),
  ]);
  $self->{completed_cv}->begin;
  $p->then (sub { $self->{completed_cv}->end });
} # _send_error

sub closed ($) {
  return $_[0]->{connection}->closed;
} # closed

sub completed ($) {
  return $_[0]->{completed};
} # completed

sub close_after_current_response ($;%) {
  my ($self, %args) = @_;
  my $timeout = $args{timeout};
  $timeout = 10 unless defined $timeout;
  $self->{connection}->close_after_current_stream;
  my $timer;
  if ($timeout > 0) {
    $timer = AE::timer $timeout, 0, sub {
      $self->{connection}->abort
          (message => "|close_after_current_response| timeout ($timeout)");
      undef $timer;
    };
  }
  return $self->completed->then (sub {
    undef $timer;
  });
} # close_after_current_response

sub DESTROY ($) {
  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

1;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
