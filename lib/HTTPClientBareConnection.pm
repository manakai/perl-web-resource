package HTTPClientBareConnection;
use strict;
use warnings;
use Promise;
use Resolver;
use Transport::TCP;
use Transport::TLS;
use HTTP;
use Web::Encoding qw(encode_web_utf8);
use Web::URL::Canonicalize qw(serialize_parsed_url get_default_port);

sub new_from_url_record ($$) {
  return bless {url_record => $_[1]}, $_[0];
} # new_from_url_record

sub proxies ($;$) {
  if (@_ > 1) {
    $_[0]->{proxies} = $_[1];
  }
  return $_[0]->{proxies};
} # proxies

sub tls_options ($;$) {
  if (@_ > 1) {
    $_[0]->{tls_options} = $_[1];
  }
  return $_[0]->{tls_options} || {};
} # tls_options

sub connect ($) {
  my $self = $_[0];
  return $self->{connect_promise} ||= do {
    my $proxies = $self->proxies;
    $proxies = [{protocol => 'tcp'}] unless defined $proxies;
    my $url_record = $self->{url_record};
    my $get_transport;
    for my $proxy (@$proxies) {
      if ($proxy->{protocol} eq 'tcp') {
        $get_transport = Resolver->resolve_name ($url_record->{host})->then (sub {
          my $addr = $_[0];
          die "Can't resolve host |$url_record->{host}|\n" unless defined $addr;

          my $port = $url_record->{port};
          $port = get_default_port $url_record->{scheme} if not defined $port;
          die "No port specified\n" unless defined $port;

          return Transport::TCP->new (addr => $addr, port => 0+$port);
        });
        last;
      } elsif ($proxy->{protocol} eq 'http') {
        $get_transport = Resolver->resolve_name ($proxy->{host})->then (sub {
          die "Can't resolve proxy host |$proxy->{host}|\n" unless defined $_[0];
          my $transport = Transport::TCP->new
              (addr => $_[0], port => 0+($proxy->{port} || 80));
          $transport->request_mode ('HTTP proxy');
          return $transport;
        });
        last;
      } else {
        warn "Proxy protocol |$proxy->{protocol}| not supported";
      }
    }
    if (defined $get_transport) {
      if (defined $url_record->{scheme} and
          $url_record->{scheme} eq 'https') {
        $get_transport = $get_transport->then (sub {
          return Transport::TLS->new (%{$self->{tls_options}},
                                      transport => $_[0]);
        });
      }
      $get_transport->then (sub {
        $self->{http} = HTTP->new (transport => $_[0]);
        return $self->{http}->connect;
      });
    } else {
      Promise->reject ("No proxy available");
    }
  };
} # connect

sub request ($$$$;$) {
  my ($self, $method, $url_record, $headers, $cb) = @_;
  return $self->connect->then (sub {
    return {failed => 1, message => "Bad input URL"}
        unless defined $url_record->{host};
    my $target;
    if ($self->{http}->transport->request_mode eq 'HTTP proxy') {
      local $url_record->{fragment} = undef;
      $target = serialize_parsed_url $url_record;
    } else {
      $target = $url_record->{path} . (defined $url_record->{query} ? '?' . $url_record->{query} : '');
    }
    my $host = $url_record->{host} . (defined $url_record->{port} ? ':' . $url_record->{port} : '');
    $headers = [['Host', encode_web_utf8 $host], ['Connection', 'keep-alive'],
                @$headers];

    my $response;
    my $result;
    $self->{http}->onevent (sub {
      my $http = $_[0];
      my $type = $_[2];
      if ($type eq 'data') {
        if (defined $cb and not defined $result) {
          my $v = $_[3]; # buffer copy!
          Promise->resolve->then (sub { return $cb->($http, $response, $v) });
        }
      } elsif ($type eq 'dataend') {
        if (defined $cb and not defined $result) {
          Promise->resolve->then (sub { return $cb->($http, $response, undef) });
        }
      } elsif ($type eq 'complete') {
        my $exit = $_[3];
        if ($exit->{failed}) {
          $response = undef;
          $result ||= $exit;
        }
      } elsif ($type eq 'headers') {
        my $transport = $_[0]->transport;
        my $res = $_[3];
        if ($transport->request_mode ne 'HTTP proxy' and
            $res->{status} == 407) {
          $response = undef;
          $result ||= {failed => 1, message => 'Status 407 from non-proxy'};
        } else {
          $response = $res;
          if ($transport->type eq 'TLS' and
              not $transport->has_alert) {
            # XXX HSTS, PKP
          }
        }
        if (defined $cb and not defined $result) {
          Promise->resolve->then (sub { return $cb->($http, $response, '') });
        }
      }
    });
    return $self->{http}->send_request_headers
        ({method => $method, target => encode_web_utf8 ($target),
          headers => $headers})->then (sub {
      return $result || $response;
    });
  }, sub {
    if (ref $_[0] eq 'HASH' and defined $_[0]->{exit}) {
      return $_[0]->{exit};
    } else {
      my $err = ''.$_[0];
      $err =~ s/\n$//;
      return {failed => 1, message => $err};
    }
  });
} # request

sub is_active ($) {
  return 0 unless defined $_[0]->{http};
  return $_[0]->{http}->is_active;
} # is_active

sub close ($) {
  my $self = $_[0];
  return Promise->resolve unless defined $self->{http};
  return $self->{http}->close->then (sub {
    delete $self->{http};
    delete $self->{connect_promise};
    return undef;
  });
} # close

sub abort ($;%) {
  my $self = shift;
  return unless defined $self->{http};
  return $self->{http}->abort (@_)->then (sub {
    delete $self->{http};
    delete $self->{connect_promise};
    return undef;
  });
} # abort

sub DESTROY ($) {
  $_[0]->abort (message => "Aborted by DESTROY of $_[0]");

  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;

} # DESTROY

1;
