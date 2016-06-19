package HTTPClientBareConnection;
use strict;
use warnings;
use AnyEvent;
use Promise;
use Transport::TCP;
use Transport::TLS;
use HTTP;
use Web::Encoding qw(encode_web_utf8);
use Web::URL::Scheme qw(get_default_port);

use constant DEBUG => $ENV{WEBUA_DEBUG} || 0;

sub new_from_url ($$) {
  return bless {url => $_[1]}, $_[0];
} # new_from_url

sub proxy_manager ($;$) {
  if (@_ > 1) {
    $_[0]->{proxy_manager} = $_[1];
  }
  return $_[0]->{proxy_manager};
} # proxy_manager

sub resolver ($;$) {
  if (@_ > 1) {
    $_[0]->{resolver} = $_[1];
    return unless defined wantarray;
  }
  return $_[0]->{resolver} ||= do {
    require Web::Transport::PlatformResolver;
    require Web::Transport::CachedResolver;
    Web::Transport::CachedResolver->new_from_resolver
        (Web::Transport::PlatformResolver->new);
  };
} # resolver

sub parent_id ($;$) {
  if (@_ > 1) {
    $_[0]->{parent_id} = $_[1];
  }
  return $_[0]->{parent_id};
} # parent_id

sub tls_options ($;$) {
  if (@_ > 1) {
    $_[0]->{tls_options} = $_[1];
  }
  return $_[0]->{tls_options} || {};
} # tls_options

sub last_resort_timeout ($;$) {
  if (@_ > 1) {
    $_[0]->{last_resort_timeout} = $_[1];
  }
  return $_[0]->{last_resort_timeout} || 0;
} # last_resort_timeout

my $proxy_to_transport = sub {
  ## create a transport for a proxy configuration
  my ($tid, $proxy, $url_record, $resolver) = @_;

  ## 1. If $proxy->{protocol} is not supported, return null.

  if ($proxy->{protocol} eq 'tcp') {
    return $resolver->resolve ($url_record->host)->then (sub {
      my $addr = $_[0];
      die "Can't resolve host |@{[$url_record->host->stringify]}|\n"
          unless defined $addr;

      my $port = $url_record->port;
      $port = get_default_port $url_record->scheme if not defined $port;
      die "No port specified\n" unless defined $port;

      $port = 0+$port;
      warn "$tid: TCP @{[$addr->stringify]}:$port...\n" if DEBUG;
      return Transport::TCP->new (host => $addr, port => $port, id => $tid);
    });
  } elsif ($proxy->{protocol} eq 'http' or
           $proxy->{protocol} eq 'https') {
    return $resolver->resolve ($proxy->{host})->then (sub {
      die "Can't resolve proxy host |@{[$proxy->{host}->stringify]}|\n"
          unless defined $_[0];
      my $pport = 0+(defined $proxy->{port} ? $proxy->{port} : ($proxy->{protocol} eq 'https' ? 443 : 80));
      warn "$tid: TCP @{[$_[0]->stringify]}:$pport...\n" if DEBUG;
      my $transport = Transport::TCP->new
          (host => $_[0], port => $pport, id => $tid);
      if ($proxy->{protocol} eq 'https') {
        $transport = Transport::TLS->new
            (%{$proxy->{tls_options} or {}},
             si_host => $proxy->{host},
             sni_host => $proxy->{host},
             transport => $transport);
      }
      if ($url_record->scheme eq 'https') {
        # XXX HTTP version
        my $http = HTTP->new (transport => $transport);
        require Transport::H1CONNECT;
        $transport = Transport::H1CONNECT->new
            (http => $http,
             target => (encode_web_utf8 $url_record->hostport));
        # XXX auth
      } else {
        $transport->request_mode ('HTTP proxy');
      }
      return $transport;
    });
  } elsif ($proxy->{protocol} eq 'socks4') {
    return Promise->all ([
      $resolver->resolve ($url_record->host), # XXX force ipv4 option ?
      $resolver->resolve ($proxy->{host}),
    ])->then (sub {
      my $addr = $_[0]->[0];
      die "Can't resolve host |@{[$url_record->host->stringify]}|\n"
          unless defined $addr;
      die "Can't resolve host |@{[$url_record->host->stringify]}| into an IPv4 address\n"
          unless $addr->is_ipv4;
      my $proxy_addr = $_[0]->[1];
      die "Can't resolve proxy host |@{[$proxy->{host}->stringify]}|\n"
          unless defined $proxy_addr;

      my $port = $url_record->port;
      $port = get_default_port $url_record->scheme if not defined $port;
      die "No port specified\n" unless defined $port;

      my $pport = 0+(defined $proxy->{port} ? $proxy->{port} : 1080);
      warn "$tid: TCP @{[$proxy_addr->stringify]}:$pport...\n" if DEBUG;
      my $tcp = Transport::TCP->new
          (host => $proxy_addr, port => $pport, id => $tid);
      require Transport::SOCKS4;
      return Transport::SOCKS4->new (transport => $tcp,
                                     addr => $addr,
                                     port => 0+$port);
    });
  } elsif ($proxy->{protocol} eq 'socks5') {
    return $resolver->resolve ($proxy->{host})->then (sub {
      die "Can't resolve proxy host |@{[$proxy->{host}->stringify]}|\n"
          unless defined $_[0];

      my $port = $url_record->port;
      $port = get_default_port $url_record->scheme if not defined $port;
      die "No port specified\n" unless defined $port;

      my $pport = 0+(defined $proxy->{port} ? $proxy->{port} : 1080);
      warn "$tid: TCP @{[$_[0]->stringify]}:$pport...\n" if DEBUG;
      my $tcp = Transport::TCP->new
          (host => $_[0], port => $pport, id => $tid);

      require Transport::SOCKS5;
      return Transport::SOCKS5->new
          (transport => $tcp, host => $url_record->host, port => 0+$port);
    });
  } elsif ($proxy->{protocol} eq 'unix') {
    require Transport::UNIXDomainSocket;
    warn "$tid: Unix $proxy->{path}...\n" if DEBUG;
    my $transport = Transport::UNIXDomainSocket->new
        (path => $proxy->{path}, id => $tid);
    return Promise->resolve ($transport);
  } else {
    return Promise->reject
        ("Proxy protocol |$proxy->{protocol}| not supported\n");
  }
}; # $proxy_to_transport

sub connect ($) {
  my $self = $_[0];
  return $self->{connect_promise} ||= do {
    ## Establish a transport

    my $parent_id = $self->parent_id;

    my $url_record = $self->{url};
    $self->proxy_manager->get_proxies_for_url ($url_record)->then (sub {
      my $proxies = [@{$_[0]}];
      my $resolver = $self->resolver;

      # XXX wait for other connections

      my $get; $get = sub {
        if (@$proxies) {
          my $proxy = shift @$proxies;
          my $tid = $parent_id . '.' . ++$self->{tid};
          return $proxy_to_transport->($tid, $proxy, $url_record, $resolver)->catch (sub {
            if (@$proxies) {
              return $get->();
            } else {
              die $_[0];
            }
          });
        } else {
          return Promise->reject ("No proxy available\n");
        }
      }; # $get
      $get->()->then (sub {
        my $transport = $_[0];
        undef $get;
        if ($url_record->scheme eq 'https') {
          return Transport::TLS->new
              (%{$self->{tls_options}},
               si_host => $url_record->host,
               sni_host => $url_record->host,
               transport => $_[0]);
        }
        return $transport;
      }, sub {
        undef $get;
        die $_[0];
      });
    })->then (sub {
      if (not $_[0]->request_mode eq 'HTTP proxy' and
          not $url_record->scheme eq 'http' and
          not $url_record->scheme eq 'https' and
          not $url_record->scheme eq 'ftp') {
        die "Bad URL scheme |@{[$url_record->scheme]}|\n";
      }
      $self->{http} = HTTP->new (transport => $_[0]);
      return $self->{http}->connect;
    });
  };
} # connect

sub request ($$$$$$) {
  my ($self, $method, $url_record, $headers, $body_ref, $cb) = @_;
  return $self->connect->then (sub {
    return {failed => 1, message => "Bad input URL"}
        unless defined $url_record->host;
    my $target;
    if ($self->{http}->transport->request_mode eq 'HTTP proxy') {
      $target = $url_record->originpathquery;
    } else {
      $target = $url_record->pathquery;
    }
    $headers = [['Host', encode_web_utf8 $url_record->hostport],
                ['Connection', 'keep-alive'],
                @$headers];

    my $timeout = $self->last_resort_timeout;
    my $timer;
    if ($timeout > 0) {
      $timer = AE::timer $timeout, 0, sub {
        $self->{http}->abort (message => "Last-resort timeout ($timeout)");
        undef $timer;
      };
    }

    my $response;
    my $result;
    $self->{http}->onevent (sub {
      my $http = $_[0];
      my $type = $_[2];
      if ($type eq 'data') {
        if (not defined $result) {
          my $v = $_[3]; # buffer copy!
          Promise->resolve->then (sub { return $cb->($http, $response, $v) });
        }
      } elsif ($type eq 'dataend') {
        if (not defined $result) {
          Promise->resolve->then (sub { return $cb->($http, $response, undef) });
        }
      } elsif ($type eq 'complete') {
        my $exit = $_[3];
        if ($exit->{failed}) {
          $response = undef;
          $result ||= $exit;
        }
        undef $timer;
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
        if (not defined $result) {
          Promise->resolve->then (sub { return $cb->($http, $response, '') });
        }
      }
    });
    my $p = $self->{http}->send_request_headers
        ({method => $method, target => encode_web_utf8 ($target),
          headers => $headers})->then (sub {
      return $result || $response;
    });
    if (defined $body_ref) {
      $self->{http}->send_data ($body_ref);
    }
    return $p;
  })->catch (sub {
    if (ref $_[0] eq 'HASH' and defined $_[0]->{exit}) {
      return $_[0]->{exit};
    } elsif (ref $_[0] eq 'HASH' and $_[0]->{failed}) {
      return $_[0];
    } else {
      my $err = ''.$_[0];
      $err =~ s/\n$//;
      return {failed => 1, message => $err};
    }
#XXX warn if DEBUG
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

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
