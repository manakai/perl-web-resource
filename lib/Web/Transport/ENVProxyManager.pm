package Web::Transport::ENVProxyManager;
use strict;
use warnings;
our $VERSION = '1.0';
use Promise;
use Web::Encoding qw(decode_web_utf8);
use Web::Host;
use Web::URL::Parser;

sub _env ($$) {
  ## Parse an environment variable
  my $value = $_[0]->{$_[1]};
  return undef if not defined $value or not length $value;

  my $uc_name = $_[1];
  $uc_name =~ tr/a-z/A-Z/;
  my $uc_value = $_[0]->{$uc_name};
  return undef if defined $uc_value and $value eq $uc_value;

  $value = decode_web_utf8 $value;

  my $parser = Web::URL::Parser->new;
  my $url = $parser->parse_proxy_env ($value);

  if (defined $url) {
    my $scheme = $url->scheme;
    if ($scheme eq 'http' or $scheme eq 'https') {
      return {protocol => $scheme,
              host => $url->host, port => $url->port,
              username => $url->username, password => $url->password};
    }

    if ($scheme eq 'socks4' or $scheme eq 'socks5') {
      my $host = $url->host;
      if (defined $host) {
        return {protocol => $url->scheme, host => $host, port => $url->port};
      }
    }
  }
  
  warn "Environment variable |$_[1]| is not a valid proxy URL ($value)";
  return undef;
} # _env

sub new ($) {
  return $_[0]->new_from_envs (\%ENV);
} # new

sub new_from_envs ($$) {
  my $envs = $_[1];
  return bless {
    http_proxy => _env ($envs, 'http_proxy'),
    https_proxy => _env ($envs, 'https_proxy'),
    ftp_proxy => _env ($envs, 'ftp_proxy'),
    no_proxy_list => [grep { defined $_ } map {
      s/\A[\x00-\x20]+//;
      s/[\x00-\x20]+\z//;
      Web::Host->parse_string ($_);
    } split /,/, defined $envs->{no_proxy} ? decode_web_utf8 ($envs->{no_proxy}) : ''],
  }, $_[0];
} # new_from_envs

sub get_proxies_for_url ($$;%) {
  my ($self, $url, %args) = @_;

  my $host = $url->host;
  return Promise->resolve ([]) unless defined $host;

  ## Get proxies

  for (@{$self->{no_proxy_list}}) {
    if ($_->equals ($host)) {
      return Promise->resolve ([{protocol => 'tcp'}]);
    }
  }

  my $scheme = $url->scheme;
  if ($scheme eq 'http' and defined $self->{http_proxy}) {
    return Promise->resolve ([$self->{http_proxy}]);
  }

  if ($scheme eq 'https' and defined $self->{https_proxy}) {
    return Promise->resolve ([$self->{https_proxy}]);
  }

  if ($scheme eq 'ftp' and defined $self->{ftp_proxy}) {
    return Promise->resolve ([$self->{ftp_proxy}]);
  }

  return Promise->resolve ([{protocol => 'tcp'}]);
} # get_proxies_for_url

1;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
