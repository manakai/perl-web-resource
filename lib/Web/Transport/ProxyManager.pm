package Web::Transport::ProxyManager;
use strict;
use warnings;
our $VERSION = '1.0';
use Promise;
use Web::DomainName::Canonicalize qw(canonicalize_url_host);
use Web::URL::Canonicalize qw(url_to_canon_url parse_url);
use Web::Encoding qw(decode_web_utf8);

sub _env ($$) {
  ## Parse an environment variable
  my $value = $_[0]->{$_[1]};
  return undef if not defined $value or not length $value;
  $value = decode_web_utf8 $value;
  $value = 'http://' . $value unless $value =~ m{^[A-Za-z][A-Za-z0-9+.-]*://};

  my $url = parse_url url_to_canon_url $value, 'about:blank';

  if (defined $url->{scheme} and
      ($url->{scheme} eq 'http' or $url->{scheme} eq 'https')) {
    return {protocol => $url->{scheme},
            host => $url->{host}, port => $url->{port},
            username => defined $url->{user} ? $url->{user} : '',
            password => $url->{password}};
  }

  if (defined $url->{scheme} and
      defined $url->{host} and
      ($url->{scheme} eq 'socks4' or $url->{scheme} eq 'socks5')) {
    return {protocol => $url->{scheme},
            host => $url->{host}, port => $url->{port}};
  }


  warn "Environment variable |$_[1]| is not a valid proxy URL ($value)";
  return undef;
} # _env

sub new_from_envs ($;$) {
  my $envs = $_[1] || \%ENV;
  return bless {
    http_proxy => _env ($envs, 'http_proxy'),
    https_proxy => _env ($envs, 'https_proxy'),
    ftp_proxy => _env ($envs, 'ftp_proxy'),
    no_proxy_list => [grep { defined $_ } map {
      s/\A[\x00-\x20]+//;
      s/[\x00-\x20]+\z//;
      canonicalize_url_host $_;
    } split /,/, defined $envs->{no_proxy} ? decode_web_utf8 ($envs->{no_proxy}) : ''],
  }, $_[0];
} # new_from_envs

sub get_proxies_for_url_record ($$) {
  my ($self, $url) = @_;

  my $host = $url->{host};
  return Promise->resolve ([]) unless defined $host;

  ## Get proxies

  for (@{$self->{no_proxy_list}}) {
    if ($_ eq $host) {
      return Promise->resolve ([{protocol => 'tcp'}]);
    }
  }

  if (defined $self->{pac_script}) {
    # XXX
  }

  if (defined $self->{socks_proxy}) {
    return Promise->resolve ([$self->{socks_proxy}]);
  }

  if ($url->{scheme} eq 'http' and defined $self->{http_proxy}) {
    return Promise->resolve ([$self->{http_proxy}]);
  }

  if ($url->{scheme} eq 'https' and defined $self->{https_proxy}) {
    return Promise->resolve ([$self->{https_proxy}]);
  }

  if ($url->{scheme} eq 'ftp' and defined $self->{ftp_proxy}) {
    return Promise->resolve ([$self->{ftp_proxy}]);
  }

  return Promise->resolve ([{protocol => 'tcp'}]);
} # get_proxies_for_url_record

1;
