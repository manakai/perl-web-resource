use strict;
use warnings;
use Web::Transport::ConnectionClient;
use Data::Dumper;
use Getopt::Long;
use Web::URL;
use Web::Encoding;

my $RequestOptions = {};
my $tls_options = {};
GetOptions (
  'url=s' => sub {
    $RequestOptions->{url} = Web::URL->parse_string (decode_web_utf8 $_[1]);
  },
  'path-segment=s' => sub {
    push @{$RequestOptions->{path} ||= []}, decode_web_utf8 $_[1];
  },
  'method=s' => \($RequestOptions->{method}),
  'param=s' => sub {
    my ($name, $value) = split /=/, (decode_web_utf8 $_[1]), 2;
    push @{$RequestOptions->{params}->{$name} ||= []},
        defined $value ? $value : '';
  },
  'basic-auth=s' => sub {
    my ($name, $value) = split /:/, (decode_web_utf8 $_[1]), 2;
    $RequestOptions->{basic_auth} = [$name, $value];
  },
  'oauth1=s' => sub {
    my (@key) = split / /, (decode_web_utf8 $_[1]), 4;
    $RequestOptions->{oauth1} = \@key;
  },
  'oauth1-container=s' => sub {
    $RequestOptions->{oauth1_container} = $_[1];
  },
  'bearer=s' => \($RequestOptions->{bearer}),
  'header=s' => sub {
    my ($name, $value) = split /:/, (decode_web_utf8 $_[1]), 2;
    push @{$RequestOptions->{headers}->{$name} ||= []},
        defined $value ? $value : '';
  },
  'body=s' => \($RequestOptions->{body}),
  'insecure' => sub {
    $tls_options->{insecure} = 1;
  },
  'ca-file=s' => sub {
    use Path::Tiny;
    $tls_options->{ca_cert} = path ($_[1])->slurp;
  },
) or exit 1;

die "No input URL" unless defined $RequestOptions->{url};

my $client = Web::Transport::ConnectionClient->new_from_url
    ($RequestOptions->{url});
delete $RequestOptions->{url} if defined $RequestOptions->{path};
#$client->max_size ($size);
$client->tls_options ($tls_options);
$client->request (%$RequestOptions)->then (sub {
  warn $_[0]->network_error_message;
  print $_[0]->body_bytes;
})->catch (sub {
  warn "ERROR:[$_[0]]";
})->then (sub {
  return $client->close;
})->to_cv->recv;
warn "done";

## License: Public Domain.
