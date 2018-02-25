use strict;
use warnings;
use Path::Tiny;
use Data::Dumper;
$Data::Dumper::Sortkeys = 1;
use Web::Transport::JSON;

my $path = path (__FILE__)->parent->parent->child ('local/browsers.json');
my $data = json_chars2perl $path->slurp_utf8;

my $Data = {};

for my $device_type (keys %{$data->{user_agents}}) {
  for my $os (keys %{$data->{user_agents}->{$device_type}}) {
    for my $mode (keys %{$data->{user_agents}->{$device_type}->{$os}}) {
      my $def = $data->{user_agents}->{$device_type}->{$os}->{$mode};
      $Data->{ua}->{$device_type, $os, $mode} = $def->{userAgent};
    }
  }
}

print q{$Web::Transport::_PlatformDefs = } . Dumper $Data;
print q{;1;};

## License: Public Domain.
