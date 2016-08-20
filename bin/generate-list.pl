use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use JSON::PS;
use Data::Dumper;

local $/ = undef;
my $json = json_bytes2perl scalar <>;

my $Data = {};

for (keys %$json) {
  if ($json->{$_}->{type} eq 'type') {
    my $type = $_;
    $type =~ s{/\*$}{};
    for my $key (keys %{$json->{$_}}) {
      $Data->{$type}->{$key} = $json->{$_}->{$key};
    }
    delete $Data->{$type}->{type};
  } elsif ($json->{$_}->{type} eq 'subtype') {
    my ($type, $subtype) = split m{/}, $_;
    my $def = {};
    for my $key (qw(
      styling scripting_language text iana iana_intended_usage
      obsolete limited_usage params syntax
    )) {
      $def->{$key} = $json->{$_}->{$key} if defined $json->{$_}->{$key};
    }
    $Data->{$type}->{subtype}->{$subtype} = $def if keys %$def;
  }
}

# XXX
$Data->{multipart}->{params}->{boundary}->{required} = 1;

$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Purity = 1;
my $value = Dumper $Data;
$value =~ s/\$VAR1\b/\$Web::MIME::_TypeDefs::Type/g;
print $value;
print "1;\n";

## License: Public Domain.
