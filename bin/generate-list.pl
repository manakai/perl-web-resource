use strict;
use warnings;
use JSON;
use Data::Dumper;

local $/ = undef;
my $json = JSON->new->utf8->decode (scalar <>);

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
    delete $json->{$_}->{type};
    delete $json->{$_}->{mac_type};
    delete $json->{$_}->{mac_creator};
    delete $json->{$_}->{extensions};
    delete $json->{$_}->{preferred_cte};
    delete $json->{$_}->{application};
    $Data->{$type}->{subtype}->{$subtype} = $json->{$_};
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
