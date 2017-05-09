use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use JSON::PS;
use Data::Dumper;

my $type_path = path (__FILE__)->parent->parent->child ('local/mime-types.json');
my $sniffing_path = path (__FILE__)->parent->parent->child ('local/mime-sniffing.json');
my $json = json_bytes2perl $type_path->slurp;
my $sniffing = json_bytes2perl $sniffing_path->slurp;

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
      obsolete limited_usage params syntax audiovideo image
    )) {
      $def->{$key} = $json->{$_}->{$key} if defined $json->{$_}->{$key};
    }
    $Data->{$type}->{subtype}->{$subtype} = $def;
  }
}

# XXX
$Data->{multipart}->{params}->{boundary}->{required} = 1;

my $SniffingData = {};
for my $name (keys %{$sniffing->{tables}}) {
  my $regexps = $sniffing->{tables}->{$name}->{regexps};
  for my $type (keys %$regexps) {
    utf8::encode $regexps->{$type};
    push @{$SniffingData->{$name} ||= []},
        [qr{$regexps->{$type}}, $type];
  }
}

$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Purity = 1;
my $value = Dumper $Data;
$value =~ s/\$VAR1\b/\$Web::MIME::_TypeDefs::Type/g;
print $value;
my $value2 = Dumper $SniffingData;
$value2 =~ s/\$VAR1\b/\$Web::MIME::_TypeDefs::Sniffing/g;
print $value2;
print "1;\n";

## License: Public Domain.
