use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use JSON::PS;
use Data::Dumper;

my $StatusCodes = json_bytes2perl path (__FILE__)->parent->parent->child ('local/http-status-codes.json')->slurp;

my $ReasonPhrases = {};

for my $code (keys %$StatusCodes) {
  my $def = $StatusCodes->{$code};
  if (defined $def->{reason}) {
    $ReasonPhrases->{$code} = $def->{reason}
        if defined $def->{protocols}->{HTTP} or
           defined $def->{protocols}->{HTCPCP};
  }
}

$Data::Dumper::Sortkeys = 1;

print map { s/^\$VAR1/\$Web::Transport::_Defs::ReasonPhrases/; $_ } Dumper $ReasonPhrases;
print qq{1;};

=head1 LICENSE

Copyright 2012-2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
