use strict;
use warnings;
use Path::Tiny;
use Web::MIME::Sniffer;

my $file = shift or die "Usage: perl $0 file";
my $data = substr path ($file)->slurp, 0, 1445;

for my $context (qw(navigate image audio_or_video font text_track object)) {
  my $sniffer = Web::MIME::Sniffer->new_from_context ($context);
  $sniffer->is_http (1);
  my $result = $sniffer->detect (undef, $data);
  print $context, ":\t", $result->as_valid_mime_type, "\n";
}

## License: Public Domain.
