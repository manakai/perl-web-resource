package Web::MIME::Sniffer;
use strict;
use warnings;
our $VERSION = '1.19';

## Table in <http://www.whatwg.org/specs/web-apps/current-work/#content-type1>.
##
## "User agents MAY support further types if desired, by implicitly adding
## to the above table. However, user agents SHOULD NOT use any other patterns
## for types already mentioned in the table above, as this could then be used
## for privilege escalation (where, e.g., a server uses the above table to 
## determine that content is not HTML and thus safe from XSS attacks, but
## then a user agent detects it as HTML anyway and allows script to execute)."
our @UnknownSniffingTable = (
  ## Mask, Pattern, Sniffed Type, Has leading "WS" flag, Security Flag
  ## (1 = Safe, 0 = Otherwise)
  [ # <!DOCTYPE HTML
    "\xFF\xFF\xDF\xDF\xDF\xDF\xDF\xDF\xDF\xFF\xDF\xDF\xDF\xDF",
    "\x3C\x21\x44\x4F\x43\x54\x59\x50\x45\x20\x48\x54\x4D\x4C",
    "text/html", 0, 0,
  ],
  [
    "\xFF\xDF\xDF\xDF\xDF",
    "\x3C\x48\x54\x4D\x4C", # "<HTML"
    "text/html", 1, 0,
  ],
  [
    "\xFF\xDF\xDF\xDF\xDF",
    "\x3C\x48\x45\x41\x44", # "<HEAD"
    "text/html", 1, 0,
  ],
  [
    "\xFF\xDF\xDF\xDF\xDF\xDF\xDF",
    "\x3C\x53\x43\x52\x49\x50\x54", # "<SCRIPT"
    "text/html", 1, 0,
  ],
  [
    "\xFF\xFF\xFF\xFF\xFF",
    "\x25\x50\x44\x46\x2D",
    "application/pdf", 0, 0,
  ],
  [
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
    "\x25\x21\x50\x53\x2D\x41\x64\x6F\x62\x65\x2D",
    "application/postscript", 0, 1,
  ],

  [
    "\xFF\xFF\x00\x00",
    "\xFE\xFF\x00\x00", # UTF-16BE BOM
    "text/plain", 0, 0,
  ],
  [
    "\xFF\xFF\x00\x00",
    "\xFF\xFE\x00\x00", # UTF-16LE BOM ## ISSUE: Spec wrong
    "text/plain", 0, 0,
  ],
  [
    "\xFF\xFF\xFF\x00",
    "\xEF\xBB\xBF\x00", # UTF-8 BOM
    "text/plain", 0, 0,
  ],

  [
    "\xFF\xFF\xFF\xFF\xFF\xFF",
    "\x47\x49\x46\x38\x37\x61",
    "image/gif", 0, 1,
  ],
  [
    "\xFF\xFF\xFF\xFF\xFF\xFF",
    "\x47\x49\x46\x38\x39\x61",
    "image/gif", 0, 1,
  ],
  [
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
    "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",
    "image/png", 0, 1,
  ],
  [
    "\xFF\xFF\xFF",
    "\xFF\xD8\xFF",
    "image/jpeg", 0, 1,
  ],
  [
    "\xFF\xFF",
    "\x42\x4D",
    "image/bmp", 0, 1, 
  ],
  [
    "\xFF\xFF\xFF\xFF",
    "\x00\x00\x01\x00",
    "image/vnd.microsoft.icon", 0, 1,
  ],
);

## Table in <http://www.whatwg.org/specs/web-apps/current-work/#content-type2>.
## 
## NOTE: User agents are not allowed (at least in an explicit way) to add
## rows to this table.
my @ImageSniffingTable = (
  ## Pattern, Sniffed Type
  [
    "\x47\x49\x46\x38\x37\x61",
    "image/gif",
  ],
  [
    "\x47\x49\x46\x38\x39\x61",
    "image/gif",
  ],
  [
    "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",
    "image/png",
  ],
  [
    "\xFF\xD8\xFF",
    "image/jpeg",
  ],
  [
    "\x42\x4D",
    "image/bmp",
  ],
  [
    "\x00\x00\x01\x00",
    "image/vnd.microsoft.icon",
  ],
);
## NOTE: Ensure |$bytes| to be longer than pattern when a new image type
## is added to the table.

## NOTE: From section "Content-Type sniffing: text or binary".
my $binary_data_bytes = qr/[\x00-\x08\x0B\x0E-\x1A\x1C-\x1F]/;

sub new ($) {
  return bless {
    supported_image_types => {},
    supported_audio_video_types => {},
  }, $_[0];
} # new

sub supported_image_types ($) {
  return $_[0]->{supported_image_types};
} # supported_image_types

sub supported_audio_video_types ($) {
  return $_[0]->{supported_audio_video_types};
} # supported_audio_video_types

sub detect ($$$%) {
  my ($self, $mime, undef, %args) = @_;

  if (defined $mime and $mime->apache_bug) { # XXX and is HTTP
    ## <https://mimesniff.spec.whatwg.org/#rules-for-text-or-binary>

    if (length $_[2] >= 2) {
      my $by = substr $_[2], 0, 2;
      return ('text/plain', 'text/plain')
          if $by eq "\xFE\xFF" or $by eq "\xFF\xFE";
    }

    if (length $_[2] >= 3) {
      my $by = substr $_[2], 0, 3;
      return ('text/plain', 'text/plain')
          if $by eq "\xEF\xBB\xBF";
    }

    return ('text/plain', 'text/plain')
        unless $_[2] =~ /$binary_data_bytes/o;

      ## Step 5
      ROW: for my $row (@UnknownSniffingTable) {
        ## $row = [Mask, Pattern, Sniffed Type, Has leading WS flag, Security];
        next ROW unless $row->[4]; # Safe
        my $pattern_length = length $row->[1];
        my $data = substr ($_[2], 0, $pattern_length);
        return ('text/plain', $row->[2]) if $data eq $row->[1];

        ## NOTE: "WS" flag and mask are ignored, since "safe" rows
        ## don't use them.
      }

      ## Step 6
      return ('text/plain', 'application/octet-stream');
  }

  my $official_type = defined $mime ? $mime->mime_type_portion : undef;

  ## Step 2 ("If") and Step 3
  if (not defined $official_type or
      $official_type eq 'unknown/unknown' or
      $official_type eq 'application/unknown') {
    ## Algorithm: "Content-Type sniffing: unknown type"

    ## NOTE: The "unknown" algorithm does not support HTML with BOM.
    
    ## Step 2
    my $stream_length = length $_[2];

    ## Step 3
    ROW: for my $row (@UnknownSniffingTable) {
      ## $row = [Mask, Pattern, Sniffed Type, Has leading WS flag, Security];
      my $pos = 0;
      if ($row->[3]) {
        $pos++ while substr ($_[2], $pos, 1) =~ /^[\x09\x0A\x0C\x0D\x20]/;
      }
      my $pattern_length = length $row->[1];
      next ROW if $pos + $pattern_length > $stream_length;
      my $data = substr ($_[2], $pos, $pattern_length) & $row->[0];
      return ($official_type, $row->[2]) if $data eq $row->[1];
    }

    ## Step 4
    return ($official_type, 'text/plain')
        unless $_[2] =~ /$binary_data_bytes/o;

    ## Step 5
    return ($official_type, 'application/octet-stream');
  }

  ## Step 4
  if ($mime->is_xml_mime_type) {
    return ($official_type, $official_type);
  }

  ## Step 5
  if ($self->{supported_image_types}->{$official_type}) {
    ## Content-Type sniffing: image
    ## <http://www.whatwg.org/specs/web-apps/current-work/#content-type6>

    if ($official_type eq 'image/svg+xml') {
      return ($official_type, $official_type);
    }

    ## Table
    for my $row (@ImageSniffingTable) { # Pattern, Sniffed Type
      return ($official_type, $row->[1])
          if substr ($_[2], 0, length $row->[0]) eq $row->[0] and
             $self->{supported_image_types}->{$row->[1]};
    }

    ## Otherwise
    return ($official_type, $official_type);
  }

  ## Step 6
  if ($official_type eq 'text/html') {
    ## Content-Type sniffing: feed or HTML
    ## <http://www.whatwg.org/specs/web-apps/current-work/#content-type7>

    ## Step 4
    pos ($_[2]) = 0;

    ## Step 5
    if (substr ($_[2], 0, 3) eq "\xEF\xBB\xBF") {
      pos ($_[2]) = 3; # skip UTF-8 BOM.
    }

    ## Step 6-9
    1 while $_[2] =~ /\G(?:[\x09\x20\x0A\x0D]+|<!--.*?-->|<![^>]*>|<\?.*?\?>)/gcs;
    return ($official_type, 'text/html') unless $_[2] =~ /\G</gc;

    ## Step 10
    if ($_[2] =~ /\Grss/gc) {
      return ($official_type, 'application/rss+xml');
    } elsif ($_[2] =~ /\Gfeed/gc) {
      return ($official_type, 'application/atom+xml');
    } elsif ($_[2] and $_[2] =~ /\Grdf:RDF/gc) {
      # 
    } else {
      return ($official_type, 'text/html');
    }

    ## Step 11
    ## ISSUE: Step 11 is not defined yet in the spec
    if ($_[2] =~ /\G([^>]+)/gc) {
      my $by = $1;
      if ($by =~ m!xmlns[^>=]*=[\x20\x0A\x0D\x09]*["']http://www\.w3\.org/1999/02/22-rdf-syntax-ns#["']! and
          $by =~ m!xmlns[^>=]*=[\x20\x0A\x0D\x09]*["']http://purl\.org/rss/1\.0/["']!) {
        return ($official_type, 'application/rss+xml');
      }
    }

    ## Step 12
    return ($official_type, 'text/html');
  }

  ## Step 8
  return ($official_type, $official_type);
} # detect

1;

=head1 LICENSE

Copyright 2007-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
