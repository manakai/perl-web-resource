package Whatpm::ContentType;
use strict;
our $VERSION=do{my @r=(q$Revision: 1.18 $=~/\d+/g);sprintf "%d."."%02d" x $#r,@r};

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

sub get_sniffed_type ($%) {
  shift;
  my %opt = @_;
  $opt{get_file_head} ||= sub () { return '' };

  ## <http://www.whatwg.org/specs/web-apps/current-work/#content-type-sniffing>
  
  ## Step 1
  if (defined $opt{http_content_type_byte}) {
    ## ISSUE: Is leading LWS ignored?
    if ($opt{http_content_type_byte} eq 'text/plain' or
        $opt{http_content_type_byte} eq 'text/plain; charset=ISO-8859-1' or
        $opt{http_content_type_byte} eq 'text/plain; charset=iso-8859-1' or
        $opt{http_content_type_byte} eq 'text/plain; charset=UTF-8') {
      ## Content-Type sniffing: text or binary
      ## <http://www.whatwg.org/specs/web-apps/current-work/#content-type4>

      ## Step 1
      my $bytes = substr $opt{get_file_head}->(512), 0, 512;

      ## Step 2
      ## Step 3
      if (length $bytes >= 4) {
        my $by = substr $bytes, 0, 4;
        return ('text/plain', 'text/plain')
            if $by =~ /^\xFE\xFF/ or
                $by =~ /^\xFF\xFE/ or
                #$by =~ /^\x00\x00\xFE\xFF/ or
                $by =~ /^\xEF\xBB\xBF/;
      }

      ## Step 4
      return ('text/plain', 'text/plain')
          unless $bytes =~ /$binary_data_bytes/o;

      ## Step 5
      ROW: for my $row (@UnknownSniffingTable) {
        ## $row = [Mask, Pattern, Sniffed Type, Has leading WS flag, Security];
        next ROW unless $row->[4]; # Safe
        my $pattern_length = length $row->[1];
        my $data = substr ($bytes, 0, $pattern_length);
        return ('text/plain', $row->[2]) if $data eq $row->[1];

        ## NOTE: "WS" flag and mask are ignored, since "safe" rows
        ## don't use them.
      }

      ## Step 6
      return ('text/plain', 'application/octet-stream');
    }
  }

  ## Step 2
  my $official_type = $opt{content_type_metadata};
  if (defined $opt{http_content_type_byte}) {
    my $lws = qr/(?>(?>\x0D\x0A)?[\x09\x20])*/;
    my $token = qr/[\x21\x23-\x27\x2A\x2B\x2D\x2E\x30-\x39\x41-\x5A\x5E-\x7A\x7C\x7E]+/;
    if ($opt{http_content_type_byte} =~ m#^$lws($token/$token)$lws(?>;$lws$token=(?>$token|"(?>[\x21\x23-\x5B\x5D-\x7E\x80-\xFF]|$lws|\\[\x00-\x7F])*")$lws)*\z#) {
      ## Strip parameters
      $official_type = $1;
      $official_type =~ tr/A-Z/a-z/; ## ASCII case-insensitive
    }
    ## If there is an error, no official type.
  } elsif (defined $official_type) {
    ## Strip parameters
    if ($official_type =~ m#^[\x09\x0A\x0D\x20]*([^/;,\s]+/[^/;,\s]+)#) {
      $official_type = $1;
      $official_type =~ tr/A-Z/a-z/; ## ASCII case-insensitive
    }
  }

  ## Step 2 ("If") and Step 3
  if (not defined $official_type or
      $official_type eq 'unknown/unknown' or
      $official_type eq 'application/unknown') {
    ## Algorithm: "Content-Type sniffing: unknown type"

    ## NOTE: The "unknown" algorithm does not support HTML with BOM.

    ## Step 1
    my $bytes = substr $opt{get_file_head}->(512), 0, 512;
    
    ## Step 2
    my $stream_length = length $bytes;

    ## Step 3
    ROW: for my $row (@UnknownSniffingTable) {
      ## $row = [Mask, Pattern, Sniffed Type, Has leading WS flag, Security];
      my $pos = 0;
      if ($row->[3]) {
        $pos++ while substr ($bytes, $pos, 1) =~ /^[\x09\x0A\x0C\x0D\x20]/;
      }
      my $pattern_length = length $row->[1];
      next ROW if $pos + $pattern_length > $stream_length;
      my $data = substr ($bytes, $pos, $pattern_length) & $row->[0];
      return ($official_type, $row->[2]) if $data eq $row->[1];
    }

    ## Step 4
    return ($official_type, 'text/plain')
        unless $bytes =~ /$binary_data_bytes/o;

    ## Step 5
    return ($official_type, 'application/octet-stream');
  }

  ## Step 4
  if ($official_type =~ /\+xml$/ or 
      $official_type eq 'text/xml' or
      $official_type eq 'application/xml') {
    return ($official_type, $official_type);
  }

  ## Step 5
  if ($opt{supported_image_types}->{$official_type}) {
    ## Content-Type sniffing: image
    ## <http://www.whatwg.org/specs/web-apps/current-work/#content-type6>

    if ($official_type eq 'image/svg+xml') {
      return ($official_type, $official_type);
    }
    
    my $bytes = substr $opt{get_file_head}->(8), 0, 8;

    ## Table
    for my $row (@ImageSniffingTable) { # Pattern, Sniffed Type
      return ($official_type, $row->[1])
          if substr ($bytes, 0, length $row->[0]) eq $row->[0] and
              $opt{supported_image_types}->{$row->[1]};
    }

    ## Otherwise
    return ($official_type, $official_type);
  }

  ## Step 6
  if ($official_type eq 'text/html') {
    ## Content-Type sniffing: feed or HTML
    ## <http://www.whatwg.org/specs/web-apps/current-work/#content-type7>

    ## Step 1
    ## Step 2
    my $bytes = substr $opt{get_file_head}->(512), 0, 512;

    ## Step 3

    ## Step 4
    pos ($bytes) = 0;

    ## Step 5
    if (substr ($bytes, 0, 3) eq "\xEF\xBB\xBF") {
      pos ($bytes) = 3; # skip UTF-8 BOM.
    }

    ## Step 6-9
    1 while $bytes =~ /\G(?:[\x09\x20\x0A\x0D]+|<!--.*?-->|<![^>]*>|<\?.*?\?>)/gcs;
    return ($official_type, 'text/html') unless $bytes =~ /\G</gc;

    ## Step 10
    if ($bytes =~ /\Grss/gc) {
      return ($official_type, 'application/rss+xml');
    } elsif ($bytes =~ /\Gfeed/gc) {
      return ($official_type, 'application/atom+xml');
    } elsif ($bytes and $bytes =~ /\Grdf:RDF/gc) {
      # 
    } else {
      return ($official_type, 'text/html');
    }

    ## Step 11
    ## ISSUE: Step 11 is not defined yet in the spec
    if ($bytes =~ /\G([^>]+)/gc) {
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
} # get_sniffed_type

1;

=head1 LICENSE

Copyright 2007-2008 Wakaba <w@suika.fam.cx>

This library is free software; you can redistribute it
and/or modify it under the same terms as Perl itself.

=cut
