package Web::MIME::Sniffer;
use strict;
use warnings;
our $VERSION = '1.19';
use Web::MIME::Type;

our @ScriptableSniffingTable = (
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
);

our @NonScriptableSniffingTable = (
  ## Mask, Pattern, Sniffed Type, Has leading "WS" flag, Security Flag
  ## (1 = Safe, 0 = Otherwise)
  [
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
    "\x25\x21\x50\x53\x2D\x41\x64\x6F\x62\x65\x2D",
    "application/postscript", 0, 1,
  ],
);

our @BOMSniffingTable = (
  ## Mask, Pattern, Sniffed Type, Has leading "WS" flag, Security Flag
  ## (1 = Safe, 0 = Otherwise)
  [
    "\xFF\xFF\x00\x00",
    "\xFE\xFF\x00\x00", # UTF-16BE BOM
    "text/plain", 0, 0,
  ],
  [
    "\xFF\xFF\x00\x00",
    "\xFF\xFE\x00\x00", # UTF-16LE BOM
    "text/plain", 0, 0,
  ],
  [
    "\xFF\xFF\xFF\x00",
    "\xEF\xBB\xBF\x00", # UTF-8 BOM
    "text/plain", 0, 0,
  ],
);

our @BOM2SniffingTable = (
  ## Mask, Pattern, Sniffed Type, Has leading "WS" flag, Security Flag
  ## (1 = Safe, 0 = Otherwise)
  [
    "\xFF\xFF",
    "\xFE\xFF", # UTF-16BE BOM
    "text/plain", 0, 0,
  ],
  [
    "\xFF\xFF",
    "\xFF\xFE", # UTF-16LE BOM
    "text/plain", 0, 0,
  ],
  [
    "\xFF\xFF\xFF",
    "\xEF\xBB\xBF", # UTF-8 BOM
    "text/plain", 0, 0,
  ],
);

my @ImageSniffingTable = (
  ## Mask, Pattern, Sniffed Type, Has leading "WS" flag, Security Flag
  ## (1 = Safe, 0 = Otherwise)
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

sub _mime ($) {
  return Web::MIME::Type->parse_web_mime_type ($_[0]);
} # _mime

sub _table ($$) {
  my $stream_length = length $_[1];
  ROW: for my $row (@{$_[0]}) { # Pattern, Sniffed Type
    ## $row = [Mask, Pattern, Sniffed Type, Has leading WS flag, Security];
    my $pos = 0;
    if ($row->[3]) {
      $pos++ while substr ($_[1], $pos, 1) =~ /^[\x09\x0A\x0C\x0D\x20]/;
    }
    my $pattern_length = length $row->[1];
    next ROW if $pos + $pattern_length > $stream_length;
    my $data = substr ($_[1], $pos, $pattern_length) & $row->[0];
    return _mime $row->[2] if $data eq $row->[1];
  } # ROW
  return undef;
} # _table

sub detect ($$$) {
  my ($self, $mime, undef) = @_;

  my $official_type = defined $mime ? $mime->mime_type_portion : undef;

  if (not defined $official_type or
      $official_type eq 'unknown/unknown' or
      $official_type eq 'application/unknown' or
      $official_type eq '*/*') {
    {
      my $computed = _table \@ScriptableSniffingTable, $_[2];
      return $computed if defined $computed;
    }
    {
      my $computed = _table \@NonScriptableSniffingTable, $_[2];
      return $computed if defined $computed;
    }
    {
      my $computed = _table \@BOMSniffingTable, $_[2];
      return $computed if defined $computed;
    }
    {
      my $computed = _table \@ImageSniffingTable, $_[2];
      return $computed if defined $computed;
    }

    ## Step 4
    return _mime 'text/plain'
        unless $_[2] =~ /$binary_data_bytes/o;

    ## Step 5
    return _mime 'application/octet-stream';
  }

  if (defined $mime and $mime->apache_bug) { # XXX and is HTTP
    my $computed = _table \@BOM2SniffingTable, $_[2];
    return $computed if defined $computed;

    return _mime 'text/plain'
        unless $_[2] =~ /$binary_data_bytes/o;

    return _mime 'application/octet-stream';
  }

  if ($mime->is_xml_mime_type) {
    return $mime;
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
    return _mime 'text/html' unless $_[2] =~ /\G</gc;

    ## Step 10
    if ($_[2] =~ /\Grss/gc) {
      return _mime 'application/rss+xml';
    } elsif ($_[2] =~ /\Gfeed/gc) {
      return _mime 'application/atom+xml';
    } elsif ($_[2] and $_[2] =~ /\Grdf:RDF/gc) {
      # 
    } else {
      return _mime 'text/html';
    }

    ## Step 11
    ## ISSUE: Step 11 is not defined yet in the spec
    if ($_[2] =~ /\G([^>]+)/gc) {
      my $by = $1;
      if ($by =~ m!xmlns[^>=]*=[\x20\x0A\x0D\x09]*["']http://www\.w3\.org/1999/02/22-rdf-syntax-ns#["']! and
          $by =~ m!xmlns[^>=]*=[\x20\x0A\x0D\x09]*["']http://purl\.org/rss/1\.0/["']!) {
        return _mime 'application/rss+xml';
      }
    }

    ## Step 12
    return _mime 'text/html';
  }

  if ($self->{supported_image_types}->{$official_type}) {
    my $computed = _table \@ImageSniffingTable, $_[2];
    return $computed if defined $computed;

    ## Otherwise
    return $mime;
  }

  # XXX audio or video

  # XXX archive

  # XXX font

  # XXX text track

  return $mime;
} # detect

1;

=head1 LICENSE

Copyright 2007-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
