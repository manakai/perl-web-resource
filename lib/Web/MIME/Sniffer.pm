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

our @BOM1SniffingTable = (
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

sub new_from_context ($$) {
  return bless {
    context => $_[1],
    supported_image_types => {},
    supported_audio_or_video_types => {},
  }, $_[0];
} # new_from_context

sub is_http ($;$) {
  if (@_ > 1) {
    $_[0]->{is_http} = $_[1];
  }
  return $_[0]->{is_http};
} # is_http

sub supported_image_types ($) {
  return $_[0]->{supported_image_types};
} # supported_image_types

sub supported_audio_or_video_types ($) {
  return $_[0]->{supported_audio_or_video_types};
} # supported_audio_or_video_types

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

  my $sniffer = 0;
  # 0b10000000000 scriptable
  # 0b01000000000 non-scriptable
  # 0b00100000000 bom1
  # 0b00010000000 bom2
  # 0b00001000000 feed or html
  # 0b00000100000 image
  # 0b00000010000 audio or video
  # 0b00000001000 archive
  # 0b00000000100 font
  # 0b00000000010 text track
  # 0b00000000001 binary

  my $official_type = defined $mime ? $mime->mime_type_portion : undef;
  if ($self->{context} eq 'navigate') {
    if (not defined $official_type or
        $official_type eq 'unknown/unknown' or
        $official_type eq 'application/unknown' or
        $official_type eq '*/*') {
      $sniffer = 0b11100110001;
      undef $mime;
    } elsif ($mime->apache_bug and $self->is_http) {
      $sniffer = 0b00010000001;
    } elsif ($mime->is_xml_mime_type) {
      return $mime;
    } elsif ($official_type eq 'text/html') {
      # XXX these steps need to be updated

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
    } elsif ($self->{supported_image_types}->{$official_type} and
             $mime->is_image) {
      $sniffer = 0b00000100000;
    } elsif ($self->{supported_audio_or_video_types}->{$official_type} and
             $mime->is_audio_or_video) {
      $sniffer = 0b00000010000;
    } else {
      #
    }
  # XXX audio_or_video
  # XXX font
  # XXX text_track
  # XXX object
  } else {
    die "Bad context |$self->{context}|";
  }

  if ($sniffer & 0b10000000000) {
    my $computed = _table \@ScriptableSniffingTable, $_[2];
    return $computed if defined $computed;
  }

  if ($sniffer & 0b01000000000) {
    my $computed = _table \@NonScriptableSniffingTable, $_[2];
    return $computed if defined $computed;
  }

  if ($sniffer & 0b00100000000) {
    my $computed = _table \@BOM1SniffingTable, $_[2];
    return $computed if defined $computed;
  }

  if ($sniffer & 0b00010000000) {
    my $computed = _table \@BOM2SniffingTable, $_[2];
    return $computed if defined $computed;
  }

  if ($sniffer & 0b00000100000) {
    my $computed = _table \@ImageSniffingTable, $_[2];
    return $computed if defined $computed;
  }

  if ($sniffer & 0b00000010000) {
    # XXX audio or video
  }

  if ($sniffer & 0b00000001000) {
    # XXX archive
  }

  if ($sniffer & 0b00000000100) {
    # XXX font
  }

  if ($sniffer & 0b00000000010) {
    # XXX text track
  }

  if ($sniffer & 0b00000000001) {
    return _mime 'application/octet-stream'
        if $_[2] =~ /[\x00-\x08\x0B\x0E-\x1A\x1C-\x1F]/;
  }

  return $mime || _mime 'text/plain';
} # detect

1;

=head1 LICENSE

Copyright 2007-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
