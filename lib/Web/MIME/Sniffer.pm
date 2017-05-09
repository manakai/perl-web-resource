package Web::MIME::Sniffer;
use strict;
use warnings;
our $VERSION = '1.20';
use Web::MIME::Type;
use Web::MIME::_TypeDefs;

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

sub _t ($$) {
  for (@{$_[0]}) {
    if ($_[1] =~ /^$_->[0]/) {
      return _mime $_->[1];
    }
  }
  return undef;
} # _t

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
  } elsif ($self->{context} eq 'text_track') {
    unless (defined $mime and $mime->is_xml_mime_type) {
      $sniffer = 0b00000000010;
    }
  } elsif ($self->{context} eq 'object') {
    if (not defined $official_type or
        $official_type eq 'unknown/unknown' or
        $official_type eq 'application/unknown' or
        $official_type eq '*/*') {
      $sniffer = 0b11100110001;
      undef $mime;
    } elsif ($official_type eq 'text/plain') {
      $sniffer = 0b00010000001;
    }
  } else {
    die "Bad context |$self->{context}|";
  }

  if ($sniffer & 0b10000000000) {
    my $computed = _t $Web::MIME::_TypeDefs::Sniffing->{scriptable}, $_[2];
    return $computed if defined $computed;
  }

  if ($sniffer & 0b01000000000) {
    my $computed = _t $Web::MIME::_TypeDefs::Sniffing->{non_scriptable}, $_[2];
    return $computed if defined $computed;
  }

  if ($sniffer & 0b00100000000) {
    my $computed = _t $Web::MIME::_TypeDefs::Sniffing->{bom1}, $_[2];
    return $computed if defined $computed;
  }

  if ($sniffer & 0b00010000000) {
    my $computed = _t $Web::MIME::_TypeDefs::Sniffing->{bom2}, $_[2];
    return $computed if defined $computed;
  }

  if ($sniffer & 0b00000100000) {
    my $computed = _t $Web::MIME::_TypeDefs::Sniffing->{image}, $_[2];
    return $computed if defined $computed;
  }

  if ($sniffer & 0b00000010000) {
    my $computed = _t $Web::MIME::_TypeDefs::Sniffing->{audio_or_video}, $_[2];
    return $computed if defined $computed;

    # XXX MP4
    ## <https://mimesniff.spec.whatwg.org/#signature-for-mp4>

    # XXX WebM
    ## <https://mimesniff.spec.whatwg.org/#signature-for-webm>

    # XXX MP3
    ## <https://mimesniff.spec.whatwg.org/#signature-for-mp3-without-id3>

  }

  if ($sniffer & 0b00000001000) {
    my $computed = _t $Web::MIME::_TypeDefs::Sniffing->{archive}, $_[2];
    return $computed if defined $computed;
  }

  if ($sniffer & 0b00000000100) {
    my $computed = _t $Web::MIME::_TypeDefs::Sniffing->{font}, $_[2];
    return $computed if defined $computed;
  }

  if ($sniffer & 0b00000000010) {
    my $computed = _t $Web::MIME::_TypeDefs::Sniffing->{text_track}, $_[2];
    return $computed if defined $computed;
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
