use strict;
use warnings;
use Path::Tiny;
use lib path (__FILE__)->parent->parent->child ('lib')->stringify;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib')->stringify;
use Test::More;
use Test::X1;
use Test::HTCT::Parser;
use Web::MIME::Type;
use Web::MIME::Sniffer;

my $test_data_path = path (__FILE__)->parent->parent->child
    ('t_deps/tests/mime/sniffing');
for my $path ($test_data_path->children (qr/\.dat$/)) {
  my $rel_path = $path->relative ($test_data_path);
  for_each_test $path, {}, sub {
    my $test = $_[0];

    my $input_data = $test->{data}->[0];
    $input_data =~ s/\\x([0-9A-Fa-f]{2})/pack 'C', hex $1/ge;

    my $x = sub {
      if (($test->{computed}->[1]->[0] || '') eq 'supplied') {
        return defined $_[0] ? $_[0]->as_valid_mime_type : 'text/plain';
      } else {
        return $test->{computed}->[0];
      }
    };

    my $ct_type = $test->{'content-type'}->[1]->[0] || '';
    if ($ct_type eq '') {
      test {
        my $c = shift;
        my $sniffer = Web::MIME::Sniffer->new_from_context
            ($test->{context}->[1]->[0]);
        $sniffer->is_http (1) unless $test->{nonhttp};
        $sniffer->supported_image_types->{$_} = 1 for qw(image/jpeg);

        my $content_type = Web::MIME::Type->parse_web_mime_type
            ($test->{'content-type'}->[0]);
        my $st = $sniffer->detect ($content_type, $input_data);
        is $st->as_valid_mime_type_with_no_params, $x->($content_type);

        done $c;
      } n => 1, name => [$rel_path, $test->{name}->[0]];
    } elsif ($ct_type eq 'unknown') {
      for my $ct (undef, 'application/unknown', 'unknown/unknown', '*/*',
                  'text', '{content_type}', '') {
        test {
          my $c = shift;
          my $sniffer = Web::MIME::Sniffer->new_from_context
              ($test->{context}->[1]->[0]);
          $sniffer->is_http (1) unless $test->{nonhttp};
          $sniffer->supported_image_types->{$_} = 1 for qw(image/jpeg);

          my $content_type = defined $ct ? Web::MIME::Type->parse_web_mime_type ($ct, sub { }) : undef;
          my $st = $sniffer->detect ($content_type, $input_data);
          is $st->as_valid_mime_type_with_no_params, $x->($content_type);

          done $c;
        } n => 1, name => [$rel_path, $test->{name}->[0] || $test->{data}->[0], $ct];
      } # $ct
    } elsif ($ct_type eq 'image') {
      for my $img_type (qw(image/png image/gif image/jpeg image/x-icon)) {
        my $content_type = Web::MIME::Type->parse_web_mime_type ($img_type);

        test {
          my $c = shift;

          test {
            my $sniffer = Web::MIME::Sniffer->new_from_context
                ($test->{context}->[1]->[0]);
            $sniffer->is_http (1) unless $test->{nonhttp};
            my $st = $sniffer->detect ($content_type, $input_data);
            if ($test->{context}->[1]->[0] eq 'text_track') {
              is $st->as_valid_mime_type_with_no_params, $x->($content_type), 'computed type';
            } else {
              is $st->as_valid_mime_type_with_no_params, $img_type, 'computed type';
            }
          } $c, name => 'If there is no supported type';

          test {
            my $sniffer = Web::MIME::Sniffer->new_from_context
                ($test->{context}->[1]->[0]);
            $sniffer->is_http (1) unless $test->{nonhttp};
            $sniffer->supported_image_types->{$img_type} = 1;
            my $st = $sniffer->detect ($content_type, $input_data);
            is $st->as_valid_mime_type_with_no_params, $x->($content_type);
          } $c, name => 'If it is the only supported type';

          test {
            my $sniffer = Web::MIME::Sniffer->new_from_context
                ($test->{context}->[1]->[0]);
            $sniffer->is_http (1) unless $test->{nonhttp};
            $sniffer->supported_image_types->{$_} = 1 for qw(
              image/png image/jpeg image/gif image/bmp image/vnd.microsoft.icon
              image/x-icon
            );
            my $st = $sniffer->detect ($content_type, $input_data);
            is $st->as_valid_mime_type_with_no_params, $x->($content_type);
          } $c, name => 'If all types are supported';

          done $c;
        } n => 3, name => [$rel_path, $test->{name}->[0], $img_type];
      } # $img_type
    } elsif ($ct_type eq 'audio_or_video') {
      for my $img_type (qw(audio/basic audio/aiff audio/mpeg)) {
        my $content_type = Web::MIME::Type->parse_web_mime_type ($img_type);

        test {
          my $c = shift;

          test {
            my $sniffer = Web::MIME::Sniffer->new_from_context
                ($test->{context}->[1]->[0]);
            $sniffer->is_http (1) unless $test->{nonhttp};
            my $st = $sniffer->detect ($content_type, $input_data);
            if ($test->{context}->[1]->[0] eq 'text_track') {
              is $st->as_valid_mime_type_with_no_params, $x->($content_type), 'computed type';
            } else {
              is $st->as_valid_mime_type_with_no_params, $img_type, 'computed type';
            }
          } $c, name => 'If there is no supported type';

          test {
            my $sniffer = Web::MIME::Sniffer->new_from_context
                ($test->{context}->[1]->[0]);
            $sniffer->is_http (1) unless $test->{nonhttp};
            $sniffer->supported_audio_or_video_types->{$img_type} = 1;
            my $st = $sniffer->detect ($content_type, $input_data);
            is $st->as_valid_mime_type_with_no_params, $x->($content_type);
          } $c, name => 'If it is the only supported type';

          test {
            my $sniffer = Web::MIME::Sniffer->new_from_context
                ($test->{context}->[1]->[0]);
            $sniffer->is_http (1) unless $test->{nonhttp};
            $sniffer->supported_audio_or_video_types->{$_} = 1 for qw(
              audio/basic audio/aiff audio/mpeg
            );
            my $st = $sniffer->detect ($content_type, $input_data);
            is $st->as_valid_mime_type_with_no_params, $x->($content_type);
          } $c, name => 'If all types are supported';

          done $c;
        } n => 3, name => [$rel_path, $test->{name}->[0], $img_type];
      } # $img_type
    } elsif ($ct_type eq 'others') {
      for my $img_type (qw(text/css audio/mpeg application/octet-stream
                           image/png font/ttf)) {
        my $content_type = Web::MIME::Type->parse_web_mime_type ($img_type);
        test {
          my $c = shift;
          my $sniffer = Web::MIME::Sniffer->new_from_context
              ($test->{context}->[1]->[0]);
          $sniffer->is_http (1) unless $test->{nonhttp};
          $sniffer->supported_audio_or_video_types->{$img_type} = 1;
          my $st = $sniffer->detect ($content_type, $input_data);
          is $st->as_valid_mime_type_with_no_params, $x->($content_type);
          done $c;
        } n => 1, name => [$rel_path, $test->{name}->[0], $img_type];
      } # $img_type
    } else {
      die "Bad ct_type |$ct_type|";
    }
  };
} # $path

## XXX We should test image sniffing rules standalone actually...

run_tests;

## License: Public Domain.
