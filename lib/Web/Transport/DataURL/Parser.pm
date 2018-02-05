package Web::Transport::DataURL::Parser;
use strict;
use warnings;
our $VERSION = '1.0';
use Carp;
use Web::Encoding;
use Web::URL::Encoding;
use Web::MIME::Type::Parser;
use Web::Transport::Base64;
use Web::Transport::DataURL;

sub new ($) {
  return bless {}, $_[0];
} # new

sub onerror ($;$) {
  if (@_ > 1) {
    $_[0]->{onerror} = $_[1];
  }
  return $_[0]->{onerror} ||= sub {
    my %opt = @_;
    my @msg = ($opt{type});
    push @msg, $opt{value} if defined $opt{value};
    warn join '; ', @msg, "\n";
  };
} # onerror

sub parse_url ($$) {
  my ($self, $url) = @_;
  croak "Not a data: URL" unless $url->scheme eq 'data';

  my $onerror = $self->onerror;

  my $input = $url->stringify_without_fragment;
  my ($mime_string, $body) = split /,/, $input, 2;

  unless (defined $body) {
    $onerror->(type => 'URL:data:no ,',
               level => 'm');
    return undef;
  }

  $mime_string =~ s/^data://;
  $mime_string =~ s/\A[\x09\x0A\x0C\x0D\x20]+//;
  $mime_string =~ s/[\x09\x0A\x0C\x0D\x20]+\z//;

  ## string percent decode
  $body = percent_decode_b encode_web_utf8 $body;

  if ($mime_string =~ s{;\x20*[Bb][Aa][Ss][Ee]64\z}{}) {
    $body = decode_web_base64 $body;
    unless (defined $body) {
      $onerror->(type => 'URL:data:bad base64 data',
                 level => 'm');
      return undef;
    }
  }

  $mime_string = 'text/plain' . $mime_string if $mime_string =~ /^;/;

  my $mime;
  my $mime_parser = Web::MIME::Type::Parser->new;
  if (length $mime_string) {
    $mime_parser->onerror (sub {
      my %error = @_;
      delete $error{index};
      $error{value} = $mime_string unless defined $error{value};
      $onerror->(%error);
    });
    $mime = $mime_parser->parse_string ($mime_string);
  }
  $mime = $mime_parser->parse_string ('text/plain;charset=US-ASCII')
      unless defined $mime;

  return Web::Transport::DataURL->new_from_mime_and_scalarref ($mime, \$body);
} # parse_url

1;

=head1 LICENSE

Copyright 2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
