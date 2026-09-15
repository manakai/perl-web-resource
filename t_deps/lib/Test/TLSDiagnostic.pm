package Test::TLSDiagnostic;
use strict;
use warnings;
use Time::HiRes ();

my $event_pid = $$;
my $event_count = 0;

sub event {
  local $!;
  local $@;
  local $?;
  return unless $ENV{WEB_TRANSPORT_TLS_DIAG};
  eval {
    if ($event_pid != $$) {
      $event_pid = $$;
      $event_count = 0;
    }
    return if $event_count >= 20000;
    $event_count++;
    my @fields = map {
      my $value = !defined $_ ? '<undef>' : ref $_ ? ref $_ : "$_";
      $value =~ s/([^\x20-\x7e])/sprintf('\\x{%x}', ord $1)/ge;
      $value;
    } @_;
    push @fields, 'event-limit-reached' if $event_count == 20000;
    my $line = sprintf("TLS_DIAG %.6f pid=%d %s\n",
                       Time::HiRes::time(), $$, join(' ', @fields));
    syswrite STDERR, $line;
  };
  return;
}

sub environment {
  local $!;
  local $@;
  local $?;
  return unless $ENV{WEB_TRANSPORT_TLS_DIAG};
  event('environment', "perl=$]", "os=$^O");
  my $loaded = eval {
    require Net::SSLeay;
    event('environment.ssl', $Net::SSLeay::VERSION,
          Net::SSLeay::SSLeay_version(0));
    1;
  };
  event('environment.ssl.unavailable') unless $loaded;
  return;
}

1;
