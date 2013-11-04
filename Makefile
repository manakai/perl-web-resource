# -*- Makefile -*-

WGET = wget
GIT = git
PERL = ./perl

all: deps update

update: lib/Web/MIME/_TypeDefs.pm

clean:
	rm -fr local/mime-types.json

dataautoupdate: clean deps update
	$(GIT) add lib/Web/MIME/_TypeDefs.pm

## ------ Setup ------

deps: git-submodules pmbp-install

git-submodules:
	$(GIT) submodule update --init

local/bin/pmbp.pl:
	mkdir -p local/bin
	$(WGET) -O $@ https://raw.github.com/wakaba/perl-setupenv/master/bin/pmbp.pl
pmbp-upgrade: local/bin/pmbp.pl
	perl local/bin/pmbp.pl --update-pmbp-pl
pmbp-update: git-submodules pmbp-upgrade
	perl local/bin/pmbp.pl --update
pmbp-install: pmbp-upgrade
	perl local/bin/pmbp.pl --install \
            --create-perl-command-shortcut perl \
            --create-perl-command-shortcut prove

## ------ Build ------

lib/Web/MIME/_TypeDefs.pm: local/mime-types.json bin/generate-list.pl
	$(PERL) bin/generate-list.pl < $< > $@
local/mime-types.json:
	$(WGET) -O $@ https://raw.github.com/manakai/data-web-defs/master/data/mime-types.json

## ------ Tests ------

PROVE = ./prove

test: test-deps test-main

test-deps: deps

test-main:
	$(PROVE) t/*.t