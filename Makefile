all: build

WGET = wget
GIT = git
PERL = ./perl

updatenightly: build
	$(GIT) add lib/Web/MIME/_TypeDefs.pm

clean:
	rm -fr local/mime-types.json

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
	-ls local/common/bin
	PMBP_VERBOSE=10 \
	perl local/bin/pmbp.pl \
	    --install-openssl \
	    --create-perl-command-shortcut @openssl
	ls local/common/bin
	perl local/bin/pmbp.pl \
	    --install \
            --create-perl-command-shortcut @perl \
            --create-perl-command-shortcut @prove

## ------ Build ------

build: build-deps build-main

build-deps: deps

build-main: lib/Web/MIME/_TypeDefs.pm

lib/Web/MIME/_TypeDefs.pm: local/mime-types.json bin/generate-list.pl
	$(PERL) bin/generate-list.pl < $< > $@
local/mime-types.json:
	$(WGET) -O $@ https://raw.github.com/manakai/data-web-defs/master/data/mime-types.json

## ------ Tests ------

PROVE = ./prove

test: test-deps test-main

test-deps: deps
	./perl local/bin/pmbp.pl --create-perl-command-shortcut which
	./which openssl
	local/common/bin/openssl version
	./openssl version
	./openssl ciphers
	./perl -MNet::SSLeay -e 'print +Net::SSLeay::SSLeay_version (0)'
	./perl -MNet::SSLeay -e 'print +Net::SSLeay::SSLeay_version (2)'
	./perl -MNet::SSLeay -e 'print +Net::SSLeay::SSLeay_version (3)'
	./perl -MNet::SSLeay -e 'print +Net::SSLeay::SSLeay_version (4)'

test-main:
	$(PROVE) t/*.t

## License: Public Domain.
