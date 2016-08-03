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

test-main:
	DUMP=1 WEBUA_DEBUG=2 TEST_CONCUR=1 TEST_METHOD="270" ./perl t/parsing.t
	DUMP=1 WEBUA_DEBUG=2 TEST_CONCUR=1 TEST_METHOD="293" ./perl t/parsing.t
	WEBUA_DEBUG=1 ./perl sketch/client.pl --url https://www.amazon.co.jp
	DUMP=1 WEBUA_DEBUG=2 TEST_CONCUR=1 TEST_METHOD="Stapled, good" ./perl t/parsing.t
	$(PROVE) t/*.t

## License: Public Domain.
