SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c

GHC  ?= 9.12

dev:
	ghciwatch --clear --no-interrupt-reloads \
		--command 'cabal repl --repl-options=-fno-code' \
		--error-file ghcid.txt \
		--watch .
