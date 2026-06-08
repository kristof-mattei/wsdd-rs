#!/usr/bin/env --split-string just --justfile

alias t := test


[group: "test"]
test:
  echo "hello"
  echo "world"
