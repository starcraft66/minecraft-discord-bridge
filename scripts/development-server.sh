#!/usr/bin/env bash

set -e

if [[ -n "${BRIDGE_DEBUG}" ]]; then
    set -x
fi

function usage() {
  echo -n \
  "Usage: $(basename "$0") [-h] [-r]
Start development bridge & minecraft server
-h  show this text
-r  rebuild containers before starting
"
}

function default() {
  touch db.sqlite
  docker-compose -f docker-compose.development.yml up
}

while getopts "hr" arg; do
  case ${arg} in
    h)
      usage
      exit 0
      ;;
    r)
      touch db.sqlite
      docker-compose -f docker-compose.development.yml up --build
      exit 0
      ;;
    *)
      echo "Invalid option: -${OPTARG}."
      exit 2
      ;;
  esac
done

default
