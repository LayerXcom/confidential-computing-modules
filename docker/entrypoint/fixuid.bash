#!/bin/bash

FIXUID_MODE=${FIXUID_MODE:-quiet}

if [ "$FIXUID_MODE" = "skip" ]; then
  echo 'skip fixuid'
elif [ "$FIXUID_MODE" = "quiet" ]; then
  echo 'Running fixuid. Wait a while...'
  fixuid -q
elif [ "$FIXUID_MODE" = "verbose" ]; then
  fixuid
else
  echo "\$FIXUID_MODE='$FIXUID_MODE', which should be one of: 'skip', 'verbose', and 'quiet' (default)."
fi

bash
