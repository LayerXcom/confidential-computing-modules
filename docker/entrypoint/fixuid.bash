#!/bin/bash

if [ "$DISABLE_FIXUID" = 1 ]; then
  echo 'skip fixuid'
else
  echo 'Running fixuid. Wait a while...'
  fixuid -q
fi

bash
