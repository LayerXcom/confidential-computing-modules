#!/bin/bash
[ "$DISABLE_FIXUID" = 1 ] && echo 'skip fixuid' || fixuid
bash
