#!/bin/bash

EDGECA_DIR="$HOME/.edgeca"
SOFTHSM_DIR="$EDGECA_DIR/hsm"

rm -rf $EDGECA_DIR/hsm
mkdir -p $SOFTHSM_DIR
mkdir -p $SOFTHSM_DIR/tokens


echo "directories.tokendir = ${SOFTHSM_DIR}/tokens
objectstore.backend = file
log.level = INFO
" > $SOFTHSM_DIR/softhsm2.conf
 

SOFTHSM2_CONF=$SOFTHSM_DIR/softhsm2.conf softhsm2-util --init-token --slot 0 --label edgeca  --pin 1234 --so-pin 1234