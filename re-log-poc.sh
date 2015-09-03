#!/bin/bash
echo "deleting /tmp/esteid-tokend.log"
rm -rf /tmp/esteid-tokend.log
echo "creating /tmp/esteid-tokend.log"
touch /tmp/esteid-tokend.log
echo "chmod 766 /tmp/esteid-tokend.log"
chmod 766 /tmp/esteid-tokend.log
echo "opening /tmp/esteid-tokend.log"
open /tmp/esteid-tokend.log