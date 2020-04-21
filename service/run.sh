#!/bin/sh
touch flags.db
sqlite3 flags.db < init_client.sql
socat TCP4-LISTEN:1337,fork EXEC:'python3 /service/cry.py'