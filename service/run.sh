#!/bin/sh
touch data/flags.db
sqlite3 data/flags.db < init_client.sql
socat TCP4-LISTEN:1337,fork,reuseaddr EXEC:'python3 /service/cry.py'