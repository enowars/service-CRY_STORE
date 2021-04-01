#!/bin/sh
touch data/store.db
sqlite3 data/store.db < init_client.sql
socat TCP4-LISTEN:1337,fork,reuseaddr EXEC:'python3 /service/cry.py'
