#!/bin/bash

printenv | sed 's/^\(.*\)$/export \1/g' > /.env.sh
chmod +x /.env.sh

exec "$@"