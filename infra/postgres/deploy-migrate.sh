#!/bin/sh

set -eu

/opt/kovcheg/migrate.sh
exec /opt/kovcheg/configure-oidc-clients.sh
