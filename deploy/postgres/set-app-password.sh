# Piped into `sh -s` inside the postgres container by `make deploy-migrate`.
# 000_rls.sql creates ctem_app with a fixed dev password; this rotates it to
# CTEM_APP_DB_PASSWORD from .env.prod. psql's :'var' form quotes it safely.
psql -v ON_ERROR_STOP=1 -U ctem -d ctem -v pw="$CTEM_APP_DB_PASSWORD" \
  -c "ALTER ROLE ctem_app PASSWORD :'pw'"
