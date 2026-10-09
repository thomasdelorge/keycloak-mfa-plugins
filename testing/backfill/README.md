# Backfill test: Postgres + Keycloak + app-authenticator

Two things live here:

1. A **scale check** (steps 1-6 below) that the startup backfill correctly indexes ~4000
   pre-existing `APP_CREDENTIAL` rows into `APP_AUTH_CREDENTIAL_INDEX` on a real Postgres backend.
2. A **functional check** (further down) that a real device credential registered and used
   *before* `AppAuthCredentialIndex` existed still authenticates correctly *after* upgrading to
   the jar that introduces it - i.e. the migration doesn't break a real login, not just DB row
   counts.

Files in this directory:
- `docker-compose.yml` - Postgres 16 + Keycloak 26.7.2, with `jars/active.jar` mounted into
  `/opt/keycloak/providers/app-authenticator.jar`.
- `build-jars.sh` - builds two app-authenticator jars into `jars/`: `app-authenticator-pre-index.jar`
  (last commit before `AppAuthCredentialIndex` existed) and `app-authenticator-with-index.jar`
  (the ref under test, defaults to `HEAD`). Swapping which one is active is just copying it to
  `jars/active.jar` and restarting Keycloak.
- `seed-credentials.sql` - inserts 4000 unindexed `APP_CREDENTIAL` rows directly into Keycloak's
  `credential` table (simulating credentials that existed before this feature was added), for the
  scale check.
- `realm-export.json` - a `dev` realm, imported automatically on first boot (`--import-realm`),
  with its browser flow already set to a copy that has `app-authenticator` wired in as an
  alternative execution, the `app-register` required action enabled, and a `user`/`pass` user
  - so the functional check below doesn't need any manual realm/flow/user setup.

## 1. Build the jars

All commands below assume `testing/backfill` as the working directory - each block starts with
`cd testing/backfill` so it also works when run from the repo root (e.g. IntelliJ's markdown
"run" executes fenced blocks from the repo root, not this file's directory).

```bash
cd testing/backfill
./build-jars.sh
```
Re-run this after any code change to app-authenticator. Pass explicit refs to override the
defaults, e.g. `./build-jars.sh <pre-index-commit> <with-index-branch>`.

## 2. First boot: create schema

```bash
cd testing/backfill
cp jars/app-authenticator-with-index.jar jars/active.jar
docker compose up -d
docker compose logs -f keycloak
```
Wait for the Keycloak ready line (dev mode prints something like
`Listening on: http://0.0.0.0:8080`), then Ctrl-C the log follow. This first boot:
- runs Keycloak's own schema migrations,
- runs this plugin's Liquibase changelog, creating `app_auth_credential_index`,
- runs the backfill once as a no-op (0 `APP_CREDENTIAL` rows exist yet),
- imports the `dev` realm from `realm-export.json` (`--import-realm`),
- creates the `master` realm and the `admin` user (from `KEYCLOAK_ADMIN`/`KEYCLOAK_ADMIN_PASSWORD`
  in `docker-compose.yml`).

## 3. Stop Keycloak and seed 4000 credentials

```bash
cd testing/backfill
docker compose stop keycloak
docker compose exec -T postgres psql -U keycloak -d keycloak < seed-credentials.sql
```

Sanity-check before restarting:
```bash
cd testing/backfill
docker compose exec postgres psql -U keycloak -d keycloak -c \
  "select count(*) from credential where type='APP_CREDENTIAL';"
docker compose exec postgres psql -U keycloak -d keycloak -c \
  "select count(*) from app_auth_credential_index;"
```

## 4. Restart Keycloak to trigger the backfill

```bash
cd testing/backfill
docker compose start keycloak
docker compose logs -f keycloak
```
There's no happy-path success log line for the backfill (only `warnf` on skip/conflict - see
`AppAuthCredentialIndexJpaEntityProviderFactory`), so watch for the *absence* of warnings from
`netzbegruenung.keycloak.app.jpa.AppAuthCredentialIndexJpaEntityProviderFactory` rather than a
success message.

## 5. Verify

```bash
cd testing/backfill
docker compose exec postgres psql -U keycloak -d keycloak -c \
  "select count(*) from app_auth_credential_index;"

docker compose exec postgres psql -U keycloak -d keycloak -c \
  "select count(*) from credential c where c.type='APP_CREDENTIAL' \
   and not exists (select 1 from app_auth_credential_index i where i.credential_id = c.id);"
```

Success = exactly 4000 indexed rows, 0 leftover unindexed rows, and no warning lines in the
Keycloak logs from the backfill (a warning would mean a `device_id` collision or unreadable
`credential_data` - shouldn't happen since the seed script gives every row a unique device_id).

This restart is also a good moment to eyeball how long the backfill takes: it should complete in
roughly a second for 4000 rows (the batched-flush fix from commits `520ea3d`/`57b7603` - before
that fix, per-row flushing took ~16-17s on Postgres for the same 4000 rows).

## 6. Cleanup

```bash
cd testing/backfill
docker compose down -v
```
Tears down both containers and the `pgdata` volume, so a re-run starts from a clean schema.

---

## Functional check: real login across the migration

This exercises an actual device registration and login - not seeded rows - to confirm the
migration doesn't break authentication for a credential that predates it. Bring your own client
(a real device/app, or whatever harness you already use to drive app-authenticator); this repo
doesn't script the registration/signing side.

1. **Start from a clean slate with the pre-index jar**, so the credential you register genuinely
   predates `AppAuthCredentialIndex`:
   ```bash
   cd testing/backfill
   docker compose down -v   # if anything from the scale check above is still running
   cp jars/app-authenticator-pre-index.jar jars/active.jar
   docker compose up -d
   ```
2. `realm-export.json` was imported on that first boot, so the `dev` realm already has its browser
   flow set to a copy with `app-authenticator` wired in and the `app-register` required action
   enabled - no manual flow setup needed. Log into the `dev` realm's account console
   (`/realms/dev/account`) as `user`/`pass` and register a real device credential through the
   actual app-register flow. Log in once with it and confirm it works.
3. Confirm there's no index table yet - this jar doesn't have the feature:
   ```bash
   cd testing/backfill
   docker compose exec postgres psql -U keycloak -d keycloak -c \
     "select to_regclass('app_auth_credential_index');"
4. **Swap to the with-index jar** without touching the database:
   ```bash
   cd testing/backfill
   docker compose stop keycloak
   cp jars/app-authenticator-with-index.jar jars/active.jar
   docker compose start keycloak
   docker compose logs -f keycloak
   ```
   This boot creates `app_auth_credential_index` and runs the backfill, which should pick up the
   credential you registered in step 2 (no warnings expected in the logs).
5. Confirm it got indexed:
   ```bash
   cd testing/backfill
   docker compose exec postgres psql -U keycloak -d keycloak -c \
     "select * from app_auth_credential_index;"
   ```
6. **Log in again with the same real device/credential** and confirm it still succeeds. This is
   the actual regression check: a credential created before the index existed must keep
   authenticating after the upgrade.
