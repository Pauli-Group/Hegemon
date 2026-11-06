-- P5: signed identity statements. Additive only: two nullable columns, no data is changed or removed.
-- Apply ONCE to a database created before P5, BEFORE deploying the Worker that reads them (the reserve statement writes
-- reservation_identity). A database created from schema.sql after P5 already has these columns; do not apply this to it.
--   1. Back up:   wrangler d1 export hegemon-swap-testnet --remote --output d1-backup-$(date +%F).sql
--   2. Check:     wrangler d1 execute hegemon-swap-testnet --remote --command "PRAGMA table_info(offers)"
--                 (apply only if owner_identity is absent)
--   3. Migrate:   wrangler d1 execute hegemon-swap-testnet --remote --file swap-service/cloudflare/migrations/0002_identity.sql
--   4. Deploy the Worker.
-- Rollback: the old Worker ignores the extra columns, so redeploying it is enough; the columns can stay.
ALTER TABLE offers ADD COLUMN owner_identity TEXT;
ALTER TABLE offers ADD COLUMN reservation_identity TEXT;
