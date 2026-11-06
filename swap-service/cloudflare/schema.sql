-- Separate from the local SQLite database. Safe to apply repeatedly to a database that already has the identity columns.
-- An existing database created before P5 needs migrations/0002_identity.sql instead (additive; back up first).
CREATE TABLE IF NOT EXISTS offers (
  id TEXT PRIMARY KEY, owner_hash TEXT NOT NULL, public INTEGER NOT NULL,
  offer TEXT NOT NULL, expires INTEGER NOT NULL, closed INTEGER NOT NULL DEFAULT 0,
  reservation_hash TEXT, reservation_id TEXT, reservation_expires INTEGER,
  owner_identity TEXT, reservation_identity TEXT
);
CREATE INDEX IF NOT EXISTS offers_public ON offers(public, closed, expires);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, offer_id TEXT NOT NULL,
  reservation_id TEXT, sender TEXT NOT NULL, payload TEXT NOT NULL, created INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_offer_session ON messages(offer_id, reservation_id, id);
CREATE TABLE IF NOT EXISTS quotas (key TEXT PRIMARY KEY, window INTEGER NOT NULL, count INTEGER NOT NULL);
