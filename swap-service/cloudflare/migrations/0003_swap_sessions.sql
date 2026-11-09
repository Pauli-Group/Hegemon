-- An accepted swap outlives the offer listing and its short reservation.
-- Only hashes of the existing participant credentials and opaque packets are stored.
CREATE TABLE IF NOT EXISTS swap_sessions (
  id TEXT PRIMARY KEY,
  offer_id TEXT NOT NULL,
  reservation_id TEXT NOT NULL,
  owner_hash TEXT NOT NULL,
  taker_hash TEXT NOT NULL,
  offer_snapshot TEXT NOT NULL,
  created INTEGER NOT NULL,
  expires INTEGER NOT NULL,
  UNIQUE (offer_id, reservation_id)
);
CREATE TABLE IF NOT EXISTS swap_packets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  sender TEXT NOT NULL CHECK (sender IN ('owner', 'taker')),
  sequence INTEGER NOT NULL CHECK (sequence BETWEEN 1 AND 256),
  ciphertext TEXT NOT NULL,
  created INTEGER NOT NULL,
  UNIQUE (session_id, sender, sequence)
);
CREATE INDEX IF NOT EXISTS swap_packets_session ON swap_packets(session_id, id);
