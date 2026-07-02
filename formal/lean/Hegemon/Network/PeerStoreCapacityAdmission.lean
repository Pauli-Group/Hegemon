namespace Hegemon
namespace Network
namespace PeerStoreCapacityAdmission

def defaultMaxPeerStoreEntries : Nat :=
  512

structure PeerStoreEntry where
  id : Nat
  recencyRank : Nat
deriving DecidableEq, Repr

def enforcePeerStoreCapacity
    (maxEntries : Nat)
    (entriesByRecency : List PeerStoreEntry) : List PeerStoreEntry :=
  entriesByRecency.take maxEntries

def enforcePeerStoreEntryIds
    (maxEntries : Nat)
    (entriesByRecency : List PeerStoreEntry) : List Nat :=
  (enforcePeerStoreCapacity maxEntries entriesByRecency).map (fun entry => entry.id)

def droppedPeerStoreCapacity
    (maxEntries : Nat)
    (entriesByRecency : List PeerStoreEntry) : List PeerStoreEntry :=
  entriesByRecency.drop maxEntries

def droppedPeerStoreEntryIds
    (maxEntries : Nat)
    (entriesByRecency : List PeerStoreEntry) : List Nat :=
  (droppedPeerStoreCapacity maxEntries entriesByRecency).map (fun entry => entry.id)

def loadedPeerStoreEntries
    (maxEntries : Nat)
    (decodedFreshEntriesByRecency : List PeerStoreEntry) :
      List PeerStoreEntry :=
  enforcePeerStoreCapacity maxEntries decodedFreshEntriesByRecency

structure AcceptedPeerStoreCapacityFacts
    (maxEntries : Nat)
    (entriesByRecency : List PeerStoreEntry) : Prop where
  retainedEntries :
    enforcePeerStoreCapacity maxEntries entriesByRecency =
      entriesByRecency.take maxEntries
  retainedIds :
    enforcePeerStoreEntryIds maxEntries entriesByRecency =
      (entriesByRecency.take maxEntries).map (fun entry => entry.id)
  droppedEntries :
    droppedPeerStoreCapacity maxEntries entriesByRecency =
      entriesByRecency.drop maxEntries
  droppedIds :
    droppedPeerStoreEntryIds maxEntries entriesByRecency =
      (entriesByRecency.drop maxEntries).map (fun entry => entry.id)
  retainedDroppedPartition :
    enforcePeerStoreCapacity maxEntries entriesByRecency ++
      droppedPeerStoreCapacity maxEntries entriesByRecency =
        entriesByRecency
  retainedCountBound :
    (enforcePeerStoreCapacity maxEntries entriesByRecency).length <= maxEntries

theorem accepted_peer_store_capacity_exposes_bound
    (maxEntries : Nat)
    (entriesByRecency : List PeerStoreEntry) :
    AcceptedPeerStoreCapacityFacts maxEntries entriesByRecency := by
  exact {
    retainedEntries := rfl,
    retainedIds := rfl,
    droppedEntries := rfl,
    droppedIds := rfl,
    retainedDroppedPartition := by
      unfold enforcePeerStoreCapacity droppedPeerStoreCapacity
      exact List.take_append_drop maxEntries entriesByRecency,
    retainedCountBound := by
      unfold enforcePeerStoreCapacity
      exact List.length_take_le maxEntries entriesByRecency
  }

theorem peer_store_capacity_retains_recency_prefix
    (maxEntries : Nat)
    (entriesByRecency : List PeerStoreEntry) :
    enforcePeerStoreEntryIds maxEntries entriesByRecency =
      (entriesByRecency.take maxEntries).map (fun entry => entry.id) := by
  rfl

theorem peer_store_capacity_drops_recency_suffix
    (maxEntries : Nat)
    (entriesByRecency : List PeerStoreEntry) :
    droppedPeerStoreEntryIds maxEntries entriesByRecency =
      (entriesByRecency.drop maxEntries).map (fun entry => entry.id) := by
  rfl

theorem peer_store_capacity_retained_and_dropped_partition_entries
    (maxEntries : Nat)
    (entriesByRecency : List PeerStoreEntry) :
    enforcePeerStoreCapacity maxEntries entriesByRecency ++
      droppedPeerStoreCapacity maxEntries entriesByRecency =
        entriesByRecency := by
  unfold enforcePeerStoreCapacity droppedPeerStoreCapacity
  exact List.take_append_drop maxEntries entriesByRecency

theorem loaded_peer_store_entries_within_capacity
    (maxEntries : Nat)
    (decodedFreshEntriesByRecency : List PeerStoreEntry) :
    (loadedPeerStoreEntries maxEntries decodedFreshEntriesByRecency).length <=
      maxEntries := by
  unfold loadedPeerStoreEntries enforcePeerStoreCapacity
  exact List.length_take_le maxEntries decodedFreshEntriesByRecency

theorem loaded_peer_store_retains_recency_prefix
    (maxEntries : Nat)
    (decodedFreshEntriesByRecency : List PeerStoreEntry) :
    loadedPeerStoreEntries maxEntries decodedFreshEntriesByRecency =
      decodedFreshEntriesByRecency.take maxEntries := by
  rfl

def belowLimitEntries : List PeerStoreEntry :=
  [
    { id := 101, recencyRank := 4 },
    { id := 102, recencyRank := 3 }
  ]

def exactLimitEntries : List PeerStoreEntry :=
  [
    { id := 201, recencyRank := 3 },
    { id := 202, recencyRank := 2 },
    { id := 203, recencyRank := 1 }
  ]

def overLimitEntries : List PeerStoreEntry :=
  [
    { id := 301, recencyRank := 5 },
    { id := 302, recencyRank := 4 },
    { id := 303, recencyRank := 3 },
    { id := 304, recencyRank := 2 },
    { id := 305, recencyRank := 1 }
  ]

theorem below_limit_peer_store_capacity_accepts_all :
    enforcePeerStoreEntryIds 4 belowLimitEntries = [101, 102] := by
  rfl

theorem exact_limit_peer_store_capacity_accepts_all :
    enforcePeerStoreEntryIds 3 exactLimitEntries = [201, 202, 203] := by
  rfl

theorem over_limit_peer_store_capacity_keeps_recent_prefix :
    enforcePeerStoreEntryIds 3 overLimitEntries = [301, 302, 303] := by
  rfl

theorem over_limit_peer_store_capacity_drops_old_suffix :
    droppedPeerStoreEntryIds 3 overLimitEntries = [304, 305] := by
  rfl

theorem zero_limit_peer_store_capacity_keeps_none :
    enforcePeerStoreEntryIds 0 overLimitEntries = [] := by
  rfl

theorem zero_limit_peer_store_capacity_drops_all :
    droppedPeerStoreEntryIds 0 overLimitEntries =
      [301, 302, 303, 304, 305] := by
  rfl

end PeerStoreCapacityAdmission
end Network
end Hegemon
