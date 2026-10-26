import Hegemon.Transaction.QualifiedAssetSameExecutionV1

/-!
Literal current SMZE SHA512 framing, public-prefix decoder and four challenge
role contexts. The source reviewed here is smallwood_engine.rs. The decoder is
an ordinary executable function of current source bytes and geometry; it does
not assume authorization, accepted-proof extraction, a quantum mass bound, or
source primitive output locators. In particular no Fin77/96/16304 fallback is
used for FPP contexts. The unchanged root prefix really IS96 bytes.
-/
namespace Hegemon.Transaction.QualifiedAssetSmzeChronologyV1
set_option autoImplicit false
open Hegemon.Transaction.QualifiedAssetSourceReadoutV1

abbrev Byte := Fin 256

def le : Nat → Nat → List Byte
  | 0, _ => []
  | k+1, n => ⟨n % 256, Nat.mod_lt _ (by decide)⟩ :: le k (n / 256)

def unLe : List Byte → Nat
  | [] => 0
  | b :: bs => b.val + 256 * unLe bs

theorem le_length (k n : Nat) : (le k n).length = k := by
  induction k generalizing n with
  | zero => rfl
  | succ k ih => simp [le, ih]

theorem unLe_le_of_bound (k n : Nat) (bound : n < 256^k) : unLe (le k n) = n := by
  induction k generalizing n with
  | zero => simp only [Nat.pow_zero] at bound; simp [le, unLe, show n = 0 by omega]
  | succ k ih =>
    have small : n / 256 < 256^k := by
      apply (Nat.div_lt_iff_lt_mul (by decide : 0 < 256)).2
      simpa [Nat.pow_succ, Nat.mul_comm] using bound
    simp only [le, unLe, ih _ small]
    exact Nat.mod_add_div n 256

def wordsBytes (words : List Nat) : List Byte := words.flatMap (le 8)

def wordsAt : Nat → List Byte → List Nat
  | 0, _ => []
  | n+1, bs => unLe (bs.take 8) :: wordsAt n (bs.drop 8)

theorem wordsBytes_length (words : List Nat) : (wordsBytes words).length = 8*words.length := by
  induction words with
  | nil => rfl
  | cons n rest ih =>
    change (le 8 n ++ wordsBytes rest).length = 8 * (rest.length + 1)
    rw [List.length_append, le_length, ih]
    omega

theorem wordsAt_source_roundtrip (words : List Nat) (suffix : List Byte)
    (canonical : ∀ n ∈ words, n < 2^64) :
    wordsAt words.length (wordsBytes words ++ suffix) = words := by
  induction words with
  | nil => rfl
  | cons n rest ih =>
    have bn : n < 256^8 := by simpa using canonical n (by simp)
    have br : ∀ x ∈ rest, x < 2^64 := by intro x hx; exact canonical x (by simp [hx])
    change unLe (((le 8 n ++ wordsBytes rest) ++ suffix).take 8) ::
      wordsAt rest.length (((le 8 n ++ wordsBytes rest) ++ suffix).drop 8) = n :: rest
    rw [List.append_assoc]
    have len : (le 8 n).length = 8 := le_length 8 n
    have ht : ((le 8 n) ++ (wordsBytes rest ++ suffix)).take 8 = le 8 n := by
      exact List.take_left' len
    have hd : ((le 8 n) ++ (wordsBytes rest ++ suffix)).drop 8 = wordsBytes rest ++ suffix := by
      exact List.drop_left' len
    rw [ht, hd, unLe_le_of_bound 8 n bn, ih br]



def stringBytes (s : String) : List Byte :=
  s.toUTF8.data.toList.map (fun b => ⟨b.toNat, b.toNat_lt⟩)

def profile : String := "hegemon.smallwood.asset-spend.smze.compff01.sha512.profile.v1"

inductive Kind where
  | root | fpp | piop | decs | decsMatrix | piopMatrix | piopOpening | decsSample
  deriving DecidableEq

def domain : Kind → String
  | .root => "hegemon.smallwood.level5.merkle-root"
  | .fpp => "hegemon.smallwood.level5.piop-input"
  | .piop => "hegemon.smallwood.level5.piop-transcript"
  | .decs => "hegemon.smallwood.level5.decs-opening"
  | .decsMatrix => "hegemon.smallwood.level5.decs-coefficient"
  | .piopMatrix => "hegemon.smallwood.level5.piop-coefficient"
  | .piopOpening => "hegemon.smallwood.level5.piop-opening"
  | .decsSample => "hegemon.smallwood.asset-spend.smze.compff01.decs-fixed-sampling.v1"

def fixedHeader (kind : Kind) : List Byte :=
  le 8 (stringBytes profile).length ++ stringBytes profile ++
  le 8 (stringBytes (domain kind)).length ++ stringBytes (domain kind)

/-- The exact concrete_smallwood_sha512_oracle_query_v1 address. The profile,
role, number of absorbed words and counter are all present. -/
def rawFrame (kind : Kind) (words : List Nat) (counter : Nat) : List Byte :=
  fixedHeader kind ++ le 8 words.length ++ wordsBytes words ++ le 8 counter

def publicWords (p : Public) : List Nat := List.ofFn (fun i => (p i).val)
def publicBytes (p : Public) : List Byte := wordsBytes (publicWords p)

theorem public_bytes_are_all1072 (p : Public) : (publicBytes p).length = 1072 := by
  simp only [publicBytes, wordsBytes_length, publicWords, List.length_ofFn]

theorem decode_public_all134 (p : Public) (suffix : List Byte) :
    wordsAt 134 (publicBytes p ++ suffix) = publicWords p := by
  have canonical : ∀ n ∈ publicWords p, n < 2^64 := by
    intro n mem
    simp only [publicWords, List.mem_ofFn] at mem
    obtain ⟨i, rfl⟩ := mem
    exact Nat.lt_trans (p i).isLt (by decide)
  have h := wordsAt_source_roundtrip (publicWords p) suffix canonical
  simpa only [publicWords, publicBytes, List.length_ofFn] using h

/-- In the current source salt32 and full SHA512 root64 remain raw bytes.
The root payload therefore still has96 bytes before its134 public words. -/
def rootPayload (salt : Fin 32 → Byte) (root : Fin 64 → Byte) (p : Public) : List Byte :=
  (List.ofFn salt ++ List.ofFn root) ++ publicBytes p

theorem root_payload_preamble_from_actual96 (salt : Fin 32 → Byte)
    (root : Fin 64 → Byte) (p : Public) :
    (rootPayload salt root p).drop 96 = publicBytes p := by
  apply List.drop_left'
  simp

def fppPrefixWords (cols : Nat) : Nat := 8 + 5*(cols+58)
def fppPrefixBytes (cols : Nat) : Nat := 8 * fppPrefixWords cols

/-- Source PCS transcript: full root digest followed by eta5 polynomials,
each lvcs_cols+58 words, then the complete public statement. -/
def fppPayload (cols : Nat) (rootHash : Fin 64 → Byte)
    (polynomials : Fin (5*(cols+58)) → F) (p : Public) : List Byte :=
  (List.ofFn rootHash ++ wordsBytes (List.ofFn (fun i => (polynomials i).val))) ++ publicBytes p

theorem fpp_payload_preamble_from_actual_geometry (cols : Nat)
    (rootHash : Fin 64 → Byte) (polynomials : Fin (5*(cols+58)) → F) (p : Public) :
    (fppPayload cols rootHash polynomials p).drop (fppPrefixBytes cols) = publicBytes p := by
  apply List.drop_left'
  simp only [List.length_append, List.length_ofFn, wordsBytes_length, fppPrefixBytes, fppPrefixWords]
  omega

theorem current_root_and_fpp_recover_same_all134 (cols : Nat)
    (salt : Fin 32 → Byte) (root rootHash : Fin 64 → Byte)
    (polynomials : Fin (5*(cols+58)) → F) (p : Public) :
    wordsAt 134 ((rootPayload salt root p).drop 96) = publicWords p ∧
    wordsAt 134 ((fppPayload cols rootHash polynomials p).drop (fppPrefixBytes cols)) = publicWords p := by
  rw [root_payload_preamble_from_actual96, fpp_payload_preamble_from_actual_geometry]
  have h := decode_public_all134 p []
  simpa using And.intro h h

/-- No whole graph is silently assigned one old2038-word FPP prefix. Values
below are the seven retained geometry receipts, with the admin cols118 derived
by the same K64 configuration constructor and separately listed in evidence. -/
inductive Geometry where
  | ordinary4 | ordinary8 | ordinary16 | bounded4 | bounded8 | bounded16 | admin
  deriving DecidableEq

def cols : Geometry → Nat
  | .ordinary4 => 4978
  | .ordinary8 => 5485
  | .ordinary16 => 6500
  | .bounded4 => 13524
  | .bounded8 => 14031
  | .bounded16 => 15045
  | .admin => 118

theorem seven_current_geometry_prefixes :
  (List.ofFn (fun i : Fin 7 => fppPrefixBytes (cols
    (match i.val with
      | 0 => .ordinary4
      | 1 => .ordinary8
      | 2 => .ordinary16
      | 3 => .bounded4
      | 4 => .bounded8
      | 5 => .bounded16
      | _ => .admin)))) =
  [201504, 221784, 262384, 543344, 563624, 604184, 7104] := by decide

theorem all_current_fpp_offsets_reject_old16304 (g : Geometry) :
    fppPrefixBytes (cols g) ≠ 16304 := by cases g <;> decide

/-- The literal u64 count in the raw frame can be read from its own bytes.
This premise bounds a SOURCE container length, not an authorization event. -/
theorem raw_frame_word_count_from_bytes (kind : Kind) (words : List Nat) (counter : Nat)
    (countFits : words.length < 2^64) :
    unLe (((rawFrame kind words counter).drop (fixedHeader kind).length).take 8) = words.length := by
  unfold rawFrame
  rw [List.append_assoc, List.append_assoc, List.drop_left]
  rw [List.take_left' (le_length 8 words.length)]
  exact unLe_le_of_bound 8 words.length (by simpa using countFits)



/-- Source byte decoder. Header matching must be checked by the caller's role
parser; this function reads its own encoded length, rather than importing one
historical fixed FPP payload size. -/
def rawPayloadBytes (kind : Kind) (bytes : List Byte) : List Byte :=
  let body := bytes.drop (fixedHeader kind).length
  let count := unLe (body.take 8)
  (body.drop 8).take (8*count)

theorem raw_payload_bytes_from_own_frame (kind : Kind) (words : List Nat) (counter : Nat)
    (countFits : words.length < 2^64) :
    rawPayloadBytes kind (rawFrame kind words counter) = wordsBytes words := by
  have count := raw_frame_word_count_from_bytes kind words counter countFits
  unfold rawPayloadBytes
  dsimp only
  rw [count]
  unfold rawFrame
  rw [List.append_assoc, List.append_assoc, List.drop_left,
    List.drop_left' (le_length 8 words.length),
    List.take_left' (wordsBytes_length words)]

/-- These are INPUT slots (Node::Input ordinal), not fabricated expanded
Poseidon output wire indices. `input()` advances this ordinal independently of
interleaved range/arithmetic nodes. Source rows must still certify actual wire
locators and primitive expansion before source-level semantic use. -/
def assetInputWords (depth : Nat) (bounded : Bool) : Nat :=
  742 + 21*depth + if bounded then 374 else 0

def noteInputSlot (slot : Fin 2) (coordinate : Fin 18) : Nat :=
  139 + 255*slot.val + coordinate.val

def positionInputSlot (slot : Fin 2) : Nat := 157 + 255*slot.val

def ordinaryKeyInputSlot (slot : Fin 2) (limb : Fin 5) : Nat := 382 + 255*slot.val + limb.val

def issuerInputSlot (depth : Nat) (limb : Fin 7) : Nat := 728 + 21*depth + limb.val

def adminSecretInputSlot (limb : Fin 7) : Nat := 134 + limb.val

def policySharedKeyInputSlot (depth : Nat) (limb : Fin 5) : Nat := 744 + 21*depth + limb.val

theorem asset_input_counts_match_six_source_receipts :
  [assetInputWords 4 false, assetInputWords 8 false, assetInputWords 16 false,
   assetInputWords 4 true, assetInputWords 8 true, assetInputWords 16 true] =
  [826, 910, 1078, 1200, 1284, 1452] := by decide

theorem ordinary_key_note_position_slots_are_exact :
    noteInputSlot 0 0 = 139 ∧ noteInputSlot 1 0 = 394 ∧
    positionInputSlot 0 = 157 ∧ positionInputSlot 1 = 412 ∧
    ordinaryKeyInputSlot 0 0 = 382 ∧ ordinaryKeyInputSlot 1 0 = 637 := by decide

theorem admin_secret_uses_actual_post_public_input_slots (limb : Fin 7) :
    134 ≤ adminSecretInputSlot limb ∧ adminSecretInputSlot limb < 141 := by
  constructor
  · exact Nat.le_add_right 134 limb.val
  · exact Nat.add_lt_add_left limb.isLt 134

theorem issuer_secret_is_private_input_in_both_graphs (depth : Nat) (limb : Fin 7)
    (bounded : Bool) :
    134 ≤ issuerInputSlot depth limb ∧ issuerInputSlot depth limb < assetInputWords depth bounded := by
  constructor
  · change 134 ≤ 728 + 21*depth + limb.val
    omega
  · cases bounded
    · change 728 + 21*depth + limb.val < 742 + 21*depth
      omega
    · change 728 + 21*depth + limb.val < 742 + 21*depth + 374
      omega

theorem shared_policy_key_and_spend_key_are_different_input_slots
    (depth : Nat) (limb : Fin 5) :
    policySharedKeyInputSlot depth limb ≠ ordinaryKeyInputSlot 0 limb := by
  simp only [policySharedKeyInputSlot, ordinaryKeyInputSlot]
  omega

end Hegemon.Transaction.QualifiedAssetSmzeChronologyV1
