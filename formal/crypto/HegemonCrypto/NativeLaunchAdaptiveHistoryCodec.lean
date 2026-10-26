import HegemonCrypto.SmallWoodV8Smz9RawCounterCompiler

/-!
# Native launch mixed-family SHA-512 challenge codec

Literal source framing for the RP06 SMZB and native HTLC SMZC four challenge
roles at source commit 7fae2698ce70a74a40062ed5dd77a865ab47327c.
The engine's concrete SHA-512 request is a profile-length/profile frame,
role-length/role frame, word count, little-endian u64 words, and u64 counter.

This module proves byte-codec injectivity for arbitrary typed words and counters.
It does not assert that arbitrary words are a valid accepted transcript, bind
Rust execution, establish challenge chronology, or prove a security bound.
Only the generic raw-word payload and counter compiler are reused; no historical
SMZA profile parser or proof geometry is used as authority for these families.
-/

set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000

namespace HegemonCrypto.NativeLaunchAdaptiveHistoryCodec

open CanonicalBytes
open SmallWood.V8Smz9RawCounterCompiler
  (typedWordPayload typed_word_payload_length typed_word_payload_is_source_payload
   typed_word_payload_injective boundedCounterInput bounded_counter_input_injective)
open SmallWood.V8Smz9WholeViewObservation (RawSha512OracleKey)

abbrev Word := Fin (2 ^ 64)
abbrev RawInput := List Byte

inductive Family where
  | rp06 | htlc
deriving DecidableEq, Fintype

inductive Role where
  | decsMatrix | piopMatrix | piopOpening | decsSample
deriving DecidableEq, Fintype

/-- Exact ASCII source domain `hegemon.smallwood.rp06.smzb.sha512.profile.v1`. -/
def rp06ProfileDomain : List Byte := [104, 101, 103, 101, 109, 111, 110, 46, 115, 109, 97, 108, 108, 119, 111, 111, 100, 46, 114, 112, 48, 54, 46, 115, 109, 122, 98, 46, 115, 104, 97, 53, 49, 50, 46, 112, 114, 111, 102, 105, 108, 101, 46, 118, 49]

/-- Exact ASCII source domain `hegemon.smallwood.native-htlc.smzc.sha512.profile.v1`. -/
def htlcProfileDomain : List Byte := [104, 101, 103, 101, 109, 111, 110, 46, 115, 109, 97, 108, 108, 119, 111, 111, 100, 46, 110, 97, 116, 105, 118, 101, 45, 104, 116, 108, 99, 46, 115, 109, 122, 99, 46, 115, 104, 97, 53, 49, 50, 46, 112, 114, 111, 102, 105, 108, 101, 46, 118, 49]

/-- Exact ASCII source domain `hegemon.smallwood.level5.decs-coefficient`. -/
def decsCoefficientDomain : List Byte := [104, 101, 103, 101, 109, 111, 110, 46, 115, 109, 97, 108, 108, 119, 111, 111, 100, 46, 108, 101, 118, 101, 108, 53, 46, 100, 101, 99, 115, 45, 99, 111, 101, 102, 102, 105, 99, 105, 101, 110, 116]

/-- Exact ASCII source domain `hegemon.smallwood.level5.piop-coefficient`. -/
def piopCoefficientDomain : List Byte := [104, 101, 103, 101, 109, 111, 110, 46, 115, 109, 97, 108, 108, 119, 111, 111, 100, 46, 108, 101, 118, 101, 108, 53, 46, 112, 105, 111, 112, 45, 99, 111, 101, 102, 102, 105, 99, 105, 101, 110, 116]

/-- Exact ASCII source domain `hegemon.smallwood.level5.piop-opening`. -/
def piopOpeningDomain : List Byte := [104, 101, 103, 101, 109, 111, 110, 46, 115, 109, 97, 108, 108, 119, 111, 111, 100, 46, 108, 101, 118, 101, 108, 53, 46, 112, 105, 111, 112, 45, 111, 112, 101, 110, 105, 110, 103]

/-- Exact ASCII source domain `hegemon.smallwood.level5.decs-fixed-sampling`. -/
def decsFixedSamplingDomain : List Byte := [104, 101, 103, 101, 109, 111, 110, 46, 115, 109, 97, 108, 108, 119, 111, 111, 100, 46, 108, 101, 118, 101, 108, 53, 46, 100, 101, 99, 115, 45, 102, 105, 120, 101, 100, 45, 115, 97, 109, 112, 108, 105, 110, 103]

/-- Exact ASCII source domain `hegemon.smallwood.native-htlc.smzc.decs-fixed-sampling.v1`. -/
def htlcDecsFixedSamplingDomain : List Byte := [104, 101, 103, 101, 109, 111, 110, 46, 115, 109, 97, 108, 108, 119, 111, 111, 100, 46, 110, 97, 116, 105, 118, 101, 45, 104, 116, 108, 99, 46, 115, 109, 122, 99, 46, 100, 101, 99, 115, 45, 102, 105, 120, 101, 100, 45, 115, 97, 109, 112, 108, 105, 110, 103, 46, 118, 49]

def profileDomain : Family → List Byte
  | .rp06 => rp06ProfileDomain
  | .htlc => htlcProfileDomain

def roleDomain : Family → Role → List Byte
  | _, .decsMatrix => decsCoefficientDomain
  | _, .piopMatrix => piopCoefficientDomain
  | _, .piopOpening => piopOpeningDomain
  | .rp06, .decsSample => decsFixedSamplingDomain
  | .htlc, .decsSample => htlcDecsFixedSamplingDomain

theorem profileDomain_injective : Function.Injective profileDomain := by
  intro left right equal
  cases left <;> cases right <;> simp_all [profileDomain, rp06ProfileDomain, htlcProfileDomain]

theorem roleDomain_injective (family : Family) : Function.Injective (roleDomain family) := by
  intro left right equal
  cases family <;> cases left <;> cases right <;>
    simp_all [roleDomain, decsCoefficientDomain, piopCoefficientDomain,
      piopOpeningDomain, decsFixedSamplingDomain, htlcDecsFixedSamplingDomain]

theorem profileDomain_length_lt (family : Family) :
    (profileDomain family).length < 256 ^ 8 := by
  cases family <;> decide

theorem roleDomain_length_lt (family : Family) (role : Role) :
    (roleDomain family role).length < 256 ^ 8 := by
  cases family <;> cases role <;> decide

/-- Complete literal prefix before the eight-byte counter suffix. -/
def sourcePrefix (family : Family) (role : Role) (words : List Word) : RawInput :=
  encodeLE 8 (profileDomain family).length ++ profileDomain family ++
    encodeLE 8 (roleDomain family role).length ++ roleDomain family role ++
      encodeLE 8 words.length ++ typedWordPayload words

def sourceFrame (family : Family) (role : Role) (words : List Word)
    (counter : Word) : RawInput :=
  sourcePrefix family role words ++ encodeLE 8 counter.val

/-- The exact generic preimage function used by the raw SHA-512 oracle model.
Its historical `Canonical` predicate is deliberately not used. -/
theorem sourceFrame_eq_raw_preimage (family : Family) (role : Role)
    (words : List Word) (counter : Word) :
    sourceFrame family role words counter =
      (RawSha512OracleKey.mk (some (profileDomain family))
        (roleDomain family role) (words.map Fin.val) counter.val).preimage := by
  simp only [sourceFrame, sourcePrefix, RawSha512OracleKey.preimage,
    List.length_map, typed_word_payload_is_source_payload, List.append_assoc]

/-- Family-neutral framing parser: it retains all decoded bytes and checks
that the u64 counter is the final field. Classification is proved separately. -/
def parseSourceFrame (input : RawInput) :
    Option (List Byte × List Byte × List Byte × Nat) := do
  let (profileLength, rest) ← readFixed 8 input
  let (profile, rest) ← readFixed (decodeLE profileLength) rest
  let (roleLength, rest) ← readFixed 8 rest
  let (role, rest) ← readFixed (decodeLE roleLength) rest
  let (wordCount, rest) ← readFixed 8 rest
  let (payload, rest) ← readFixed (8 * decodeLE wordCount) rest
  let (counter, suffix) ← readFixed 8 rest
  if suffix = [] then some (profile, role, payload, decodeLE counter) else none

theorem parse_source_frame_roundtrip (family : Family) (role : Role)
    (words : List Word) (counter : Word) (wordBound : words.length < 2 ^ 64) :
    parseSourceFrame (sourceFrame family role words counter) =
      some (profileDomain family, roleDomain family role,
        typedWordPayload words, counter.val) := by
  have profileMod : (profileDomain family).length % 18446744073709551616 =
      (profileDomain family).length :=
    Nat.mod_eq_of_lt (profileDomain_length_lt family)
  have roleMod : (roleDomain family role).length % 18446744073709551616 =
      (roleDomain family role).length :=
    Nat.mod_eq_of_lt (roleDomain_length_lt family role)
  have wordMod : words.length % 18446744073709551616 = words.length :=
    Nat.mod_eq_of_lt wordBound
  have counterMod : counter.val % 18446744073709551616 = counter.val :=
    Nat.mod_eq_of_lt counter.isLt
  simp [parseSourceFrame, sourceFrame, sourcePrefix, List.append_assoc, readFixed,
    encodeLE_length, decodeLE_encodeLE, profileMod, roleMod, wordMod,
    typed_word_payload_length]
  have counterTake : (encodeLE 8 counter.val).take 8 = encodeLE 8 counter.val := by
    simpa only [encodeLE_length] using (List.take_length (l := encodeLE 8 counter.val))
  rw [counterTake, decodeLE_encodeLE]
  exact counterMod

/-- Equality of literal requests determines the family, role, words, and
counter. Distinct families or roles therefore cannot alias a source request. -/
theorem sourceFrame_injective
    (lf rf : Family) (lr rr : Role) (lw rw : List Word) (lc rc : Word)
    (lb : lw.length < 2 ^ 64) (rb : rw.length < 2 ^ 64)
    (equal : sourceFrame lf lr lw lc = sourceFrame rf rr rw rc) :
    lf = rf ∧ lr = rr ∧ lw = rw ∧ lc = rc := by
  have parsed := congrArg parseSourceFrame equal
  rw [parse_source_frame_roundtrip lf lr lw lc lb,
    parse_source_frame_roundtrip rf rr rw rc rb] at parsed
  have parts := Option.some.inj parsed
  have familyEq := profileDomain_injective (congrArg Prod.fst parts)
  subst rf
  refine ⟨rfl, roleDomain_injective lf (congrArg (fun value => value.2.1) parts),
    ?_, ?_⟩
  · exact typed_word_payload_injective (congrArg (fun value => value.2.2.1) parts)
  · exact Fin.ext (congrArg (fun value => value.2.2.2) parts)

/-- Typed prefixes require the word-count length frame to fit a u64.
No proof relation, validity predicate, or fixed payload shape is assumed. -/
structure CanonicalPrefix where
  family : Family
  role : Role
  words : List Word
  wordCountBound : words.length < 2 ^ 64

def encodePrefix (key : CanonicalPrefix) : RawInput :=
  sourcePrefix key.family key.role key.words

theorem encodePrefix_injective : Function.Injective encodePrefix := by
  intro left right equal
  have frames : sourceFrame left.family left.role left.words 0 =
      sourceFrame right.family right.role right.words 0 :=
    congrArg (fun leading => leading ++ encodeLE 8 0) equal
  obtain ⟨families, roles, words, _⟩ := sourceFrame_injective _ _ _ _ _ _ _ _
    left.wordCountBound right.wordCountBound frames
  cases left
  cases right
  simp_all

def boundedFrame (blocks : Nat) (bound : blocks ≤ 2 ^ 64)
    (key : CanonicalPrefix × Fin blocks) : RawInput :=
  boundedCounterInput blocks bound (encodePrefix key.1, key.2)

theorem boundedFrame_injective (blocks : Nat) (bound : blocks ≤ 2 ^ 64) :
    Function.Injective (boundedFrame blocks bound) := by
  intro left right equal
  have pairs := bounded_counter_input_injective blocks bound equal
  have prefixes : encodePrefix left.1 = encodePrefix right.1 :=
    congrArg (fun pair : RawInput × Fin blocks => pair.1) pairs
  have counters : left.2 = right.2 :=
    congrArg (fun pair : RawInput × Fin blocks => pair.2) pairs
  exact Prod.ext (encodePrefix_injective prefixes) counters

end HegemonCrypto.NativeLaunchAdaptiveHistoryCodec
