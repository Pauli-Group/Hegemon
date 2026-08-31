# CFW26 Section 11 source-specification audit

Status: unresolved primary-specification ambiguity; production and proof-system
authority remain false.

This is a source-only audit of the R1CS reduction used by the CFW26
HVZK-WHIR challenger. It does not repair the paper, implement the reduction,
or certify either candidate interpretation.

## Source identity

- Primary paper: Chiesa, Fenzi, and Weng, “Zero-Knowledge IOPPs with
  Applications to Post-Quantum Succinct Arguments,” ePrint 2026/391,
  https://eprint.iacr.org/2026/391.
- PDF examined on 2026-08-22: 82 pages, SHA-512
  be9595b264ccbb6e5d848a10e24f907089ff478c7efe99967a5d0f236bffcaf87c53cc82eec53f74856a08a4db8a6884084c8238291f44d06aa2d703eef5c2dd.
- The ePrint history visible on 2026-08-22 showed the received/approved
  February 25/26, 2026 entry. No author erratum or revised equation resolving
  the points below was found.
- Plonky3 issue 1590,
  https://github.com/Plonky3/Plonky3/issues/1590, explicitly treats the
  paper’s Section 11 R1CS reduction as out of scope. Plonky3 therefore cannot
  select an authoritative interpretation.

The negative erratum result is bounded to the sources checked on that date; it
is not a claim that no private author clarification exists.

## Printed inconsistencies

### Inner-mask coefficient

Construction 11.4, Step 3 (printed pages 67–68) defines every masked matrix
linear form as the matrix/witness contraction plus one copy of the sum of
inner masks.

Construction 11.4, Step 8 (printed pages 68–69) first defines v_M with the
same coefficient 1. Its immediately following displayed “equals” line instead
expands v_M as the public contribution plus witness contribution plus
2 times the mask sum. That second equality does not follow from the first
definition or from the Step 3 definition.

The “Value claim” in the proof sketch (printed page 71) repeats coefficient 2
and uses invertibility of 2 when char(F) is not 2. This supports coefficient 2
as one possible intent, but the protocol equations that generate and verify
the value still print coefficient 1.

The theorem’s characteristic restriction does not resolve intent by itself:
characteristic not equal to 2 is also used by the earlier outer-sumcheck
masking argument in Lemma 6.4 (printed pages 38–39).

### Ill-typed inner succinct-linear-form state

Theorem 11.3 and Construction 11.4, Step 9 (printed pages 66 and 69) set each
inner succinct linear form sl_in,M,i to the identity while Step 9 gives it the
pair state (pow(alpha_i), ze(rho)_M).

Definition 5.2 (printed page 35) defines the identity form as accepting one
matrix state V and returning V. Definition 5.4 on the same page defines the
scalar-multiplied form times(sl) as accepting a pair (state, scalar) and
returning scalar times sl(state). The Step 9 pair is therefore ill-typed for
the printed identity form and has exactly the shape expected by times(identity).

Definition 11.1 (printed pages 65–66) requires the output relation to add the
inner products of each mask with the result of its inner succinct linear form.
As printed, the Step 9 target includes ze(rho)_M times (v_M minus u_M), so the
scalar must reach the inner-mask contribution through that linear form.

## Candidate repairs and admission decision

One internally consistent candidate is:

1. retain coefficient 1 in Steps 3 and 8;
2. remove coefficient 2 from Step 8’s second equality and the value-claim
   proof; and
3. replace each inner identity form by times(identity), retaining state
   (pow(alpha_i), ze(rho)_M).

Another algebraically coherent family of repairs could retain coefficient 2,
but it would have to change the Step 3 and Step 8 first equations and also
carry the factor 2 into Step 9, for example through the scalar state. The
printed construction does none of those changes.

The coefficient-1 plus times(identity) repair is supported by more of the
printed construction, but no checked author source uniquely endorses it.
Neither repair is selected by this profile. Until an authoritative correction
or an independently proved formal restatement is pinned, the
r1cs_to_cic_ior security term remains missing and the profile must reject
production authority.
