import SmzaRp05StatementNamespace

/-! The RP05 public-word projection has no dependency on an accepted trace. -/
namespace HegemonCrypto.SmallWood.SmzaRp05TracePrefixes

open SmzaRp05StatementNamespace

set_option autoImplicit false

/-- The exact 120 public words begin at byte 84 of the current preamble.
They are deliberately not inherited from an RP04 relation digest or other
hard-coded public context. -/
def publicWords (statement : SmzaRp05StatementNamespace.Statement) : List Nat :=
  (List.range 120).map fun word =>
    V8SmzaOracleParser.wordAt
      ((SmzaRp05StatementNamespace.Statement.toBytes statement).drop 84) word

theorem public_words_length (statement : SmzaRp05StatementNamespace.Statement) :
    (publicWords statement).length = 120 := by
  simp [publicWords]

end HegemonCrypto.SmallWood.SmzaRp05TracePrefixes
