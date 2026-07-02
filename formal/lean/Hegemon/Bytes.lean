namespace Hegemon

abbrev Byte := Nat

def byte (value : Nat) : Byte :=
  value % 256

def littleEndianBytes (width value : Nat) : List Byte :=
  (List.range width).map fun index => byte (value / (256 ^ index))

theorem littleEndianBytes_length (width value : Nat) :
    (littleEndianBytes width value).length = width := by
  simp [littleEndianBytes]

def u16le (value : Nat) : List Byte :=
  littleEndianBytes 2 value

theorem u16le_length (value : Nat) : (u16le value).length = 2 := by
  simp [u16le, littleEndianBytes_length]

def u32le (value : Nat) : List Byte :=
  littleEndianBytes 4 value

theorem u32le_length (value : Nat) : (u32le value).length = 4 := by
  simp [u32le, littleEndianBytes_length]

def u64le (value : Nat) : List Byte :=
  littleEndianBytes 8 value

theorem u64le_length (value : Nat) : (u64le value).length = 8 := by
  simp [u64le, littleEndianBytes_length]

def u128le (value : Nat) : List Byte :=
  littleEndianBytes 16 value

theorem u128le_length (value : Nat) : (u128le value).length = 16 := by
  simp [u128le, littleEndianBytes_length]

def hexDigit (value : Nat) : Char :=
  match value with
  | 0 => '0'
  | 1 => '1'
  | 2 => '2'
  | 3 => '3'
  | 4 => '4'
  | 5 => '5'
  | 6 => '6'
  | 7 => '7'
  | 8 => '8'
  | 9 => '9'
  | 10 => 'a'
  | 11 => 'b'
  | 12 => 'c'
  | 13 => 'd'
  | 14 => 'e'
  | _ => 'f'

def byteHex (value : Nat) : String :=
  String.singleton (hexDigit ((byte value) / 16)) ++ String.singleton (hexDigit ((byte value) % 16))

def hexBytes (bytes : List Byte) : String :=
  "0x" ++ String.join (bytes.map byteHex)

def asciiBytes (value : String) : List Byte :=
  value.toList.map fun char => byte char.toNat

def patternedBytes (length seed : Nat) : List Byte :=
  (List.range length).map fun index => byte (seed + index * 17)

theorem patternedBytes_length (length seed : Nat) :
    (patternedBytes length seed).length = length := by
  simp [patternedBytes]

end Hegemon
