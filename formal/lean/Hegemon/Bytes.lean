namespace Hegemon

abbrev Byte := Nat

def byte (value : Nat) : Byte :=
  value % 256

def littleEndianBytes (width value : Nat) : List Byte :=
  (List.range width).map fun index => byte (value / (256 ^ index))

def u16le (value : Nat) : List Byte :=
  littleEndianBytes 2 value

def u32le (value : Nat) : List Byte :=
  littleEndianBytes 4 value

def u64le (value : Nat) : List Byte :=
  littleEndianBytes 8 value

def u128le (value : Nat) : List Byte :=
  littleEndianBytes 16 value

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

end Hegemon
