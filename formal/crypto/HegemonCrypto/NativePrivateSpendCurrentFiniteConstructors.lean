import HegemonCrypto.NativePrivateSpendSelectedNullifier
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
namespace HegemonCrypto.NativePrivateSpendCurrentFiniteConstructors
open NativePrivateSpendSelectedNullifier NativePrivateSpendPackedLowering
open NativePrivateSpendArithmeticTopology NativeLaunchConstraintAdapterBridge
open NativePrivateSpendLocalSemantics
noncomputable section
variable [Fact (Nat.Prime modulus)]
structure SliceFacts (g : Graph K) (count : g.count = 676622) : Prop where
  node_6919 : g.nodes ⟨6919, by omega⟩ = .linear (.wire 6913) (.constant (1 : K)) true
  node_6920 : g.nodes ⟨6920, by omega⟩ = .product (.wire 6913) (.wire 6919)
  node_6921 : g.nodes ⟨6921, by omega⟩ = .linear (.wire 6914) (.constant (1 : K)) true
  node_6922 : g.nodes ⟨6922, by omega⟩ = .product (.wire 6914) (.wire 6921)
  node_6923 : g.nodes ⟨6923, by omega⟩ = .linear (.wire 6915) (.constant (1 : K)) true
  node_6924 : g.nodes ⟨6924, by omega⟩ = .product (.wire 6915) (.wire 6923)
  node_6925 : g.nodes ⟨6925, by omega⟩ = .linear (.wire 6916) (.constant (1 : K)) true
  node_6926 : g.nodes ⟨6926, by omega⟩ = .product (.wire 6916) (.wire 6925)
  node_6927 : g.nodes ⟨6927, by omega⟩ = .linear (.wire 6917) (.constant (1 : K)) true
  node_6928 : g.nodes ⟨6928, by omega⟩ = .product (.wire 6917) (.wire 6927)
  node_6929 : g.nodes ⟨6929, by omega⟩ = .linear (.wire 6918) (.constant (1 : K)) true
  node_6930 : g.nodes ⟨6930, by omega⟩ = .product (.wire 6918) (.wire 6929)
  node_458003 : g.nodes ⟨458003, by omega⟩ = .linear (.wire 455560) (.wire 457968) true
  node_458004 : g.nodes ⟨458004, by omega⟩ = .product (.wire 6941) (.wire 458003)
  node_458005 : g.nodes ⟨458005, by omega⟩ = .linear (.wire 457968) (.wire 458004) false
  node_458006 : g.nodes ⟨458006, by omega⟩ = .linear (.wire 455571) (.wire 457979) true
  node_458007 : g.nodes ⟨458007, by omega⟩ = .product (.wire 6941) (.wire 458006)
  node_458008 : g.nodes ⟨458008, by omega⟩ = .linear (.wire 457979) (.wire 458007) false
  node_458009 : g.nodes ⟨458009, by omega⟩ = .linear (.wire 455582) (.wire 457990) true
  node_458010 : g.nodes ⟨458010, by omega⟩ = .product (.wire 6941) (.wire 458009)
  node_458011 : g.nodes ⟨458011, by omega⟩ = .linear (.wire 457990) (.wire 458010) false
  node_458012 : g.nodes ⟨458012, by omega⟩ = .linear (.wire 455593) (.wire 458001) true
  node_458013 : g.nodes ⟨458013, by omega⟩ = .product (.wire 6941) (.wire 458012)
  node_458014 : g.nodes ⟨458014, by omega⟩ = .linear (.wire 458001) (.wire 458013) false
  node_458015 : g.nodes ⟨458015, by omega⟩ = .linear (.wire 455559) (.wire 457967) true
  node_458016 : g.nodes ⟨458016, by omega⟩ = .product (.wire 6941) (.wire 458015)
  node_458017 : g.nodes ⟨458017, by omega⟩ = .linear (.wire 457967) (.wire 458016) false
  node_458018 : g.nodes ⟨458018, by omega⟩ = .linear (.wire 455570) (.wire 457978) true
  node_458019 : g.nodes ⟨458019, by omega⟩ = .product (.wire 6941) (.wire 458018)
  node_458020 : g.nodes ⟨458020, by omega⟩ = .linear (.wire 457978) (.wire 458019) false
  node_458021 : g.nodes ⟨458021, by omega⟩ = .linear (.wire 455581) (.wire 457989) true
  node_458022 : g.nodes ⟨458022, by omega⟩ = .product (.wire 6941) (.wire 458021)
  node_458023 : g.nodes ⟨458023, by omega⟩ = .linear (.wire 457989) (.wire 458022) false
  node_458024 : g.nodes ⟨458024, by omega⟩ = .linear (.wire 6956) (.wire 458005) true
  node_458025 : g.nodes ⟨458025, by omega⟩ = .product (.wire 453172) (.wire 458024)
  node_458026 : g.nodes ⟨458026, by omega⟩ = .linear (.wire 6957) (.wire 458008) true
  node_458027 : g.nodes ⟨458027, by omega⟩ = .product (.wire 453172) (.wire 458026)
  node_458028 : g.nodes ⟨458028, by omega⟩ = .linear (.wire 6958) (.wire 458011) true
  node_458029 : g.nodes ⟨458029, by omega⟩ = .product (.wire 453172) (.wire 458028)
  node_458030 : g.nodes ⟨458030, by omega⟩ = .linear (.wire 6959) (.wire 458014) true
  node_458031 : g.nodes ⟨458031, by omega⟩ = .product (.wire 453172) (.wire 458030)
  node_458032 : g.nodes ⟨458032, by omega⟩ = .linear (.wire 6952) (.wire 458017) true
  node_458033 : g.nodes ⟨458033, by omega⟩ = .product (.wire 453172) (.wire 458032)
  node_458034 : g.nodes ⟨458034, by omega⟩ = .linear (.wire 6953) (.wire 458020) true
  node_458035 : g.nodes ⟨458035, by omega⟩ = .product (.wire 453172) (.wire 458034)
  node_458036 : g.nodes ⟨458036, by omega⟩ = .linear (.wire 6954) (.wire 458023) true
  node_458037 : g.nodes ⟨458037, by omega⟩ = .product (.wire 453172) (.wire 458036)
  node_458067 : g.nodes ⟨458067, by omega⟩ = .linear (.wire 6956) (.wire 52292) true
  node_458068 : g.nodes ⟨458068, by omega⟩ = .product (.wire 458066) (.wire 458067)
  node_458069 : g.nodes ⟨458069, by omega⟩ = .linear (.wire 6957) (.wire 52303) true
  node_458070 : g.nodes ⟨458070, by omega⟩ = .product (.wire 458066) (.wire 458069)
  node_458071 : g.nodes ⟨458071, by omega⟩ = .linear (.wire 6958) (.wire 52314) true
  node_458072 : g.nodes ⟨458072, by omega⟩ = .product (.wire 458066) (.wire 458071)
  node_458073 : g.nodes ⟨458073, by omega⟩ = .linear (.wire 6959) (.wire 52325) true
  node_458074 : g.nodes ⟨458074, by omega⟩ = .product (.wire 458066) (.wire 458073)
  node_458075 : g.nodes ⟨458075, by omega⟩ = .linear (.wire 6952) (.wire 52291) true
  node_458076 : g.nodes ⟨458076, by omega⟩ = .product (.wire 458066) (.wire 458075)
  node_458077 : g.nodes ⟨458077, by omega⟩ = .linear (.wire 6953) (.wire 52302) true
  node_458078 : g.nodes ⟨458078, by omega⟩ = .product (.wire 458066) (.wire 458077)
  node_458079 : g.nodes ⟨458079, by omega⟩ = .linear (.wire 6954) (.wire 52313) true
  node_458080 : g.nodes ⟨458080, by omega⟩ = .product (.wire 458066) (.wire 458079)
  node_458081 : g.nodes ⟨458081, by omega⟩ = .linear (.wire 6956) (.wire 66841) true
  node_458082 : g.nodes ⟨458082, by omega⟩ = .product (.wire 6915) (.wire 458081)
  node_458083 : g.nodes ⟨458083, by omega⟩ = .linear (.wire 6957) (.wire 66852) true
  node_458084 : g.nodes ⟨458084, by omega⟩ = .product (.wire 6915) (.wire 458083)
  node_458085 : g.nodes ⟨458085, by omega⟩ = .linear (.wire 6958) (.wire 66863) true
  node_458086 : g.nodes ⟨458086, by omega⟩ = .product (.wire 6915) (.wire 458085)
  node_458087 : g.nodes ⟨458087, by omega⟩ = .linear (.wire 6959) (.wire 66874) true
  node_458088 : g.nodes ⟨458088, by omega⟩ = .product (.wire 6915) (.wire 458087)
  node_458089 : g.nodes ⟨458089, by omega⟩ = .linear (.wire 6952) (.wire 66840) true
  node_458090 : g.nodes ⟨458090, by omega⟩ = .product (.wire 6915) (.wire 458089)
  node_458091 : g.nodes ⟨458091, by omega⟩ = .linear (.wire 6953) (.wire 66851) true
  node_458092 : g.nodes ⟨458092, by omega⟩ = .product (.wire 6915) (.wire 458091)
  node_458093 : g.nodes ⟨458093, by omega⟩ = .linear (.wire 6954) (.wire 66862) true
  node_458094 : g.nodes ⟨458094, by omega⟩ = .product (.wire 6915) (.wire 458093)
  node_458095 : g.nodes ⟨458095, by omega⟩ = .linear (.wire 6956) (.wire 86901) true
  node_458096 : g.nodes ⟨458096, by omega⟩ = .product (.wire 6939) (.wire 458095)
  node_458097 : g.nodes ⟨458097, by omega⟩ = .linear (.wire 6957) (.wire 86912) true
  node_458098 : g.nodes ⟨458098, by omega⟩ = .product (.wire 6939) (.wire 458097)
  node_458099 : g.nodes ⟨458099, by omega⟩ = .linear (.wire 6958) (.wire 86923) true
  node_458100 : g.nodes ⟨458100, by omega⟩ = .product (.wire 6939) (.wire 458099)
  node_458101 : g.nodes ⟨458101, by omega⟩ = .linear (.wire 6959) (.wire 86934) true
  node_458102 : g.nodes ⟨458102, by omega⟩ = .product (.wire 6939) (.wire 458101)
  node_458103 : g.nodes ⟨458103, by omega⟩ = .linear (.wire 6952) (.wire 86900) true
  node_458104 : g.nodes ⟨458104, by omega⟩ = .product (.wire 6939) (.wire 458103)
  node_458105 : g.nodes ⟨458105, by omega⟩ = .linear (.wire 6953) (.wire 86911) true
  node_458106 : g.nodes ⟨458106, by omega⟩ = .product (.wire 6939) (.wire 458105)
  node_458107 : g.nodes ⟨458107, by omega⟩ = .linear (.wire 6954) (.wire 86922) true
  node_458108 : g.nodes ⟨458108, by omega⟩ = .product (.wire 6939) (.wire 458107)
  node_465553 : g.nodes ⟨465553, by omega⟩ = .linear (.wire 6961) (.wire 465518) true
  node_465554 : g.nodes ⟨465554, by omega⟩ = .product (.wire 458110) (.wire 465553)
  node_465555 : g.nodes ⟨465555, by omega⟩ = .linear (.wire 465518) (.wire 465554) false
  node_465556 : g.nodes ⟨465556, by omega⟩ = .linear (.wire 6962) (.wire 465529) true
  node_465557 : g.nodes ⟨465557, by omega⟩ = .product (.wire 458110) (.wire 465556)
  node_465558 : g.nodes ⟨465558, by omega⟩ = .linear (.wire 465529) (.wire 465557) false
  node_465559 : g.nodes ⟨465559, by omega⟩ = .linear (.wire 6963) (.wire 465540) true
  node_465560 : g.nodes ⟨465560, by omega⟩ = .product (.wire 458110) (.wire 465559)
  node_465561 : g.nodes ⟨465561, by omega⟩ = .linear (.wire 465540) (.wire 465560) false
  node_465562 : g.nodes ⟨465562, by omega⟩ = .linear (.wire 6964) (.wire 465551) true
  node_465563 : g.nodes ⟨465563, by omega⟩ = .product (.wire 458110) (.wire 465562)
  node_465564 : g.nodes ⟨465564, by omega⟩ = .linear (.wire 465551) (.wire 465563) false
  node_465565 : g.nodes ⟨465565, by omega⟩ = .linear (.wire 6965) (.wire 465517) true
  node_465566 : g.nodes ⟨465566, by omega⟩ = .product (.wire 458110) (.wire 465565)
  node_465567 : g.nodes ⟨465567, by omega⟩ = .linear (.wire 465517) (.wire 465566) false
  node_465568 : g.nodes ⟨465568, by omega⟩ = .linear (.wire 6966) (.wire 465528) true
  node_465569 : g.nodes ⟨465569, by omega⟩ = .product (.wire 458110) (.wire 465568)
  node_465570 : g.nodes ⟨465570, by omega⟩ = .linear (.wire 465528) (.wire 465569) false
  node_465571 : g.nodes ⟨465571, by omega⟩ = .linear (.wire 6967) (.wire 465539) true
  node_465572 : g.nodes ⟨465572, by omega⟩ = .product (.wire 458110) (.wire 465571)
  node_465573 : g.nodes ⟨465573, by omega⟩ = .linear (.wire 465539) (.wire 465572) false
  node_465574 : g.nodes ⟨465574, by omega⟩ = .linear (.wire 465518) (.wire 6961) true
  node_465575 : g.nodes ⟨465575, by omega⟩ = .product (.wire 458110) (.wire 465574)
  node_465576 : g.nodes ⟨465576, by omega⟩ = .linear (.wire 6961) (.wire 465575) false
  node_465577 : g.nodes ⟨465577, by omega⟩ = .linear (.wire 465529) (.wire 6962) true
  node_465578 : g.nodes ⟨465578, by omega⟩ = .product (.wire 458110) (.wire 465577)
  node_465579 : g.nodes ⟨465579, by omega⟩ = .linear (.wire 6962) (.wire 465578) false
  node_465580 : g.nodes ⟨465580, by omega⟩ = .linear (.wire 465540) (.wire 6963) true
  node_465581 : g.nodes ⟨465581, by omega⟩ = .product (.wire 458110) (.wire 465580)
  node_465582 : g.nodes ⟨465582, by omega⟩ = .linear (.wire 6963) (.wire 465581) false
  node_465583 : g.nodes ⟨465583, by omega⟩ = .linear (.wire 465551) (.wire 6964) true
  node_465584 : g.nodes ⟨465584, by omega⟩ = .product (.wire 458110) (.wire 465583)
  node_465585 : g.nodes ⟨465585, by omega⟩ = .linear (.wire 6964) (.wire 465584) false
  node_465586 : g.nodes ⟨465586, by omega⟩ = .linear (.wire 465517) (.wire 6965) true
  node_465587 : g.nodes ⟨465587, by omega⟩ = .product (.wire 458110) (.wire 465586)
  node_465588 : g.nodes ⟨465588, by omega⟩ = .linear (.wire 6965) (.wire 465587) false
  node_465589 : g.nodes ⟨465589, by omega⟩ = .linear (.wire 465528) (.wire 6966) true
  node_465590 : g.nodes ⟨465590, by omega⟩ = .product (.wire 458110) (.wire 465589)
  node_465591 : g.nodes ⟨465591, by omega⟩ = .linear (.wire 6966) (.wire 465590) false
  node_465592 : g.nodes ⟨465592, by omega⟩ = .linear (.wire 465539) (.wire 6967) true
  node_465593 : g.nodes ⟨465593, by omega⟩ = .product (.wire 458110) (.wire 465592)
  node_465594 : g.nodes ⟨465594, by omega⟩ = .linear (.wire 6967) (.wire 465593) false
  node_468027 : g.nodes ⟨468027, by omega⟩ = .linear (.wire 6968) (.wire 467992) true
  node_468028 : g.nodes ⟨468028, by omega⟩ = .product (.wire 458113) (.wire 468027)
  node_468029 : g.nodes ⟨468029, by omega⟩ = .linear (.wire 467992) (.wire 468028) false
  node_468030 : g.nodes ⟨468030, by omega⟩ = .linear (.wire 6969) (.wire 468003) true
  node_468031 : g.nodes ⟨468031, by omega⟩ = .product (.wire 458113) (.wire 468030)
  node_468032 : g.nodes ⟨468032, by omega⟩ = .linear (.wire 468003) (.wire 468031) false
  node_468033 : g.nodes ⟨468033, by omega⟩ = .linear (.wire 6970) (.wire 468014) true
  node_468034 : g.nodes ⟨468034, by omega⟩ = .product (.wire 458113) (.wire 468033)
  node_468035 : g.nodes ⟨468035, by omega⟩ = .linear (.wire 468014) (.wire 468034) false
  node_468036 : g.nodes ⟨468036, by omega⟩ = .linear (.wire 6971) (.wire 468025) true
  node_468037 : g.nodes ⟨468037, by omega⟩ = .product (.wire 458113) (.wire 468036)
  node_468038 : g.nodes ⟨468038, by omega⟩ = .linear (.wire 468025) (.wire 468037) false
  node_468039 : g.nodes ⟨468039, by omega⟩ = .linear (.wire 6972) (.wire 467991) true
  node_468040 : g.nodes ⟨468040, by omega⟩ = .product (.wire 458113) (.wire 468039)
  node_468041 : g.nodes ⟨468041, by omega⟩ = .linear (.wire 467991) (.wire 468040) false
  node_468042 : g.nodes ⟨468042, by omega⟩ = .linear (.wire 6973) (.wire 468002) true
  node_468043 : g.nodes ⟨468043, by omega⟩ = .product (.wire 458113) (.wire 468042)
  node_468044 : g.nodes ⟨468044, by omega⟩ = .linear (.wire 468002) (.wire 468043) false
  node_468045 : g.nodes ⟨468045, by omega⟩ = .linear (.wire 6974) (.wire 468013) true
  node_468046 : g.nodes ⟨468046, by omega⟩ = .product (.wire 458113) (.wire 468045)
  node_468047 : g.nodes ⟨468047, by omega⟩ = .linear (.wire 468013) (.wire 468046) false
  node_468048 : g.nodes ⟨468048, by omega⟩ = .linear (.wire 467992) (.wire 6968) true
  node_468049 : g.nodes ⟨468049, by omega⟩ = .product (.wire 458113) (.wire 468048)
  node_468050 : g.nodes ⟨468050, by omega⟩ = .linear (.wire 6968) (.wire 468049) false
  node_468051 : g.nodes ⟨468051, by omega⟩ = .linear (.wire 468003) (.wire 6969) true
  node_468052 : g.nodes ⟨468052, by omega⟩ = .product (.wire 458113) (.wire 468051)
  node_468053 : g.nodes ⟨468053, by omega⟩ = .linear (.wire 6969) (.wire 468052) false
  node_468054 : g.nodes ⟨468054, by omega⟩ = .linear (.wire 468014) (.wire 6970) true
  node_468055 : g.nodes ⟨468055, by omega⟩ = .product (.wire 458113) (.wire 468054)
  node_468056 : g.nodes ⟨468056, by omega⟩ = .linear (.wire 6970) (.wire 468055) false
  node_468057 : g.nodes ⟨468057, by omega⟩ = .linear (.wire 468025) (.wire 6971) true
  node_468058 : g.nodes ⟨468058, by omega⟩ = .product (.wire 458113) (.wire 468057)
  node_468059 : g.nodes ⟨468059, by omega⟩ = .linear (.wire 6971) (.wire 468058) false
  node_468060 : g.nodes ⟨468060, by omega⟩ = .linear (.wire 467991) (.wire 6972) true
  node_468061 : g.nodes ⟨468061, by omega⟩ = .product (.wire 458113) (.wire 468060)
  node_468062 : g.nodes ⟨468062, by omega⟩ = .linear (.wire 6972) (.wire 468061) false
  node_468063 : g.nodes ⟨468063, by omega⟩ = .linear (.wire 468002) (.wire 6973) true
  node_468064 : g.nodes ⟨468064, by omega⟩ = .product (.wire 458113) (.wire 468063)
  node_468065 : g.nodes ⟨468065, by omega⟩ = .linear (.wire 6973) (.wire 468064) false
  node_468066 : g.nodes ⟨468066, by omega⟩ = .linear (.wire 468013) (.wire 6974) true
  node_468067 : g.nodes ⟨468067, by omega⟩ = .product (.wire 458113) (.wire 468066)
  node_468068 : g.nodes ⟨468068, by omega⟩ = .linear (.wire 6974) (.wire 468067) false
  node_470501 : g.nodes ⟨470501, by omega⟩ = .linear (.wire 6975) (.wire 470466) true
  node_470502 : g.nodes ⟨470502, by omega⟩ = .product (.wire 458118) (.wire 470501)
  node_470503 : g.nodes ⟨470503, by omega⟩ = .linear (.wire 470466) (.wire 470502) false
  node_470504 : g.nodes ⟨470504, by omega⟩ = .linear (.wire 6976) (.wire 470477) true
  node_470505 : g.nodes ⟨470505, by omega⟩ = .product (.wire 458118) (.wire 470504)
  node_470506 : g.nodes ⟨470506, by omega⟩ = .linear (.wire 470477) (.wire 470505) false
  node_470507 : g.nodes ⟨470507, by omega⟩ = .linear (.wire 6977) (.wire 470488) true
  node_470508 : g.nodes ⟨470508, by omega⟩ = .product (.wire 458118) (.wire 470507)
  node_470509 : g.nodes ⟨470509, by omega⟩ = .linear (.wire 470488) (.wire 470508) false
  node_470510 : g.nodes ⟨470510, by omega⟩ = .linear (.wire 6978) (.wire 470499) true
  node_470511 : g.nodes ⟨470511, by omega⟩ = .product (.wire 458118) (.wire 470510)
  node_470512 : g.nodes ⟨470512, by omega⟩ = .linear (.wire 470499) (.wire 470511) false
  node_470513 : g.nodes ⟨470513, by omega⟩ = .linear (.wire 6979) (.wire 470465) true
  node_470514 : g.nodes ⟨470514, by omega⟩ = .product (.wire 458118) (.wire 470513)
  node_470515 : g.nodes ⟨470515, by omega⟩ = .linear (.wire 470465) (.wire 470514) false
  node_470516 : g.nodes ⟨470516, by omega⟩ = .linear (.wire 6980) (.wire 470476) true
  node_470517 : g.nodes ⟨470517, by omega⟩ = .product (.wire 458118) (.wire 470516)
  node_470518 : g.nodes ⟨470518, by omega⟩ = .linear (.wire 470476) (.wire 470517) false
  node_470519 : g.nodes ⟨470519, by omega⟩ = .linear (.wire 6981) (.wire 470487) true
  node_470520 : g.nodes ⟨470520, by omega⟩ = .product (.wire 458118) (.wire 470519)
  node_470521 : g.nodes ⟨470521, by omega⟩ = .linear (.wire 470487) (.wire 470520) false
  node_470522 : g.nodes ⟨470522, by omega⟩ = .linear (.wire 470466) (.wire 6975) true
  node_470523 : g.nodes ⟨470523, by omega⟩ = .product (.wire 458118) (.wire 470522)
  node_470524 : g.nodes ⟨470524, by omega⟩ = .linear (.wire 6975) (.wire 470523) false
  node_470525 : g.nodes ⟨470525, by omega⟩ = .linear (.wire 470477) (.wire 6976) true
  node_470526 : g.nodes ⟨470526, by omega⟩ = .product (.wire 458118) (.wire 470525)
  node_470527 : g.nodes ⟨470527, by omega⟩ = .linear (.wire 6976) (.wire 470526) false
  node_470528 : g.nodes ⟨470528, by omega⟩ = .linear (.wire 470488) (.wire 6977) true
  node_470529 : g.nodes ⟨470529, by omega⟩ = .product (.wire 458118) (.wire 470528)
  node_470530 : g.nodes ⟨470530, by omega⟩ = .linear (.wire 6977) (.wire 470529) false
  node_470531 : g.nodes ⟨470531, by omega⟩ = .linear (.wire 470499) (.wire 6978) true
  node_470532 : g.nodes ⟨470532, by omega⟩ = .product (.wire 458118) (.wire 470531)
  node_470533 : g.nodes ⟨470533, by omega⟩ = .linear (.wire 6978) (.wire 470532) false
  node_470534 : g.nodes ⟨470534, by omega⟩ = .linear (.wire 470465) (.wire 6979) true
  node_470535 : g.nodes ⟨470535, by omega⟩ = .product (.wire 458118) (.wire 470534)
  node_470536 : g.nodes ⟨470536, by omega⟩ = .linear (.wire 6979) (.wire 470535) false
  node_470537 : g.nodes ⟨470537, by omega⟩ = .linear (.wire 470476) (.wire 6980) true
  node_470538 : g.nodes ⟨470538, by omega⟩ = .product (.wire 458118) (.wire 470537)
  node_470539 : g.nodes ⟨470539, by omega⟩ = .linear (.wire 6980) (.wire 470538) false
  node_470540 : g.nodes ⟨470540, by omega⟩ = .linear (.wire 470487) (.wire 6981) true
  node_470541 : g.nodes ⟨470541, by omega⟩ = .product (.wire 458118) (.wire 470540)
  node_470542 : g.nodes ⟨470542, by omega⟩ = .linear (.wire 6981) (.wire 470541) false
  node_472975 : g.nodes ⟨472975, by omega⟩ = .linear (.wire 6982) (.wire 472940) true
  node_472976 : g.nodes ⟨472976, by omega⟩ = .product (.wire 458123) (.wire 472975)
  node_472977 : g.nodes ⟨472977, by omega⟩ = .linear (.wire 472940) (.wire 472976) false
  node_472978 : g.nodes ⟨472978, by omega⟩ = .linear (.wire 6983) (.wire 472951) true
  node_472979 : g.nodes ⟨472979, by omega⟩ = .product (.wire 458123) (.wire 472978)
  node_472980 : g.nodes ⟨472980, by omega⟩ = .linear (.wire 472951) (.wire 472979) false
  node_472981 : g.nodes ⟨472981, by omega⟩ = .linear (.wire 6984) (.wire 472962) true
  node_472982 : g.nodes ⟨472982, by omega⟩ = .product (.wire 458123) (.wire 472981)
  node_472983 : g.nodes ⟨472983, by omega⟩ = .linear (.wire 472962) (.wire 472982) false
  node_472984 : g.nodes ⟨472984, by omega⟩ = .linear (.wire 6985) (.wire 472973) true
  node_472985 : g.nodes ⟨472985, by omega⟩ = .product (.wire 458123) (.wire 472984)
  node_472986 : g.nodes ⟨472986, by omega⟩ = .linear (.wire 472973) (.wire 472985) false
  node_472987 : g.nodes ⟨472987, by omega⟩ = .linear (.wire 6986) (.wire 472939) true
  node_472988 : g.nodes ⟨472988, by omega⟩ = .product (.wire 458123) (.wire 472987)
  node_472989 : g.nodes ⟨472989, by omega⟩ = .linear (.wire 472939) (.wire 472988) false
  node_472990 : g.nodes ⟨472990, by omega⟩ = .linear (.wire 6987) (.wire 472950) true
  node_472991 : g.nodes ⟨472991, by omega⟩ = .product (.wire 458123) (.wire 472990)
  node_472992 : g.nodes ⟨472992, by omega⟩ = .linear (.wire 472950) (.wire 472991) false
  node_472993 : g.nodes ⟨472993, by omega⟩ = .linear (.wire 6988) (.wire 472961) true
  node_472994 : g.nodes ⟨472994, by omega⟩ = .product (.wire 458123) (.wire 472993)
  node_472995 : g.nodes ⟨472995, by omega⟩ = .linear (.wire 472961) (.wire 472994) false
  node_472996 : g.nodes ⟨472996, by omega⟩ = .linear (.wire 472940) (.wire 6982) true
  node_472997 : g.nodes ⟨472997, by omega⟩ = .product (.wire 458123) (.wire 472996)
  node_472998 : g.nodes ⟨472998, by omega⟩ = .linear (.wire 6982) (.wire 472997) false
  node_472999 : g.nodes ⟨472999, by omega⟩ = .linear (.wire 472951) (.wire 6983) true
  node_473000 : g.nodes ⟨473000, by omega⟩ = .product (.wire 458123) (.wire 472999)
  node_473001 : g.nodes ⟨473001, by omega⟩ = .linear (.wire 6983) (.wire 473000) false
  node_473002 : g.nodes ⟨473002, by omega⟩ = .linear (.wire 472962) (.wire 6984) true
  node_473003 : g.nodes ⟨473003, by omega⟩ = .product (.wire 458123) (.wire 473002)
  node_473004 : g.nodes ⟨473004, by omega⟩ = .linear (.wire 6984) (.wire 473003) false
  node_473005 : g.nodes ⟨473005, by omega⟩ = .linear (.wire 472973) (.wire 6985) true
  node_473006 : g.nodes ⟨473006, by omega⟩ = .product (.wire 458123) (.wire 473005)
  node_473007 : g.nodes ⟨473007, by omega⟩ = .linear (.wire 6985) (.wire 473006) false
  node_473008 : g.nodes ⟨473008, by omega⟩ = .linear (.wire 472939) (.wire 6986) true
  node_473009 : g.nodes ⟨473009, by omega⟩ = .product (.wire 458123) (.wire 473008)
  node_473010 : g.nodes ⟨473010, by omega⟩ = .linear (.wire 6986) (.wire 473009) false
  node_473011 : g.nodes ⟨473011, by omega⟩ = .linear (.wire 472950) (.wire 6987) true
  node_473012 : g.nodes ⟨473012, by omega⟩ = .product (.wire 458123) (.wire 473011)
  node_473013 : g.nodes ⟨473013, by omega⟩ = .linear (.wire 6987) (.wire 473012) false
  node_473014 : g.nodes ⟨473014, by omega⟩ = .linear (.wire 472961) (.wire 6988) true
  node_473015 : g.nodes ⟨473015, by omega⟩ = .product (.wire 458123) (.wire 473014)
  node_473016 : g.nodes ⟨473016, by omega⟩ = .linear (.wire 6988) (.wire 473015) false
  node_475449 : g.nodes ⟨475449, by omega⟩ = .linear (.wire 6989) (.wire 475414) true
  node_475450 : g.nodes ⟨475450, by omega⟩ = .product (.wire 458128) (.wire 475449)
  node_475451 : g.nodes ⟨475451, by omega⟩ = .linear (.wire 475414) (.wire 475450) false
  node_475452 : g.nodes ⟨475452, by omega⟩ = .linear (.wire 6990) (.wire 475425) true
  node_475453 : g.nodes ⟨475453, by omega⟩ = .product (.wire 458128) (.wire 475452)
  node_475454 : g.nodes ⟨475454, by omega⟩ = .linear (.wire 475425) (.wire 475453) false
  node_475455 : g.nodes ⟨475455, by omega⟩ = .linear (.wire 6991) (.wire 475436) true
  node_475456 : g.nodes ⟨475456, by omega⟩ = .product (.wire 458128) (.wire 475455)
  node_475457 : g.nodes ⟨475457, by omega⟩ = .linear (.wire 475436) (.wire 475456) false
  node_475458 : g.nodes ⟨475458, by omega⟩ = .linear (.wire 6992) (.wire 475447) true
  node_475459 : g.nodes ⟨475459, by omega⟩ = .product (.wire 458128) (.wire 475458)
  node_475460 : g.nodes ⟨475460, by omega⟩ = .linear (.wire 475447) (.wire 475459) false
  node_475461 : g.nodes ⟨475461, by omega⟩ = .linear (.wire 6993) (.wire 475413) true
  node_475462 : g.nodes ⟨475462, by omega⟩ = .product (.wire 458128) (.wire 475461)
  node_475463 : g.nodes ⟨475463, by omega⟩ = .linear (.wire 475413) (.wire 475462) false
  node_475464 : g.nodes ⟨475464, by omega⟩ = .linear (.wire 6994) (.wire 475424) true
  node_475465 : g.nodes ⟨475465, by omega⟩ = .product (.wire 458128) (.wire 475464)
  node_475466 : g.nodes ⟨475466, by omega⟩ = .linear (.wire 475424) (.wire 475465) false
  node_475467 : g.nodes ⟨475467, by omega⟩ = .linear (.wire 6995) (.wire 475435) true
  node_475468 : g.nodes ⟨475468, by omega⟩ = .product (.wire 458128) (.wire 475467)
  node_475469 : g.nodes ⟨475469, by omega⟩ = .linear (.wire 475435) (.wire 475468) false
  node_475470 : g.nodes ⟨475470, by omega⟩ = .linear (.wire 475414) (.wire 6989) true
  node_475471 : g.nodes ⟨475471, by omega⟩ = .product (.wire 458128) (.wire 475470)
  node_475472 : g.nodes ⟨475472, by omega⟩ = .linear (.wire 6989) (.wire 475471) false
  node_475473 : g.nodes ⟨475473, by omega⟩ = .linear (.wire 475425) (.wire 6990) true
  node_475474 : g.nodes ⟨475474, by omega⟩ = .product (.wire 458128) (.wire 475473)
  node_475475 : g.nodes ⟨475475, by omega⟩ = .linear (.wire 6990) (.wire 475474) false
  node_475476 : g.nodes ⟨475476, by omega⟩ = .linear (.wire 475436) (.wire 6991) true
  node_475477 : g.nodes ⟨475477, by omega⟩ = .product (.wire 458128) (.wire 475476)
  node_475478 : g.nodes ⟨475478, by omega⟩ = .linear (.wire 6991) (.wire 475477) false
  node_475479 : g.nodes ⟨475479, by omega⟩ = .linear (.wire 475447) (.wire 6992) true
  node_475480 : g.nodes ⟨475480, by omega⟩ = .product (.wire 458128) (.wire 475479)
  node_475481 : g.nodes ⟨475481, by omega⟩ = .linear (.wire 6992) (.wire 475480) false
  node_475482 : g.nodes ⟨475482, by omega⟩ = .linear (.wire 475413) (.wire 6993) true
  node_475483 : g.nodes ⟨475483, by omega⟩ = .product (.wire 458128) (.wire 475482)
  node_475484 : g.nodes ⟨475484, by omega⟩ = .linear (.wire 6993) (.wire 475483) false
  node_475485 : g.nodes ⟨475485, by omega⟩ = .linear (.wire 475424) (.wire 6994) true
  node_475486 : g.nodes ⟨475486, by omega⟩ = .product (.wire 458128) (.wire 475485)
  node_475487 : g.nodes ⟨475487, by omega⟩ = .linear (.wire 6994) (.wire 475486) false
  node_475488 : g.nodes ⟨475488, by omega⟩ = .linear (.wire 475435) (.wire 6995) true
  node_475489 : g.nodes ⟨475489, by omega⟩ = .product (.wire 458128) (.wire 475488)
  node_475490 : g.nodes ⟨475490, by omega⟩ = .linear (.wire 6995) (.wire 475489) false
  node_477923 : g.nodes ⟨477923, by omega⟩ = .linear (.wire 6996) (.wire 477888) true
  node_477924 : g.nodes ⟨477924, by omega⟩ = .product (.wire 458133) (.wire 477923)
  node_477925 : g.nodes ⟨477925, by omega⟩ = .linear (.wire 477888) (.wire 477924) false
  node_477926 : g.nodes ⟨477926, by omega⟩ = .linear (.wire 6997) (.wire 477899) true
  node_477927 : g.nodes ⟨477927, by omega⟩ = .product (.wire 458133) (.wire 477926)
  node_477928 : g.nodes ⟨477928, by omega⟩ = .linear (.wire 477899) (.wire 477927) false
  node_477929 : g.nodes ⟨477929, by omega⟩ = .linear (.wire 6998) (.wire 477910) true
  node_477930 : g.nodes ⟨477930, by omega⟩ = .product (.wire 458133) (.wire 477929)
  node_477931 : g.nodes ⟨477931, by omega⟩ = .linear (.wire 477910) (.wire 477930) false
  node_477932 : g.nodes ⟨477932, by omega⟩ = .linear (.wire 6999) (.wire 477921) true
  node_477933 : g.nodes ⟨477933, by omega⟩ = .product (.wire 458133) (.wire 477932)
  node_477934 : g.nodes ⟨477934, by omega⟩ = .linear (.wire 477921) (.wire 477933) false
  node_477935 : g.nodes ⟨477935, by omega⟩ = .linear (.wire 7000) (.wire 477887) true
  node_477936 : g.nodes ⟨477936, by omega⟩ = .product (.wire 458133) (.wire 477935)
  node_477937 : g.nodes ⟨477937, by omega⟩ = .linear (.wire 477887) (.wire 477936) false
  node_477938 : g.nodes ⟨477938, by omega⟩ = .linear (.wire 7001) (.wire 477898) true
  node_477939 : g.nodes ⟨477939, by omega⟩ = .product (.wire 458133) (.wire 477938)
  node_477940 : g.nodes ⟨477940, by omega⟩ = .linear (.wire 477898) (.wire 477939) false
  node_477941 : g.nodes ⟨477941, by omega⟩ = .linear (.wire 7002) (.wire 477909) true
  node_477942 : g.nodes ⟨477942, by omega⟩ = .product (.wire 458133) (.wire 477941)
  node_477943 : g.nodes ⟨477943, by omega⟩ = .linear (.wire 477909) (.wire 477942) false
  node_477944 : g.nodes ⟨477944, by omega⟩ = .linear (.wire 477888) (.wire 6996) true
  node_477945 : g.nodes ⟨477945, by omega⟩ = .product (.wire 458133) (.wire 477944)
  node_477946 : g.nodes ⟨477946, by omega⟩ = .linear (.wire 6996) (.wire 477945) false
  node_477947 : g.nodes ⟨477947, by omega⟩ = .linear (.wire 477899) (.wire 6997) true
  node_477948 : g.nodes ⟨477948, by omega⟩ = .product (.wire 458133) (.wire 477947)
  node_477949 : g.nodes ⟨477949, by omega⟩ = .linear (.wire 6997) (.wire 477948) false
  node_477950 : g.nodes ⟨477950, by omega⟩ = .linear (.wire 477910) (.wire 6998) true
  node_477951 : g.nodes ⟨477951, by omega⟩ = .product (.wire 458133) (.wire 477950)
  node_477952 : g.nodes ⟨477952, by omega⟩ = .linear (.wire 6998) (.wire 477951) false
  node_477953 : g.nodes ⟨477953, by omega⟩ = .linear (.wire 477921) (.wire 6999) true
  node_477954 : g.nodes ⟨477954, by omega⟩ = .product (.wire 458133) (.wire 477953)
  node_477955 : g.nodes ⟨477955, by omega⟩ = .linear (.wire 6999) (.wire 477954) false
  node_477956 : g.nodes ⟨477956, by omega⟩ = .linear (.wire 477887) (.wire 7000) true
  node_477957 : g.nodes ⟨477957, by omega⟩ = .product (.wire 458133) (.wire 477956)
  node_477958 : g.nodes ⟨477958, by omega⟩ = .linear (.wire 7000) (.wire 477957) false
  node_477959 : g.nodes ⟨477959, by omega⟩ = .linear (.wire 477898) (.wire 7001) true
  node_477960 : g.nodes ⟨477960, by omega⟩ = .product (.wire 458133) (.wire 477959)
  node_477961 : g.nodes ⟨477961, by omega⟩ = .linear (.wire 7001) (.wire 477960) false
  node_477962 : g.nodes ⟨477962, by omega⟩ = .linear (.wire 477909) (.wire 7002) true
  node_477963 : g.nodes ⟨477963, by omega⟩ = .product (.wire 458133) (.wire 477962)
  node_477964 : g.nodes ⟨477964, by omega⟩ = .linear (.wire 7002) (.wire 477963) false
  node_480397 : g.nodes ⟨480397, by omega⟩ = .linear (.wire 7003) (.wire 480362) true
  node_480398 : g.nodes ⟨480398, by omega⟩ = .product (.wire 458138) (.wire 480397)
  node_480399 : g.nodes ⟨480399, by omega⟩ = .linear (.wire 480362) (.wire 480398) false
  node_480400 : g.nodes ⟨480400, by omega⟩ = .linear (.wire 7004) (.wire 480373) true
  node_480401 : g.nodes ⟨480401, by omega⟩ = .product (.wire 458138) (.wire 480400)
  node_480402 : g.nodes ⟨480402, by omega⟩ = .linear (.wire 480373) (.wire 480401) false
  node_480403 : g.nodes ⟨480403, by omega⟩ = .linear (.wire 7005) (.wire 480384) true
  node_480404 : g.nodes ⟨480404, by omega⟩ = .product (.wire 458138) (.wire 480403)
  node_480405 : g.nodes ⟨480405, by omega⟩ = .linear (.wire 480384) (.wire 480404) false
  node_480406 : g.nodes ⟨480406, by omega⟩ = .linear (.wire 7006) (.wire 480395) true
  node_480407 : g.nodes ⟨480407, by omega⟩ = .product (.wire 458138) (.wire 480406)
  node_480408 : g.nodes ⟨480408, by omega⟩ = .linear (.wire 480395) (.wire 480407) false
  node_480409 : g.nodes ⟨480409, by omega⟩ = .linear (.wire 7007) (.wire 480361) true
  node_480410 : g.nodes ⟨480410, by omega⟩ = .product (.wire 458138) (.wire 480409)
  node_480411 : g.nodes ⟨480411, by omega⟩ = .linear (.wire 480361) (.wire 480410) false
  node_480412 : g.nodes ⟨480412, by omega⟩ = .linear (.wire 7008) (.wire 480372) true
  node_480413 : g.nodes ⟨480413, by omega⟩ = .product (.wire 458138) (.wire 480412)
  node_480414 : g.nodes ⟨480414, by omega⟩ = .linear (.wire 480372) (.wire 480413) false
  node_480415 : g.nodes ⟨480415, by omega⟩ = .linear (.wire 7009) (.wire 480383) true
  node_480416 : g.nodes ⟨480416, by omega⟩ = .product (.wire 458138) (.wire 480415)
  node_480417 : g.nodes ⟨480417, by omega⟩ = .linear (.wire 480383) (.wire 480416) false
  node_480418 : g.nodes ⟨480418, by omega⟩ = .linear (.wire 480362) (.wire 7003) true
  node_480419 : g.nodes ⟨480419, by omega⟩ = .product (.wire 458138) (.wire 480418)
  node_480420 : g.nodes ⟨480420, by omega⟩ = .linear (.wire 7003) (.wire 480419) false
  node_480421 : g.nodes ⟨480421, by omega⟩ = .linear (.wire 480373) (.wire 7004) true
  node_480422 : g.nodes ⟨480422, by omega⟩ = .product (.wire 458138) (.wire 480421)
  node_480423 : g.nodes ⟨480423, by omega⟩ = .linear (.wire 7004) (.wire 480422) false
  node_480424 : g.nodes ⟨480424, by omega⟩ = .linear (.wire 480384) (.wire 7005) true
  node_480425 : g.nodes ⟨480425, by omega⟩ = .product (.wire 458138) (.wire 480424)
  node_480426 : g.nodes ⟨480426, by omega⟩ = .linear (.wire 7005) (.wire 480425) false
  node_480427 : g.nodes ⟨480427, by omega⟩ = .linear (.wire 480395) (.wire 7006) true
  node_480428 : g.nodes ⟨480428, by omega⟩ = .product (.wire 458138) (.wire 480427)
  node_480429 : g.nodes ⟨480429, by omega⟩ = .linear (.wire 7006) (.wire 480428) false
  node_480430 : g.nodes ⟨480430, by omega⟩ = .linear (.wire 480361) (.wire 7007) true
  node_480431 : g.nodes ⟨480431, by omega⟩ = .product (.wire 458138) (.wire 480430)
  node_480432 : g.nodes ⟨480432, by omega⟩ = .linear (.wire 7007) (.wire 480431) false
  node_480433 : g.nodes ⟨480433, by omega⟩ = .linear (.wire 480372) (.wire 7008) true
  node_480434 : g.nodes ⟨480434, by omega⟩ = .product (.wire 458138) (.wire 480433)
  node_480435 : g.nodes ⟨480435, by omega⟩ = .linear (.wire 7008) (.wire 480434) false
  node_480436 : g.nodes ⟨480436, by omega⟩ = .linear (.wire 480383) (.wire 7009) true
  node_480437 : g.nodes ⟨480437, by omega⟩ = .product (.wire 458138) (.wire 480436)
  node_480438 : g.nodes ⟨480438, by omega⟩ = .linear (.wire 7009) (.wire 480437) false
  node_482871 : g.nodes ⟨482871, by omega⟩ = .linear (.wire 7010) (.wire 482836) true
  node_482872 : g.nodes ⟨482872, by omega⟩ = .product (.wire 458143) (.wire 482871)
  node_482873 : g.nodes ⟨482873, by omega⟩ = .linear (.wire 482836) (.wire 482872) false
  node_482874 : g.nodes ⟨482874, by omega⟩ = .linear (.wire 7011) (.wire 482847) true
  node_482875 : g.nodes ⟨482875, by omega⟩ = .product (.wire 458143) (.wire 482874)
  node_482876 : g.nodes ⟨482876, by omega⟩ = .linear (.wire 482847) (.wire 482875) false
  node_482877 : g.nodes ⟨482877, by omega⟩ = .linear (.wire 7012) (.wire 482858) true
  node_482878 : g.nodes ⟨482878, by omega⟩ = .product (.wire 458143) (.wire 482877)
  node_482879 : g.nodes ⟨482879, by omega⟩ = .linear (.wire 482858) (.wire 482878) false
  node_482880 : g.nodes ⟨482880, by omega⟩ = .linear (.wire 7013) (.wire 482869) true
  node_482881 : g.nodes ⟨482881, by omega⟩ = .product (.wire 458143) (.wire 482880)
  node_482882 : g.nodes ⟨482882, by omega⟩ = .linear (.wire 482869) (.wire 482881) false
  node_482883 : g.nodes ⟨482883, by omega⟩ = .linear (.wire 7014) (.wire 482835) true
  node_482884 : g.nodes ⟨482884, by omega⟩ = .product (.wire 458143) (.wire 482883)
  node_482885 : g.nodes ⟨482885, by omega⟩ = .linear (.wire 482835) (.wire 482884) false
  node_482886 : g.nodes ⟨482886, by omega⟩ = .linear (.wire 7015) (.wire 482846) true
  node_482887 : g.nodes ⟨482887, by omega⟩ = .product (.wire 458143) (.wire 482886)
  node_482888 : g.nodes ⟨482888, by omega⟩ = .linear (.wire 482846) (.wire 482887) false
  node_482889 : g.nodes ⟨482889, by omega⟩ = .linear (.wire 7016) (.wire 482857) true
  node_482890 : g.nodes ⟨482890, by omega⟩ = .product (.wire 458143) (.wire 482889)
  node_482891 : g.nodes ⟨482891, by omega⟩ = .linear (.wire 482857) (.wire 482890) false
  node_482892 : g.nodes ⟨482892, by omega⟩ = .linear (.wire 482836) (.wire 7010) true
  node_482893 : g.nodes ⟨482893, by omega⟩ = .product (.wire 458143) (.wire 482892)
  node_482894 : g.nodes ⟨482894, by omega⟩ = .linear (.wire 7010) (.wire 482893) false
  node_482895 : g.nodes ⟨482895, by omega⟩ = .linear (.wire 482847) (.wire 7011) true
  node_482896 : g.nodes ⟨482896, by omega⟩ = .product (.wire 458143) (.wire 482895)
  node_482897 : g.nodes ⟨482897, by omega⟩ = .linear (.wire 7011) (.wire 482896) false
  node_482898 : g.nodes ⟨482898, by omega⟩ = .linear (.wire 482858) (.wire 7012) true
  node_482899 : g.nodes ⟨482899, by omega⟩ = .product (.wire 458143) (.wire 482898)
  node_482900 : g.nodes ⟨482900, by omega⟩ = .linear (.wire 7012) (.wire 482899) false
  node_482901 : g.nodes ⟨482901, by omega⟩ = .linear (.wire 482869) (.wire 7013) true
  node_482902 : g.nodes ⟨482902, by omega⟩ = .product (.wire 458143) (.wire 482901)
  node_482903 : g.nodes ⟨482903, by omega⟩ = .linear (.wire 7013) (.wire 482902) false
  node_482904 : g.nodes ⟨482904, by omega⟩ = .linear (.wire 482835) (.wire 7014) true
  node_482905 : g.nodes ⟨482905, by omega⟩ = .product (.wire 458143) (.wire 482904)
  node_482906 : g.nodes ⟨482906, by omega⟩ = .linear (.wire 7014) (.wire 482905) false
  node_482907 : g.nodes ⟨482907, by omega⟩ = .linear (.wire 482846) (.wire 7015) true
  node_482908 : g.nodes ⟨482908, by omega⟩ = .product (.wire 458143) (.wire 482907)
  node_482909 : g.nodes ⟨482909, by omega⟩ = .linear (.wire 7015) (.wire 482908) false
  node_482910 : g.nodes ⟨482910, by omega⟩ = .linear (.wire 482857) (.wire 7016) true
  node_482911 : g.nodes ⟨482911, by omega⟩ = .product (.wire 458143) (.wire 482910)
  node_482912 : g.nodes ⟨482912, by omega⟩ = .linear (.wire 7016) (.wire 482911) false
  node_485345 : g.nodes ⟨485345, by omega⟩ = .linear (.wire 7017) (.wire 485310) true
  node_485346 : g.nodes ⟨485346, by omega⟩ = .product (.wire 458148) (.wire 485345)
  node_485347 : g.nodes ⟨485347, by omega⟩ = .linear (.wire 485310) (.wire 485346) false
  node_485348 : g.nodes ⟨485348, by omega⟩ = .linear (.wire 7018) (.wire 485321) true
  node_485349 : g.nodes ⟨485349, by omega⟩ = .product (.wire 458148) (.wire 485348)
  node_485350 : g.nodes ⟨485350, by omega⟩ = .linear (.wire 485321) (.wire 485349) false
  node_485351 : g.nodes ⟨485351, by omega⟩ = .linear (.wire 7019) (.wire 485332) true
  node_485352 : g.nodes ⟨485352, by omega⟩ = .product (.wire 458148) (.wire 485351)
  node_485353 : g.nodes ⟨485353, by omega⟩ = .linear (.wire 485332) (.wire 485352) false
  node_485354 : g.nodes ⟨485354, by omega⟩ = .linear (.wire 7020) (.wire 485343) true
  node_485355 : g.nodes ⟨485355, by omega⟩ = .product (.wire 458148) (.wire 485354)
  node_485356 : g.nodes ⟨485356, by omega⟩ = .linear (.wire 485343) (.wire 485355) false
  node_485357 : g.nodes ⟨485357, by omega⟩ = .linear (.wire 7021) (.wire 485309) true
  node_485358 : g.nodes ⟨485358, by omega⟩ = .product (.wire 458148) (.wire 485357)
  node_485359 : g.nodes ⟨485359, by omega⟩ = .linear (.wire 485309) (.wire 485358) false
  node_485360 : g.nodes ⟨485360, by omega⟩ = .linear (.wire 7022) (.wire 485320) true
  node_485361 : g.nodes ⟨485361, by omega⟩ = .product (.wire 458148) (.wire 485360)
  node_485362 : g.nodes ⟨485362, by omega⟩ = .linear (.wire 485320) (.wire 485361) false
  node_485363 : g.nodes ⟨485363, by omega⟩ = .linear (.wire 7023) (.wire 485331) true
  node_485364 : g.nodes ⟨485364, by omega⟩ = .product (.wire 458148) (.wire 485363)
  node_485365 : g.nodes ⟨485365, by omega⟩ = .linear (.wire 485331) (.wire 485364) false
  node_485366 : g.nodes ⟨485366, by omega⟩ = .linear (.wire 485310) (.wire 7017) true
  node_485367 : g.nodes ⟨485367, by omega⟩ = .product (.wire 458148) (.wire 485366)
  node_485368 : g.nodes ⟨485368, by omega⟩ = .linear (.wire 7017) (.wire 485367) false
  node_485369 : g.nodes ⟨485369, by omega⟩ = .linear (.wire 485321) (.wire 7018) true
  node_485370 : g.nodes ⟨485370, by omega⟩ = .product (.wire 458148) (.wire 485369)
  node_485371 : g.nodes ⟨485371, by omega⟩ = .linear (.wire 7018) (.wire 485370) false
  node_485372 : g.nodes ⟨485372, by omega⟩ = .linear (.wire 485332) (.wire 7019) true
  node_485373 : g.nodes ⟨485373, by omega⟩ = .product (.wire 458148) (.wire 485372)
  node_485374 : g.nodes ⟨485374, by omega⟩ = .linear (.wire 7019) (.wire 485373) false
  node_485375 : g.nodes ⟨485375, by omega⟩ = .linear (.wire 485343) (.wire 7020) true
  node_485376 : g.nodes ⟨485376, by omega⟩ = .product (.wire 458148) (.wire 485375)
  node_485377 : g.nodes ⟨485377, by omega⟩ = .linear (.wire 7020) (.wire 485376) false
  node_485378 : g.nodes ⟨485378, by omega⟩ = .linear (.wire 485309) (.wire 7021) true
  node_485379 : g.nodes ⟨485379, by omega⟩ = .product (.wire 458148) (.wire 485378)
  node_485380 : g.nodes ⟨485380, by omega⟩ = .linear (.wire 7021) (.wire 485379) false
  node_485381 : g.nodes ⟨485381, by omega⟩ = .linear (.wire 485320) (.wire 7022) true
  node_485382 : g.nodes ⟨485382, by omega⟩ = .product (.wire 458148) (.wire 485381)
  node_485383 : g.nodes ⟨485383, by omega⟩ = .linear (.wire 7022) (.wire 485382) false
  node_485384 : g.nodes ⟨485384, by omega⟩ = .linear (.wire 485331) (.wire 7023) true
  node_485385 : g.nodes ⟨485385, by omega⟩ = .product (.wire 458148) (.wire 485384)
  node_485386 : g.nodes ⟨485386, by omega⟩ = .linear (.wire 7023) (.wire 485385) false
  node_487819 : g.nodes ⟨487819, by omega⟩ = .linear (.wire 7024) (.wire 487784) true
  node_487820 : g.nodes ⟨487820, by omega⟩ = .product (.wire 458153) (.wire 487819)
  node_487821 : g.nodes ⟨487821, by omega⟩ = .linear (.wire 487784) (.wire 487820) false
  node_487822 : g.nodes ⟨487822, by omega⟩ = .linear (.wire 7025) (.wire 487795) true
  node_487823 : g.nodes ⟨487823, by omega⟩ = .product (.wire 458153) (.wire 487822)
  node_487824 : g.nodes ⟨487824, by omega⟩ = .linear (.wire 487795) (.wire 487823) false
  node_487825 : g.nodes ⟨487825, by omega⟩ = .linear (.wire 7026) (.wire 487806) true
  node_487826 : g.nodes ⟨487826, by omega⟩ = .product (.wire 458153) (.wire 487825)
  node_487827 : g.nodes ⟨487827, by omega⟩ = .linear (.wire 487806) (.wire 487826) false
  node_487828 : g.nodes ⟨487828, by omega⟩ = .linear (.wire 7027) (.wire 487817) true
  node_487829 : g.nodes ⟨487829, by omega⟩ = .product (.wire 458153) (.wire 487828)
  node_487830 : g.nodes ⟨487830, by omega⟩ = .linear (.wire 487817) (.wire 487829) false
  node_487831 : g.nodes ⟨487831, by omega⟩ = .linear (.wire 7028) (.wire 487783) true
  node_487832 : g.nodes ⟨487832, by omega⟩ = .product (.wire 458153) (.wire 487831)
  node_487833 : g.nodes ⟨487833, by omega⟩ = .linear (.wire 487783) (.wire 487832) false
  node_487834 : g.nodes ⟨487834, by omega⟩ = .linear (.wire 7029) (.wire 487794) true
  node_487835 : g.nodes ⟨487835, by omega⟩ = .product (.wire 458153) (.wire 487834)
  node_487836 : g.nodes ⟨487836, by omega⟩ = .linear (.wire 487794) (.wire 487835) false
  node_487837 : g.nodes ⟨487837, by omega⟩ = .linear (.wire 7030) (.wire 487805) true
  node_487838 : g.nodes ⟨487838, by omega⟩ = .product (.wire 458153) (.wire 487837)
  node_487839 : g.nodes ⟨487839, by omega⟩ = .linear (.wire 487805) (.wire 487838) false
  node_487840 : g.nodes ⟨487840, by omega⟩ = .linear (.wire 487784) (.wire 7024) true
  node_487841 : g.nodes ⟨487841, by omega⟩ = .product (.wire 458153) (.wire 487840)
  node_487842 : g.nodes ⟨487842, by omega⟩ = .linear (.wire 7024) (.wire 487841) false
  node_487843 : g.nodes ⟨487843, by omega⟩ = .linear (.wire 487795) (.wire 7025) true
  node_487844 : g.nodes ⟨487844, by omega⟩ = .product (.wire 458153) (.wire 487843)
  node_487845 : g.nodes ⟨487845, by omega⟩ = .linear (.wire 7025) (.wire 487844) false
  node_487846 : g.nodes ⟨487846, by omega⟩ = .linear (.wire 487806) (.wire 7026) true
  node_487847 : g.nodes ⟨487847, by omega⟩ = .product (.wire 458153) (.wire 487846)
  node_487848 : g.nodes ⟨487848, by omega⟩ = .linear (.wire 7026) (.wire 487847) false
  node_487849 : g.nodes ⟨487849, by omega⟩ = .linear (.wire 487817) (.wire 7027) true
  node_487850 : g.nodes ⟨487850, by omega⟩ = .product (.wire 458153) (.wire 487849)
  node_487851 : g.nodes ⟨487851, by omega⟩ = .linear (.wire 7027) (.wire 487850) false
  node_487852 : g.nodes ⟨487852, by omega⟩ = .linear (.wire 487783) (.wire 7028) true
  node_487853 : g.nodes ⟨487853, by omega⟩ = .product (.wire 458153) (.wire 487852)
  node_487854 : g.nodes ⟨487854, by omega⟩ = .linear (.wire 7028) (.wire 487853) false
  node_487855 : g.nodes ⟨487855, by omega⟩ = .linear (.wire 487794) (.wire 7029) true
  node_487856 : g.nodes ⟨487856, by omega⟩ = .product (.wire 458153) (.wire 487855)
  node_487857 : g.nodes ⟨487857, by omega⟩ = .linear (.wire 7029) (.wire 487856) false
  node_487858 : g.nodes ⟨487858, by omega⟩ = .linear (.wire 487805) (.wire 7030) true
  node_487859 : g.nodes ⟨487859, by omega⟩ = .product (.wire 458153) (.wire 487858)
  node_487860 : g.nodes ⟨487860, by omega⟩ = .linear (.wire 7030) (.wire 487859) false
  node_490293 : g.nodes ⟨490293, by omega⟩ = .linear (.wire 7031) (.wire 490258) true
  node_490294 : g.nodes ⟨490294, by omega⟩ = .product (.wire 458158) (.wire 490293)
  node_490295 : g.nodes ⟨490295, by omega⟩ = .linear (.wire 490258) (.wire 490294) false
  node_490296 : g.nodes ⟨490296, by omega⟩ = .linear (.wire 7032) (.wire 490269) true
  node_490297 : g.nodes ⟨490297, by omega⟩ = .product (.wire 458158) (.wire 490296)
  node_490298 : g.nodes ⟨490298, by omega⟩ = .linear (.wire 490269) (.wire 490297) false
  node_490299 : g.nodes ⟨490299, by omega⟩ = .linear (.wire 7033) (.wire 490280) true
  node_490300 : g.nodes ⟨490300, by omega⟩ = .product (.wire 458158) (.wire 490299)
  node_490301 : g.nodes ⟨490301, by omega⟩ = .linear (.wire 490280) (.wire 490300) false
  node_490302 : g.nodes ⟨490302, by omega⟩ = .linear (.wire 7034) (.wire 490291) true
  node_490303 : g.nodes ⟨490303, by omega⟩ = .product (.wire 458158) (.wire 490302)
  node_490304 : g.nodes ⟨490304, by omega⟩ = .linear (.wire 490291) (.wire 490303) false
  node_490305 : g.nodes ⟨490305, by omega⟩ = .linear (.wire 7035) (.wire 490257) true
  node_490306 : g.nodes ⟨490306, by omega⟩ = .product (.wire 458158) (.wire 490305)
  node_490307 : g.nodes ⟨490307, by omega⟩ = .linear (.wire 490257) (.wire 490306) false
  node_490308 : g.nodes ⟨490308, by omega⟩ = .linear (.wire 7036) (.wire 490268) true
  node_490309 : g.nodes ⟨490309, by omega⟩ = .product (.wire 458158) (.wire 490308)
  node_490310 : g.nodes ⟨490310, by omega⟩ = .linear (.wire 490268) (.wire 490309) false
  node_490311 : g.nodes ⟨490311, by omega⟩ = .linear (.wire 7037) (.wire 490279) true
  node_490312 : g.nodes ⟨490312, by omega⟩ = .product (.wire 458158) (.wire 490311)
  node_490313 : g.nodes ⟨490313, by omega⟩ = .linear (.wire 490279) (.wire 490312) false
  node_490314 : g.nodes ⟨490314, by omega⟩ = .linear (.wire 490258) (.wire 7031) true
  node_490315 : g.nodes ⟨490315, by omega⟩ = .product (.wire 458158) (.wire 490314)
  node_490316 : g.nodes ⟨490316, by omega⟩ = .linear (.wire 7031) (.wire 490315) false
  node_490317 : g.nodes ⟨490317, by omega⟩ = .linear (.wire 490269) (.wire 7032) true
  node_490318 : g.nodes ⟨490318, by omega⟩ = .product (.wire 458158) (.wire 490317)
  node_490319 : g.nodes ⟨490319, by omega⟩ = .linear (.wire 7032) (.wire 490318) false
  node_490320 : g.nodes ⟨490320, by omega⟩ = .linear (.wire 490280) (.wire 7033) true
  node_490321 : g.nodes ⟨490321, by omega⟩ = .product (.wire 458158) (.wire 490320)
  node_490322 : g.nodes ⟨490322, by omega⟩ = .linear (.wire 7033) (.wire 490321) false
  node_490323 : g.nodes ⟨490323, by omega⟩ = .linear (.wire 490291) (.wire 7034) true
  node_490324 : g.nodes ⟨490324, by omega⟩ = .product (.wire 458158) (.wire 490323)
  node_490325 : g.nodes ⟨490325, by omega⟩ = .linear (.wire 7034) (.wire 490324) false
  node_490326 : g.nodes ⟨490326, by omega⟩ = .linear (.wire 490257) (.wire 7035) true
  node_490327 : g.nodes ⟨490327, by omega⟩ = .product (.wire 458158) (.wire 490326)
  node_490328 : g.nodes ⟨490328, by omega⟩ = .linear (.wire 7035) (.wire 490327) false
  node_490329 : g.nodes ⟨490329, by omega⟩ = .linear (.wire 490268) (.wire 7036) true
  node_490330 : g.nodes ⟨490330, by omega⟩ = .product (.wire 458158) (.wire 490329)
  node_490331 : g.nodes ⟨490331, by omega⟩ = .linear (.wire 7036) (.wire 490330) false
  node_490332 : g.nodes ⟨490332, by omega⟩ = .linear (.wire 490279) (.wire 7037) true
  node_490333 : g.nodes ⟨490333, by omega⟩ = .product (.wire 458158) (.wire 490332)
  node_490334 : g.nodes ⟨490334, by omega⟩ = .linear (.wire 7037) (.wire 490333) false
  node_492767 : g.nodes ⟨492767, by omega⟩ = .linear (.wire 7038) (.wire 492732) true
  node_492768 : g.nodes ⟨492768, by omega⟩ = .product (.wire 458163) (.wire 492767)
  node_492769 : g.nodes ⟨492769, by omega⟩ = .linear (.wire 492732) (.wire 492768) false
  node_492770 : g.nodes ⟨492770, by omega⟩ = .linear (.wire 7039) (.wire 492743) true
  node_492771 : g.nodes ⟨492771, by omega⟩ = .product (.wire 458163) (.wire 492770)
  node_492772 : g.nodes ⟨492772, by omega⟩ = .linear (.wire 492743) (.wire 492771) false
  node_492773 : g.nodes ⟨492773, by omega⟩ = .linear (.wire 7040) (.wire 492754) true
  node_492774 : g.nodes ⟨492774, by omega⟩ = .product (.wire 458163) (.wire 492773)
  node_492775 : g.nodes ⟨492775, by omega⟩ = .linear (.wire 492754) (.wire 492774) false
  node_492776 : g.nodes ⟨492776, by omega⟩ = .linear (.wire 7041) (.wire 492765) true
  node_492777 : g.nodes ⟨492777, by omega⟩ = .product (.wire 458163) (.wire 492776)
  node_492778 : g.nodes ⟨492778, by omega⟩ = .linear (.wire 492765) (.wire 492777) false
  node_492779 : g.nodes ⟨492779, by omega⟩ = .linear (.wire 7042) (.wire 492731) true
  node_492780 : g.nodes ⟨492780, by omega⟩ = .product (.wire 458163) (.wire 492779)
  node_492781 : g.nodes ⟨492781, by omega⟩ = .linear (.wire 492731) (.wire 492780) false
  node_492782 : g.nodes ⟨492782, by omega⟩ = .linear (.wire 7043) (.wire 492742) true
  node_492783 : g.nodes ⟨492783, by omega⟩ = .product (.wire 458163) (.wire 492782)
  node_492784 : g.nodes ⟨492784, by omega⟩ = .linear (.wire 492742) (.wire 492783) false
  node_492785 : g.nodes ⟨492785, by omega⟩ = .linear (.wire 7044) (.wire 492753) true
  node_492786 : g.nodes ⟨492786, by omega⟩ = .product (.wire 458163) (.wire 492785)
  node_492787 : g.nodes ⟨492787, by omega⟩ = .linear (.wire 492753) (.wire 492786) false
  node_492788 : g.nodes ⟨492788, by omega⟩ = .linear (.wire 492732) (.wire 7038) true
  node_492789 : g.nodes ⟨492789, by omega⟩ = .product (.wire 458163) (.wire 492788)
  node_492790 : g.nodes ⟨492790, by omega⟩ = .linear (.wire 7038) (.wire 492789) false
  node_492791 : g.nodes ⟨492791, by omega⟩ = .linear (.wire 492743) (.wire 7039) true
  node_492792 : g.nodes ⟨492792, by omega⟩ = .product (.wire 458163) (.wire 492791)
  node_492793 : g.nodes ⟨492793, by omega⟩ = .linear (.wire 7039) (.wire 492792) false
  node_492794 : g.nodes ⟨492794, by omega⟩ = .linear (.wire 492754) (.wire 7040) true
  node_492795 : g.nodes ⟨492795, by omega⟩ = .product (.wire 458163) (.wire 492794)
  node_492796 : g.nodes ⟨492796, by omega⟩ = .linear (.wire 7040) (.wire 492795) false
  node_492797 : g.nodes ⟨492797, by omega⟩ = .linear (.wire 492765) (.wire 7041) true
  node_492798 : g.nodes ⟨492798, by omega⟩ = .product (.wire 458163) (.wire 492797)
  node_492799 : g.nodes ⟨492799, by omega⟩ = .linear (.wire 7041) (.wire 492798) false
  node_492800 : g.nodes ⟨492800, by omega⟩ = .linear (.wire 492731) (.wire 7042) true
  node_492801 : g.nodes ⟨492801, by omega⟩ = .product (.wire 458163) (.wire 492800)
  node_492802 : g.nodes ⟨492802, by omega⟩ = .linear (.wire 7042) (.wire 492801) false
  node_492803 : g.nodes ⟨492803, by omega⟩ = .linear (.wire 492742) (.wire 7043) true
  node_492804 : g.nodes ⟨492804, by omega⟩ = .product (.wire 458163) (.wire 492803)
  node_492805 : g.nodes ⟨492805, by omega⟩ = .linear (.wire 7043) (.wire 492804) false
  node_492806 : g.nodes ⟨492806, by omega⟩ = .linear (.wire 492753) (.wire 7044) true
  node_492807 : g.nodes ⟨492807, by omega⟩ = .product (.wire 458163) (.wire 492806)
  node_492808 : g.nodes ⟨492808, by omega⟩ = .linear (.wire 7044) (.wire 492807) false
  node_495241 : g.nodes ⟨495241, by omega⟩ = .linear (.wire 7045) (.wire 495206) true
  node_495242 : g.nodes ⟨495242, by omega⟩ = .product (.wire 458168) (.wire 495241)
  node_495243 : g.nodes ⟨495243, by omega⟩ = .linear (.wire 495206) (.wire 495242) false
  node_495244 : g.nodes ⟨495244, by omega⟩ = .linear (.wire 7046) (.wire 495217) true
  node_495245 : g.nodes ⟨495245, by omega⟩ = .product (.wire 458168) (.wire 495244)
  node_495246 : g.nodes ⟨495246, by omega⟩ = .linear (.wire 495217) (.wire 495245) false
  node_495247 : g.nodes ⟨495247, by omega⟩ = .linear (.wire 7047) (.wire 495228) true
  node_495248 : g.nodes ⟨495248, by omega⟩ = .product (.wire 458168) (.wire 495247)
  node_495249 : g.nodes ⟨495249, by omega⟩ = .linear (.wire 495228) (.wire 495248) false
  node_495250 : g.nodes ⟨495250, by omega⟩ = .linear (.wire 7048) (.wire 495239) true
  node_495251 : g.nodes ⟨495251, by omega⟩ = .product (.wire 458168) (.wire 495250)
  node_495252 : g.nodes ⟨495252, by omega⟩ = .linear (.wire 495239) (.wire 495251) false
  node_495253 : g.nodes ⟨495253, by omega⟩ = .linear (.wire 7049) (.wire 495205) true
  node_495254 : g.nodes ⟨495254, by omega⟩ = .product (.wire 458168) (.wire 495253)
  node_495255 : g.nodes ⟨495255, by omega⟩ = .linear (.wire 495205) (.wire 495254) false
  node_495256 : g.nodes ⟨495256, by omega⟩ = .linear (.wire 7050) (.wire 495216) true
  node_495257 : g.nodes ⟨495257, by omega⟩ = .product (.wire 458168) (.wire 495256)
  node_495258 : g.nodes ⟨495258, by omega⟩ = .linear (.wire 495216) (.wire 495257) false
  node_495259 : g.nodes ⟨495259, by omega⟩ = .linear (.wire 7051) (.wire 495227) true
  node_495260 : g.nodes ⟨495260, by omega⟩ = .product (.wire 458168) (.wire 495259)
  node_495261 : g.nodes ⟨495261, by omega⟩ = .linear (.wire 495227) (.wire 495260) false
  node_495262 : g.nodes ⟨495262, by omega⟩ = .linear (.wire 495206) (.wire 7045) true
  node_495263 : g.nodes ⟨495263, by omega⟩ = .product (.wire 458168) (.wire 495262)
  node_495264 : g.nodes ⟨495264, by omega⟩ = .linear (.wire 7045) (.wire 495263) false
  node_495265 : g.nodes ⟨495265, by omega⟩ = .linear (.wire 495217) (.wire 7046) true
  node_495266 : g.nodes ⟨495266, by omega⟩ = .product (.wire 458168) (.wire 495265)
  node_495267 : g.nodes ⟨495267, by omega⟩ = .linear (.wire 7046) (.wire 495266) false
  node_495268 : g.nodes ⟨495268, by omega⟩ = .linear (.wire 495228) (.wire 7047) true
  node_495269 : g.nodes ⟨495269, by omega⟩ = .product (.wire 458168) (.wire 495268)
  node_495270 : g.nodes ⟨495270, by omega⟩ = .linear (.wire 7047) (.wire 495269) false
  node_495271 : g.nodes ⟨495271, by omega⟩ = .linear (.wire 495239) (.wire 7048) true
  node_495272 : g.nodes ⟨495272, by omega⟩ = .product (.wire 458168) (.wire 495271)
  node_495273 : g.nodes ⟨495273, by omega⟩ = .linear (.wire 7048) (.wire 495272) false
  node_495274 : g.nodes ⟨495274, by omega⟩ = .linear (.wire 495205) (.wire 7049) true
  node_495275 : g.nodes ⟨495275, by omega⟩ = .product (.wire 458168) (.wire 495274)
  node_495276 : g.nodes ⟨495276, by omega⟩ = .linear (.wire 7049) (.wire 495275) false
  node_495277 : g.nodes ⟨495277, by omega⟩ = .linear (.wire 495216) (.wire 7050) true
  node_495278 : g.nodes ⟨495278, by omega⟩ = .product (.wire 458168) (.wire 495277)
  node_495279 : g.nodes ⟨495279, by omega⟩ = .linear (.wire 7050) (.wire 495278) false
  node_495280 : g.nodes ⟨495280, by omega⟩ = .linear (.wire 495227) (.wire 7051) true
  node_495281 : g.nodes ⟨495281, by omega⟩ = .product (.wire 458168) (.wire 495280)
  node_495282 : g.nodes ⟨495282, by omega⟩ = .linear (.wire 7051) (.wire 495281) false
  node_497715 : g.nodes ⟨497715, by omega⟩ = .linear (.wire 7052) (.wire 497680) true
  node_497716 : g.nodes ⟨497716, by omega⟩ = .product (.wire 458173) (.wire 497715)
  node_497717 : g.nodes ⟨497717, by omega⟩ = .linear (.wire 497680) (.wire 497716) false
  node_497718 : g.nodes ⟨497718, by omega⟩ = .linear (.wire 7053) (.wire 497691) true
  node_497719 : g.nodes ⟨497719, by omega⟩ = .product (.wire 458173) (.wire 497718)
  node_497720 : g.nodes ⟨497720, by omega⟩ = .linear (.wire 497691) (.wire 497719) false
  node_497721 : g.nodes ⟨497721, by omega⟩ = .linear (.wire 7054) (.wire 497702) true
  node_497722 : g.nodes ⟨497722, by omega⟩ = .product (.wire 458173) (.wire 497721)
  node_497723 : g.nodes ⟨497723, by omega⟩ = .linear (.wire 497702) (.wire 497722) false
  node_497724 : g.nodes ⟨497724, by omega⟩ = .linear (.wire 7055) (.wire 497713) true
  node_497725 : g.nodes ⟨497725, by omega⟩ = .product (.wire 458173) (.wire 497724)
  node_497726 : g.nodes ⟨497726, by omega⟩ = .linear (.wire 497713) (.wire 497725) false
  node_497727 : g.nodes ⟨497727, by omega⟩ = .linear (.wire 7056) (.wire 497679) true
  node_497728 : g.nodes ⟨497728, by omega⟩ = .product (.wire 458173) (.wire 497727)
  node_497729 : g.nodes ⟨497729, by omega⟩ = .linear (.wire 497679) (.wire 497728) false
  node_497730 : g.nodes ⟨497730, by omega⟩ = .linear (.wire 7057) (.wire 497690) true
  node_497731 : g.nodes ⟨497731, by omega⟩ = .product (.wire 458173) (.wire 497730)
  node_497732 : g.nodes ⟨497732, by omega⟩ = .linear (.wire 497690) (.wire 497731) false
  node_497733 : g.nodes ⟨497733, by omega⟩ = .linear (.wire 7058) (.wire 497701) true
  node_497734 : g.nodes ⟨497734, by omega⟩ = .product (.wire 458173) (.wire 497733)
  node_497735 : g.nodes ⟨497735, by omega⟩ = .linear (.wire 497701) (.wire 497734) false
  node_497736 : g.nodes ⟨497736, by omega⟩ = .linear (.wire 497680) (.wire 7052) true
  node_497737 : g.nodes ⟨497737, by omega⟩ = .product (.wire 458173) (.wire 497736)
  node_497738 : g.nodes ⟨497738, by omega⟩ = .linear (.wire 7052) (.wire 497737) false
  node_497739 : g.nodes ⟨497739, by omega⟩ = .linear (.wire 497691) (.wire 7053) true
  node_497740 : g.nodes ⟨497740, by omega⟩ = .product (.wire 458173) (.wire 497739)
  node_497741 : g.nodes ⟨497741, by omega⟩ = .linear (.wire 7053) (.wire 497740) false
  node_497742 : g.nodes ⟨497742, by omega⟩ = .linear (.wire 497702) (.wire 7054) true
  node_497743 : g.nodes ⟨497743, by omega⟩ = .product (.wire 458173) (.wire 497742)
  node_497744 : g.nodes ⟨497744, by omega⟩ = .linear (.wire 7054) (.wire 497743) false
  node_497745 : g.nodes ⟨497745, by omega⟩ = .linear (.wire 497713) (.wire 7055) true
  node_497746 : g.nodes ⟨497746, by omega⟩ = .product (.wire 458173) (.wire 497745)
  node_497747 : g.nodes ⟨497747, by omega⟩ = .linear (.wire 7055) (.wire 497746) false
  node_497748 : g.nodes ⟨497748, by omega⟩ = .linear (.wire 497679) (.wire 7056) true
  node_497749 : g.nodes ⟨497749, by omega⟩ = .product (.wire 458173) (.wire 497748)
  node_497750 : g.nodes ⟨497750, by omega⟩ = .linear (.wire 7056) (.wire 497749) false
  node_497751 : g.nodes ⟨497751, by omega⟩ = .linear (.wire 497690) (.wire 7057) true
  node_497752 : g.nodes ⟨497752, by omega⟩ = .product (.wire 458173) (.wire 497751)
  node_497753 : g.nodes ⟨497753, by omega⟩ = .linear (.wire 7057) (.wire 497752) false
  node_497754 : g.nodes ⟨497754, by omega⟩ = .linear (.wire 497701) (.wire 7058) true
  node_497755 : g.nodes ⟨497755, by omega⟩ = .product (.wire 458173) (.wire 497754)
  node_497756 : g.nodes ⟨497756, by omega⟩ = .linear (.wire 7058) (.wire 497755) false
  node_500189 : g.nodes ⟨500189, by omega⟩ = .linear (.wire 7059) (.wire 500154) true
  node_500190 : g.nodes ⟨500190, by omega⟩ = .product (.wire 458178) (.wire 500189)
  node_500191 : g.nodes ⟨500191, by omega⟩ = .linear (.wire 500154) (.wire 500190) false
  node_500192 : g.nodes ⟨500192, by omega⟩ = .linear (.wire 7060) (.wire 500165) true
  node_500193 : g.nodes ⟨500193, by omega⟩ = .product (.wire 458178) (.wire 500192)
  node_500194 : g.nodes ⟨500194, by omega⟩ = .linear (.wire 500165) (.wire 500193) false
  node_500195 : g.nodes ⟨500195, by omega⟩ = .linear (.wire 7061) (.wire 500176) true
  node_500196 : g.nodes ⟨500196, by omega⟩ = .product (.wire 458178) (.wire 500195)
  node_500197 : g.nodes ⟨500197, by omega⟩ = .linear (.wire 500176) (.wire 500196) false
  node_500198 : g.nodes ⟨500198, by omega⟩ = .linear (.wire 7062) (.wire 500187) true
  node_500199 : g.nodes ⟨500199, by omega⟩ = .product (.wire 458178) (.wire 500198)
  node_500200 : g.nodes ⟨500200, by omega⟩ = .linear (.wire 500187) (.wire 500199) false
  node_500201 : g.nodes ⟨500201, by omega⟩ = .linear (.wire 7063) (.wire 500153) true
  node_500202 : g.nodes ⟨500202, by omega⟩ = .product (.wire 458178) (.wire 500201)
  node_500203 : g.nodes ⟨500203, by omega⟩ = .linear (.wire 500153) (.wire 500202) false
  node_500204 : g.nodes ⟨500204, by omega⟩ = .linear (.wire 7064) (.wire 500164) true
  node_500205 : g.nodes ⟨500205, by omega⟩ = .product (.wire 458178) (.wire 500204)
  node_500206 : g.nodes ⟨500206, by omega⟩ = .linear (.wire 500164) (.wire 500205) false
  node_500207 : g.nodes ⟨500207, by omega⟩ = .linear (.wire 7065) (.wire 500175) true
  node_500208 : g.nodes ⟨500208, by omega⟩ = .product (.wire 458178) (.wire 500207)
  node_500209 : g.nodes ⟨500209, by omega⟩ = .linear (.wire 500175) (.wire 500208) false
  node_500210 : g.nodes ⟨500210, by omega⟩ = .linear (.wire 500154) (.wire 7059) true
  node_500211 : g.nodes ⟨500211, by omega⟩ = .product (.wire 458178) (.wire 500210)
  node_500212 : g.nodes ⟨500212, by omega⟩ = .linear (.wire 7059) (.wire 500211) false
  node_500213 : g.nodes ⟨500213, by omega⟩ = .linear (.wire 500165) (.wire 7060) true
  node_500214 : g.nodes ⟨500214, by omega⟩ = .product (.wire 458178) (.wire 500213)
  node_500215 : g.nodes ⟨500215, by omega⟩ = .linear (.wire 7060) (.wire 500214) false
  node_500216 : g.nodes ⟨500216, by omega⟩ = .linear (.wire 500176) (.wire 7061) true
  node_500217 : g.nodes ⟨500217, by omega⟩ = .product (.wire 458178) (.wire 500216)
  node_500218 : g.nodes ⟨500218, by omega⟩ = .linear (.wire 7061) (.wire 500217) false
  node_500219 : g.nodes ⟨500219, by omega⟩ = .linear (.wire 500187) (.wire 7062) true
  node_500220 : g.nodes ⟨500220, by omega⟩ = .product (.wire 458178) (.wire 500219)
  node_500221 : g.nodes ⟨500221, by omega⟩ = .linear (.wire 7062) (.wire 500220) false
  node_500222 : g.nodes ⟨500222, by omega⟩ = .linear (.wire 500153) (.wire 7063) true
  node_500223 : g.nodes ⟨500223, by omega⟩ = .product (.wire 458178) (.wire 500222)
  node_500224 : g.nodes ⟨500224, by omega⟩ = .linear (.wire 7063) (.wire 500223) false
  node_500225 : g.nodes ⟨500225, by omega⟩ = .linear (.wire 500164) (.wire 7064) true
  node_500226 : g.nodes ⟨500226, by omega⟩ = .product (.wire 458178) (.wire 500225)
  node_500227 : g.nodes ⟨500227, by omega⟩ = .linear (.wire 7064) (.wire 500226) false
  node_500228 : g.nodes ⟨500228, by omega⟩ = .linear (.wire 500175) (.wire 7065) true
  node_500229 : g.nodes ⟨500229, by omega⟩ = .product (.wire 458178) (.wire 500228)
  node_500230 : g.nodes ⟨500230, by omega⟩ = .linear (.wire 7065) (.wire 500229) false
  node_502663 : g.nodes ⟨502663, by omega⟩ = .linear (.wire 7066) (.wire 502628) true
  node_502664 : g.nodes ⟨502664, by omega⟩ = .product (.wire 458183) (.wire 502663)
  node_502665 : g.nodes ⟨502665, by omega⟩ = .linear (.wire 502628) (.wire 502664) false
  node_502666 : g.nodes ⟨502666, by omega⟩ = .linear (.wire 7067) (.wire 502639) true
  node_502667 : g.nodes ⟨502667, by omega⟩ = .product (.wire 458183) (.wire 502666)
  node_502668 : g.nodes ⟨502668, by omega⟩ = .linear (.wire 502639) (.wire 502667) false
  node_502669 : g.nodes ⟨502669, by omega⟩ = .linear (.wire 7068) (.wire 502650) true
  node_502670 : g.nodes ⟨502670, by omega⟩ = .product (.wire 458183) (.wire 502669)
  node_502671 : g.nodes ⟨502671, by omega⟩ = .linear (.wire 502650) (.wire 502670) false
  node_502672 : g.nodes ⟨502672, by omega⟩ = .linear (.wire 7069) (.wire 502661) true
  node_502673 : g.nodes ⟨502673, by omega⟩ = .product (.wire 458183) (.wire 502672)
  node_502674 : g.nodes ⟨502674, by omega⟩ = .linear (.wire 502661) (.wire 502673) false
  node_502675 : g.nodes ⟨502675, by omega⟩ = .linear (.wire 7070) (.wire 502627) true
  node_502676 : g.nodes ⟨502676, by omega⟩ = .product (.wire 458183) (.wire 502675)
  node_502677 : g.nodes ⟨502677, by omega⟩ = .linear (.wire 502627) (.wire 502676) false
  node_502678 : g.nodes ⟨502678, by omega⟩ = .linear (.wire 7071) (.wire 502638) true
  node_502679 : g.nodes ⟨502679, by omega⟩ = .product (.wire 458183) (.wire 502678)
  node_502680 : g.nodes ⟨502680, by omega⟩ = .linear (.wire 502638) (.wire 502679) false
  node_502681 : g.nodes ⟨502681, by omega⟩ = .linear (.wire 7072) (.wire 502649) true
  node_502682 : g.nodes ⟨502682, by omega⟩ = .product (.wire 458183) (.wire 502681)
  node_502683 : g.nodes ⟨502683, by omega⟩ = .linear (.wire 502649) (.wire 502682) false
  node_502684 : g.nodes ⟨502684, by omega⟩ = .linear (.wire 502628) (.wire 7066) true
  node_502685 : g.nodes ⟨502685, by omega⟩ = .product (.wire 458183) (.wire 502684)
  node_502686 : g.nodes ⟨502686, by omega⟩ = .linear (.wire 7066) (.wire 502685) false
  node_502687 : g.nodes ⟨502687, by omega⟩ = .linear (.wire 502639) (.wire 7067) true
  node_502688 : g.nodes ⟨502688, by omega⟩ = .product (.wire 458183) (.wire 502687)
  node_502689 : g.nodes ⟨502689, by omega⟩ = .linear (.wire 7067) (.wire 502688) false
  node_502690 : g.nodes ⟨502690, by omega⟩ = .linear (.wire 502650) (.wire 7068) true
  node_502691 : g.nodes ⟨502691, by omega⟩ = .product (.wire 458183) (.wire 502690)
  node_502692 : g.nodes ⟨502692, by omega⟩ = .linear (.wire 7068) (.wire 502691) false
  node_502693 : g.nodes ⟨502693, by omega⟩ = .linear (.wire 502661) (.wire 7069) true
  node_502694 : g.nodes ⟨502694, by omega⟩ = .product (.wire 458183) (.wire 502693)
  node_502695 : g.nodes ⟨502695, by omega⟩ = .linear (.wire 7069) (.wire 502694) false
  node_502696 : g.nodes ⟨502696, by omega⟩ = .linear (.wire 502627) (.wire 7070) true
  node_502697 : g.nodes ⟨502697, by omega⟩ = .product (.wire 458183) (.wire 502696)
  node_502698 : g.nodes ⟨502698, by omega⟩ = .linear (.wire 7070) (.wire 502697) false
  node_502699 : g.nodes ⟨502699, by omega⟩ = .linear (.wire 502638) (.wire 7071) true
  node_502700 : g.nodes ⟨502700, by omega⟩ = .product (.wire 458183) (.wire 502699)
  node_502701 : g.nodes ⟨502701, by omega⟩ = .linear (.wire 7071) (.wire 502700) false
  node_502702 : g.nodes ⟨502702, by omega⟩ = .linear (.wire 502649) (.wire 7072) true
  node_502703 : g.nodes ⟨502703, by omega⟩ = .product (.wire 458183) (.wire 502702)
  node_502704 : g.nodes ⟨502704, by omega⟩ = .linear (.wire 7072) (.wire 502703) false
  node_505137 : g.nodes ⟨505137, by omega⟩ = .linear (.wire 7073) (.wire 505102) true
  node_505138 : g.nodes ⟨505138, by omega⟩ = .product (.wire 458188) (.wire 505137)
  node_505139 : g.nodes ⟨505139, by omega⟩ = .linear (.wire 505102) (.wire 505138) false
  node_505140 : g.nodes ⟨505140, by omega⟩ = .linear (.wire 7074) (.wire 505113) true
  node_505141 : g.nodes ⟨505141, by omega⟩ = .product (.wire 458188) (.wire 505140)
  node_505142 : g.nodes ⟨505142, by omega⟩ = .linear (.wire 505113) (.wire 505141) false
  node_505143 : g.nodes ⟨505143, by omega⟩ = .linear (.wire 7075) (.wire 505124) true
  node_505144 : g.nodes ⟨505144, by omega⟩ = .product (.wire 458188) (.wire 505143)
  node_505145 : g.nodes ⟨505145, by omega⟩ = .linear (.wire 505124) (.wire 505144) false
  node_505146 : g.nodes ⟨505146, by omega⟩ = .linear (.wire 7076) (.wire 505135) true
  node_505147 : g.nodes ⟨505147, by omega⟩ = .product (.wire 458188) (.wire 505146)
  node_505148 : g.nodes ⟨505148, by omega⟩ = .linear (.wire 505135) (.wire 505147) false
  node_505149 : g.nodes ⟨505149, by omega⟩ = .linear (.wire 7077) (.wire 505101) true
  node_505150 : g.nodes ⟨505150, by omega⟩ = .product (.wire 458188) (.wire 505149)
  node_505151 : g.nodes ⟨505151, by omega⟩ = .linear (.wire 505101) (.wire 505150) false
  node_505152 : g.nodes ⟨505152, by omega⟩ = .linear (.wire 7078) (.wire 505112) true
  node_505153 : g.nodes ⟨505153, by omega⟩ = .product (.wire 458188) (.wire 505152)
  node_505154 : g.nodes ⟨505154, by omega⟩ = .linear (.wire 505112) (.wire 505153) false
  node_505155 : g.nodes ⟨505155, by omega⟩ = .linear (.wire 7079) (.wire 505123) true
  node_505156 : g.nodes ⟨505156, by omega⟩ = .product (.wire 458188) (.wire 505155)
  node_505157 : g.nodes ⟨505157, by omega⟩ = .linear (.wire 505123) (.wire 505156) false
  node_505158 : g.nodes ⟨505158, by omega⟩ = .linear (.wire 505102) (.wire 7073) true
  node_505159 : g.nodes ⟨505159, by omega⟩ = .product (.wire 458188) (.wire 505158)
  node_505160 : g.nodes ⟨505160, by omega⟩ = .linear (.wire 7073) (.wire 505159) false
  node_505161 : g.nodes ⟨505161, by omega⟩ = .linear (.wire 505113) (.wire 7074) true
  node_505162 : g.nodes ⟨505162, by omega⟩ = .product (.wire 458188) (.wire 505161)
  node_505163 : g.nodes ⟨505163, by omega⟩ = .linear (.wire 7074) (.wire 505162) false
  node_505164 : g.nodes ⟨505164, by omega⟩ = .linear (.wire 505124) (.wire 7075) true
  node_505165 : g.nodes ⟨505165, by omega⟩ = .product (.wire 458188) (.wire 505164)
  node_505166 : g.nodes ⟨505166, by omega⟩ = .linear (.wire 7075) (.wire 505165) false
  node_505167 : g.nodes ⟨505167, by omega⟩ = .linear (.wire 505135) (.wire 7076) true
  node_505168 : g.nodes ⟨505168, by omega⟩ = .product (.wire 458188) (.wire 505167)
  node_505169 : g.nodes ⟨505169, by omega⟩ = .linear (.wire 7076) (.wire 505168) false
  node_505170 : g.nodes ⟨505170, by omega⟩ = .linear (.wire 505101) (.wire 7077) true
  node_505171 : g.nodes ⟨505171, by omega⟩ = .product (.wire 458188) (.wire 505170)
  node_505172 : g.nodes ⟨505172, by omega⟩ = .linear (.wire 7077) (.wire 505171) false
  node_505173 : g.nodes ⟨505173, by omega⟩ = .linear (.wire 505112) (.wire 7078) true
  node_505174 : g.nodes ⟨505174, by omega⟩ = .product (.wire 458188) (.wire 505173)
  node_505175 : g.nodes ⟨505175, by omega⟩ = .linear (.wire 7078) (.wire 505174) false
  node_505176 : g.nodes ⟨505176, by omega⟩ = .linear (.wire 505123) (.wire 7079) true
  node_505177 : g.nodes ⟨505177, by omega⟩ = .product (.wire 458188) (.wire 505176)
  node_505178 : g.nodes ⟨505178, by omega⟩ = .linear (.wire 7079) (.wire 505177) false
  node_507611 : g.nodes ⟨507611, by omega⟩ = .linear (.wire 7080) (.wire 507576) true
  node_507612 : g.nodes ⟨507612, by omega⟩ = .product (.wire 458193) (.wire 507611)
  node_507613 : g.nodes ⟨507613, by omega⟩ = .linear (.wire 507576) (.wire 507612) false
  node_507614 : g.nodes ⟨507614, by omega⟩ = .linear (.wire 7081) (.wire 507587) true
  node_507615 : g.nodes ⟨507615, by omega⟩ = .product (.wire 458193) (.wire 507614)
  node_507616 : g.nodes ⟨507616, by omega⟩ = .linear (.wire 507587) (.wire 507615) false
  node_507617 : g.nodes ⟨507617, by omega⟩ = .linear (.wire 7082) (.wire 507598) true
  node_507618 : g.nodes ⟨507618, by omega⟩ = .product (.wire 458193) (.wire 507617)
  node_507619 : g.nodes ⟨507619, by omega⟩ = .linear (.wire 507598) (.wire 507618) false
  node_507620 : g.nodes ⟨507620, by omega⟩ = .linear (.wire 7083) (.wire 507609) true
  node_507621 : g.nodes ⟨507621, by omega⟩ = .product (.wire 458193) (.wire 507620)
  node_507622 : g.nodes ⟨507622, by omega⟩ = .linear (.wire 507609) (.wire 507621) false
  node_507623 : g.nodes ⟨507623, by omega⟩ = .linear (.wire 7084) (.wire 507575) true
  node_507624 : g.nodes ⟨507624, by omega⟩ = .product (.wire 458193) (.wire 507623)
  node_507625 : g.nodes ⟨507625, by omega⟩ = .linear (.wire 507575) (.wire 507624) false
  node_507626 : g.nodes ⟨507626, by omega⟩ = .linear (.wire 7085) (.wire 507586) true
  node_507627 : g.nodes ⟨507627, by omega⟩ = .product (.wire 458193) (.wire 507626)
  node_507628 : g.nodes ⟨507628, by omega⟩ = .linear (.wire 507586) (.wire 507627) false
  node_507629 : g.nodes ⟨507629, by omega⟩ = .linear (.wire 7086) (.wire 507597) true
  node_507630 : g.nodes ⟨507630, by omega⟩ = .product (.wire 458193) (.wire 507629)
  node_507631 : g.nodes ⟨507631, by omega⟩ = .linear (.wire 507597) (.wire 507630) false
  node_507632 : g.nodes ⟨507632, by omega⟩ = .linear (.wire 507576) (.wire 7080) true
  node_507633 : g.nodes ⟨507633, by omega⟩ = .product (.wire 458193) (.wire 507632)
  node_507634 : g.nodes ⟨507634, by omega⟩ = .linear (.wire 7080) (.wire 507633) false
  node_507635 : g.nodes ⟨507635, by omega⟩ = .linear (.wire 507587) (.wire 7081) true
  node_507636 : g.nodes ⟨507636, by omega⟩ = .product (.wire 458193) (.wire 507635)
  node_507637 : g.nodes ⟨507637, by omega⟩ = .linear (.wire 7081) (.wire 507636) false
  node_507638 : g.nodes ⟨507638, by omega⟩ = .linear (.wire 507598) (.wire 7082) true
  node_507639 : g.nodes ⟨507639, by omega⟩ = .product (.wire 458193) (.wire 507638)
  node_507640 : g.nodes ⟨507640, by omega⟩ = .linear (.wire 7082) (.wire 507639) false
  node_507641 : g.nodes ⟨507641, by omega⟩ = .linear (.wire 507609) (.wire 7083) true
  node_507642 : g.nodes ⟨507642, by omega⟩ = .product (.wire 458193) (.wire 507641)
  node_507643 : g.nodes ⟨507643, by omega⟩ = .linear (.wire 7083) (.wire 507642) false
  node_507644 : g.nodes ⟨507644, by omega⟩ = .linear (.wire 507575) (.wire 7084) true
  node_507645 : g.nodes ⟨507645, by omega⟩ = .product (.wire 458193) (.wire 507644)
  node_507646 : g.nodes ⟨507646, by omega⟩ = .linear (.wire 7084) (.wire 507645) false
  node_507647 : g.nodes ⟨507647, by omega⟩ = .linear (.wire 507586) (.wire 7085) true
  node_507648 : g.nodes ⟨507648, by omega⟩ = .product (.wire 458193) (.wire 507647)
  node_507649 : g.nodes ⟨507649, by omega⟩ = .linear (.wire 7085) (.wire 507648) false
  node_507650 : g.nodes ⟨507650, by omega⟩ = .linear (.wire 507597) (.wire 7086) true
  node_507651 : g.nodes ⟨507651, by omega⟩ = .product (.wire 458193) (.wire 507650)
  node_507652 : g.nodes ⟨507652, by omega⟩ = .linear (.wire 7086) (.wire 507651) false
  node_510085 : g.nodes ⟨510085, by omega⟩ = .linear (.wire 7087) (.wire 510050) true
  node_510086 : g.nodes ⟨510086, by omega⟩ = .product (.wire 458198) (.wire 510085)
  node_510087 : g.nodes ⟨510087, by omega⟩ = .linear (.wire 510050) (.wire 510086) false
  node_510088 : g.nodes ⟨510088, by omega⟩ = .linear (.wire 7088) (.wire 510061) true
  node_510089 : g.nodes ⟨510089, by omega⟩ = .product (.wire 458198) (.wire 510088)
  node_510090 : g.nodes ⟨510090, by omega⟩ = .linear (.wire 510061) (.wire 510089) false
  node_510091 : g.nodes ⟨510091, by omega⟩ = .linear (.wire 7089) (.wire 510072) true
  node_510092 : g.nodes ⟨510092, by omega⟩ = .product (.wire 458198) (.wire 510091)
  node_510093 : g.nodes ⟨510093, by omega⟩ = .linear (.wire 510072) (.wire 510092) false
  node_510094 : g.nodes ⟨510094, by omega⟩ = .linear (.wire 7090) (.wire 510083) true
  node_510095 : g.nodes ⟨510095, by omega⟩ = .product (.wire 458198) (.wire 510094)
  node_510096 : g.nodes ⟨510096, by omega⟩ = .linear (.wire 510083) (.wire 510095) false
  node_510097 : g.nodes ⟨510097, by omega⟩ = .linear (.wire 7091) (.wire 510049) true
  node_510098 : g.nodes ⟨510098, by omega⟩ = .product (.wire 458198) (.wire 510097)
  node_510099 : g.nodes ⟨510099, by omega⟩ = .linear (.wire 510049) (.wire 510098) false
  node_510100 : g.nodes ⟨510100, by omega⟩ = .linear (.wire 7092) (.wire 510060) true
  node_510101 : g.nodes ⟨510101, by omega⟩ = .product (.wire 458198) (.wire 510100)
  node_510102 : g.nodes ⟨510102, by omega⟩ = .linear (.wire 510060) (.wire 510101) false
  node_510103 : g.nodes ⟨510103, by omega⟩ = .linear (.wire 7093) (.wire 510071) true
  node_510104 : g.nodes ⟨510104, by omega⟩ = .product (.wire 458198) (.wire 510103)
  node_510105 : g.nodes ⟨510105, by omega⟩ = .linear (.wire 510071) (.wire 510104) false
  node_510106 : g.nodes ⟨510106, by omega⟩ = .linear (.wire 510050) (.wire 7087) true
  node_510107 : g.nodes ⟨510107, by omega⟩ = .product (.wire 458198) (.wire 510106)
  node_510108 : g.nodes ⟨510108, by omega⟩ = .linear (.wire 7087) (.wire 510107) false
  node_510109 : g.nodes ⟨510109, by omega⟩ = .linear (.wire 510061) (.wire 7088) true
  node_510110 : g.nodes ⟨510110, by omega⟩ = .product (.wire 458198) (.wire 510109)
  node_510111 : g.nodes ⟨510111, by omega⟩ = .linear (.wire 7088) (.wire 510110) false
  node_510112 : g.nodes ⟨510112, by omega⟩ = .linear (.wire 510072) (.wire 7089) true
  node_510113 : g.nodes ⟨510113, by omega⟩ = .product (.wire 458198) (.wire 510112)
  node_510114 : g.nodes ⟨510114, by omega⟩ = .linear (.wire 7089) (.wire 510113) false
  node_510115 : g.nodes ⟨510115, by omega⟩ = .linear (.wire 510083) (.wire 7090) true
  node_510116 : g.nodes ⟨510116, by omega⟩ = .product (.wire 458198) (.wire 510115)
  node_510117 : g.nodes ⟨510117, by omega⟩ = .linear (.wire 7090) (.wire 510116) false
  node_510118 : g.nodes ⟨510118, by omega⟩ = .linear (.wire 510049) (.wire 7091) true
  node_510119 : g.nodes ⟨510119, by omega⟩ = .product (.wire 458198) (.wire 510118)
  node_510120 : g.nodes ⟨510120, by omega⟩ = .linear (.wire 7091) (.wire 510119) false
  node_510121 : g.nodes ⟨510121, by omega⟩ = .linear (.wire 510060) (.wire 7092) true
  node_510122 : g.nodes ⟨510122, by omega⟩ = .product (.wire 458198) (.wire 510121)
  node_510123 : g.nodes ⟨510123, by omega⟩ = .linear (.wire 7092) (.wire 510122) false
  node_510124 : g.nodes ⟨510124, by omega⟩ = .linear (.wire 510071) (.wire 7093) true
  node_510125 : g.nodes ⟨510125, by omega⟩ = .product (.wire 458198) (.wire 510124)
  node_510126 : g.nodes ⟨510126, by omega⟩ = .linear (.wire 7093) (.wire 510125) false
  node_512559 : g.nodes ⟨512559, by omega⟩ = .linear (.wire 7094) (.wire 512524) true
  node_512560 : g.nodes ⟨512560, by omega⟩ = .product (.wire 458203) (.wire 512559)
  node_512561 : g.nodes ⟨512561, by omega⟩ = .linear (.wire 512524) (.wire 512560) false
  node_512562 : g.nodes ⟨512562, by omega⟩ = .linear (.wire 7095) (.wire 512535) true
  node_512563 : g.nodes ⟨512563, by omega⟩ = .product (.wire 458203) (.wire 512562)
  node_512564 : g.nodes ⟨512564, by omega⟩ = .linear (.wire 512535) (.wire 512563) false
  node_512565 : g.nodes ⟨512565, by omega⟩ = .linear (.wire 7096) (.wire 512546) true
  node_512566 : g.nodes ⟨512566, by omega⟩ = .product (.wire 458203) (.wire 512565)
  node_512567 : g.nodes ⟨512567, by omega⟩ = .linear (.wire 512546) (.wire 512566) false
  node_512568 : g.nodes ⟨512568, by omega⟩ = .linear (.wire 7097) (.wire 512557) true
  node_512569 : g.nodes ⟨512569, by omega⟩ = .product (.wire 458203) (.wire 512568)
  node_512570 : g.nodes ⟨512570, by omega⟩ = .linear (.wire 512557) (.wire 512569) false
  node_512571 : g.nodes ⟨512571, by omega⟩ = .linear (.wire 7098) (.wire 512523) true
  node_512572 : g.nodes ⟨512572, by omega⟩ = .product (.wire 458203) (.wire 512571)
  node_512573 : g.nodes ⟨512573, by omega⟩ = .linear (.wire 512523) (.wire 512572) false
  node_512574 : g.nodes ⟨512574, by omega⟩ = .linear (.wire 7099) (.wire 512534) true
  node_512575 : g.nodes ⟨512575, by omega⟩ = .product (.wire 458203) (.wire 512574)
  node_512576 : g.nodes ⟨512576, by omega⟩ = .linear (.wire 512534) (.wire 512575) false
  node_512577 : g.nodes ⟨512577, by omega⟩ = .linear (.wire 7100) (.wire 512545) true
  node_512578 : g.nodes ⟨512578, by omega⟩ = .product (.wire 458203) (.wire 512577)
  node_512579 : g.nodes ⟨512579, by omega⟩ = .linear (.wire 512545) (.wire 512578) false
  node_512580 : g.nodes ⟨512580, by omega⟩ = .linear (.wire 512524) (.wire 7094) true
  node_512581 : g.nodes ⟨512581, by omega⟩ = .product (.wire 458203) (.wire 512580)
  node_512582 : g.nodes ⟨512582, by omega⟩ = .linear (.wire 7094) (.wire 512581) false
  node_512583 : g.nodes ⟨512583, by omega⟩ = .linear (.wire 512535) (.wire 7095) true
  node_512584 : g.nodes ⟨512584, by omega⟩ = .product (.wire 458203) (.wire 512583)
  node_512585 : g.nodes ⟨512585, by omega⟩ = .linear (.wire 7095) (.wire 512584) false
  node_512586 : g.nodes ⟨512586, by omega⟩ = .linear (.wire 512546) (.wire 7096) true
  node_512587 : g.nodes ⟨512587, by omega⟩ = .product (.wire 458203) (.wire 512586)
  node_512588 : g.nodes ⟨512588, by omega⟩ = .linear (.wire 7096) (.wire 512587) false
  node_512589 : g.nodes ⟨512589, by omega⟩ = .linear (.wire 512557) (.wire 7097) true
  node_512590 : g.nodes ⟨512590, by omega⟩ = .product (.wire 458203) (.wire 512589)
  node_512591 : g.nodes ⟨512591, by omega⟩ = .linear (.wire 7097) (.wire 512590) false
  node_512592 : g.nodes ⟨512592, by omega⟩ = .linear (.wire 512523) (.wire 7098) true
  node_512593 : g.nodes ⟨512593, by omega⟩ = .product (.wire 458203) (.wire 512592)
  node_512594 : g.nodes ⟨512594, by omega⟩ = .linear (.wire 7098) (.wire 512593) false
  node_512595 : g.nodes ⟨512595, by omega⟩ = .linear (.wire 512534) (.wire 7099) true
  node_512596 : g.nodes ⟨512596, by omega⟩ = .product (.wire 458203) (.wire 512595)
  node_512597 : g.nodes ⟨512597, by omega⟩ = .linear (.wire 7099) (.wire 512596) false
  node_512598 : g.nodes ⟨512598, by omega⟩ = .linear (.wire 512545) (.wire 7100) true
  node_512599 : g.nodes ⟨512599, by omega⟩ = .product (.wire 458203) (.wire 512598)
  node_512600 : g.nodes ⟨512600, by omega⟩ = .linear (.wire 7100) (.wire 512599) false
  node_515033 : g.nodes ⟨515033, by omega⟩ = .linear (.wire 7101) (.wire 514998) true
  node_515034 : g.nodes ⟨515034, by omega⟩ = .product (.wire 458208) (.wire 515033)
  node_515035 : g.nodes ⟨515035, by omega⟩ = .linear (.wire 514998) (.wire 515034) false
  node_515036 : g.nodes ⟨515036, by omega⟩ = .linear (.wire 7102) (.wire 515009) true
  node_515037 : g.nodes ⟨515037, by omega⟩ = .product (.wire 458208) (.wire 515036)
  node_515038 : g.nodes ⟨515038, by omega⟩ = .linear (.wire 515009) (.wire 515037) false
  node_515039 : g.nodes ⟨515039, by omega⟩ = .linear (.wire 7103) (.wire 515020) true
  node_515040 : g.nodes ⟨515040, by omega⟩ = .product (.wire 458208) (.wire 515039)
  node_515041 : g.nodes ⟨515041, by omega⟩ = .linear (.wire 515020) (.wire 515040) false
  node_515042 : g.nodes ⟨515042, by omega⟩ = .linear (.wire 7104) (.wire 515031) true
  node_515043 : g.nodes ⟨515043, by omega⟩ = .product (.wire 458208) (.wire 515042)
  node_515044 : g.nodes ⟨515044, by omega⟩ = .linear (.wire 515031) (.wire 515043) false
  node_515045 : g.nodes ⟨515045, by omega⟩ = .linear (.wire 7105) (.wire 514997) true
  node_515046 : g.nodes ⟨515046, by omega⟩ = .product (.wire 458208) (.wire 515045)
  node_515047 : g.nodes ⟨515047, by omega⟩ = .linear (.wire 514997) (.wire 515046) false
  node_515048 : g.nodes ⟨515048, by omega⟩ = .linear (.wire 7106) (.wire 515008) true
  node_515049 : g.nodes ⟨515049, by omega⟩ = .product (.wire 458208) (.wire 515048)
  node_515050 : g.nodes ⟨515050, by omega⟩ = .linear (.wire 515008) (.wire 515049) false
  node_515051 : g.nodes ⟨515051, by omega⟩ = .linear (.wire 7107) (.wire 515019) true
  node_515052 : g.nodes ⟨515052, by omega⟩ = .product (.wire 458208) (.wire 515051)
  node_515053 : g.nodes ⟨515053, by omega⟩ = .linear (.wire 515019) (.wire 515052) false
  node_515054 : g.nodes ⟨515054, by omega⟩ = .linear (.wire 514998) (.wire 7101) true
  node_515055 : g.nodes ⟨515055, by omega⟩ = .product (.wire 458208) (.wire 515054)
  node_515056 : g.nodes ⟨515056, by omega⟩ = .linear (.wire 7101) (.wire 515055) false
  node_515057 : g.nodes ⟨515057, by omega⟩ = .linear (.wire 515009) (.wire 7102) true
  node_515058 : g.nodes ⟨515058, by omega⟩ = .product (.wire 458208) (.wire 515057)
  node_515059 : g.nodes ⟨515059, by omega⟩ = .linear (.wire 7102) (.wire 515058) false
  node_515060 : g.nodes ⟨515060, by omega⟩ = .linear (.wire 515020) (.wire 7103) true
  node_515061 : g.nodes ⟨515061, by omega⟩ = .product (.wire 458208) (.wire 515060)
  node_515062 : g.nodes ⟨515062, by omega⟩ = .linear (.wire 7103) (.wire 515061) false
  node_515063 : g.nodes ⟨515063, by omega⟩ = .linear (.wire 515031) (.wire 7104) true
  node_515064 : g.nodes ⟨515064, by omega⟩ = .product (.wire 458208) (.wire 515063)
  node_515065 : g.nodes ⟨515065, by omega⟩ = .linear (.wire 7104) (.wire 515064) false
  node_515066 : g.nodes ⟨515066, by omega⟩ = .linear (.wire 514997) (.wire 7105) true
  node_515067 : g.nodes ⟨515067, by omega⟩ = .product (.wire 458208) (.wire 515066)
  node_515068 : g.nodes ⟨515068, by omega⟩ = .linear (.wire 7105) (.wire 515067) false
  node_515069 : g.nodes ⟨515069, by omega⟩ = .linear (.wire 515008) (.wire 7106) true
  node_515070 : g.nodes ⟨515070, by omega⟩ = .product (.wire 458208) (.wire 515069)
  node_515071 : g.nodes ⟨515071, by omega⟩ = .linear (.wire 7106) (.wire 515070) false
  node_515072 : g.nodes ⟨515072, by omega⟩ = .linear (.wire 515019) (.wire 7107) true
  node_515073 : g.nodes ⟨515073, by omega⟩ = .product (.wire 458208) (.wire 515072)
  node_515074 : g.nodes ⟨515074, by omega⟩ = .linear (.wire 7107) (.wire 515073) false
  node_517507 : g.nodes ⟨517507, by omega⟩ = .linear (.wire 7108) (.wire 517472) true
  node_517508 : g.nodes ⟨517508, by omega⟩ = .product (.wire 458213) (.wire 517507)
  node_517509 : g.nodes ⟨517509, by omega⟩ = .linear (.wire 517472) (.wire 517508) false
  node_517510 : g.nodes ⟨517510, by omega⟩ = .linear (.wire 7109) (.wire 517483) true
  node_517511 : g.nodes ⟨517511, by omega⟩ = .product (.wire 458213) (.wire 517510)
  node_517512 : g.nodes ⟨517512, by omega⟩ = .linear (.wire 517483) (.wire 517511) false
  node_517513 : g.nodes ⟨517513, by omega⟩ = .linear (.wire 7110) (.wire 517494) true
  node_517514 : g.nodes ⟨517514, by omega⟩ = .product (.wire 458213) (.wire 517513)
  node_517515 : g.nodes ⟨517515, by omega⟩ = .linear (.wire 517494) (.wire 517514) false
  node_517516 : g.nodes ⟨517516, by omega⟩ = .linear (.wire 7111) (.wire 517505) true
  node_517517 : g.nodes ⟨517517, by omega⟩ = .product (.wire 458213) (.wire 517516)
  node_517518 : g.nodes ⟨517518, by omega⟩ = .linear (.wire 517505) (.wire 517517) false
  node_517519 : g.nodes ⟨517519, by omega⟩ = .linear (.wire 7112) (.wire 517471) true
  node_517520 : g.nodes ⟨517520, by omega⟩ = .product (.wire 458213) (.wire 517519)
  node_517521 : g.nodes ⟨517521, by omega⟩ = .linear (.wire 517471) (.wire 517520) false
  node_517522 : g.nodes ⟨517522, by omega⟩ = .linear (.wire 7113) (.wire 517482) true
  node_517523 : g.nodes ⟨517523, by omega⟩ = .product (.wire 458213) (.wire 517522)
  node_517524 : g.nodes ⟨517524, by omega⟩ = .linear (.wire 517482) (.wire 517523) false
  node_517525 : g.nodes ⟨517525, by omega⟩ = .linear (.wire 7114) (.wire 517493) true
  node_517526 : g.nodes ⟨517526, by omega⟩ = .product (.wire 458213) (.wire 517525)
  node_517527 : g.nodes ⟨517527, by omega⟩ = .linear (.wire 517493) (.wire 517526) false
  node_517528 : g.nodes ⟨517528, by omega⟩ = .linear (.wire 517472) (.wire 7108) true
  node_517529 : g.nodes ⟨517529, by omega⟩ = .product (.wire 458213) (.wire 517528)
  node_517530 : g.nodes ⟨517530, by omega⟩ = .linear (.wire 7108) (.wire 517529) false
  node_517531 : g.nodes ⟨517531, by omega⟩ = .linear (.wire 517483) (.wire 7109) true
  node_517532 : g.nodes ⟨517532, by omega⟩ = .product (.wire 458213) (.wire 517531)
  node_517533 : g.nodes ⟨517533, by omega⟩ = .linear (.wire 7109) (.wire 517532) false
  node_517534 : g.nodes ⟨517534, by omega⟩ = .linear (.wire 517494) (.wire 7110) true
  node_517535 : g.nodes ⟨517535, by omega⟩ = .product (.wire 458213) (.wire 517534)
  node_517536 : g.nodes ⟨517536, by omega⟩ = .linear (.wire 7110) (.wire 517535) false
  node_517537 : g.nodes ⟨517537, by omega⟩ = .linear (.wire 517505) (.wire 7111) true
  node_517538 : g.nodes ⟨517538, by omega⟩ = .product (.wire 458213) (.wire 517537)
  node_517539 : g.nodes ⟨517539, by omega⟩ = .linear (.wire 7111) (.wire 517538) false
  node_517540 : g.nodes ⟨517540, by omega⟩ = .linear (.wire 517471) (.wire 7112) true
  node_517541 : g.nodes ⟨517541, by omega⟩ = .product (.wire 458213) (.wire 517540)
  node_517542 : g.nodes ⟨517542, by omega⟩ = .linear (.wire 7112) (.wire 517541) false
  node_517543 : g.nodes ⟨517543, by omega⟩ = .linear (.wire 517482) (.wire 7113) true
  node_517544 : g.nodes ⟨517544, by omega⟩ = .product (.wire 458213) (.wire 517543)
  node_517545 : g.nodes ⟨517545, by omega⟩ = .linear (.wire 7113) (.wire 517544) false
  node_517546 : g.nodes ⟨517546, by omega⟩ = .linear (.wire 517493) (.wire 7114) true
  node_517547 : g.nodes ⟨517547, by omega⟩ = .product (.wire 458213) (.wire 517546)
  node_517548 : g.nodes ⟨517548, by omega⟩ = .linear (.wire 7114) (.wire 517547) false
  node_519981 : g.nodes ⟨519981, by omega⟩ = .linear (.wire 7115) (.wire 519946) true
  node_519982 : g.nodes ⟨519982, by omega⟩ = .product (.wire 458218) (.wire 519981)
  node_519983 : g.nodes ⟨519983, by omega⟩ = .linear (.wire 519946) (.wire 519982) false
  node_519984 : g.nodes ⟨519984, by omega⟩ = .linear (.wire 7116) (.wire 519957) true
  node_519985 : g.nodes ⟨519985, by omega⟩ = .product (.wire 458218) (.wire 519984)
  node_519986 : g.nodes ⟨519986, by omega⟩ = .linear (.wire 519957) (.wire 519985) false
  node_519987 : g.nodes ⟨519987, by omega⟩ = .linear (.wire 7117) (.wire 519968) true
  node_519988 : g.nodes ⟨519988, by omega⟩ = .product (.wire 458218) (.wire 519987)
  node_519989 : g.nodes ⟨519989, by omega⟩ = .linear (.wire 519968) (.wire 519988) false
  node_519990 : g.nodes ⟨519990, by omega⟩ = .linear (.wire 7118) (.wire 519979) true
  node_519991 : g.nodes ⟨519991, by omega⟩ = .product (.wire 458218) (.wire 519990)
  node_519992 : g.nodes ⟨519992, by omega⟩ = .linear (.wire 519979) (.wire 519991) false
  node_519993 : g.nodes ⟨519993, by omega⟩ = .linear (.wire 7119) (.wire 519945) true
  node_519994 : g.nodes ⟨519994, by omega⟩ = .product (.wire 458218) (.wire 519993)
  node_519995 : g.nodes ⟨519995, by omega⟩ = .linear (.wire 519945) (.wire 519994) false
  node_519996 : g.nodes ⟨519996, by omega⟩ = .linear (.wire 7120) (.wire 519956) true
  node_519997 : g.nodes ⟨519997, by omega⟩ = .product (.wire 458218) (.wire 519996)
  node_519998 : g.nodes ⟨519998, by omega⟩ = .linear (.wire 519956) (.wire 519997) false
  node_519999 : g.nodes ⟨519999, by omega⟩ = .linear (.wire 7121) (.wire 519967) true
  node_520000 : g.nodes ⟨520000, by omega⟩ = .product (.wire 458218) (.wire 519999)
  node_520001 : g.nodes ⟨520001, by omega⟩ = .linear (.wire 519967) (.wire 520000) false
  node_520002 : g.nodes ⟨520002, by omega⟩ = .linear (.wire 519946) (.wire 7115) true
  node_520003 : g.nodes ⟨520003, by omega⟩ = .product (.wire 458218) (.wire 520002)
  node_520004 : g.nodes ⟨520004, by omega⟩ = .linear (.wire 7115) (.wire 520003) false
  node_520005 : g.nodes ⟨520005, by omega⟩ = .linear (.wire 519957) (.wire 7116) true
  node_520006 : g.nodes ⟨520006, by omega⟩ = .product (.wire 458218) (.wire 520005)
  node_520007 : g.nodes ⟨520007, by omega⟩ = .linear (.wire 7116) (.wire 520006) false
  node_520008 : g.nodes ⟨520008, by omega⟩ = .linear (.wire 519968) (.wire 7117) true
  node_520009 : g.nodes ⟨520009, by omega⟩ = .product (.wire 458218) (.wire 520008)
  node_520010 : g.nodes ⟨520010, by omega⟩ = .linear (.wire 7117) (.wire 520009) false
  node_520011 : g.nodes ⟨520011, by omega⟩ = .linear (.wire 519979) (.wire 7118) true
  node_520012 : g.nodes ⟨520012, by omega⟩ = .product (.wire 458218) (.wire 520011)
  node_520013 : g.nodes ⟨520013, by omega⟩ = .linear (.wire 7118) (.wire 520012) false
  node_520014 : g.nodes ⟨520014, by omega⟩ = .linear (.wire 519945) (.wire 7119) true
  node_520015 : g.nodes ⟨520015, by omega⟩ = .product (.wire 458218) (.wire 520014)
  node_520016 : g.nodes ⟨520016, by omega⟩ = .linear (.wire 7119) (.wire 520015) false
  node_520017 : g.nodes ⟨520017, by omega⟩ = .linear (.wire 519956) (.wire 7120) true
  node_520018 : g.nodes ⟨520018, by omega⟩ = .product (.wire 458218) (.wire 520017)
  node_520019 : g.nodes ⟨520019, by omega⟩ = .linear (.wire 7120) (.wire 520018) false
  node_520020 : g.nodes ⟨520020, by omega⟩ = .linear (.wire 519967) (.wire 7121) true
  node_520021 : g.nodes ⟨520021, by omega⟩ = .product (.wire 458218) (.wire 520020)
  node_520022 : g.nodes ⟨520022, by omega⟩ = .linear (.wire 7121) (.wire 520021) false
  node_522455 : g.nodes ⟨522455, by omega⟩ = .linear (.wire 7122) (.wire 522420) true
  node_522456 : g.nodes ⟨522456, by omega⟩ = .product (.wire 458223) (.wire 522455)
  node_522457 : g.nodes ⟨522457, by omega⟩ = .linear (.wire 522420) (.wire 522456) false
  node_522458 : g.nodes ⟨522458, by omega⟩ = .linear (.wire 7123) (.wire 522431) true
  node_522459 : g.nodes ⟨522459, by omega⟩ = .product (.wire 458223) (.wire 522458)
  node_522460 : g.nodes ⟨522460, by omega⟩ = .linear (.wire 522431) (.wire 522459) false
  node_522461 : g.nodes ⟨522461, by omega⟩ = .linear (.wire 7124) (.wire 522442) true
  node_522462 : g.nodes ⟨522462, by omega⟩ = .product (.wire 458223) (.wire 522461)
  node_522463 : g.nodes ⟨522463, by omega⟩ = .linear (.wire 522442) (.wire 522462) false
  node_522464 : g.nodes ⟨522464, by omega⟩ = .linear (.wire 7125) (.wire 522453) true
  node_522465 : g.nodes ⟨522465, by omega⟩ = .product (.wire 458223) (.wire 522464)
  node_522466 : g.nodes ⟨522466, by omega⟩ = .linear (.wire 522453) (.wire 522465) false
  node_522467 : g.nodes ⟨522467, by omega⟩ = .linear (.wire 7126) (.wire 522419) true
  node_522468 : g.nodes ⟨522468, by omega⟩ = .product (.wire 458223) (.wire 522467)
  node_522469 : g.nodes ⟨522469, by omega⟩ = .linear (.wire 522419) (.wire 522468) false
  node_522470 : g.nodes ⟨522470, by omega⟩ = .linear (.wire 7127) (.wire 522430) true
  node_522471 : g.nodes ⟨522471, by omega⟩ = .product (.wire 458223) (.wire 522470)
  node_522472 : g.nodes ⟨522472, by omega⟩ = .linear (.wire 522430) (.wire 522471) false
  node_522473 : g.nodes ⟨522473, by omega⟩ = .linear (.wire 7128) (.wire 522441) true
  node_522474 : g.nodes ⟨522474, by omega⟩ = .product (.wire 458223) (.wire 522473)
  node_522475 : g.nodes ⟨522475, by omega⟩ = .linear (.wire 522441) (.wire 522474) false
  node_522476 : g.nodes ⟨522476, by omega⟩ = .linear (.wire 522420) (.wire 7122) true
  node_522477 : g.nodes ⟨522477, by omega⟩ = .product (.wire 458223) (.wire 522476)
  node_522478 : g.nodes ⟨522478, by omega⟩ = .linear (.wire 7122) (.wire 522477) false
  node_522479 : g.nodes ⟨522479, by omega⟩ = .linear (.wire 522431) (.wire 7123) true
  node_522480 : g.nodes ⟨522480, by omega⟩ = .product (.wire 458223) (.wire 522479)
  node_522481 : g.nodes ⟨522481, by omega⟩ = .linear (.wire 7123) (.wire 522480) false
  node_522482 : g.nodes ⟨522482, by omega⟩ = .linear (.wire 522442) (.wire 7124) true
  node_522483 : g.nodes ⟨522483, by omega⟩ = .product (.wire 458223) (.wire 522482)
  node_522484 : g.nodes ⟨522484, by omega⟩ = .linear (.wire 7124) (.wire 522483) false
  node_522485 : g.nodes ⟨522485, by omega⟩ = .linear (.wire 522453) (.wire 7125) true
  node_522486 : g.nodes ⟨522486, by omega⟩ = .product (.wire 458223) (.wire 522485)
  node_522487 : g.nodes ⟨522487, by omega⟩ = .linear (.wire 7125) (.wire 522486) false
  node_522488 : g.nodes ⟨522488, by omega⟩ = .linear (.wire 522419) (.wire 7126) true
  node_522489 : g.nodes ⟨522489, by omega⟩ = .product (.wire 458223) (.wire 522488)
  node_522490 : g.nodes ⟨522490, by omega⟩ = .linear (.wire 7126) (.wire 522489) false
  node_522491 : g.nodes ⟨522491, by omega⟩ = .linear (.wire 522430) (.wire 7127) true
  node_522492 : g.nodes ⟨522492, by omega⟩ = .product (.wire 458223) (.wire 522491)
  node_522493 : g.nodes ⟨522493, by omega⟩ = .linear (.wire 7127) (.wire 522492) false
  node_522494 : g.nodes ⟨522494, by omega⟩ = .linear (.wire 522441) (.wire 7128) true
  node_522495 : g.nodes ⟨522495, by omega⟩ = .product (.wire 458223) (.wire 522494)
  node_522496 : g.nodes ⟨522496, by omega⟩ = .linear (.wire 7128) (.wire 522495) false
  node_524929 : g.nodes ⟨524929, by omega⟩ = .linear (.wire 7129) (.wire 524894) true
  node_524930 : g.nodes ⟨524930, by omega⟩ = .product (.wire 458228) (.wire 524929)
  node_524931 : g.nodes ⟨524931, by omega⟩ = .linear (.wire 524894) (.wire 524930) false
  node_524932 : g.nodes ⟨524932, by omega⟩ = .linear (.wire 7130) (.wire 524905) true
  node_524933 : g.nodes ⟨524933, by omega⟩ = .product (.wire 458228) (.wire 524932)
  node_524934 : g.nodes ⟨524934, by omega⟩ = .linear (.wire 524905) (.wire 524933) false
  node_524935 : g.nodes ⟨524935, by omega⟩ = .linear (.wire 7131) (.wire 524916) true
  node_524936 : g.nodes ⟨524936, by omega⟩ = .product (.wire 458228) (.wire 524935)
  node_524937 : g.nodes ⟨524937, by omega⟩ = .linear (.wire 524916) (.wire 524936) false
  node_524938 : g.nodes ⟨524938, by omega⟩ = .linear (.wire 7132) (.wire 524927) true
  node_524939 : g.nodes ⟨524939, by omega⟩ = .product (.wire 458228) (.wire 524938)
  node_524940 : g.nodes ⟨524940, by omega⟩ = .linear (.wire 524927) (.wire 524939) false
  node_524941 : g.nodes ⟨524941, by omega⟩ = .linear (.wire 7133) (.wire 524893) true
  node_524942 : g.nodes ⟨524942, by omega⟩ = .product (.wire 458228) (.wire 524941)
  node_524943 : g.nodes ⟨524943, by omega⟩ = .linear (.wire 524893) (.wire 524942) false
  node_524944 : g.nodes ⟨524944, by omega⟩ = .linear (.wire 7134) (.wire 524904) true
  node_524945 : g.nodes ⟨524945, by omega⟩ = .product (.wire 458228) (.wire 524944)
  node_524946 : g.nodes ⟨524946, by omega⟩ = .linear (.wire 524904) (.wire 524945) false
  node_524947 : g.nodes ⟨524947, by omega⟩ = .linear (.wire 7135) (.wire 524915) true
  node_524948 : g.nodes ⟨524948, by omega⟩ = .product (.wire 458228) (.wire 524947)
  node_524949 : g.nodes ⟨524949, by omega⟩ = .linear (.wire 524915) (.wire 524948) false
  node_524950 : g.nodes ⟨524950, by omega⟩ = .linear (.wire 524894) (.wire 7129) true
  node_524951 : g.nodes ⟨524951, by omega⟩ = .product (.wire 458228) (.wire 524950)
  node_524952 : g.nodes ⟨524952, by omega⟩ = .linear (.wire 7129) (.wire 524951) false
  node_524953 : g.nodes ⟨524953, by omega⟩ = .linear (.wire 524905) (.wire 7130) true
  node_524954 : g.nodes ⟨524954, by omega⟩ = .product (.wire 458228) (.wire 524953)
  node_524955 : g.nodes ⟨524955, by omega⟩ = .linear (.wire 7130) (.wire 524954) false
  node_524956 : g.nodes ⟨524956, by omega⟩ = .linear (.wire 524916) (.wire 7131) true
  node_524957 : g.nodes ⟨524957, by omega⟩ = .product (.wire 458228) (.wire 524956)
  node_524958 : g.nodes ⟨524958, by omega⟩ = .linear (.wire 7131) (.wire 524957) false
  node_524959 : g.nodes ⟨524959, by omega⟩ = .linear (.wire 524927) (.wire 7132) true
  node_524960 : g.nodes ⟨524960, by omega⟩ = .product (.wire 458228) (.wire 524959)
  node_524961 : g.nodes ⟨524961, by omega⟩ = .linear (.wire 7132) (.wire 524960) false
  node_524962 : g.nodes ⟨524962, by omega⟩ = .linear (.wire 524893) (.wire 7133) true
  node_524963 : g.nodes ⟨524963, by omega⟩ = .product (.wire 458228) (.wire 524962)
  node_524964 : g.nodes ⟨524964, by omega⟩ = .linear (.wire 7133) (.wire 524963) false
  node_524965 : g.nodes ⟨524965, by omega⟩ = .linear (.wire 524904) (.wire 7134) true
  node_524966 : g.nodes ⟨524966, by omega⟩ = .product (.wire 458228) (.wire 524965)
  node_524967 : g.nodes ⟨524967, by omega⟩ = .linear (.wire 7134) (.wire 524966) false
  node_524968 : g.nodes ⟨524968, by omega⟩ = .linear (.wire 524915) (.wire 7135) true
  node_524969 : g.nodes ⟨524969, by omega⟩ = .product (.wire 458228) (.wire 524968)
  node_524970 : g.nodes ⟨524970, by omega⟩ = .linear (.wire 7135) (.wire 524969) false
  node_527403 : g.nodes ⟨527403, by omega⟩ = .linear (.wire 7136) (.wire 527368) true
  node_527404 : g.nodes ⟨527404, by omega⟩ = .product (.wire 458233) (.wire 527403)
  node_527405 : g.nodes ⟨527405, by omega⟩ = .linear (.wire 527368) (.wire 527404) false
  node_527406 : g.nodes ⟨527406, by omega⟩ = .linear (.wire 7137) (.wire 527379) true
  node_527407 : g.nodes ⟨527407, by omega⟩ = .product (.wire 458233) (.wire 527406)
  node_527408 : g.nodes ⟨527408, by omega⟩ = .linear (.wire 527379) (.wire 527407) false
  node_527409 : g.nodes ⟨527409, by omega⟩ = .linear (.wire 7138) (.wire 527390) true
  node_527410 : g.nodes ⟨527410, by omega⟩ = .product (.wire 458233) (.wire 527409)
  node_527411 : g.nodes ⟨527411, by omega⟩ = .linear (.wire 527390) (.wire 527410) false
  node_527412 : g.nodes ⟨527412, by omega⟩ = .linear (.wire 7139) (.wire 527401) true
  node_527413 : g.nodes ⟨527413, by omega⟩ = .product (.wire 458233) (.wire 527412)
  node_527414 : g.nodes ⟨527414, by omega⟩ = .linear (.wire 527401) (.wire 527413) false
  node_527415 : g.nodes ⟨527415, by omega⟩ = .linear (.wire 7140) (.wire 527367) true
  node_527416 : g.nodes ⟨527416, by omega⟩ = .product (.wire 458233) (.wire 527415)
  node_527417 : g.nodes ⟨527417, by omega⟩ = .linear (.wire 527367) (.wire 527416) false
  node_527418 : g.nodes ⟨527418, by omega⟩ = .linear (.wire 7141) (.wire 527378) true
  node_527419 : g.nodes ⟨527419, by omega⟩ = .product (.wire 458233) (.wire 527418)
  node_527420 : g.nodes ⟨527420, by omega⟩ = .linear (.wire 527378) (.wire 527419) false
  node_527421 : g.nodes ⟨527421, by omega⟩ = .linear (.wire 7142) (.wire 527389) true
  node_527422 : g.nodes ⟨527422, by omega⟩ = .product (.wire 458233) (.wire 527421)
  node_527423 : g.nodes ⟨527423, by omega⟩ = .linear (.wire 527389) (.wire 527422) false
  node_527424 : g.nodes ⟨527424, by omega⟩ = .linear (.wire 527368) (.wire 7136) true
  node_527425 : g.nodes ⟨527425, by omega⟩ = .product (.wire 458233) (.wire 527424)
  node_527426 : g.nodes ⟨527426, by omega⟩ = .linear (.wire 7136) (.wire 527425) false
  node_527427 : g.nodes ⟨527427, by omega⟩ = .linear (.wire 527379) (.wire 7137) true
  node_527428 : g.nodes ⟨527428, by omega⟩ = .product (.wire 458233) (.wire 527427)
  node_527429 : g.nodes ⟨527429, by omega⟩ = .linear (.wire 7137) (.wire 527428) false
  node_527430 : g.nodes ⟨527430, by omega⟩ = .linear (.wire 527390) (.wire 7138) true
  node_527431 : g.nodes ⟨527431, by omega⟩ = .product (.wire 458233) (.wire 527430)
  node_527432 : g.nodes ⟨527432, by omega⟩ = .linear (.wire 7138) (.wire 527431) false
  node_527433 : g.nodes ⟨527433, by omega⟩ = .linear (.wire 527401) (.wire 7139) true
  node_527434 : g.nodes ⟨527434, by omega⟩ = .product (.wire 458233) (.wire 527433)
  node_527435 : g.nodes ⟨527435, by omega⟩ = .linear (.wire 7139) (.wire 527434) false
  node_527436 : g.nodes ⟨527436, by omega⟩ = .linear (.wire 527367) (.wire 7140) true
  node_527437 : g.nodes ⟨527437, by omega⟩ = .product (.wire 458233) (.wire 527436)
  node_527438 : g.nodes ⟨527438, by omega⟩ = .linear (.wire 7140) (.wire 527437) false
  node_527439 : g.nodes ⟨527439, by omega⟩ = .linear (.wire 527378) (.wire 7141) true
  node_527440 : g.nodes ⟨527440, by omega⟩ = .product (.wire 458233) (.wire 527439)
  node_527441 : g.nodes ⟨527441, by omega⟩ = .linear (.wire 7141) (.wire 527440) false
  node_527442 : g.nodes ⟨527442, by omega⟩ = .linear (.wire 527389) (.wire 7142) true
  node_527443 : g.nodes ⟨527443, by omega⟩ = .product (.wire 458233) (.wire 527442)
  node_527444 : g.nodes ⟨527444, by omega⟩ = .linear (.wire 7142) (.wire 527443) false
  node_529877 : g.nodes ⟨529877, by omega⟩ = .linear (.wire 7143) (.wire 529842) true
  node_529878 : g.nodes ⟨529878, by omega⟩ = .product (.wire 458238) (.wire 529877)
  node_529879 : g.nodes ⟨529879, by omega⟩ = .linear (.wire 529842) (.wire 529878) false
  node_529880 : g.nodes ⟨529880, by omega⟩ = .linear (.wire 7144) (.wire 529853) true
  node_529881 : g.nodes ⟨529881, by omega⟩ = .product (.wire 458238) (.wire 529880)
  node_529882 : g.nodes ⟨529882, by omega⟩ = .linear (.wire 529853) (.wire 529881) false
  node_529883 : g.nodes ⟨529883, by omega⟩ = .linear (.wire 7145) (.wire 529864) true
  node_529884 : g.nodes ⟨529884, by omega⟩ = .product (.wire 458238) (.wire 529883)
  node_529885 : g.nodes ⟨529885, by omega⟩ = .linear (.wire 529864) (.wire 529884) false
  node_529886 : g.nodes ⟨529886, by omega⟩ = .linear (.wire 7146) (.wire 529875) true
  node_529887 : g.nodes ⟨529887, by omega⟩ = .product (.wire 458238) (.wire 529886)
  node_529888 : g.nodes ⟨529888, by omega⟩ = .linear (.wire 529875) (.wire 529887) false
  node_529889 : g.nodes ⟨529889, by omega⟩ = .linear (.wire 7147) (.wire 529841) true
  node_529890 : g.nodes ⟨529890, by omega⟩ = .product (.wire 458238) (.wire 529889)
  node_529891 : g.nodes ⟨529891, by omega⟩ = .linear (.wire 529841) (.wire 529890) false
  node_529892 : g.nodes ⟨529892, by omega⟩ = .linear (.wire 7148) (.wire 529852) true
  node_529893 : g.nodes ⟨529893, by omega⟩ = .product (.wire 458238) (.wire 529892)
  node_529894 : g.nodes ⟨529894, by omega⟩ = .linear (.wire 529852) (.wire 529893) false
  node_529895 : g.nodes ⟨529895, by omega⟩ = .linear (.wire 7149) (.wire 529863) true
  node_529896 : g.nodes ⟨529896, by omega⟩ = .product (.wire 458238) (.wire 529895)
  node_529897 : g.nodes ⟨529897, by omega⟩ = .linear (.wire 529863) (.wire 529896) false
  node_529898 : g.nodes ⟨529898, by omega⟩ = .linear (.wire 529842) (.wire 7143) true
  node_529899 : g.nodes ⟨529899, by omega⟩ = .product (.wire 458238) (.wire 529898)
  node_529900 : g.nodes ⟨529900, by omega⟩ = .linear (.wire 7143) (.wire 529899) false
  node_529901 : g.nodes ⟨529901, by omega⟩ = .linear (.wire 529853) (.wire 7144) true
  node_529902 : g.nodes ⟨529902, by omega⟩ = .product (.wire 458238) (.wire 529901)
  node_529903 : g.nodes ⟨529903, by omega⟩ = .linear (.wire 7144) (.wire 529902) false
  node_529904 : g.nodes ⟨529904, by omega⟩ = .linear (.wire 529864) (.wire 7145) true
  node_529905 : g.nodes ⟨529905, by omega⟩ = .product (.wire 458238) (.wire 529904)
  node_529906 : g.nodes ⟨529906, by omega⟩ = .linear (.wire 7145) (.wire 529905) false
  node_529907 : g.nodes ⟨529907, by omega⟩ = .linear (.wire 529875) (.wire 7146) true
  node_529908 : g.nodes ⟨529908, by omega⟩ = .product (.wire 458238) (.wire 529907)
  node_529909 : g.nodes ⟨529909, by omega⟩ = .linear (.wire 7146) (.wire 529908) false
  node_529910 : g.nodes ⟨529910, by omega⟩ = .linear (.wire 529841) (.wire 7147) true
  node_529911 : g.nodes ⟨529911, by omega⟩ = .product (.wire 458238) (.wire 529910)
  node_529912 : g.nodes ⟨529912, by omega⟩ = .linear (.wire 7147) (.wire 529911) false
  node_529913 : g.nodes ⟨529913, by omega⟩ = .linear (.wire 529852) (.wire 7148) true
  node_529914 : g.nodes ⟨529914, by omega⟩ = .product (.wire 458238) (.wire 529913)
  node_529915 : g.nodes ⟨529915, by omega⟩ = .linear (.wire 7148) (.wire 529914) false
  node_529916 : g.nodes ⟨529916, by omega⟩ = .linear (.wire 529863) (.wire 7149) true
  node_529917 : g.nodes ⟨529917, by omega⟩ = .product (.wire 458238) (.wire 529916)
  node_529918 : g.nodes ⟨529918, by omega⟩ = .linear (.wire 7149) (.wire 529917) false
  node_532351 : g.nodes ⟨532351, by omega⟩ = .linear (.wire 7150) (.wire 532316) true
  node_532352 : g.nodes ⟨532352, by omega⟩ = .product (.wire 458243) (.wire 532351)
  node_532353 : g.nodes ⟨532353, by omega⟩ = .linear (.wire 532316) (.wire 532352) false
  node_532354 : g.nodes ⟨532354, by omega⟩ = .linear (.wire 7151) (.wire 532327) true
  node_532355 : g.nodes ⟨532355, by omega⟩ = .product (.wire 458243) (.wire 532354)
  node_532356 : g.nodes ⟨532356, by omega⟩ = .linear (.wire 532327) (.wire 532355) false
  node_532357 : g.nodes ⟨532357, by omega⟩ = .linear (.wire 7152) (.wire 532338) true
  node_532358 : g.nodes ⟨532358, by omega⟩ = .product (.wire 458243) (.wire 532357)
  node_532359 : g.nodes ⟨532359, by omega⟩ = .linear (.wire 532338) (.wire 532358) false
  node_532360 : g.nodes ⟨532360, by omega⟩ = .linear (.wire 7153) (.wire 532349) true
  node_532361 : g.nodes ⟨532361, by omega⟩ = .product (.wire 458243) (.wire 532360)
  node_532362 : g.nodes ⟨532362, by omega⟩ = .linear (.wire 532349) (.wire 532361) false
  node_532363 : g.nodes ⟨532363, by omega⟩ = .linear (.wire 7154) (.wire 532315) true
  node_532364 : g.nodes ⟨532364, by omega⟩ = .product (.wire 458243) (.wire 532363)
  node_532365 : g.nodes ⟨532365, by omega⟩ = .linear (.wire 532315) (.wire 532364) false
  node_532366 : g.nodes ⟨532366, by omega⟩ = .linear (.wire 7155) (.wire 532326) true
  node_532367 : g.nodes ⟨532367, by omega⟩ = .product (.wire 458243) (.wire 532366)
  node_532368 : g.nodes ⟨532368, by omega⟩ = .linear (.wire 532326) (.wire 532367) false
  node_532369 : g.nodes ⟨532369, by omega⟩ = .linear (.wire 7156) (.wire 532337) true
  node_532370 : g.nodes ⟨532370, by omega⟩ = .product (.wire 458243) (.wire 532369)
  node_532371 : g.nodes ⟨532371, by omega⟩ = .linear (.wire 532337) (.wire 532370) false
  node_532372 : g.nodes ⟨532372, by omega⟩ = .linear (.wire 532316) (.wire 7150) true
  node_532373 : g.nodes ⟨532373, by omega⟩ = .product (.wire 458243) (.wire 532372)
  node_532374 : g.nodes ⟨532374, by omega⟩ = .linear (.wire 7150) (.wire 532373) false
  node_532375 : g.nodes ⟨532375, by omega⟩ = .linear (.wire 532327) (.wire 7151) true
  node_532376 : g.nodes ⟨532376, by omega⟩ = .product (.wire 458243) (.wire 532375)
  node_532377 : g.nodes ⟨532377, by omega⟩ = .linear (.wire 7151) (.wire 532376) false
  node_532378 : g.nodes ⟨532378, by omega⟩ = .linear (.wire 532338) (.wire 7152) true
  node_532379 : g.nodes ⟨532379, by omega⟩ = .product (.wire 458243) (.wire 532378)
  node_532380 : g.nodes ⟨532380, by omega⟩ = .linear (.wire 7152) (.wire 532379) false
  node_532381 : g.nodes ⟨532381, by omega⟩ = .linear (.wire 532349) (.wire 7153) true
  node_532382 : g.nodes ⟨532382, by omega⟩ = .product (.wire 458243) (.wire 532381)
  node_532383 : g.nodes ⟨532383, by omega⟩ = .linear (.wire 7153) (.wire 532382) false
  node_532384 : g.nodes ⟨532384, by omega⟩ = .linear (.wire 532315) (.wire 7154) true
  node_532385 : g.nodes ⟨532385, by omega⟩ = .product (.wire 458243) (.wire 532384)
  node_532386 : g.nodes ⟨532386, by omega⟩ = .linear (.wire 7154) (.wire 532385) false
  node_532387 : g.nodes ⟨532387, by omega⟩ = .linear (.wire 532326) (.wire 7155) true
  node_532388 : g.nodes ⟨532388, by omega⟩ = .product (.wire 458243) (.wire 532387)
  node_532389 : g.nodes ⟨532389, by omega⟩ = .linear (.wire 7155) (.wire 532388) false
  node_532390 : g.nodes ⟨532390, by omega⟩ = .linear (.wire 532337) (.wire 7156) true
  node_532391 : g.nodes ⟨532391, by omega⟩ = .product (.wire 458243) (.wire 532390)
  node_532392 : g.nodes ⟨532392, by omega⟩ = .linear (.wire 7156) (.wire 532391) false
  node_534825 : g.nodes ⟨534825, by omega⟩ = .linear (.wire 7157) (.wire 534790) true
  node_534826 : g.nodes ⟨534826, by omega⟩ = .product (.wire 458248) (.wire 534825)
  node_534827 : g.nodes ⟨534827, by omega⟩ = .linear (.wire 534790) (.wire 534826) false
  node_534828 : g.nodes ⟨534828, by omega⟩ = .linear (.wire 7158) (.wire 534801) true
  node_534829 : g.nodes ⟨534829, by omega⟩ = .product (.wire 458248) (.wire 534828)
  node_534830 : g.nodes ⟨534830, by omega⟩ = .linear (.wire 534801) (.wire 534829) false
  node_534831 : g.nodes ⟨534831, by omega⟩ = .linear (.wire 7159) (.wire 534812) true
  node_534832 : g.nodes ⟨534832, by omega⟩ = .product (.wire 458248) (.wire 534831)
  node_534833 : g.nodes ⟨534833, by omega⟩ = .linear (.wire 534812) (.wire 534832) false
  node_534834 : g.nodes ⟨534834, by omega⟩ = .linear (.wire 7160) (.wire 534823) true
  node_534835 : g.nodes ⟨534835, by omega⟩ = .product (.wire 458248) (.wire 534834)
  node_534836 : g.nodes ⟨534836, by omega⟩ = .linear (.wire 534823) (.wire 534835) false
  node_534837 : g.nodes ⟨534837, by omega⟩ = .linear (.wire 7161) (.wire 534789) true
  node_534838 : g.nodes ⟨534838, by omega⟩ = .product (.wire 458248) (.wire 534837)
  node_534839 : g.nodes ⟨534839, by omega⟩ = .linear (.wire 534789) (.wire 534838) false
  node_534840 : g.nodes ⟨534840, by omega⟩ = .linear (.wire 7162) (.wire 534800) true
  node_534841 : g.nodes ⟨534841, by omega⟩ = .product (.wire 458248) (.wire 534840)
  node_534842 : g.nodes ⟨534842, by omega⟩ = .linear (.wire 534800) (.wire 534841) false
  node_534843 : g.nodes ⟨534843, by omega⟩ = .linear (.wire 7163) (.wire 534811) true
  node_534844 : g.nodes ⟨534844, by omega⟩ = .product (.wire 458248) (.wire 534843)
  node_534845 : g.nodes ⟨534845, by omega⟩ = .linear (.wire 534811) (.wire 534844) false
  node_534846 : g.nodes ⟨534846, by omega⟩ = .linear (.wire 534790) (.wire 7157) true
  node_534847 : g.nodes ⟨534847, by omega⟩ = .product (.wire 458248) (.wire 534846)
  node_534848 : g.nodes ⟨534848, by omega⟩ = .linear (.wire 7157) (.wire 534847) false
  node_534849 : g.nodes ⟨534849, by omega⟩ = .linear (.wire 534801) (.wire 7158) true
  node_534850 : g.nodes ⟨534850, by omega⟩ = .product (.wire 458248) (.wire 534849)
  node_534851 : g.nodes ⟨534851, by omega⟩ = .linear (.wire 7158) (.wire 534850) false
  node_534852 : g.nodes ⟨534852, by omega⟩ = .linear (.wire 534812) (.wire 7159) true
  node_534853 : g.nodes ⟨534853, by omega⟩ = .product (.wire 458248) (.wire 534852)
  node_534854 : g.nodes ⟨534854, by omega⟩ = .linear (.wire 7159) (.wire 534853) false
  node_534855 : g.nodes ⟨534855, by omega⟩ = .linear (.wire 534823) (.wire 7160) true
  node_534856 : g.nodes ⟨534856, by omega⟩ = .product (.wire 458248) (.wire 534855)
  node_534857 : g.nodes ⟨534857, by omega⟩ = .linear (.wire 7160) (.wire 534856) false
  node_534858 : g.nodes ⟨534858, by omega⟩ = .linear (.wire 534789) (.wire 7161) true
  node_534859 : g.nodes ⟨534859, by omega⟩ = .product (.wire 458248) (.wire 534858)
  node_534860 : g.nodes ⟨534860, by omega⟩ = .linear (.wire 7161) (.wire 534859) false
  node_534861 : g.nodes ⟨534861, by omega⟩ = .linear (.wire 534800) (.wire 7162) true
  node_534862 : g.nodes ⟨534862, by omega⟩ = .product (.wire 458248) (.wire 534861)
  node_534863 : g.nodes ⟨534863, by omega⟩ = .linear (.wire 7162) (.wire 534862) false
  node_534864 : g.nodes ⟨534864, by omega⟩ = .linear (.wire 534811) (.wire 7163) true
  node_534865 : g.nodes ⟨534865, by omega⟩ = .product (.wire 458248) (.wire 534864)
  node_534866 : g.nodes ⟨534866, by omega⟩ = .linear (.wire 7163) (.wire 534865) false
  node_537299 : g.nodes ⟨537299, by omega⟩ = .linear (.wire 7164) (.wire 537264) true
  node_537300 : g.nodes ⟨537300, by omega⟩ = .product (.wire 458253) (.wire 537299)
  node_537301 : g.nodes ⟨537301, by omega⟩ = .linear (.wire 537264) (.wire 537300) false
  node_537302 : g.nodes ⟨537302, by omega⟩ = .linear (.wire 7165) (.wire 537275) true
  node_537303 : g.nodes ⟨537303, by omega⟩ = .product (.wire 458253) (.wire 537302)
  node_537304 : g.nodes ⟨537304, by omega⟩ = .linear (.wire 537275) (.wire 537303) false
  node_537305 : g.nodes ⟨537305, by omega⟩ = .linear (.wire 7166) (.wire 537286) true
  node_537306 : g.nodes ⟨537306, by omega⟩ = .product (.wire 458253) (.wire 537305)
  node_537307 : g.nodes ⟨537307, by omega⟩ = .linear (.wire 537286) (.wire 537306) false
  node_537308 : g.nodes ⟨537308, by omega⟩ = .linear (.wire 7167) (.wire 537297) true
  node_537309 : g.nodes ⟨537309, by omega⟩ = .product (.wire 458253) (.wire 537308)
  node_537310 : g.nodes ⟨537310, by omega⟩ = .linear (.wire 537297) (.wire 537309) false
  node_537311 : g.nodes ⟨537311, by omega⟩ = .linear (.wire 7168) (.wire 537263) true
  node_537312 : g.nodes ⟨537312, by omega⟩ = .product (.wire 458253) (.wire 537311)
  node_537313 : g.nodes ⟨537313, by omega⟩ = .linear (.wire 537263) (.wire 537312) false
  node_537314 : g.nodes ⟨537314, by omega⟩ = .linear (.wire 7169) (.wire 537274) true
  node_537315 : g.nodes ⟨537315, by omega⟩ = .product (.wire 458253) (.wire 537314)
  node_537316 : g.nodes ⟨537316, by omega⟩ = .linear (.wire 537274) (.wire 537315) false
  node_537317 : g.nodes ⟨537317, by omega⟩ = .linear (.wire 7170) (.wire 537285) true
  node_537318 : g.nodes ⟨537318, by omega⟩ = .product (.wire 458253) (.wire 537317)
  node_537319 : g.nodes ⟨537319, by omega⟩ = .linear (.wire 537285) (.wire 537318) false
  node_537320 : g.nodes ⟨537320, by omega⟩ = .linear (.wire 537264) (.wire 7164) true
  node_537321 : g.nodes ⟨537321, by omega⟩ = .product (.wire 458253) (.wire 537320)
  node_537322 : g.nodes ⟨537322, by omega⟩ = .linear (.wire 7164) (.wire 537321) false
  node_537323 : g.nodes ⟨537323, by omega⟩ = .linear (.wire 537275) (.wire 7165) true
  node_537324 : g.nodes ⟨537324, by omega⟩ = .product (.wire 458253) (.wire 537323)
  node_537325 : g.nodes ⟨537325, by omega⟩ = .linear (.wire 7165) (.wire 537324) false
  node_537326 : g.nodes ⟨537326, by omega⟩ = .linear (.wire 537286) (.wire 7166) true
  node_537327 : g.nodes ⟨537327, by omega⟩ = .product (.wire 458253) (.wire 537326)
  node_537328 : g.nodes ⟨537328, by omega⟩ = .linear (.wire 7166) (.wire 537327) false
  node_537329 : g.nodes ⟨537329, by omega⟩ = .linear (.wire 537297) (.wire 7167) true
  node_537330 : g.nodes ⟨537330, by omega⟩ = .product (.wire 458253) (.wire 537329)
  node_537331 : g.nodes ⟨537331, by omega⟩ = .linear (.wire 7167) (.wire 537330) false
  node_537332 : g.nodes ⟨537332, by omega⟩ = .linear (.wire 537263) (.wire 7168) true
  node_537333 : g.nodes ⟨537333, by omega⟩ = .product (.wire 458253) (.wire 537332)
  node_537334 : g.nodes ⟨537334, by omega⟩ = .linear (.wire 7168) (.wire 537333) false
  node_537335 : g.nodes ⟨537335, by omega⟩ = .linear (.wire 537274) (.wire 7169) true
  node_537336 : g.nodes ⟨537336, by omega⟩ = .product (.wire 458253) (.wire 537335)
  node_537337 : g.nodes ⟨537337, by omega⟩ = .linear (.wire 7169) (.wire 537336) false
  node_537338 : g.nodes ⟨537338, by omega⟩ = .linear (.wire 537285) (.wire 7170) true
  node_537339 : g.nodes ⟨537339, by omega⟩ = .product (.wire 458253) (.wire 537338)
  node_537340 : g.nodes ⟨537340, by omega⟩ = .linear (.wire 7170) (.wire 537339) false
  node_539773 : g.nodes ⟨539773, by omega⟩ = .linear (.wire 7171) (.wire 539738) true
  node_539774 : g.nodes ⟨539774, by omega⟩ = .product (.wire 458258) (.wire 539773)
  node_539775 : g.nodes ⟨539775, by omega⟩ = .linear (.wire 539738) (.wire 539774) false
  node_539776 : g.nodes ⟨539776, by omega⟩ = .linear (.wire 7172) (.wire 539749) true
  node_539777 : g.nodes ⟨539777, by omega⟩ = .product (.wire 458258) (.wire 539776)
  node_539778 : g.nodes ⟨539778, by omega⟩ = .linear (.wire 539749) (.wire 539777) false
  node_539779 : g.nodes ⟨539779, by omega⟩ = .linear (.wire 7173) (.wire 539760) true
  node_539780 : g.nodes ⟨539780, by omega⟩ = .product (.wire 458258) (.wire 539779)
  node_539781 : g.nodes ⟨539781, by omega⟩ = .linear (.wire 539760) (.wire 539780) false
  node_539782 : g.nodes ⟨539782, by omega⟩ = .linear (.wire 7174) (.wire 539771) true
  node_539783 : g.nodes ⟨539783, by omega⟩ = .product (.wire 458258) (.wire 539782)
  node_539784 : g.nodes ⟨539784, by omega⟩ = .linear (.wire 539771) (.wire 539783) false
  node_539785 : g.nodes ⟨539785, by omega⟩ = .linear (.wire 7175) (.wire 539737) true
  node_539786 : g.nodes ⟨539786, by omega⟩ = .product (.wire 458258) (.wire 539785)
  node_539787 : g.nodes ⟨539787, by omega⟩ = .linear (.wire 539737) (.wire 539786) false
  node_539788 : g.nodes ⟨539788, by omega⟩ = .linear (.wire 7176) (.wire 539748) true
  node_539789 : g.nodes ⟨539789, by omega⟩ = .product (.wire 458258) (.wire 539788)
  node_539790 : g.nodes ⟨539790, by omega⟩ = .linear (.wire 539748) (.wire 539789) false
  node_539791 : g.nodes ⟨539791, by omega⟩ = .linear (.wire 7177) (.wire 539759) true
  node_539792 : g.nodes ⟨539792, by omega⟩ = .product (.wire 458258) (.wire 539791)
  node_539793 : g.nodes ⟨539793, by omega⟩ = .linear (.wire 539759) (.wire 539792) false
  node_539794 : g.nodes ⟨539794, by omega⟩ = .linear (.wire 539738) (.wire 7171) true
  node_539795 : g.nodes ⟨539795, by omega⟩ = .product (.wire 458258) (.wire 539794)
  node_539796 : g.nodes ⟨539796, by omega⟩ = .linear (.wire 7171) (.wire 539795) false
  node_539797 : g.nodes ⟨539797, by omega⟩ = .linear (.wire 539749) (.wire 7172) true
  node_539798 : g.nodes ⟨539798, by omega⟩ = .product (.wire 458258) (.wire 539797)
  node_539799 : g.nodes ⟨539799, by omega⟩ = .linear (.wire 7172) (.wire 539798) false
  node_539800 : g.nodes ⟨539800, by omega⟩ = .linear (.wire 539760) (.wire 7173) true
  node_539801 : g.nodes ⟨539801, by omega⟩ = .product (.wire 458258) (.wire 539800)
  node_539802 : g.nodes ⟨539802, by omega⟩ = .linear (.wire 7173) (.wire 539801) false
  node_539803 : g.nodes ⟨539803, by omega⟩ = .linear (.wire 539771) (.wire 7174) true
  node_539804 : g.nodes ⟨539804, by omega⟩ = .product (.wire 458258) (.wire 539803)
  node_539805 : g.nodes ⟨539805, by omega⟩ = .linear (.wire 7174) (.wire 539804) false
  node_539806 : g.nodes ⟨539806, by omega⟩ = .linear (.wire 539737) (.wire 7175) true
  node_539807 : g.nodes ⟨539807, by omega⟩ = .product (.wire 458258) (.wire 539806)
  node_539808 : g.nodes ⟨539808, by omega⟩ = .linear (.wire 7175) (.wire 539807) false
  node_539809 : g.nodes ⟨539809, by omega⟩ = .linear (.wire 539748) (.wire 7176) true
  node_539810 : g.nodes ⟨539810, by omega⟩ = .product (.wire 458258) (.wire 539809)
  node_539811 : g.nodes ⟨539811, by omega⟩ = .linear (.wire 7176) (.wire 539810) false
  node_539812 : g.nodes ⟨539812, by omega⟩ = .linear (.wire 539759) (.wire 7177) true
  node_539813 : g.nodes ⟨539813, by omega⟩ = .product (.wire 458258) (.wire 539812)
  node_539814 : g.nodes ⟨539814, by omega⟩ = .linear (.wire 7177) (.wire 539813) false
  node_542247 : g.nodes ⟨542247, by omega⟩ = .linear (.wire 7178) (.wire 542212) true
  node_542248 : g.nodes ⟨542248, by omega⟩ = .product (.wire 458263) (.wire 542247)
  node_542249 : g.nodes ⟨542249, by omega⟩ = .linear (.wire 542212) (.wire 542248) false
  node_542250 : g.nodes ⟨542250, by omega⟩ = .linear (.wire 7179) (.wire 542223) true
  node_542251 : g.nodes ⟨542251, by omega⟩ = .product (.wire 458263) (.wire 542250)
  node_542252 : g.nodes ⟨542252, by omega⟩ = .linear (.wire 542223) (.wire 542251) false
  node_542253 : g.nodes ⟨542253, by omega⟩ = .linear (.wire 7180) (.wire 542234) true
  node_542254 : g.nodes ⟨542254, by omega⟩ = .product (.wire 458263) (.wire 542253)
  node_542255 : g.nodes ⟨542255, by omega⟩ = .linear (.wire 542234) (.wire 542254) false
  node_542256 : g.nodes ⟨542256, by omega⟩ = .linear (.wire 7181) (.wire 542245) true
  node_542257 : g.nodes ⟨542257, by omega⟩ = .product (.wire 458263) (.wire 542256)
  node_542258 : g.nodes ⟨542258, by omega⟩ = .linear (.wire 542245) (.wire 542257) false
  node_542259 : g.nodes ⟨542259, by omega⟩ = .linear (.wire 7182) (.wire 542211) true
  node_542260 : g.nodes ⟨542260, by omega⟩ = .product (.wire 458263) (.wire 542259)
  node_542261 : g.nodes ⟨542261, by omega⟩ = .linear (.wire 542211) (.wire 542260) false
  node_542262 : g.nodes ⟨542262, by omega⟩ = .linear (.wire 7183) (.wire 542222) true
  node_542263 : g.nodes ⟨542263, by omega⟩ = .product (.wire 458263) (.wire 542262)
  node_542264 : g.nodes ⟨542264, by omega⟩ = .linear (.wire 542222) (.wire 542263) false
  node_542265 : g.nodes ⟨542265, by omega⟩ = .linear (.wire 7184) (.wire 542233) true
  node_542266 : g.nodes ⟨542266, by omega⟩ = .product (.wire 458263) (.wire 542265)
  node_542267 : g.nodes ⟨542267, by omega⟩ = .linear (.wire 542233) (.wire 542266) false
  node_542268 : g.nodes ⟨542268, by omega⟩ = .linear (.wire 542212) (.wire 7178) true
  node_542269 : g.nodes ⟨542269, by omega⟩ = .product (.wire 458263) (.wire 542268)
  node_542270 : g.nodes ⟨542270, by omega⟩ = .linear (.wire 7178) (.wire 542269) false
  node_542271 : g.nodes ⟨542271, by omega⟩ = .linear (.wire 542223) (.wire 7179) true
  node_542272 : g.nodes ⟨542272, by omega⟩ = .product (.wire 458263) (.wire 542271)
  node_542273 : g.nodes ⟨542273, by omega⟩ = .linear (.wire 7179) (.wire 542272) false
  node_542274 : g.nodes ⟨542274, by omega⟩ = .linear (.wire 542234) (.wire 7180) true
  node_542275 : g.nodes ⟨542275, by omega⟩ = .product (.wire 458263) (.wire 542274)
  node_542276 : g.nodes ⟨542276, by omega⟩ = .linear (.wire 7180) (.wire 542275) false
  node_542277 : g.nodes ⟨542277, by omega⟩ = .linear (.wire 542245) (.wire 7181) true
  node_542278 : g.nodes ⟨542278, by omega⟩ = .product (.wire 458263) (.wire 542277)
  node_542279 : g.nodes ⟨542279, by omega⟩ = .linear (.wire 7181) (.wire 542278) false
  node_542280 : g.nodes ⟨542280, by omega⟩ = .linear (.wire 542211) (.wire 7182) true
  node_542281 : g.nodes ⟨542281, by omega⟩ = .product (.wire 458263) (.wire 542280)
  node_542282 : g.nodes ⟨542282, by omega⟩ = .linear (.wire 7182) (.wire 542281) false
  node_542283 : g.nodes ⟨542283, by omega⟩ = .linear (.wire 542222) (.wire 7183) true
  node_542284 : g.nodes ⟨542284, by omega⟩ = .product (.wire 458263) (.wire 542283)
  node_542285 : g.nodes ⟨542285, by omega⟩ = .linear (.wire 7183) (.wire 542284) false
  node_542286 : g.nodes ⟨542286, by omega⟩ = .linear (.wire 542233) (.wire 7184) true
  node_542287 : g.nodes ⟨542287, by omega⟩ = .product (.wire 458263) (.wire 542286)
  node_542288 : g.nodes ⟨542288, by omega⟩ = .linear (.wire 7184) (.wire 542287) false
  node_544721 : g.nodes ⟨544721, by omega⟩ = .linear (.wire 544686) (.wire 17) true
  node_544722 : g.nodes ⟨544722, by omega⟩ = .product (.wire 6940) (.wire 544721)
  node_544723 : g.nodes ⟨544723, by omega⟩ = .linear (.wire 544697) (.wire 18) true
  node_544724 : g.nodes ⟨544724, by omega⟩ = .product (.wire 6940) (.wire 544723)
  node_544725 : g.nodes ⟨544725, by omega⟩ = .linear (.wire 544708) (.wire 19) true
  node_544726 : g.nodes ⟨544726, by omega⟩ = .product (.wire 6940) (.wire 544725)
  node_544727 : g.nodes ⟨544727, by omega⟩ = .linear (.wire 544719) (.wire 20) true
  node_544728 : g.nodes ⟨544728, by omega⟩ = .product (.wire 6940) (.wire 544727)
  node_544729 : g.nodes ⟨544729, by omega⟩ = .linear (.wire 544685) (.wire 21) true
  node_544730 : g.nodes ⟨544730, by omega⟩ = .product (.wire 6940) (.wire 544729)
  node_544731 : g.nodes ⟨544731, by omega⟩ = .linear (.wire 544696) (.wire 22) true
  node_544732 : g.nodes ⟨544732, by omega⟩ = .product (.wire 6940) (.wire 544731)
  node_544733 : g.nodes ⟨544733, by omega⟩ = .linear (.wire 544707) (.wire 23) true
  node_544734 : g.nodes ⟨544734, by omega⟩ = .product (.wire 6940) (.wire 544733)
  node_554451 : g.nodes ⟨554451, by omega⟩ = .linear (.wire 549568) (.wire 554416) true
  node_554452 : g.nodes ⟨554452, by omega⟩ = .product (.wire 6940) (.wire 554451)
  node_554453 : g.nodes ⟨554453, by omega⟩ = .linear (.wire 554416) (.wire 554452) false
  node_554454 : g.nodes ⟨554454, by omega⟩ = .linear (.wire 549579) (.wire 554427) true
  node_554455 : g.nodes ⟨554455, by omega⟩ = .product (.wire 6940) (.wire 554454)
  node_554456 : g.nodes ⟨554456, by omega⟩ = .linear (.wire 554427) (.wire 554455) false
  node_554457 : g.nodes ⟨554457, by omega⟩ = .linear (.wire 549590) (.wire 554438) true
  node_554458 : g.nodes ⟨554458, by omega⟩ = .product (.wire 6940) (.wire 554457)
  node_554459 : g.nodes ⟨554459, by omega⟩ = .linear (.wire 554438) (.wire 554458) false
  node_554460 : g.nodes ⟨554460, by omega⟩ = .linear (.wire 549601) (.wire 554449) true
  node_554461 : g.nodes ⟨554461, by omega⟩ = .product (.wire 6940) (.wire 554460)
  node_554462 : g.nodes ⟨554462, by omega⟩ = .linear (.wire 554449) (.wire 554461) false
  node_554463 : g.nodes ⟨554463, by omega⟩ = .linear (.wire 549567) (.wire 554415) true
  node_554464 : g.nodes ⟨554464, by omega⟩ = .product (.wire 6940) (.wire 554463)
  node_554465 : g.nodes ⟨554465, by omega⟩ = .linear (.wire 554415) (.wire 554464) false
  node_554466 : g.nodes ⟨554466, by omega⟩ = .linear (.wire 549578) (.wire 554426) true
  node_554467 : g.nodes ⟨554467, by omega⟩ = .product (.wire 6940) (.wire 554466)
  node_554468 : g.nodes ⟨554468, by omega⟩ = .linear (.wire 554426) (.wire 554467) false
  node_554469 : g.nodes ⟨554469, by omega⟩ = .linear (.wire 549589) (.wire 554437) true
  node_554470 : g.nodes ⟨554470, by omega⟩ = .product (.wire 6940) (.wire 554469)
  node_554471 : g.nodes ⟨554471, by omega⟩ = .linear (.wire 554437) (.wire 554470) false
  node_554472 : g.nodes ⟨554472, by omega⟩ = .linear (.wire 554453) (.wire 25) true
  node_554473 : g.nodes ⟨554473, by omega⟩ = .linear (.wire 554456) (.wire 26) true
  node_554474 : g.nodes ⟨554474, by omega⟩ = .linear (.wire 554459) (.wire 27) true
  node_554475 : g.nodes ⟨554475, by omega⟩ = .linear (.wire 554462) (.wire 28) true
  node_554476 : g.nodes ⟨554476, by omega⟩ = .linear (.wire 554465) (.wire 29) true
  node_554477 : g.nodes ⟨554477, by omega⟩ = .linear (.wire 554468) (.wire 30) true
  node_554478 : g.nodes ⟨554478, by omega⟩ = .linear (.wire 554471) (.wire 31) true
  node_560097 : g.nodes ⟨560097, by omega⟩ = .linear (.wire 557654) (.wire 560062) true
  node_560098 : g.nodes ⟨560098, by omega⟩ = .product (.wire 7196) (.wire 560097)
  node_560099 : g.nodes ⟨560099, by omega⟩ = .linear (.wire 560062) (.wire 560098) false
  node_560100 : g.nodes ⟨560100, by omega⟩ = .linear (.wire 557665) (.wire 560073) true
  node_560101 : g.nodes ⟨560101, by omega⟩ = .product (.wire 7196) (.wire 560100)
  node_560102 : g.nodes ⟨560102, by omega⟩ = .linear (.wire 560073) (.wire 560101) false
  node_560103 : g.nodes ⟨560103, by omega⟩ = .linear (.wire 557676) (.wire 560084) true
  node_560104 : g.nodes ⟨560104, by omega⟩ = .product (.wire 7196) (.wire 560103)
  node_560105 : g.nodes ⟨560105, by omega⟩ = .linear (.wire 560084) (.wire 560104) false
  node_560106 : g.nodes ⟨560106, by omega⟩ = .linear (.wire 557687) (.wire 560095) true
  node_560107 : g.nodes ⟨560107, by omega⟩ = .product (.wire 7196) (.wire 560106)
  node_560108 : g.nodes ⟨560108, by omega⟩ = .linear (.wire 560095) (.wire 560107) false
  node_560109 : g.nodes ⟨560109, by omega⟩ = .linear (.wire 557653) (.wire 560061) true
  node_560110 : g.nodes ⟨560110, by omega⟩ = .product (.wire 7196) (.wire 560109)
  node_560111 : g.nodes ⟨560111, by omega⟩ = .linear (.wire 560061) (.wire 560110) false
  node_560112 : g.nodes ⟨560112, by omega⟩ = .linear (.wire 557664) (.wire 560072) true
  node_560113 : g.nodes ⟨560113, by omega⟩ = .product (.wire 7196) (.wire 560112)
  node_560114 : g.nodes ⟨560114, by omega⟩ = .linear (.wire 560072) (.wire 560113) false
  node_560115 : g.nodes ⟨560115, by omega⟩ = .linear (.wire 557675) (.wire 560083) true
  node_560116 : g.nodes ⟨560116, by omega⟩ = .product (.wire 7196) (.wire 560115)
  node_560117 : g.nodes ⟨560117, by omega⟩ = .linear (.wire 560083) (.wire 560116) false
  node_560118 : g.nodes ⟨560118, by omega⟩ = .linear (.wire 7211) (.wire 560099) true
  node_560119 : g.nodes ⟨560119, by omega⟩ = .product (.wire 555267) (.wire 560118)
  node_560120 : g.nodes ⟨560120, by omega⟩ = .linear (.wire 7212) (.wire 560102) true
  node_560121 : g.nodes ⟨560121, by omega⟩ = .product (.wire 555267) (.wire 560120)
  node_560122 : g.nodes ⟨560122, by omega⟩ = .linear (.wire 7213) (.wire 560105) true
  node_560123 : g.nodes ⟨560123, by omega⟩ = .product (.wire 555267) (.wire 560122)
  node_560124 : g.nodes ⟨560124, by omega⟩ = .linear (.wire 7214) (.wire 560108) true
  node_560125 : g.nodes ⟨560125, by omega⟩ = .product (.wire 555267) (.wire 560124)
  node_560126 : g.nodes ⟨560126, by omega⟩ = .linear (.wire 7207) (.wire 560111) true
  node_560127 : g.nodes ⟨560127, by omega⟩ = .product (.wire 555267) (.wire 560126)
  node_560128 : g.nodes ⟨560128, by omega⟩ = .linear (.wire 7208) (.wire 560114) true
  node_560129 : g.nodes ⟨560129, by omega⟩ = .product (.wire 555267) (.wire 560128)
  node_560130 : g.nodes ⟨560130, by omega⟩ = .linear (.wire 7209) (.wire 560117) true
  node_560131 : g.nodes ⟨560131, by omega⟩ = .product (.wire 555267) (.wire 560130)
  node_560132 : g.nodes ⟨560132, by omega⟩ = .linear (.wire 7211) (.wire 52292) true
  node_560133 : g.nodes ⟨560133, by omega⟩ = .product (.wire 6915) (.wire 560132)
  node_560134 : g.nodes ⟨560134, by omega⟩ = .linear (.wire 7212) (.wire 52303) true
  node_560135 : g.nodes ⟨560135, by omega⟩ = .product (.wire 6915) (.wire 560134)
  node_560136 : g.nodes ⟨560136, by omega⟩ = .linear (.wire 7213) (.wire 52314) true
  node_560137 : g.nodes ⟨560137, by omega⟩ = .product (.wire 6915) (.wire 560136)
  node_560138 : g.nodes ⟨560138, by omega⟩ = .linear (.wire 7214) (.wire 52325) true
  node_560139 : g.nodes ⟨560139, by omega⟩ = .product (.wire 6915) (.wire 560138)
  node_560140 : g.nodes ⟨560140, by omega⟩ = .linear (.wire 7207) (.wire 52291) true
  node_560141 : g.nodes ⟨560141, by omega⟩ = .product (.wire 6915) (.wire 560140)
  node_560142 : g.nodes ⟨560142, by omega⟩ = .linear (.wire 7208) (.wire 52302) true
  node_560143 : g.nodes ⟨560143, by omega⟩ = .product (.wire 6915) (.wire 560142)
  node_560144 : g.nodes ⟨560144, by omega⟩ = .linear (.wire 7209) (.wire 52313) true
  node_560145 : g.nodes ⟨560145, by omega⟩ = .product (.wire 6915) (.wire 560144)
  node_567635 : g.nodes ⟨567635, by omega⟩ = .linear (.wire 7216) (.wire 567600) true
  node_567636 : g.nodes ⟨567636, by omega⟩ = .product (.wire 560192) (.wire 567635)
  node_567637 : g.nodes ⟨567637, by omega⟩ = .linear (.wire 567600) (.wire 567636) false
  node_567638 : g.nodes ⟨567638, by omega⟩ = .linear (.wire 7217) (.wire 567611) true
  node_567639 : g.nodes ⟨567639, by omega⟩ = .product (.wire 560192) (.wire 567638)
  node_567640 : g.nodes ⟨567640, by omega⟩ = .linear (.wire 567611) (.wire 567639) false
  node_567641 : g.nodes ⟨567641, by omega⟩ = .linear (.wire 7218) (.wire 567622) true
  node_567642 : g.nodes ⟨567642, by omega⟩ = .product (.wire 560192) (.wire 567641)
  node_567643 : g.nodes ⟨567643, by omega⟩ = .linear (.wire 567622) (.wire 567642) false
  node_567644 : g.nodes ⟨567644, by omega⟩ = .linear (.wire 7219) (.wire 567633) true
  node_567645 : g.nodes ⟨567645, by omega⟩ = .product (.wire 560192) (.wire 567644)
  node_567646 : g.nodes ⟨567646, by omega⟩ = .linear (.wire 567633) (.wire 567645) false
  node_567647 : g.nodes ⟨567647, by omega⟩ = .linear (.wire 7220) (.wire 567599) true
  node_567648 : g.nodes ⟨567648, by omega⟩ = .product (.wire 560192) (.wire 567647)
  node_567649 : g.nodes ⟨567649, by omega⟩ = .linear (.wire 567599) (.wire 567648) false
  node_567650 : g.nodes ⟨567650, by omega⟩ = .linear (.wire 7221) (.wire 567610) true
  node_567651 : g.nodes ⟨567651, by omega⟩ = .product (.wire 560192) (.wire 567650)
  node_567652 : g.nodes ⟨567652, by omega⟩ = .linear (.wire 567610) (.wire 567651) false
  node_567653 : g.nodes ⟨567653, by omega⟩ = .linear (.wire 7222) (.wire 567621) true
  node_567654 : g.nodes ⟨567654, by omega⟩ = .product (.wire 560192) (.wire 567653)
  node_567655 : g.nodes ⟨567655, by omega⟩ = .linear (.wire 567621) (.wire 567654) false
  node_567656 : g.nodes ⟨567656, by omega⟩ = .linear (.wire 567600) (.wire 7216) true
  node_567657 : g.nodes ⟨567657, by omega⟩ = .product (.wire 560192) (.wire 567656)
  node_567658 : g.nodes ⟨567658, by omega⟩ = .linear (.wire 7216) (.wire 567657) false
  node_567659 : g.nodes ⟨567659, by omega⟩ = .linear (.wire 567611) (.wire 7217) true
  node_567660 : g.nodes ⟨567660, by omega⟩ = .product (.wire 560192) (.wire 567659)
  node_567661 : g.nodes ⟨567661, by omega⟩ = .linear (.wire 7217) (.wire 567660) false
  node_567662 : g.nodes ⟨567662, by omega⟩ = .linear (.wire 567622) (.wire 7218) true
  node_567663 : g.nodes ⟨567663, by omega⟩ = .product (.wire 560192) (.wire 567662)
  node_567664 : g.nodes ⟨567664, by omega⟩ = .linear (.wire 7218) (.wire 567663) false
  node_567665 : g.nodes ⟨567665, by omega⟩ = .linear (.wire 567633) (.wire 7219) true
  node_567666 : g.nodes ⟨567666, by omega⟩ = .product (.wire 560192) (.wire 567665)
  node_567667 : g.nodes ⟨567667, by omega⟩ = .linear (.wire 7219) (.wire 567666) false
  node_567668 : g.nodes ⟨567668, by omega⟩ = .linear (.wire 567599) (.wire 7220) true
  node_567669 : g.nodes ⟨567669, by omega⟩ = .product (.wire 560192) (.wire 567668)
  node_567670 : g.nodes ⟨567670, by omega⟩ = .linear (.wire 7220) (.wire 567669) false
  node_567671 : g.nodes ⟨567671, by omega⟩ = .linear (.wire 567610) (.wire 7221) true
  node_567672 : g.nodes ⟨567672, by omega⟩ = .product (.wire 560192) (.wire 567671)
  node_567673 : g.nodes ⟨567673, by omega⟩ = .linear (.wire 7221) (.wire 567672) false
  node_567674 : g.nodes ⟨567674, by omega⟩ = .linear (.wire 567621) (.wire 7222) true
  node_567675 : g.nodes ⟨567675, by omega⟩ = .product (.wire 560192) (.wire 567674)
  node_567676 : g.nodes ⟨567676, by omega⟩ = .linear (.wire 7222) (.wire 567675) false
  node_570109 : g.nodes ⟨570109, by omega⟩ = .linear (.wire 7223) (.wire 570074) true
  node_570110 : g.nodes ⟨570110, by omega⟩ = .product (.wire 560195) (.wire 570109)
  node_570111 : g.nodes ⟨570111, by omega⟩ = .linear (.wire 570074) (.wire 570110) false
  node_570112 : g.nodes ⟨570112, by omega⟩ = .linear (.wire 7224) (.wire 570085) true
  node_570113 : g.nodes ⟨570113, by omega⟩ = .product (.wire 560195) (.wire 570112)
  node_570114 : g.nodes ⟨570114, by omega⟩ = .linear (.wire 570085) (.wire 570113) false
  node_570115 : g.nodes ⟨570115, by omega⟩ = .linear (.wire 7225) (.wire 570096) true
  node_570116 : g.nodes ⟨570116, by omega⟩ = .product (.wire 560195) (.wire 570115)
  node_570117 : g.nodes ⟨570117, by omega⟩ = .linear (.wire 570096) (.wire 570116) false
  node_570118 : g.nodes ⟨570118, by omega⟩ = .linear (.wire 7226) (.wire 570107) true
  node_570119 : g.nodes ⟨570119, by omega⟩ = .product (.wire 560195) (.wire 570118)
  node_570120 : g.nodes ⟨570120, by omega⟩ = .linear (.wire 570107) (.wire 570119) false
  node_570121 : g.nodes ⟨570121, by omega⟩ = .linear (.wire 7227) (.wire 570073) true
  node_570122 : g.nodes ⟨570122, by omega⟩ = .product (.wire 560195) (.wire 570121)
  node_570123 : g.nodes ⟨570123, by omega⟩ = .linear (.wire 570073) (.wire 570122) false
  node_570124 : g.nodes ⟨570124, by omega⟩ = .linear (.wire 7228) (.wire 570084) true
  node_570125 : g.nodes ⟨570125, by omega⟩ = .product (.wire 560195) (.wire 570124)
  node_570126 : g.nodes ⟨570126, by omega⟩ = .linear (.wire 570084) (.wire 570125) false
  node_570127 : g.nodes ⟨570127, by omega⟩ = .linear (.wire 7229) (.wire 570095) true
  node_570128 : g.nodes ⟨570128, by omega⟩ = .product (.wire 560195) (.wire 570127)
  node_570129 : g.nodes ⟨570129, by omega⟩ = .linear (.wire 570095) (.wire 570128) false
  node_570130 : g.nodes ⟨570130, by omega⟩ = .linear (.wire 570074) (.wire 7223) true
  node_570131 : g.nodes ⟨570131, by omega⟩ = .product (.wire 560195) (.wire 570130)
  node_570132 : g.nodes ⟨570132, by omega⟩ = .linear (.wire 7223) (.wire 570131) false
  node_570133 : g.nodes ⟨570133, by omega⟩ = .linear (.wire 570085) (.wire 7224) true
  node_570134 : g.nodes ⟨570134, by omega⟩ = .product (.wire 560195) (.wire 570133)
  node_570135 : g.nodes ⟨570135, by omega⟩ = .linear (.wire 7224) (.wire 570134) false
  node_570136 : g.nodes ⟨570136, by omega⟩ = .linear (.wire 570096) (.wire 7225) true
  node_570137 : g.nodes ⟨570137, by omega⟩ = .product (.wire 560195) (.wire 570136)
  node_570138 : g.nodes ⟨570138, by omega⟩ = .linear (.wire 7225) (.wire 570137) false
  node_570139 : g.nodes ⟨570139, by omega⟩ = .linear (.wire 570107) (.wire 7226) true
  node_570140 : g.nodes ⟨570140, by omega⟩ = .product (.wire 560195) (.wire 570139)
  node_570141 : g.nodes ⟨570141, by omega⟩ = .linear (.wire 7226) (.wire 570140) false
  node_570142 : g.nodes ⟨570142, by omega⟩ = .linear (.wire 570073) (.wire 7227) true
  node_570143 : g.nodes ⟨570143, by omega⟩ = .product (.wire 560195) (.wire 570142)
  node_570144 : g.nodes ⟨570144, by omega⟩ = .linear (.wire 7227) (.wire 570143) false
  node_570145 : g.nodes ⟨570145, by omega⟩ = .linear (.wire 570084) (.wire 7228) true
  node_570146 : g.nodes ⟨570146, by omega⟩ = .product (.wire 560195) (.wire 570145)
  node_570147 : g.nodes ⟨570147, by omega⟩ = .linear (.wire 7228) (.wire 570146) false
  node_570148 : g.nodes ⟨570148, by omega⟩ = .linear (.wire 570095) (.wire 7229) true
  node_570149 : g.nodes ⟨570149, by omega⟩ = .product (.wire 560195) (.wire 570148)
  node_570150 : g.nodes ⟨570150, by omega⟩ = .linear (.wire 7229) (.wire 570149) false
  node_572583 : g.nodes ⟨572583, by omega⟩ = .linear (.wire 7230) (.wire 572548) true
  node_572584 : g.nodes ⟨572584, by omega⟩ = .product (.wire 560200) (.wire 572583)
  node_572585 : g.nodes ⟨572585, by omega⟩ = .linear (.wire 572548) (.wire 572584) false
  node_572586 : g.nodes ⟨572586, by omega⟩ = .linear (.wire 7231) (.wire 572559) true
  node_572587 : g.nodes ⟨572587, by omega⟩ = .product (.wire 560200) (.wire 572586)
  node_572588 : g.nodes ⟨572588, by omega⟩ = .linear (.wire 572559) (.wire 572587) false
  node_572589 : g.nodes ⟨572589, by omega⟩ = .linear (.wire 7232) (.wire 572570) true
  node_572590 : g.nodes ⟨572590, by omega⟩ = .product (.wire 560200) (.wire 572589)
  node_572591 : g.nodes ⟨572591, by omega⟩ = .linear (.wire 572570) (.wire 572590) false
  node_572592 : g.nodes ⟨572592, by omega⟩ = .linear (.wire 7233) (.wire 572581) true
  node_572593 : g.nodes ⟨572593, by omega⟩ = .product (.wire 560200) (.wire 572592)
  node_572594 : g.nodes ⟨572594, by omega⟩ = .linear (.wire 572581) (.wire 572593) false
  node_572595 : g.nodes ⟨572595, by omega⟩ = .linear (.wire 7234) (.wire 572547) true
  node_572596 : g.nodes ⟨572596, by omega⟩ = .product (.wire 560200) (.wire 572595)
  node_572597 : g.nodes ⟨572597, by omega⟩ = .linear (.wire 572547) (.wire 572596) false
  node_572598 : g.nodes ⟨572598, by omega⟩ = .linear (.wire 7235) (.wire 572558) true
  node_572599 : g.nodes ⟨572599, by omega⟩ = .product (.wire 560200) (.wire 572598)
  node_572600 : g.nodes ⟨572600, by omega⟩ = .linear (.wire 572558) (.wire 572599) false
  node_572601 : g.nodes ⟨572601, by omega⟩ = .linear (.wire 7236) (.wire 572569) true
  node_572602 : g.nodes ⟨572602, by omega⟩ = .product (.wire 560200) (.wire 572601)
  node_572603 : g.nodes ⟨572603, by omega⟩ = .linear (.wire 572569) (.wire 572602) false
  node_572604 : g.nodes ⟨572604, by omega⟩ = .linear (.wire 572548) (.wire 7230) true
  node_572605 : g.nodes ⟨572605, by omega⟩ = .product (.wire 560200) (.wire 572604)
  node_572606 : g.nodes ⟨572606, by omega⟩ = .linear (.wire 7230) (.wire 572605) false
  node_572607 : g.nodes ⟨572607, by omega⟩ = .linear (.wire 572559) (.wire 7231) true
  node_572608 : g.nodes ⟨572608, by omega⟩ = .product (.wire 560200) (.wire 572607)
  node_572609 : g.nodes ⟨572609, by omega⟩ = .linear (.wire 7231) (.wire 572608) false
  node_572610 : g.nodes ⟨572610, by omega⟩ = .linear (.wire 572570) (.wire 7232) true
  node_572611 : g.nodes ⟨572611, by omega⟩ = .product (.wire 560200) (.wire 572610)
  node_572612 : g.nodes ⟨572612, by omega⟩ = .linear (.wire 7232) (.wire 572611) false
  node_572613 : g.nodes ⟨572613, by omega⟩ = .linear (.wire 572581) (.wire 7233) true
  node_572614 : g.nodes ⟨572614, by omega⟩ = .product (.wire 560200) (.wire 572613)
  node_572615 : g.nodes ⟨572615, by omega⟩ = .linear (.wire 7233) (.wire 572614) false
  node_572616 : g.nodes ⟨572616, by omega⟩ = .linear (.wire 572547) (.wire 7234) true
  node_572617 : g.nodes ⟨572617, by omega⟩ = .product (.wire 560200) (.wire 572616)
  node_572618 : g.nodes ⟨572618, by omega⟩ = .linear (.wire 7234) (.wire 572617) false
  node_572619 : g.nodes ⟨572619, by omega⟩ = .linear (.wire 572558) (.wire 7235) true
  node_572620 : g.nodes ⟨572620, by omega⟩ = .product (.wire 560200) (.wire 572619)
  node_572621 : g.nodes ⟨572621, by omega⟩ = .linear (.wire 7235) (.wire 572620) false
  node_572622 : g.nodes ⟨572622, by omega⟩ = .linear (.wire 572569) (.wire 7236) true
  node_572623 : g.nodes ⟨572623, by omega⟩ = .product (.wire 560200) (.wire 572622)
  node_572624 : g.nodes ⟨572624, by omega⟩ = .linear (.wire 7236) (.wire 572623) false
  node_575057 : g.nodes ⟨575057, by omega⟩ = .linear (.wire 7237) (.wire 575022) true
  node_575058 : g.nodes ⟨575058, by omega⟩ = .product (.wire 560205) (.wire 575057)
  node_575059 : g.nodes ⟨575059, by omega⟩ = .linear (.wire 575022) (.wire 575058) false
  node_575060 : g.nodes ⟨575060, by omega⟩ = .linear (.wire 7238) (.wire 575033) true
  node_575061 : g.nodes ⟨575061, by omega⟩ = .product (.wire 560205) (.wire 575060)
  node_575062 : g.nodes ⟨575062, by omega⟩ = .linear (.wire 575033) (.wire 575061) false
  node_575063 : g.nodes ⟨575063, by omega⟩ = .linear (.wire 7239) (.wire 575044) true
  node_575064 : g.nodes ⟨575064, by omega⟩ = .product (.wire 560205) (.wire 575063)
  node_575065 : g.nodes ⟨575065, by omega⟩ = .linear (.wire 575044) (.wire 575064) false
  node_575066 : g.nodes ⟨575066, by omega⟩ = .linear (.wire 7240) (.wire 575055) true
  node_575067 : g.nodes ⟨575067, by omega⟩ = .product (.wire 560205) (.wire 575066)
  node_575068 : g.nodes ⟨575068, by omega⟩ = .linear (.wire 575055) (.wire 575067) false
  node_575069 : g.nodes ⟨575069, by omega⟩ = .linear (.wire 7241) (.wire 575021) true
  node_575070 : g.nodes ⟨575070, by omega⟩ = .product (.wire 560205) (.wire 575069)
  node_575071 : g.nodes ⟨575071, by omega⟩ = .linear (.wire 575021) (.wire 575070) false
  node_575072 : g.nodes ⟨575072, by omega⟩ = .linear (.wire 7242) (.wire 575032) true
  node_575073 : g.nodes ⟨575073, by omega⟩ = .product (.wire 560205) (.wire 575072)
  node_575074 : g.nodes ⟨575074, by omega⟩ = .linear (.wire 575032) (.wire 575073) false
  node_575075 : g.nodes ⟨575075, by omega⟩ = .linear (.wire 7243) (.wire 575043) true
  node_575076 : g.nodes ⟨575076, by omega⟩ = .product (.wire 560205) (.wire 575075)
  node_575077 : g.nodes ⟨575077, by omega⟩ = .linear (.wire 575043) (.wire 575076) false
  node_575078 : g.nodes ⟨575078, by omega⟩ = .linear (.wire 575022) (.wire 7237) true
  node_575079 : g.nodes ⟨575079, by omega⟩ = .product (.wire 560205) (.wire 575078)
  node_575080 : g.nodes ⟨575080, by omega⟩ = .linear (.wire 7237) (.wire 575079) false
  node_575081 : g.nodes ⟨575081, by omega⟩ = .linear (.wire 575033) (.wire 7238) true
  node_575082 : g.nodes ⟨575082, by omega⟩ = .product (.wire 560205) (.wire 575081)
  node_575083 : g.nodes ⟨575083, by omega⟩ = .linear (.wire 7238) (.wire 575082) false
  node_575084 : g.nodes ⟨575084, by omega⟩ = .linear (.wire 575044) (.wire 7239) true
  node_575085 : g.nodes ⟨575085, by omega⟩ = .product (.wire 560205) (.wire 575084)
  node_575086 : g.nodes ⟨575086, by omega⟩ = .linear (.wire 7239) (.wire 575085) false
  node_575087 : g.nodes ⟨575087, by omega⟩ = .linear (.wire 575055) (.wire 7240) true
  node_575088 : g.nodes ⟨575088, by omega⟩ = .product (.wire 560205) (.wire 575087)
  node_575089 : g.nodes ⟨575089, by omega⟩ = .linear (.wire 7240) (.wire 575088) false
  node_575090 : g.nodes ⟨575090, by omega⟩ = .linear (.wire 575021) (.wire 7241) true
  node_575091 : g.nodes ⟨575091, by omega⟩ = .product (.wire 560205) (.wire 575090)
  node_575092 : g.nodes ⟨575092, by omega⟩ = .linear (.wire 7241) (.wire 575091) false
  node_575093 : g.nodes ⟨575093, by omega⟩ = .linear (.wire 575032) (.wire 7242) true
  node_575094 : g.nodes ⟨575094, by omega⟩ = .product (.wire 560205) (.wire 575093)
  node_575095 : g.nodes ⟨575095, by omega⟩ = .linear (.wire 7242) (.wire 575094) false
  node_575096 : g.nodes ⟨575096, by omega⟩ = .linear (.wire 575043) (.wire 7243) true
  node_575097 : g.nodes ⟨575097, by omega⟩ = .product (.wire 560205) (.wire 575096)
  node_575098 : g.nodes ⟨575098, by omega⟩ = .linear (.wire 7243) (.wire 575097) false
  node_577531 : g.nodes ⟨577531, by omega⟩ = .linear (.wire 7244) (.wire 577496) true
  node_577532 : g.nodes ⟨577532, by omega⟩ = .product (.wire 560210) (.wire 577531)
  node_577533 : g.nodes ⟨577533, by omega⟩ = .linear (.wire 577496) (.wire 577532) false
  node_577534 : g.nodes ⟨577534, by omega⟩ = .linear (.wire 7245) (.wire 577507) true
  node_577535 : g.nodes ⟨577535, by omega⟩ = .product (.wire 560210) (.wire 577534)
  node_577536 : g.nodes ⟨577536, by omega⟩ = .linear (.wire 577507) (.wire 577535) false
  node_577537 : g.nodes ⟨577537, by omega⟩ = .linear (.wire 7246) (.wire 577518) true
  node_577538 : g.nodes ⟨577538, by omega⟩ = .product (.wire 560210) (.wire 577537)
  node_577539 : g.nodes ⟨577539, by omega⟩ = .linear (.wire 577518) (.wire 577538) false
  node_577540 : g.nodes ⟨577540, by omega⟩ = .linear (.wire 7247) (.wire 577529) true
  node_577541 : g.nodes ⟨577541, by omega⟩ = .product (.wire 560210) (.wire 577540)
  node_577542 : g.nodes ⟨577542, by omega⟩ = .linear (.wire 577529) (.wire 577541) false
  node_577543 : g.nodes ⟨577543, by omega⟩ = .linear (.wire 7248) (.wire 577495) true
  node_577544 : g.nodes ⟨577544, by omega⟩ = .product (.wire 560210) (.wire 577543)
  node_577545 : g.nodes ⟨577545, by omega⟩ = .linear (.wire 577495) (.wire 577544) false
  node_577546 : g.nodes ⟨577546, by omega⟩ = .linear (.wire 7249) (.wire 577506) true
  node_577547 : g.nodes ⟨577547, by omega⟩ = .product (.wire 560210) (.wire 577546)
  node_577548 : g.nodes ⟨577548, by omega⟩ = .linear (.wire 577506) (.wire 577547) false
  node_577549 : g.nodes ⟨577549, by omega⟩ = .linear (.wire 7250) (.wire 577517) true
  node_577550 : g.nodes ⟨577550, by omega⟩ = .product (.wire 560210) (.wire 577549)
  node_577551 : g.nodes ⟨577551, by omega⟩ = .linear (.wire 577517) (.wire 577550) false
  node_577552 : g.nodes ⟨577552, by omega⟩ = .linear (.wire 577496) (.wire 7244) true
  node_577553 : g.nodes ⟨577553, by omega⟩ = .product (.wire 560210) (.wire 577552)
  node_577554 : g.nodes ⟨577554, by omega⟩ = .linear (.wire 7244) (.wire 577553) false
  node_577555 : g.nodes ⟨577555, by omega⟩ = .linear (.wire 577507) (.wire 7245) true
  node_577556 : g.nodes ⟨577556, by omega⟩ = .product (.wire 560210) (.wire 577555)
  node_577557 : g.nodes ⟨577557, by omega⟩ = .linear (.wire 7245) (.wire 577556) false
  node_577558 : g.nodes ⟨577558, by omega⟩ = .linear (.wire 577518) (.wire 7246) true
  node_577559 : g.nodes ⟨577559, by omega⟩ = .product (.wire 560210) (.wire 577558)
  node_577560 : g.nodes ⟨577560, by omega⟩ = .linear (.wire 7246) (.wire 577559) false
  node_577561 : g.nodes ⟨577561, by omega⟩ = .linear (.wire 577529) (.wire 7247) true
  node_577562 : g.nodes ⟨577562, by omega⟩ = .product (.wire 560210) (.wire 577561)
  node_577563 : g.nodes ⟨577563, by omega⟩ = .linear (.wire 7247) (.wire 577562) false
  node_577564 : g.nodes ⟨577564, by omega⟩ = .linear (.wire 577495) (.wire 7248) true
  node_577565 : g.nodes ⟨577565, by omega⟩ = .product (.wire 560210) (.wire 577564)
  node_577566 : g.nodes ⟨577566, by omega⟩ = .linear (.wire 7248) (.wire 577565) false
  node_577567 : g.nodes ⟨577567, by omega⟩ = .linear (.wire 577506) (.wire 7249) true
  node_577568 : g.nodes ⟨577568, by omega⟩ = .product (.wire 560210) (.wire 577567)
  node_577569 : g.nodes ⟨577569, by omega⟩ = .linear (.wire 7249) (.wire 577568) false
  node_577570 : g.nodes ⟨577570, by omega⟩ = .linear (.wire 577517) (.wire 7250) true
  node_577571 : g.nodes ⟨577571, by omega⟩ = .product (.wire 560210) (.wire 577570)
  node_577572 : g.nodes ⟨577572, by omega⟩ = .linear (.wire 7250) (.wire 577571) false
  node_580005 : g.nodes ⟨580005, by omega⟩ = .linear (.wire 7251) (.wire 579970) true
  node_580006 : g.nodes ⟨580006, by omega⟩ = .product (.wire 560215) (.wire 580005)
  node_580007 : g.nodes ⟨580007, by omega⟩ = .linear (.wire 579970) (.wire 580006) false
  node_580008 : g.nodes ⟨580008, by omega⟩ = .linear (.wire 7252) (.wire 579981) true
  node_580009 : g.nodes ⟨580009, by omega⟩ = .product (.wire 560215) (.wire 580008)
  node_580010 : g.nodes ⟨580010, by omega⟩ = .linear (.wire 579981) (.wire 580009) false
  node_580011 : g.nodes ⟨580011, by omega⟩ = .linear (.wire 7253) (.wire 579992) true
  node_580012 : g.nodes ⟨580012, by omega⟩ = .product (.wire 560215) (.wire 580011)
  node_580013 : g.nodes ⟨580013, by omega⟩ = .linear (.wire 579992) (.wire 580012) false
  node_580014 : g.nodes ⟨580014, by omega⟩ = .linear (.wire 7254) (.wire 580003) true
  node_580015 : g.nodes ⟨580015, by omega⟩ = .product (.wire 560215) (.wire 580014)
  node_580016 : g.nodes ⟨580016, by omega⟩ = .linear (.wire 580003) (.wire 580015) false
  node_580017 : g.nodes ⟨580017, by omega⟩ = .linear (.wire 7255) (.wire 579969) true
  node_580018 : g.nodes ⟨580018, by omega⟩ = .product (.wire 560215) (.wire 580017)
  node_580019 : g.nodes ⟨580019, by omega⟩ = .linear (.wire 579969) (.wire 580018) false
  node_580020 : g.nodes ⟨580020, by omega⟩ = .linear (.wire 7256) (.wire 579980) true
  node_580021 : g.nodes ⟨580021, by omega⟩ = .product (.wire 560215) (.wire 580020)
  node_580022 : g.nodes ⟨580022, by omega⟩ = .linear (.wire 579980) (.wire 580021) false
  node_580023 : g.nodes ⟨580023, by omega⟩ = .linear (.wire 7257) (.wire 579991) true
  node_580024 : g.nodes ⟨580024, by omega⟩ = .product (.wire 560215) (.wire 580023)
  node_580025 : g.nodes ⟨580025, by omega⟩ = .linear (.wire 579991) (.wire 580024) false
  node_580026 : g.nodes ⟨580026, by omega⟩ = .linear (.wire 579970) (.wire 7251) true
  node_580027 : g.nodes ⟨580027, by omega⟩ = .product (.wire 560215) (.wire 580026)
  node_580028 : g.nodes ⟨580028, by omega⟩ = .linear (.wire 7251) (.wire 580027) false
  node_580029 : g.nodes ⟨580029, by omega⟩ = .linear (.wire 579981) (.wire 7252) true
  node_580030 : g.nodes ⟨580030, by omega⟩ = .product (.wire 560215) (.wire 580029)
  node_580031 : g.nodes ⟨580031, by omega⟩ = .linear (.wire 7252) (.wire 580030) false
  node_580032 : g.nodes ⟨580032, by omega⟩ = .linear (.wire 579992) (.wire 7253) true
  node_580033 : g.nodes ⟨580033, by omega⟩ = .product (.wire 560215) (.wire 580032)
  node_580034 : g.nodes ⟨580034, by omega⟩ = .linear (.wire 7253) (.wire 580033) false
  node_580035 : g.nodes ⟨580035, by omega⟩ = .linear (.wire 580003) (.wire 7254) true
  node_580036 : g.nodes ⟨580036, by omega⟩ = .product (.wire 560215) (.wire 580035)
  node_580037 : g.nodes ⟨580037, by omega⟩ = .linear (.wire 7254) (.wire 580036) false
  node_580038 : g.nodes ⟨580038, by omega⟩ = .linear (.wire 579969) (.wire 7255) true
  node_580039 : g.nodes ⟨580039, by omega⟩ = .product (.wire 560215) (.wire 580038)
  node_580040 : g.nodes ⟨580040, by omega⟩ = .linear (.wire 7255) (.wire 580039) false
  node_580041 : g.nodes ⟨580041, by omega⟩ = .linear (.wire 579980) (.wire 7256) true
  node_580042 : g.nodes ⟨580042, by omega⟩ = .product (.wire 560215) (.wire 580041)
  node_580043 : g.nodes ⟨580043, by omega⟩ = .linear (.wire 7256) (.wire 580042) false
  node_580044 : g.nodes ⟨580044, by omega⟩ = .linear (.wire 579991) (.wire 7257) true
  node_580045 : g.nodes ⟨580045, by omega⟩ = .product (.wire 560215) (.wire 580044)
  node_580046 : g.nodes ⟨580046, by omega⟩ = .linear (.wire 7257) (.wire 580045) false
  node_582479 : g.nodes ⟨582479, by omega⟩ = .linear (.wire 7258) (.wire 582444) true
  node_582480 : g.nodes ⟨582480, by omega⟩ = .product (.wire 560220) (.wire 582479)
  node_582481 : g.nodes ⟨582481, by omega⟩ = .linear (.wire 582444) (.wire 582480) false
  node_582482 : g.nodes ⟨582482, by omega⟩ = .linear (.wire 7259) (.wire 582455) true
  node_582483 : g.nodes ⟨582483, by omega⟩ = .product (.wire 560220) (.wire 582482)
  node_582484 : g.nodes ⟨582484, by omega⟩ = .linear (.wire 582455) (.wire 582483) false
  node_582485 : g.nodes ⟨582485, by omega⟩ = .linear (.wire 7260) (.wire 582466) true
  node_582486 : g.nodes ⟨582486, by omega⟩ = .product (.wire 560220) (.wire 582485)
  node_582487 : g.nodes ⟨582487, by omega⟩ = .linear (.wire 582466) (.wire 582486) false
  node_582488 : g.nodes ⟨582488, by omega⟩ = .linear (.wire 7261) (.wire 582477) true
  node_582489 : g.nodes ⟨582489, by omega⟩ = .product (.wire 560220) (.wire 582488)
  node_582490 : g.nodes ⟨582490, by omega⟩ = .linear (.wire 582477) (.wire 582489) false
  node_582491 : g.nodes ⟨582491, by omega⟩ = .linear (.wire 7262) (.wire 582443) true
  node_582492 : g.nodes ⟨582492, by omega⟩ = .product (.wire 560220) (.wire 582491)
  node_582493 : g.nodes ⟨582493, by omega⟩ = .linear (.wire 582443) (.wire 582492) false
  node_582494 : g.nodes ⟨582494, by omega⟩ = .linear (.wire 7263) (.wire 582454) true
  node_582495 : g.nodes ⟨582495, by omega⟩ = .product (.wire 560220) (.wire 582494)
  node_582496 : g.nodes ⟨582496, by omega⟩ = .linear (.wire 582454) (.wire 582495) false
  node_582497 : g.nodes ⟨582497, by omega⟩ = .linear (.wire 7264) (.wire 582465) true
  node_582498 : g.nodes ⟨582498, by omega⟩ = .product (.wire 560220) (.wire 582497)
  node_582499 : g.nodes ⟨582499, by omega⟩ = .linear (.wire 582465) (.wire 582498) false
  node_582500 : g.nodes ⟨582500, by omega⟩ = .linear (.wire 582444) (.wire 7258) true
  node_582501 : g.nodes ⟨582501, by omega⟩ = .product (.wire 560220) (.wire 582500)
  node_582502 : g.nodes ⟨582502, by omega⟩ = .linear (.wire 7258) (.wire 582501) false
  node_582503 : g.nodes ⟨582503, by omega⟩ = .linear (.wire 582455) (.wire 7259) true
  node_582504 : g.nodes ⟨582504, by omega⟩ = .product (.wire 560220) (.wire 582503)
  node_582505 : g.nodes ⟨582505, by omega⟩ = .linear (.wire 7259) (.wire 582504) false
  node_582506 : g.nodes ⟨582506, by omega⟩ = .linear (.wire 582466) (.wire 7260) true
  node_582507 : g.nodes ⟨582507, by omega⟩ = .product (.wire 560220) (.wire 582506)
  node_582508 : g.nodes ⟨582508, by omega⟩ = .linear (.wire 7260) (.wire 582507) false
  node_582509 : g.nodes ⟨582509, by omega⟩ = .linear (.wire 582477) (.wire 7261) true
  node_582510 : g.nodes ⟨582510, by omega⟩ = .product (.wire 560220) (.wire 582509)
  node_582511 : g.nodes ⟨582511, by omega⟩ = .linear (.wire 7261) (.wire 582510) false
  node_582512 : g.nodes ⟨582512, by omega⟩ = .linear (.wire 582443) (.wire 7262) true
  node_582513 : g.nodes ⟨582513, by omega⟩ = .product (.wire 560220) (.wire 582512)
  node_582514 : g.nodes ⟨582514, by omega⟩ = .linear (.wire 7262) (.wire 582513) false
  node_582515 : g.nodes ⟨582515, by omega⟩ = .linear (.wire 582454) (.wire 7263) true
  node_582516 : g.nodes ⟨582516, by omega⟩ = .product (.wire 560220) (.wire 582515)
  node_582517 : g.nodes ⟨582517, by omega⟩ = .linear (.wire 7263) (.wire 582516) false
  node_582518 : g.nodes ⟨582518, by omega⟩ = .linear (.wire 582465) (.wire 7264) true
  node_582519 : g.nodes ⟨582519, by omega⟩ = .product (.wire 560220) (.wire 582518)
  node_582520 : g.nodes ⟨582520, by omega⟩ = .linear (.wire 7264) (.wire 582519) false
  node_584953 : g.nodes ⟨584953, by omega⟩ = .linear (.wire 7265) (.wire 584918) true
  node_584954 : g.nodes ⟨584954, by omega⟩ = .product (.wire 560225) (.wire 584953)
  node_584955 : g.nodes ⟨584955, by omega⟩ = .linear (.wire 584918) (.wire 584954) false
  node_584956 : g.nodes ⟨584956, by omega⟩ = .linear (.wire 7266) (.wire 584929) true
  node_584957 : g.nodes ⟨584957, by omega⟩ = .product (.wire 560225) (.wire 584956)
  node_584958 : g.nodes ⟨584958, by omega⟩ = .linear (.wire 584929) (.wire 584957) false
  node_584959 : g.nodes ⟨584959, by omega⟩ = .linear (.wire 7267) (.wire 584940) true
  node_584960 : g.nodes ⟨584960, by omega⟩ = .product (.wire 560225) (.wire 584959)
  node_584961 : g.nodes ⟨584961, by omega⟩ = .linear (.wire 584940) (.wire 584960) false
  node_584962 : g.nodes ⟨584962, by omega⟩ = .linear (.wire 7268) (.wire 584951) true
  node_584963 : g.nodes ⟨584963, by omega⟩ = .product (.wire 560225) (.wire 584962)
  node_584964 : g.nodes ⟨584964, by omega⟩ = .linear (.wire 584951) (.wire 584963) false
  node_584965 : g.nodes ⟨584965, by omega⟩ = .linear (.wire 7269) (.wire 584917) true
  node_584966 : g.nodes ⟨584966, by omega⟩ = .product (.wire 560225) (.wire 584965)
  node_584967 : g.nodes ⟨584967, by omega⟩ = .linear (.wire 584917) (.wire 584966) false
  node_584968 : g.nodes ⟨584968, by omega⟩ = .linear (.wire 7270) (.wire 584928) true
  node_584969 : g.nodes ⟨584969, by omega⟩ = .product (.wire 560225) (.wire 584968)
  node_584970 : g.nodes ⟨584970, by omega⟩ = .linear (.wire 584928) (.wire 584969) false
  node_584971 : g.nodes ⟨584971, by omega⟩ = .linear (.wire 7271) (.wire 584939) true
  node_584972 : g.nodes ⟨584972, by omega⟩ = .product (.wire 560225) (.wire 584971)
  node_584973 : g.nodes ⟨584973, by omega⟩ = .linear (.wire 584939) (.wire 584972) false
  node_584974 : g.nodes ⟨584974, by omega⟩ = .linear (.wire 584918) (.wire 7265) true
  node_584975 : g.nodes ⟨584975, by omega⟩ = .product (.wire 560225) (.wire 584974)
  node_584976 : g.nodes ⟨584976, by omega⟩ = .linear (.wire 7265) (.wire 584975) false
  node_584977 : g.nodes ⟨584977, by omega⟩ = .linear (.wire 584929) (.wire 7266) true
  node_584978 : g.nodes ⟨584978, by omega⟩ = .product (.wire 560225) (.wire 584977)
  node_584979 : g.nodes ⟨584979, by omega⟩ = .linear (.wire 7266) (.wire 584978) false
  node_584980 : g.nodes ⟨584980, by omega⟩ = .linear (.wire 584940) (.wire 7267) true
  node_584981 : g.nodes ⟨584981, by omega⟩ = .product (.wire 560225) (.wire 584980)
  node_584982 : g.nodes ⟨584982, by omega⟩ = .linear (.wire 7267) (.wire 584981) false
  node_584983 : g.nodes ⟨584983, by omega⟩ = .linear (.wire 584951) (.wire 7268) true
  node_584984 : g.nodes ⟨584984, by omega⟩ = .product (.wire 560225) (.wire 584983)
  node_584985 : g.nodes ⟨584985, by omega⟩ = .linear (.wire 7268) (.wire 584984) false
  node_584986 : g.nodes ⟨584986, by omega⟩ = .linear (.wire 584917) (.wire 7269) true
  node_584987 : g.nodes ⟨584987, by omega⟩ = .product (.wire 560225) (.wire 584986)
  node_584988 : g.nodes ⟨584988, by omega⟩ = .linear (.wire 7269) (.wire 584987) false
  node_584989 : g.nodes ⟨584989, by omega⟩ = .linear (.wire 584928) (.wire 7270) true
  node_584990 : g.nodes ⟨584990, by omega⟩ = .product (.wire 560225) (.wire 584989)
  node_584991 : g.nodes ⟨584991, by omega⟩ = .linear (.wire 7270) (.wire 584990) false
  node_584992 : g.nodes ⟨584992, by omega⟩ = .linear (.wire 584939) (.wire 7271) true
  node_584993 : g.nodes ⟨584993, by omega⟩ = .product (.wire 560225) (.wire 584992)
  node_584994 : g.nodes ⟨584994, by omega⟩ = .linear (.wire 7271) (.wire 584993) false
  node_587427 : g.nodes ⟨587427, by omega⟩ = .linear (.wire 7272) (.wire 587392) true
  node_587428 : g.nodes ⟨587428, by omega⟩ = .product (.wire 560230) (.wire 587427)
  node_587429 : g.nodes ⟨587429, by omega⟩ = .linear (.wire 587392) (.wire 587428) false
  node_587430 : g.nodes ⟨587430, by omega⟩ = .linear (.wire 7273) (.wire 587403) true
  node_587431 : g.nodes ⟨587431, by omega⟩ = .product (.wire 560230) (.wire 587430)
  node_587432 : g.nodes ⟨587432, by omega⟩ = .linear (.wire 587403) (.wire 587431) false
  node_587433 : g.nodes ⟨587433, by omega⟩ = .linear (.wire 7274) (.wire 587414) true
  node_587434 : g.nodes ⟨587434, by omega⟩ = .product (.wire 560230) (.wire 587433)
  node_587435 : g.nodes ⟨587435, by omega⟩ = .linear (.wire 587414) (.wire 587434) false
  node_587436 : g.nodes ⟨587436, by omega⟩ = .linear (.wire 7275) (.wire 587425) true
  node_587437 : g.nodes ⟨587437, by omega⟩ = .product (.wire 560230) (.wire 587436)
  node_587438 : g.nodes ⟨587438, by omega⟩ = .linear (.wire 587425) (.wire 587437) false
  node_587439 : g.nodes ⟨587439, by omega⟩ = .linear (.wire 7276) (.wire 587391) true
  node_587440 : g.nodes ⟨587440, by omega⟩ = .product (.wire 560230) (.wire 587439)
  node_587441 : g.nodes ⟨587441, by omega⟩ = .linear (.wire 587391) (.wire 587440) false
  node_587442 : g.nodes ⟨587442, by omega⟩ = .linear (.wire 7277) (.wire 587402) true
  node_587443 : g.nodes ⟨587443, by omega⟩ = .product (.wire 560230) (.wire 587442)
  node_587444 : g.nodes ⟨587444, by omega⟩ = .linear (.wire 587402) (.wire 587443) false
  node_587445 : g.nodes ⟨587445, by omega⟩ = .linear (.wire 7278) (.wire 587413) true
  node_587446 : g.nodes ⟨587446, by omega⟩ = .product (.wire 560230) (.wire 587445)
  node_587447 : g.nodes ⟨587447, by omega⟩ = .linear (.wire 587413) (.wire 587446) false
  node_587448 : g.nodes ⟨587448, by omega⟩ = .linear (.wire 587392) (.wire 7272) true
  node_587449 : g.nodes ⟨587449, by omega⟩ = .product (.wire 560230) (.wire 587448)
  node_587450 : g.nodes ⟨587450, by omega⟩ = .linear (.wire 7272) (.wire 587449) false
  node_587451 : g.nodes ⟨587451, by omega⟩ = .linear (.wire 587403) (.wire 7273) true
  node_587452 : g.nodes ⟨587452, by omega⟩ = .product (.wire 560230) (.wire 587451)
  node_587453 : g.nodes ⟨587453, by omega⟩ = .linear (.wire 7273) (.wire 587452) false
  node_587454 : g.nodes ⟨587454, by omega⟩ = .linear (.wire 587414) (.wire 7274) true
  node_587455 : g.nodes ⟨587455, by omega⟩ = .product (.wire 560230) (.wire 587454)
  node_587456 : g.nodes ⟨587456, by omega⟩ = .linear (.wire 7274) (.wire 587455) false
  node_587457 : g.nodes ⟨587457, by omega⟩ = .linear (.wire 587425) (.wire 7275) true
  node_587458 : g.nodes ⟨587458, by omega⟩ = .product (.wire 560230) (.wire 587457)
  node_587459 : g.nodes ⟨587459, by omega⟩ = .linear (.wire 7275) (.wire 587458) false
  node_587460 : g.nodes ⟨587460, by omega⟩ = .linear (.wire 587391) (.wire 7276) true
  node_587461 : g.nodes ⟨587461, by omega⟩ = .product (.wire 560230) (.wire 587460)
  node_587462 : g.nodes ⟨587462, by omega⟩ = .linear (.wire 7276) (.wire 587461) false
  node_587463 : g.nodes ⟨587463, by omega⟩ = .linear (.wire 587402) (.wire 7277) true
  node_587464 : g.nodes ⟨587464, by omega⟩ = .product (.wire 560230) (.wire 587463)
  node_587465 : g.nodes ⟨587465, by omega⟩ = .linear (.wire 7277) (.wire 587464) false
  node_587466 : g.nodes ⟨587466, by omega⟩ = .linear (.wire 587413) (.wire 7278) true
  node_587467 : g.nodes ⟨587467, by omega⟩ = .product (.wire 560230) (.wire 587466)
  node_587468 : g.nodes ⟨587468, by omega⟩ = .linear (.wire 7278) (.wire 587467) false
  node_589901 : g.nodes ⟨589901, by omega⟩ = .linear (.wire 7279) (.wire 589866) true
  node_589902 : g.nodes ⟨589902, by omega⟩ = .product (.wire 560235) (.wire 589901)
  node_589903 : g.nodes ⟨589903, by omega⟩ = .linear (.wire 589866) (.wire 589902) false
  node_589904 : g.nodes ⟨589904, by omega⟩ = .linear (.wire 7280) (.wire 589877) true
  node_589905 : g.nodes ⟨589905, by omega⟩ = .product (.wire 560235) (.wire 589904)
  node_589906 : g.nodes ⟨589906, by omega⟩ = .linear (.wire 589877) (.wire 589905) false
  node_589907 : g.nodes ⟨589907, by omega⟩ = .linear (.wire 7281) (.wire 589888) true
  node_589908 : g.nodes ⟨589908, by omega⟩ = .product (.wire 560235) (.wire 589907)
  node_589909 : g.nodes ⟨589909, by omega⟩ = .linear (.wire 589888) (.wire 589908) false
  node_589910 : g.nodes ⟨589910, by omega⟩ = .linear (.wire 7282) (.wire 589899) true
  node_589911 : g.nodes ⟨589911, by omega⟩ = .product (.wire 560235) (.wire 589910)
  node_589912 : g.nodes ⟨589912, by omega⟩ = .linear (.wire 589899) (.wire 589911) false
  node_589913 : g.nodes ⟨589913, by omega⟩ = .linear (.wire 7283) (.wire 589865) true
  node_589914 : g.nodes ⟨589914, by omega⟩ = .product (.wire 560235) (.wire 589913)
  node_589915 : g.nodes ⟨589915, by omega⟩ = .linear (.wire 589865) (.wire 589914) false
  node_589916 : g.nodes ⟨589916, by omega⟩ = .linear (.wire 7284) (.wire 589876) true
  node_589917 : g.nodes ⟨589917, by omega⟩ = .product (.wire 560235) (.wire 589916)
  node_589918 : g.nodes ⟨589918, by omega⟩ = .linear (.wire 589876) (.wire 589917) false
  node_589919 : g.nodes ⟨589919, by omega⟩ = .linear (.wire 7285) (.wire 589887) true
  node_589920 : g.nodes ⟨589920, by omega⟩ = .product (.wire 560235) (.wire 589919)
  node_589921 : g.nodes ⟨589921, by omega⟩ = .linear (.wire 589887) (.wire 589920) false
  node_589922 : g.nodes ⟨589922, by omega⟩ = .linear (.wire 589866) (.wire 7279) true
  node_589923 : g.nodes ⟨589923, by omega⟩ = .product (.wire 560235) (.wire 589922)
  node_589924 : g.nodes ⟨589924, by omega⟩ = .linear (.wire 7279) (.wire 589923) false
  node_589925 : g.nodes ⟨589925, by omega⟩ = .linear (.wire 589877) (.wire 7280) true
  node_589926 : g.nodes ⟨589926, by omega⟩ = .product (.wire 560235) (.wire 589925)
  node_589927 : g.nodes ⟨589927, by omega⟩ = .linear (.wire 7280) (.wire 589926) false
  node_589928 : g.nodes ⟨589928, by omega⟩ = .linear (.wire 589888) (.wire 7281) true
  node_589929 : g.nodes ⟨589929, by omega⟩ = .product (.wire 560235) (.wire 589928)
  node_589930 : g.nodes ⟨589930, by omega⟩ = .linear (.wire 7281) (.wire 589929) false
  node_589931 : g.nodes ⟨589931, by omega⟩ = .linear (.wire 589899) (.wire 7282) true
  node_589932 : g.nodes ⟨589932, by omega⟩ = .product (.wire 560235) (.wire 589931)
  node_589933 : g.nodes ⟨589933, by omega⟩ = .linear (.wire 7282) (.wire 589932) false
  node_589934 : g.nodes ⟨589934, by omega⟩ = .linear (.wire 589865) (.wire 7283) true
  node_589935 : g.nodes ⟨589935, by omega⟩ = .product (.wire 560235) (.wire 589934)
  node_589936 : g.nodes ⟨589936, by omega⟩ = .linear (.wire 7283) (.wire 589935) false
  node_589937 : g.nodes ⟨589937, by omega⟩ = .linear (.wire 589876) (.wire 7284) true
  node_589938 : g.nodes ⟨589938, by omega⟩ = .product (.wire 560235) (.wire 589937)
  node_589939 : g.nodes ⟨589939, by omega⟩ = .linear (.wire 7284) (.wire 589938) false
  node_589940 : g.nodes ⟨589940, by omega⟩ = .linear (.wire 589887) (.wire 7285) true
  node_589941 : g.nodes ⟨589941, by omega⟩ = .product (.wire 560235) (.wire 589940)
  node_589942 : g.nodes ⟨589942, by omega⟩ = .linear (.wire 7285) (.wire 589941) false
  node_592375 : g.nodes ⟨592375, by omega⟩ = .linear (.wire 7286) (.wire 592340) true
  node_592376 : g.nodes ⟨592376, by omega⟩ = .product (.wire 560240) (.wire 592375)
  node_592377 : g.nodes ⟨592377, by omega⟩ = .linear (.wire 592340) (.wire 592376) false
  node_592378 : g.nodes ⟨592378, by omega⟩ = .linear (.wire 7287) (.wire 592351) true
  node_592379 : g.nodes ⟨592379, by omega⟩ = .product (.wire 560240) (.wire 592378)
  node_592380 : g.nodes ⟨592380, by omega⟩ = .linear (.wire 592351) (.wire 592379) false
  node_592381 : g.nodes ⟨592381, by omega⟩ = .linear (.wire 7288) (.wire 592362) true
  node_592382 : g.nodes ⟨592382, by omega⟩ = .product (.wire 560240) (.wire 592381)
  node_592383 : g.nodes ⟨592383, by omega⟩ = .linear (.wire 592362) (.wire 592382) false
  node_592384 : g.nodes ⟨592384, by omega⟩ = .linear (.wire 7289) (.wire 592373) true
  node_592385 : g.nodes ⟨592385, by omega⟩ = .product (.wire 560240) (.wire 592384)
  node_592386 : g.nodes ⟨592386, by omega⟩ = .linear (.wire 592373) (.wire 592385) false
  node_592387 : g.nodes ⟨592387, by omega⟩ = .linear (.wire 7290) (.wire 592339) true
  node_592388 : g.nodes ⟨592388, by omega⟩ = .product (.wire 560240) (.wire 592387)
  node_592389 : g.nodes ⟨592389, by omega⟩ = .linear (.wire 592339) (.wire 592388) false
  node_592390 : g.nodes ⟨592390, by omega⟩ = .linear (.wire 7291) (.wire 592350) true
  node_592391 : g.nodes ⟨592391, by omega⟩ = .product (.wire 560240) (.wire 592390)
  node_592392 : g.nodes ⟨592392, by omega⟩ = .linear (.wire 592350) (.wire 592391) false
  node_592393 : g.nodes ⟨592393, by omega⟩ = .linear (.wire 7292) (.wire 592361) true
  node_592394 : g.nodes ⟨592394, by omega⟩ = .product (.wire 560240) (.wire 592393)
  node_592395 : g.nodes ⟨592395, by omega⟩ = .linear (.wire 592361) (.wire 592394) false
  node_592396 : g.nodes ⟨592396, by omega⟩ = .linear (.wire 592340) (.wire 7286) true
  node_592397 : g.nodes ⟨592397, by omega⟩ = .product (.wire 560240) (.wire 592396)
  node_592398 : g.nodes ⟨592398, by omega⟩ = .linear (.wire 7286) (.wire 592397) false
  node_592399 : g.nodes ⟨592399, by omega⟩ = .linear (.wire 592351) (.wire 7287) true
  node_592400 : g.nodes ⟨592400, by omega⟩ = .product (.wire 560240) (.wire 592399)
  node_592401 : g.nodes ⟨592401, by omega⟩ = .linear (.wire 7287) (.wire 592400) false
  node_592402 : g.nodes ⟨592402, by omega⟩ = .linear (.wire 592362) (.wire 7288) true
  node_592403 : g.nodes ⟨592403, by omega⟩ = .product (.wire 560240) (.wire 592402)
  node_592404 : g.nodes ⟨592404, by omega⟩ = .linear (.wire 7288) (.wire 592403) false
  node_592405 : g.nodes ⟨592405, by omega⟩ = .linear (.wire 592373) (.wire 7289) true
  node_592406 : g.nodes ⟨592406, by omega⟩ = .product (.wire 560240) (.wire 592405)
  node_592407 : g.nodes ⟨592407, by omega⟩ = .linear (.wire 7289) (.wire 592406) false
  node_592408 : g.nodes ⟨592408, by omega⟩ = .linear (.wire 592339) (.wire 7290) true
  node_592409 : g.nodes ⟨592409, by omega⟩ = .product (.wire 560240) (.wire 592408)
  node_592410 : g.nodes ⟨592410, by omega⟩ = .linear (.wire 7290) (.wire 592409) false
  node_592411 : g.nodes ⟨592411, by omega⟩ = .linear (.wire 592350) (.wire 7291) true
  node_592412 : g.nodes ⟨592412, by omega⟩ = .product (.wire 560240) (.wire 592411)
  node_592413 : g.nodes ⟨592413, by omega⟩ = .linear (.wire 7291) (.wire 592412) false
  node_592414 : g.nodes ⟨592414, by omega⟩ = .linear (.wire 592361) (.wire 7292) true
  node_592415 : g.nodes ⟨592415, by omega⟩ = .product (.wire 560240) (.wire 592414)
  node_592416 : g.nodes ⟨592416, by omega⟩ = .linear (.wire 7292) (.wire 592415) false
  node_594849 : g.nodes ⟨594849, by omega⟩ = .linear (.wire 7293) (.wire 594814) true
  node_594850 : g.nodes ⟨594850, by omega⟩ = .product (.wire 560245) (.wire 594849)
  node_594851 : g.nodes ⟨594851, by omega⟩ = .linear (.wire 594814) (.wire 594850) false
  node_594852 : g.nodes ⟨594852, by omega⟩ = .linear (.wire 7294) (.wire 594825) true
  node_594853 : g.nodes ⟨594853, by omega⟩ = .product (.wire 560245) (.wire 594852)
  node_594854 : g.nodes ⟨594854, by omega⟩ = .linear (.wire 594825) (.wire 594853) false
  node_594855 : g.nodes ⟨594855, by omega⟩ = .linear (.wire 7295) (.wire 594836) true
  node_594856 : g.nodes ⟨594856, by omega⟩ = .product (.wire 560245) (.wire 594855)
  node_594857 : g.nodes ⟨594857, by omega⟩ = .linear (.wire 594836) (.wire 594856) false
  node_594858 : g.nodes ⟨594858, by omega⟩ = .linear (.wire 7296) (.wire 594847) true
  node_594859 : g.nodes ⟨594859, by omega⟩ = .product (.wire 560245) (.wire 594858)
  node_594860 : g.nodes ⟨594860, by omega⟩ = .linear (.wire 594847) (.wire 594859) false
  node_594861 : g.nodes ⟨594861, by omega⟩ = .linear (.wire 7297) (.wire 594813) true
  node_594862 : g.nodes ⟨594862, by omega⟩ = .product (.wire 560245) (.wire 594861)
  node_594863 : g.nodes ⟨594863, by omega⟩ = .linear (.wire 594813) (.wire 594862) false
  node_594864 : g.nodes ⟨594864, by omega⟩ = .linear (.wire 7298) (.wire 594824) true
  node_594865 : g.nodes ⟨594865, by omega⟩ = .product (.wire 560245) (.wire 594864)
  node_594866 : g.nodes ⟨594866, by omega⟩ = .linear (.wire 594824) (.wire 594865) false
  node_594867 : g.nodes ⟨594867, by omega⟩ = .linear (.wire 7299) (.wire 594835) true
  node_594868 : g.nodes ⟨594868, by omega⟩ = .product (.wire 560245) (.wire 594867)
  node_594869 : g.nodes ⟨594869, by omega⟩ = .linear (.wire 594835) (.wire 594868) false
  node_594870 : g.nodes ⟨594870, by omega⟩ = .linear (.wire 594814) (.wire 7293) true
  node_594871 : g.nodes ⟨594871, by omega⟩ = .product (.wire 560245) (.wire 594870)
  node_594872 : g.nodes ⟨594872, by omega⟩ = .linear (.wire 7293) (.wire 594871) false
  node_594873 : g.nodes ⟨594873, by omega⟩ = .linear (.wire 594825) (.wire 7294) true
  node_594874 : g.nodes ⟨594874, by omega⟩ = .product (.wire 560245) (.wire 594873)
  node_594875 : g.nodes ⟨594875, by omega⟩ = .linear (.wire 7294) (.wire 594874) false
  node_594876 : g.nodes ⟨594876, by omega⟩ = .linear (.wire 594836) (.wire 7295) true
  node_594877 : g.nodes ⟨594877, by omega⟩ = .product (.wire 560245) (.wire 594876)
  node_594878 : g.nodes ⟨594878, by omega⟩ = .linear (.wire 7295) (.wire 594877) false
  node_594879 : g.nodes ⟨594879, by omega⟩ = .linear (.wire 594847) (.wire 7296) true
  node_594880 : g.nodes ⟨594880, by omega⟩ = .product (.wire 560245) (.wire 594879)
  node_594881 : g.nodes ⟨594881, by omega⟩ = .linear (.wire 7296) (.wire 594880) false
  node_594882 : g.nodes ⟨594882, by omega⟩ = .linear (.wire 594813) (.wire 7297) true
  node_594883 : g.nodes ⟨594883, by omega⟩ = .product (.wire 560245) (.wire 594882)
  node_594884 : g.nodes ⟨594884, by omega⟩ = .linear (.wire 7297) (.wire 594883) false
  node_594885 : g.nodes ⟨594885, by omega⟩ = .linear (.wire 594824) (.wire 7298) true
  node_594886 : g.nodes ⟨594886, by omega⟩ = .product (.wire 560245) (.wire 594885)
  node_594887 : g.nodes ⟨594887, by omega⟩ = .linear (.wire 7298) (.wire 594886) false
  node_594888 : g.nodes ⟨594888, by omega⟩ = .linear (.wire 594835) (.wire 7299) true
  node_594889 : g.nodes ⟨594889, by omega⟩ = .product (.wire 560245) (.wire 594888)
  node_594890 : g.nodes ⟨594890, by omega⟩ = .linear (.wire 7299) (.wire 594889) false
  node_597323 : g.nodes ⟨597323, by omega⟩ = .linear (.wire 7300) (.wire 597288) true
  node_597324 : g.nodes ⟨597324, by omega⟩ = .product (.wire 560250) (.wire 597323)
  node_597325 : g.nodes ⟨597325, by omega⟩ = .linear (.wire 597288) (.wire 597324) false
  node_597326 : g.nodes ⟨597326, by omega⟩ = .linear (.wire 7301) (.wire 597299) true
  node_597327 : g.nodes ⟨597327, by omega⟩ = .product (.wire 560250) (.wire 597326)
  node_597328 : g.nodes ⟨597328, by omega⟩ = .linear (.wire 597299) (.wire 597327) false
  node_597329 : g.nodes ⟨597329, by omega⟩ = .linear (.wire 7302) (.wire 597310) true
  node_597330 : g.nodes ⟨597330, by omega⟩ = .product (.wire 560250) (.wire 597329)
  node_597331 : g.nodes ⟨597331, by omega⟩ = .linear (.wire 597310) (.wire 597330) false
  node_597332 : g.nodes ⟨597332, by omega⟩ = .linear (.wire 7303) (.wire 597321) true
  node_597333 : g.nodes ⟨597333, by omega⟩ = .product (.wire 560250) (.wire 597332)
  node_597334 : g.nodes ⟨597334, by omega⟩ = .linear (.wire 597321) (.wire 597333) false
  node_597335 : g.nodes ⟨597335, by omega⟩ = .linear (.wire 7304) (.wire 597287) true
  node_597336 : g.nodes ⟨597336, by omega⟩ = .product (.wire 560250) (.wire 597335)
  node_597337 : g.nodes ⟨597337, by omega⟩ = .linear (.wire 597287) (.wire 597336) false
  node_597338 : g.nodes ⟨597338, by omega⟩ = .linear (.wire 7305) (.wire 597298) true
  node_597339 : g.nodes ⟨597339, by omega⟩ = .product (.wire 560250) (.wire 597338)
  node_597340 : g.nodes ⟨597340, by omega⟩ = .linear (.wire 597298) (.wire 597339) false
  node_597341 : g.nodes ⟨597341, by omega⟩ = .linear (.wire 7306) (.wire 597309) true
  node_597342 : g.nodes ⟨597342, by omega⟩ = .product (.wire 560250) (.wire 597341)
  node_597343 : g.nodes ⟨597343, by omega⟩ = .linear (.wire 597309) (.wire 597342) false
  node_597344 : g.nodes ⟨597344, by omega⟩ = .linear (.wire 597288) (.wire 7300) true
  node_597345 : g.nodes ⟨597345, by omega⟩ = .product (.wire 560250) (.wire 597344)
  node_597346 : g.nodes ⟨597346, by omega⟩ = .linear (.wire 7300) (.wire 597345) false
  node_597347 : g.nodes ⟨597347, by omega⟩ = .linear (.wire 597299) (.wire 7301) true
  node_597348 : g.nodes ⟨597348, by omega⟩ = .product (.wire 560250) (.wire 597347)
  node_597349 : g.nodes ⟨597349, by omega⟩ = .linear (.wire 7301) (.wire 597348) false
  node_597350 : g.nodes ⟨597350, by omega⟩ = .linear (.wire 597310) (.wire 7302) true
  node_597351 : g.nodes ⟨597351, by omega⟩ = .product (.wire 560250) (.wire 597350)
  node_597352 : g.nodes ⟨597352, by omega⟩ = .linear (.wire 7302) (.wire 597351) false
  node_597353 : g.nodes ⟨597353, by omega⟩ = .linear (.wire 597321) (.wire 7303) true
  node_597354 : g.nodes ⟨597354, by omega⟩ = .product (.wire 560250) (.wire 597353)
  node_597355 : g.nodes ⟨597355, by omega⟩ = .linear (.wire 7303) (.wire 597354) false
  node_597356 : g.nodes ⟨597356, by omega⟩ = .linear (.wire 597287) (.wire 7304) true
  node_597357 : g.nodes ⟨597357, by omega⟩ = .product (.wire 560250) (.wire 597356)
  node_597358 : g.nodes ⟨597358, by omega⟩ = .linear (.wire 7304) (.wire 597357) false
  node_597359 : g.nodes ⟨597359, by omega⟩ = .linear (.wire 597298) (.wire 7305) true
  node_597360 : g.nodes ⟨597360, by omega⟩ = .product (.wire 560250) (.wire 597359)
  node_597361 : g.nodes ⟨597361, by omega⟩ = .linear (.wire 7305) (.wire 597360) false
  node_597362 : g.nodes ⟨597362, by omega⟩ = .linear (.wire 597309) (.wire 7306) true
  node_597363 : g.nodes ⟨597363, by omega⟩ = .product (.wire 560250) (.wire 597362)
  node_597364 : g.nodes ⟨597364, by omega⟩ = .linear (.wire 7306) (.wire 597363) false
  node_599797 : g.nodes ⟨599797, by omega⟩ = .linear (.wire 7307) (.wire 599762) true
  node_599798 : g.nodes ⟨599798, by omega⟩ = .product (.wire 560255) (.wire 599797)
  node_599799 : g.nodes ⟨599799, by omega⟩ = .linear (.wire 599762) (.wire 599798) false
  node_599800 : g.nodes ⟨599800, by omega⟩ = .linear (.wire 7308) (.wire 599773) true
  node_599801 : g.nodes ⟨599801, by omega⟩ = .product (.wire 560255) (.wire 599800)
  node_599802 : g.nodes ⟨599802, by omega⟩ = .linear (.wire 599773) (.wire 599801) false
  node_599803 : g.nodes ⟨599803, by omega⟩ = .linear (.wire 7309) (.wire 599784) true
  node_599804 : g.nodes ⟨599804, by omega⟩ = .product (.wire 560255) (.wire 599803)
  node_599805 : g.nodes ⟨599805, by omega⟩ = .linear (.wire 599784) (.wire 599804) false
  node_599806 : g.nodes ⟨599806, by omega⟩ = .linear (.wire 7310) (.wire 599795) true
  node_599807 : g.nodes ⟨599807, by omega⟩ = .product (.wire 560255) (.wire 599806)
  node_599808 : g.nodes ⟨599808, by omega⟩ = .linear (.wire 599795) (.wire 599807) false
  node_599809 : g.nodes ⟨599809, by omega⟩ = .linear (.wire 7311) (.wire 599761) true
  node_599810 : g.nodes ⟨599810, by omega⟩ = .product (.wire 560255) (.wire 599809)
  node_599811 : g.nodes ⟨599811, by omega⟩ = .linear (.wire 599761) (.wire 599810) false
  node_599812 : g.nodes ⟨599812, by omega⟩ = .linear (.wire 7312) (.wire 599772) true
  node_599813 : g.nodes ⟨599813, by omega⟩ = .product (.wire 560255) (.wire 599812)
  node_599814 : g.nodes ⟨599814, by omega⟩ = .linear (.wire 599772) (.wire 599813) false
  node_599815 : g.nodes ⟨599815, by omega⟩ = .linear (.wire 7313) (.wire 599783) true
  node_599816 : g.nodes ⟨599816, by omega⟩ = .product (.wire 560255) (.wire 599815)
  node_599817 : g.nodes ⟨599817, by omega⟩ = .linear (.wire 599783) (.wire 599816) false
  node_599818 : g.nodes ⟨599818, by omega⟩ = .linear (.wire 599762) (.wire 7307) true
  node_599819 : g.nodes ⟨599819, by omega⟩ = .product (.wire 560255) (.wire 599818)
  node_599820 : g.nodes ⟨599820, by omega⟩ = .linear (.wire 7307) (.wire 599819) false
  node_599821 : g.nodes ⟨599821, by omega⟩ = .linear (.wire 599773) (.wire 7308) true
  node_599822 : g.nodes ⟨599822, by omega⟩ = .product (.wire 560255) (.wire 599821)
  node_599823 : g.nodes ⟨599823, by omega⟩ = .linear (.wire 7308) (.wire 599822) false
  node_599824 : g.nodes ⟨599824, by omega⟩ = .linear (.wire 599784) (.wire 7309) true
  node_599825 : g.nodes ⟨599825, by omega⟩ = .product (.wire 560255) (.wire 599824)
  node_599826 : g.nodes ⟨599826, by omega⟩ = .linear (.wire 7309) (.wire 599825) false
  node_599827 : g.nodes ⟨599827, by omega⟩ = .linear (.wire 599795) (.wire 7310) true
  node_599828 : g.nodes ⟨599828, by omega⟩ = .product (.wire 560255) (.wire 599827)
  node_599829 : g.nodes ⟨599829, by omega⟩ = .linear (.wire 7310) (.wire 599828) false
  node_599830 : g.nodes ⟨599830, by omega⟩ = .linear (.wire 599761) (.wire 7311) true
  node_599831 : g.nodes ⟨599831, by omega⟩ = .product (.wire 560255) (.wire 599830)
  node_599832 : g.nodes ⟨599832, by omega⟩ = .linear (.wire 7311) (.wire 599831) false
  node_599833 : g.nodes ⟨599833, by omega⟩ = .linear (.wire 599772) (.wire 7312) true
  node_599834 : g.nodes ⟨599834, by omega⟩ = .product (.wire 560255) (.wire 599833)
  node_599835 : g.nodes ⟨599835, by omega⟩ = .linear (.wire 7312) (.wire 599834) false
  node_599836 : g.nodes ⟨599836, by omega⟩ = .linear (.wire 599783) (.wire 7313) true
  node_599837 : g.nodes ⟨599837, by omega⟩ = .product (.wire 560255) (.wire 599836)
  node_599838 : g.nodes ⟨599838, by omega⟩ = .linear (.wire 7313) (.wire 599837) false
  node_602271 : g.nodes ⟨602271, by omega⟩ = .linear (.wire 7314) (.wire 602236) true
  node_602272 : g.nodes ⟨602272, by omega⟩ = .product (.wire 560260) (.wire 602271)
  node_602273 : g.nodes ⟨602273, by omega⟩ = .linear (.wire 602236) (.wire 602272) false
  node_602274 : g.nodes ⟨602274, by omega⟩ = .linear (.wire 7315) (.wire 602247) true
  node_602275 : g.nodes ⟨602275, by omega⟩ = .product (.wire 560260) (.wire 602274)
  node_602276 : g.nodes ⟨602276, by omega⟩ = .linear (.wire 602247) (.wire 602275) false
  node_602277 : g.nodes ⟨602277, by omega⟩ = .linear (.wire 7316) (.wire 602258) true
  node_602278 : g.nodes ⟨602278, by omega⟩ = .product (.wire 560260) (.wire 602277)
  node_602279 : g.nodes ⟨602279, by omega⟩ = .linear (.wire 602258) (.wire 602278) false
  node_602280 : g.nodes ⟨602280, by omega⟩ = .linear (.wire 7317) (.wire 602269) true
  node_602281 : g.nodes ⟨602281, by omega⟩ = .product (.wire 560260) (.wire 602280)
  node_602282 : g.nodes ⟨602282, by omega⟩ = .linear (.wire 602269) (.wire 602281) false
  node_602283 : g.nodes ⟨602283, by omega⟩ = .linear (.wire 7318) (.wire 602235) true
  node_602284 : g.nodes ⟨602284, by omega⟩ = .product (.wire 560260) (.wire 602283)
  node_602285 : g.nodes ⟨602285, by omega⟩ = .linear (.wire 602235) (.wire 602284) false
  node_602286 : g.nodes ⟨602286, by omega⟩ = .linear (.wire 7319) (.wire 602246) true
  node_602287 : g.nodes ⟨602287, by omega⟩ = .product (.wire 560260) (.wire 602286)
  node_602288 : g.nodes ⟨602288, by omega⟩ = .linear (.wire 602246) (.wire 602287) false
  node_602289 : g.nodes ⟨602289, by omega⟩ = .linear (.wire 7320) (.wire 602257) true
  node_602290 : g.nodes ⟨602290, by omega⟩ = .product (.wire 560260) (.wire 602289)
  node_602291 : g.nodes ⟨602291, by omega⟩ = .linear (.wire 602257) (.wire 602290) false
  node_602292 : g.nodes ⟨602292, by omega⟩ = .linear (.wire 602236) (.wire 7314) true
  node_602293 : g.nodes ⟨602293, by omega⟩ = .product (.wire 560260) (.wire 602292)
  node_602294 : g.nodes ⟨602294, by omega⟩ = .linear (.wire 7314) (.wire 602293) false
  node_602295 : g.nodes ⟨602295, by omega⟩ = .linear (.wire 602247) (.wire 7315) true
  node_602296 : g.nodes ⟨602296, by omega⟩ = .product (.wire 560260) (.wire 602295)
  node_602297 : g.nodes ⟨602297, by omega⟩ = .linear (.wire 7315) (.wire 602296) false
  node_602298 : g.nodes ⟨602298, by omega⟩ = .linear (.wire 602258) (.wire 7316) true
  node_602299 : g.nodes ⟨602299, by omega⟩ = .product (.wire 560260) (.wire 602298)
  node_602300 : g.nodes ⟨602300, by omega⟩ = .linear (.wire 7316) (.wire 602299) false
  node_602301 : g.nodes ⟨602301, by omega⟩ = .linear (.wire 602269) (.wire 7317) true
  node_602302 : g.nodes ⟨602302, by omega⟩ = .product (.wire 560260) (.wire 602301)
  node_602303 : g.nodes ⟨602303, by omega⟩ = .linear (.wire 7317) (.wire 602302) false
  node_602304 : g.nodes ⟨602304, by omega⟩ = .linear (.wire 602235) (.wire 7318) true
  node_602305 : g.nodes ⟨602305, by omega⟩ = .product (.wire 560260) (.wire 602304)
  node_602306 : g.nodes ⟨602306, by omega⟩ = .linear (.wire 7318) (.wire 602305) false
  node_602307 : g.nodes ⟨602307, by omega⟩ = .linear (.wire 602246) (.wire 7319) true
  node_602308 : g.nodes ⟨602308, by omega⟩ = .product (.wire 560260) (.wire 602307)
  node_602309 : g.nodes ⟨602309, by omega⟩ = .linear (.wire 7319) (.wire 602308) false
  node_602310 : g.nodes ⟨602310, by omega⟩ = .linear (.wire 602257) (.wire 7320) true
  node_602311 : g.nodes ⟨602311, by omega⟩ = .product (.wire 560260) (.wire 602310)
  node_602312 : g.nodes ⟨602312, by omega⟩ = .linear (.wire 7320) (.wire 602311) false
  node_604745 : g.nodes ⟨604745, by omega⟩ = .linear (.wire 7321) (.wire 604710) true
  node_604746 : g.nodes ⟨604746, by omega⟩ = .product (.wire 560265) (.wire 604745)
  node_604747 : g.nodes ⟨604747, by omega⟩ = .linear (.wire 604710) (.wire 604746) false
  node_604748 : g.nodes ⟨604748, by omega⟩ = .linear (.wire 7322) (.wire 604721) true
  node_604749 : g.nodes ⟨604749, by omega⟩ = .product (.wire 560265) (.wire 604748)
  node_604750 : g.nodes ⟨604750, by omega⟩ = .linear (.wire 604721) (.wire 604749) false
  node_604751 : g.nodes ⟨604751, by omega⟩ = .linear (.wire 7323) (.wire 604732) true
  node_604752 : g.nodes ⟨604752, by omega⟩ = .product (.wire 560265) (.wire 604751)
  node_604753 : g.nodes ⟨604753, by omega⟩ = .linear (.wire 604732) (.wire 604752) false
  node_604754 : g.nodes ⟨604754, by omega⟩ = .linear (.wire 7324) (.wire 604743) true
  node_604755 : g.nodes ⟨604755, by omega⟩ = .product (.wire 560265) (.wire 604754)
  node_604756 : g.nodes ⟨604756, by omega⟩ = .linear (.wire 604743) (.wire 604755) false
  node_604757 : g.nodes ⟨604757, by omega⟩ = .linear (.wire 7325) (.wire 604709) true
  node_604758 : g.nodes ⟨604758, by omega⟩ = .product (.wire 560265) (.wire 604757)
  node_604759 : g.nodes ⟨604759, by omega⟩ = .linear (.wire 604709) (.wire 604758) false
  node_604760 : g.nodes ⟨604760, by omega⟩ = .linear (.wire 7326) (.wire 604720) true
  node_604761 : g.nodes ⟨604761, by omega⟩ = .product (.wire 560265) (.wire 604760)
  node_604762 : g.nodes ⟨604762, by omega⟩ = .linear (.wire 604720) (.wire 604761) false
  node_604763 : g.nodes ⟨604763, by omega⟩ = .linear (.wire 7327) (.wire 604731) true
  node_604764 : g.nodes ⟨604764, by omega⟩ = .product (.wire 560265) (.wire 604763)
  node_604765 : g.nodes ⟨604765, by omega⟩ = .linear (.wire 604731) (.wire 604764) false
  node_604766 : g.nodes ⟨604766, by omega⟩ = .linear (.wire 604710) (.wire 7321) true
  node_604767 : g.nodes ⟨604767, by omega⟩ = .product (.wire 560265) (.wire 604766)
  node_604768 : g.nodes ⟨604768, by omega⟩ = .linear (.wire 7321) (.wire 604767) false
  node_604769 : g.nodes ⟨604769, by omega⟩ = .linear (.wire 604721) (.wire 7322) true
  node_604770 : g.nodes ⟨604770, by omega⟩ = .product (.wire 560265) (.wire 604769)
  node_604771 : g.nodes ⟨604771, by omega⟩ = .linear (.wire 7322) (.wire 604770) false
  node_604772 : g.nodes ⟨604772, by omega⟩ = .linear (.wire 604732) (.wire 7323) true
  node_604773 : g.nodes ⟨604773, by omega⟩ = .product (.wire 560265) (.wire 604772)
  node_604774 : g.nodes ⟨604774, by omega⟩ = .linear (.wire 7323) (.wire 604773) false
  node_604775 : g.nodes ⟨604775, by omega⟩ = .linear (.wire 604743) (.wire 7324) true
  node_604776 : g.nodes ⟨604776, by omega⟩ = .product (.wire 560265) (.wire 604775)
  node_604777 : g.nodes ⟨604777, by omega⟩ = .linear (.wire 7324) (.wire 604776) false
  node_604778 : g.nodes ⟨604778, by omega⟩ = .linear (.wire 604709) (.wire 7325) true
  node_604779 : g.nodes ⟨604779, by omega⟩ = .product (.wire 560265) (.wire 604778)
  node_604780 : g.nodes ⟨604780, by omega⟩ = .linear (.wire 7325) (.wire 604779) false
  node_604781 : g.nodes ⟨604781, by omega⟩ = .linear (.wire 604720) (.wire 7326) true
  node_604782 : g.nodes ⟨604782, by omega⟩ = .product (.wire 560265) (.wire 604781)
  node_604783 : g.nodes ⟨604783, by omega⟩ = .linear (.wire 7326) (.wire 604782) false
  node_604784 : g.nodes ⟨604784, by omega⟩ = .linear (.wire 604731) (.wire 7327) true
  node_604785 : g.nodes ⟨604785, by omega⟩ = .product (.wire 560265) (.wire 604784)
  node_604786 : g.nodes ⟨604786, by omega⟩ = .linear (.wire 7327) (.wire 604785) false
  node_607219 : g.nodes ⟨607219, by omega⟩ = .linear (.wire 7328) (.wire 607184) true
  node_607220 : g.nodes ⟨607220, by omega⟩ = .product (.wire 560270) (.wire 607219)
  node_607221 : g.nodes ⟨607221, by omega⟩ = .linear (.wire 607184) (.wire 607220) false
  node_607222 : g.nodes ⟨607222, by omega⟩ = .linear (.wire 7329) (.wire 607195) true
  node_607223 : g.nodes ⟨607223, by omega⟩ = .product (.wire 560270) (.wire 607222)
  node_607224 : g.nodes ⟨607224, by omega⟩ = .linear (.wire 607195) (.wire 607223) false
  node_607225 : g.nodes ⟨607225, by omega⟩ = .linear (.wire 7330) (.wire 607206) true
  node_607226 : g.nodes ⟨607226, by omega⟩ = .product (.wire 560270) (.wire 607225)
  node_607227 : g.nodes ⟨607227, by omega⟩ = .linear (.wire 607206) (.wire 607226) false
  node_607228 : g.nodes ⟨607228, by omega⟩ = .linear (.wire 7331) (.wire 607217) true
  node_607229 : g.nodes ⟨607229, by omega⟩ = .product (.wire 560270) (.wire 607228)
  node_607230 : g.nodes ⟨607230, by omega⟩ = .linear (.wire 607217) (.wire 607229) false
  node_607231 : g.nodes ⟨607231, by omega⟩ = .linear (.wire 7332) (.wire 607183) true
  node_607232 : g.nodes ⟨607232, by omega⟩ = .product (.wire 560270) (.wire 607231)
  node_607233 : g.nodes ⟨607233, by omega⟩ = .linear (.wire 607183) (.wire 607232) false
  node_607234 : g.nodes ⟨607234, by omega⟩ = .linear (.wire 7333) (.wire 607194) true
  node_607235 : g.nodes ⟨607235, by omega⟩ = .product (.wire 560270) (.wire 607234)
  node_607236 : g.nodes ⟨607236, by omega⟩ = .linear (.wire 607194) (.wire 607235) false
  node_607237 : g.nodes ⟨607237, by omega⟩ = .linear (.wire 7334) (.wire 607205) true
  node_607238 : g.nodes ⟨607238, by omega⟩ = .product (.wire 560270) (.wire 607237)
  node_607239 : g.nodes ⟨607239, by omega⟩ = .linear (.wire 607205) (.wire 607238) false
  node_607240 : g.nodes ⟨607240, by omega⟩ = .linear (.wire 607184) (.wire 7328) true
  node_607241 : g.nodes ⟨607241, by omega⟩ = .product (.wire 560270) (.wire 607240)
  node_607242 : g.nodes ⟨607242, by omega⟩ = .linear (.wire 7328) (.wire 607241) false
  node_607243 : g.nodes ⟨607243, by omega⟩ = .linear (.wire 607195) (.wire 7329) true
  node_607244 : g.nodes ⟨607244, by omega⟩ = .product (.wire 560270) (.wire 607243)
  node_607245 : g.nodes ⟨607245, by omega⟩ = .linear (.wire 7329) (.wire 607244) false
  node_607246 : g.nodes ⟨607246, by omega⟩ = .linear (.wire 607206) (.wire 7330) true
  node_607247 : g.nodes ⟨607247, by omega⟩ = .product (.wire 560270) (.wire 607246)
  node_607248 : g.nodes ⟨607248, by omega⟩ = .linear (.wire 7330) (.wire 607247) false
  node_607249 : g.nodes ⟨607249, by omega⟩ = .linear (.wire 607217) (.wire 7331) true
  node_607250 : g.nodes ⟨607250, by omega⟩ = .product (.wire 560270) (.wire 607249)
  node_607251 : g.nodes ⟨607251, by omega⟩ = .linear (.wire 7331) (.wire 607250) false
  node_607252 : g.nodes ⟨607252, by omega⟩ = .linear (.wire 607183) (.wire 7332) true
  node_607253 : g.nodes ⟨607253, by omega⟩ = .product (.wire 560270) (.wire 607252)
  node_607254 : g.nodes ⟨607254, by omega⟩ = .linear (.wire 7332) (.wire 607253) false
  node_607255 : g.nodes ⟨607255, by omega⟩ = .linear (.wire 607194) (.wire 7333) true
  node_607256 : g.nodes ⟨607256, by omega⟩ = .product (.wire 560270) (.wire 607255)
  node_607257 : g.nodes ⟨607257, by omega⟩ = .linear (.wire 7333) (.wire 607256) false
  node_607258 : g.nodes ⟨607258, by omega⟩ = .linear (.wire 607205) (.wire 7334) true
  node_607259 : g.nodes ⟨607259, by omega⟩ = .product (.wire 560270) (.wire 607258)
  node_607260 : g.nodes ⟨607260, by omega⟩ = .linear (.wire 7334) (.wire 607259) false
  node_609693 : g.nodes ⟨609693, by omega⟩ = .linear (.wire 7335) (.wire 609658) true
  node_609694 : g.nodes ⟨609694, by omega⟩ = .product (.wire 560275) (.wire 609693)
  node_609695 : g.nodes ⟨609695, by omega⟩ = .linear (.wire 609658) (.wire 609694) false
  node_609696 : g.nodes ⟨609696, by omega⟩ = .linear (.wire 7336) (.wire 609669) true
  node_609697 : g.nodes ⟨609697, by omega⟩ = .product (.wire 560275) (.wire 609696)
  node_609698 : g.nodes ⟨609698, by omega⟩ = .linear (.wire 609669) (.wire 609697) false
  node_609699 : g.nodes ⟨609699, by omega⟩ = .linear (.wire 7337) (.wire 609680) true
  node_609700 : g.nodes ⟨609700, by omega⟩ = .product (.wire 560275) (.wire 609699)
  node_609701 : g.nodes ⟨609701, by omega⟩ = .linear (.wire 609680) (.wire 609700) false
  node_609702 : g.nodes ⟨609702, by omega⟩ = .linear (.wire 7338) (.wire 609691) true
  node_609703 : g.nodes ⟨609703, by omega⟩ = .product (.wire 560275) (.wire 609702)
  node_609704 : g.nodes ⟨609704, by omega⟩ = .linear (.wire 609691) (.wire 609703) false
  node_609705 : g.nodes ⟨609705, by omega⟩ = .linear (.wire 7339) (.wire 609657) true
  node_609706 : g.nodes ⟨609706, by omega⟩ = .product (.wire 560275) (.wire 609705)
  node_609707 : g.nodes ⟨609707, by omega⟩ = .linear (.wire 609657) (.wire 609706) false
  node_609708 : g.nodes ⟨609708, by omega⟩ = .linear (.wire 7340) (.wire 609668) true
  node_609709 : g.nodes ⟨609709, by omega⟩ = .product (.wire 560275) (.wire 609708)
  node_609710 : g.nodes ⟨609710, by omega⟩ = .linear (.wire 609668) (.wire 609709) false
  node_609711 : g.nodes ⟨609711, by omega⟩ = .linear (.wire 7341) (.wire 609679) true
  node_609712 : g.nodes ⟨609712, by omega⟩ = .product (.wire 560275) (.wire 609711)
  node_609713 : g.nodes ⟨609713, by omega⟩ = .linear (.wire 609679) (.wire 609712) false
  node_609714 : g.nodes ⟨609714, by omega⟩ = .linear (.wire 609658) (.wire 7335) true
  node_609715 : g.nodes ⟨609715, by omega⟩ = .product (.wire 560275) (.wire 609714)
  node_609716 : g.nodes ⟨609716, by omega⟩ = .linear (.wire 7335) (.wire 609715) false
  node_609717 : g.nodes ⟨609717, by omega⟩ = .linear (.wire 609669) (.wire 7336) true
  node_609718 : g.nodes ⟨609718, by omega⟩ = .product (.wire 560275) (.wire 609717)
  node_609719 : g.nodes ⟨609719, by omega⟩ = .linear (.wire 7336) (.wire 609718) false
  node_609720 : g.nodes ⟨609720, by omega⟩ = .linear (.wire 609680) (.wire 7337) true
  node_609721 : g.nodes ⟨609721, by omega⟩ = .product (.wire 560275) (.wire 609720)
  node_609722 : g.nodes ⟨609722, by omega⟩ = .linear (.wire 7337) (.wire 609721) false
  node_609723 : g.nodes ⟨609723, by omega⟩ = .linear (.wire 609691) (.wire 7338) true
  node_609724 : g.nodes ⟨609724, by omega⟩ = .product (.wire 560275) (.wire 609723)
  node_609725 : g.nodes ⟨609725, by omega⟩ = .linear (.wire 7338) (.wire 609724) false
  node_609726 : g.nodes ⟨609726, by omega⟩ = .linear (.wire 609657) (.wire 7339) true
  node_609727 : g.nodes ⟨609727, by omega⟩ = .product (.wire 560275) (.wire 609726)
  node_609728 : g.nodes ⟨609728, by omega⟩ = .linear (.wire 7339) (.wire 609727) false
  node_609729 : g.nodes ⟨609729, by omega⟩ = .linear (.wire 609668) (.wire 7340) true
  node_609730 : g.nodes ⟨609730, by omega⟩ = .product (.wire 560275) (.wire 609729)
  node_609731 : g.nodes ⟨609731, by omega⟩ = .linear (.wire 7340) (.wire 609730) false
  node_609732 : g.nodes ⟨609732, by omega⟩ = .linear (.wire 609679) (.wire 7341) true
  node_609733 : g.nodes ⟨609733, by omega⟩ = .product (.wire 560275) (.wire 609732)
  node_609734 : g.nodes ⟨609734, by omega⟩ = .linear (.wire 7341) (.wire 609733) false
  node_612167 : g.nodes ⟨612167, by omega⟩ = .linear (.wire 7342) (.wire 612132) true
  node_612168 : g.nodes ⟨612168, by omega⟩ = .product (.wire 560280) (.wire 612167)
  node_612169 : g.nodes ⟨612169, by omega⟩ = .linear (.wire 612132) (.wire 612168) false
  node_612170 : g.nodes ⟨612170, by omega⟩ = .linear (.wire 7343) (.wire 612143) true
  node_612171 : g.nodes ⟨612171, by omega⟩ = .product (.wire 560280) (.wire 612170)
  node_612172 : g.nodes ⟨612172, by omega⟩ = .linear (.wire 612143) (.wire 612171) false
  node_612173 : g.nodes ⟨612173, by omega⟩ = .linear (.wire 7344) (.wire 612154) true
  node_612174 : g.nodes ⟨612174, by omega⟩ = .product (.wire 560280) (.wire 612173)
  node_612175 : g.nodes ⟨612175, by omega⟩ = .linear (.wire 612154) (.wire 612174) false
  node_612176 : g.nodes ⟨612176, by omega⟩ = .linear (.wire 7345) (.wire 612165) true
  node_612177 : g.nodes ⟨612177, by omega⟩ = .product (.wire 560280) (.wire 612176)
  node_612178 : g.nodes ⟨612178, by omega⟩ = .linear (.wire 612165) (.wire 612177) false
  node_612179 : g.nodes ⟨612179, by omega⟩ = .linear (.wire 7346) (.wire 612131) true
  node_612180 : g.nodes ⟨612180, by omega⟩ = .product (.wire 560280) (.wire 612179)
  node_612181 : g.nodes ⟨612181, by omega⟩ = .linear (.wire 612131) (.wire 612180) false
  node_612182 : g.nodes ⟨612182, by omega⟩ = .linear (.wire 7347) (.wire 612142) true
  node_612183 : g.nodes ⟨612183, by omega⟩ = .product (.wire 560280) (.wire 612182)
  node_612184 : g.nodes ⟨612184, by omega⟩ = .linear (.wire 612142) (.wire 612183) false
  node_612185 : g.nodes ⟨612185, by omega⟩ = .linear (.wire 7348) (.wire 612153) true
  node_612186 : g.nodes ⟨612186, by omega⟩ = .product (.wire 560280) (.wire 612185)
  node_612187 : g.nodes ⟨612187, by omega⟩ = .linear (.wire 612153) (.wire 612186) false
  node_612188 : g.nodes ⟨612188, by omega⟩ = .linear (.wire 612132) (.wire 7342) true
  node_612189 : g.nodes ⟨612189, by omega⟩ = .product (.wire 560280) (.wire 612188)
  node_612190 : g.nodes ⟨612190, by omega⟩ = .linear (.wire 7342) (.wire 612189) false
  node_612191 : g.nodes ⟨612191, by omega⟩ = .linear (.wire 612143) (.wire 7343) true
  node_612192 : g.nodes ⟨612192, by omega⟩ = .product (.wire 560280) (.wire 612191)
  node_612193 : g.nodes ⟨612193, by omega⟩ = .linear (.wire 7343) (.wire 612192) false
  node_612194 : g.nodes ⟨612194, by omega⟩ = .linear (.wire 612154) (.wire 7344) true
  node_612195 : g.nodes ⟨612195, by omega⟩ = .product (.wire 560280) (.wire 612194)
  node_612196 : g.nodes ⟨612196, by omega⟩ = .linear (.wire 7344) (.wire 612195) false
  node_612197 : g.nodes ⟨612197, by omega⟩ = .linear (.wire 612165) (.wire 7345) true
  node_612198 : g.nodes ⟨612198, by omega⟩ = .product (.wire 560280) (.wire 612197)
  node_612199 : g.nodes ⟨612199, by omega⟩ = .linear (.wire 7345) (.wire 612198) false
  node_612200 : g.nodes ⟨612200, by omega⟩ = .linear (.wire 612131) (.wire 7346) true
  node_612201 : g.nodes ⟨612201, by omega⟩ = .product (.wire 560280) (.wire 612200)
  node_612202 : g.nodes ⟨612202, by omega⟩ = .linear (.wire 7346) (.wire 612201) false
  node_612203 : g.nodes ⟨612203, by omega⟩ = .linear (.wire 612142) (.wire 7347) true
  node_612204 : g.nodes ⟨612204, by omega⟩ = .product (.wire 560280) (.wire 612203)
  node_612205 : g.nodes ⟨612205, by omega⟩ = .linear (.wire 7347) (.wire 612204) false
  node_612206 : g.nodes ⟨612206, by omega⟩ = .linear (.wire 612153) (.wire 7348) true
  node_612207 : g.nodes ⟨612207, by omega⟩ = .product (.wire 560280) (.wire 612206)
  node_612208 : g.nodes ⟨612208, by omega⟩ = .linear (.wire 7348) (.wire 612207) false
  node_614641 : g.nodes ⟨614641, by omega⟩ = .linear (.wire 7349) (.wire 614606) true
  node_614642 : g.nodes ⟨614642, by omega⟩ = .product (.wire 560285) (.wire 614641)
  node_614643 : g.nodes ⟨614643, by omega⟩ = .linear (.wire 614606) (.wire 614642) false
  node_614644 : g.nodes ⟨614644, by omega⟩ = .linear (.wire 7350) (.wire 614617) true
  node_614645 : g.nodes ⟨614645, by omega⟩ = .product (.wire 560285) (.wire 614644)
  node_614646 : g.nodes ⟨614646, by omega⟩ = .linear (.wire 614617) (.wire 614645) false
  node_614647 : g.nodes ⟨614647, by omega⟩ = .linear (.wire 7351) (.wire 614628) true
  node_614648 : g.nodes ⟨614648, by omega⟩ = .product (.wire 560285) (.wire 614647)
  node_614649 : g.nodes ⟨614649, by omega⟩ = .linear (.wire 614628) (.wire 614648) false
  node_614650 : g.nodes ⟨614650, by omega⟩ = .linear (.wire 7352) (.wire 614639) true
  node_614651 : g.nodes ⟨614651, by omega⟩ = .product (.wire 560285) (.wire 614650)
  node_614652 : g.nodes ⟨614652, by omega⟩ = .linear (.wire 614639) (.wire 614651) false
  node_614653 : g.nodes ⟨614653, by omega⟩ = .linear (.wire 7353) (.wire 614605) true
  node_614654 : g.nodes ⟨614654, by omega⟩ = .product (.wire 560285) (.wire 614653)
  node_614655 : g.nodes ⟨614655, by omega⟩ = .linear (.wire 614605) (.wire 614654) false
  node_614656 : g.nodes ⟨614656, by omega⟩ = .linear (.wire 7354) (.wire 614616) true
  node_614657 : g.nodes ⟨614657, by omega⟩ = .product (.wire 560285) (.wire 614656)
  node_614658 : g.nodes ⟨614658, by omega⟩ = .linear (.wire 614616) (.wire 614657) false
  node_614659 : g.nodes ⟨614659, by omega⟩ = .linear (.wire 7355) (.wire 614627) true
  node_614660 : g.nodes ⟨614660, by omega⟩ = .product (.wire 560285) (.wire 614659)
  node_614661 : g.nodes ⟨614661, by omega⟩ = .linear (.wire 614627) (.wire 614660) false
  node_614662 : g.nodes ⟨614662, by omega⟩ = .linear (.wire 614606) (.wire 7349) true
  node_614663 : g.nodes ⟨614663, by omega⟩ = .product (.wire 560285) (.wire 614662)
  node_614664 : g.nodes ⟨614664, by omega⟩ = .linear (.wire 7349) (.wire 614663) false
  node_614665 : g.nodes ⟨614665, by omega⟩ = .linear (.wire 614617) (.wire 7350) true
  node_614666 : g.nodes ⟨614666, by omega⟩ = .product (.wire 560285) (.wire 614665)
  node_614667 : g.nodes ⟨614667, by omega⟩ = .linear (.wire 7350) (.wire 614666) false
  node_614668 : g.nodes ⟨614668, by omega⟩ = .linear (.wire 614628) (.wire 7351) true
  node_614669 : g.nodes ⟨614669, by omega⟩ = .product (.wire 560285) (.wire 614668)
  node_614670 : g.nodes ⟨614670, by omega⟩ = .linear (.wire 7351) (.wire 614669) false
  node_614671 : g.nodes ⟨614671, by omega⟩ = .linear (.wire 614639) (.wire 7352) true
  node_614672 : g.nodes ⟨614672, by omega⟩ = .product (.wire 560285) (.wire 614671)
  node_614673 : g.nodes ⟨614673, by omega⟩ = .linear (.wire 7352) (.wire 614672) false
  node_614674 : g.nodes ⟨614674, by omega⟩ = .linear (.wire 614605) (.wire 7353) true
  node_614675 : g.nodes ⟨614675, by omega⟩ = .product (.wire 560285) (.wire 614674)
  node_614676 : g.nodes ⟨614676, by omega⟩ = .linear (.wire 7353) (.wire 614675) false
  node_614677 : g.nodes ⟨614677, by omega⟩ = .linear (.wire 614616) (.wire 7354) true
  node_614678 : g.nodes ⟨614678, by omega⟩ = .product (.wire 560285) (.wire 614677)
  node_614679 : g.nodes ⟨614679, by omega⟩ = .linear (.wire 7354) (.wire 614678) false
  node_614680 : g.nodes ⟨614680, by omega⟩ = .linear (.wire 614627) (.wire 7355) true
  node_614681 : g.nodes ⟨614681, by omega⟩ = .product (.wire 560285) (.wire 614680)
  node_614682 : g.nodes ⟨614682, by omega⟩ = .linear (.wire 7355) (.wire 614681) false
  node_617115 : g.nodes ⟨617115, by omega⟩ = .linear (.wire 7356) (.wire 617080) true
  node_617116 : g.nodes ⟨617116, by omega⟩ = .product (.wire 560290) (.wire 617115)
  node_617117 : g.nodes ⟨617117, by omega⟩ = .linear (.wire 617080) (.wire 617116) false
  node_617118 : g.nodes ⟨617118, by omega⟩ = .linear (.wire 7357) (.wire 617091) true
  node_617119 : g.nodes ⟨617119, by omega⟩ = .product (.wire 560290) (.wire 617118)
  node_617120 : g.nodes ⟨617120, by omega⟩ = .linear (.wire 617091) (.wire 617119) false
  node_617121 : g.nodes ⟨617121, by omega⟩ = .linear (.wire 7358) (.wire 617102) true
  node_617122 : g.nodes ⟨617122, by omega⟩ = .product (.wire 560290) (.wire 617121)
  node_617123 : g.nodes ⟨617123, by omega⟩ = .linear (.wire 617102) (.wire 617122) false
  node_617124 : g.nodes ⟨617124, by omega⟩ = .linear (.wire 7359) (.wire 617113) true
  node_617125 : g.nodes ⟨617125, by omega⟩ = .product (.wire 560290) (.wire 617124)
  node_617126 : g.nodes ⟨617126, by omega⟩ = .linear (.wire 617113) (.wire 617125) false
  node_617127 : g.nodes ⟨617127, by omega⟩ = .linear (.wire 7360) (.wire 617079) true
  node_617128 : g.nodes ⟨617128, by omega⟩ = .product (.wire 560290) (.wire 617127)
  node_617129 : g.nodes ⟨617129, by omega⟩ = .linear (.wire 617079) (.wire 617128) false
  node_617130 : g.nodes ⟨617130, by omega⟩ = .linear (.wire 7361) (.wire 617090) true
  node_617131 : g.nodes ⟨617131, by omega⟩ = .product (.wire 560290) (.wire 617130)
  node_617132 : g.nodes ⟨617132, by omega⟩ = .linear (.wire 617090) (.wire 617131) false
  node_617133 : g.nodes ⟨617133, by omega⟩ = .linear (.wire 7362) (.wire 617101) true
  node_617134 : g.nodes ⟨617134, by omega⟩ = .product (.wire 560290) (.wire 617133)
  node_617135 : g.nodes ⟨617135, by omega⟩ = .linear (.wire 617101) (.wire 617134) false
  node_617136 : g.nodes ⟨617136, by omega⟩ = .linear (.wire 617080) (.wire 7356) true
  node_617137 : g.nodes ⟨617137, by omega⟩ = .product (.wire 560290) (.wire 617136)
  node_617138 : g.nodes ⟨617138, by omega⟩ = .linear (.wire 7356) (.wire 617137) false
  node_617139 : g.nodes ⟨617139, by omega⟩ = .linear (.wire 617091) (.wire 7357) true
  node_617140 : g.nodes ⟨617140, by omega⟩ = .product (.wire 560290) (.wire 617139)
  node_617141 : g.nodes ⟨617141, by omega⟩ = .linear (.wire 7357) (.wire 617140) false
  node_617142 : g.nodes ⟨617142, by omega⟩ = .linear (.wire 617102) (.wire 7358) true
  node_617143 : g.nodes ⟨617143, by omega⟩ = .product (.wire 560290) (.wire 617142)
  node_617144 : g.nodes ⟨617144, by omega⟩ = .linear (.wire 7358) (.wire 617143) false
  node_617145 : g.nodes ⟨617145, by omega⟩ = .linear (.wire 617113) (.wire 7359) true
  node_617146 : g.nodes ⟨617146, by omega⟩ = .product (.wire 560290) (.wire 617145)
  node_617147 : g.nodes ⟨617147, by omega⟩ = .linear (.wire 7359) (.wire 617146) false
  node_617148 : g.nodes ⟨617148, by omega⟩ = .linear (.wire 617079) (.wire 7360) true
  node_617149 : g.nodes ⟨617149, by omega⟩ = .product (.wire 560290) (.wire 617148)
  node_617150 : g.nodes ⟨617150, by omega⟩ = .linear (.wire 7360) (.wire 617149) false
  node_617151 : g.nodes ⟨617151, by omega⟩ = .linear (.wire 617090) (.wire 7361) true
  node_617152 : g.nodes ⟨617152, by omega⟩ = .product (.wire 560290) (.wire 617151)
  node_617153 : g.nodes ⟨617153, by omega⟩ = .linear (.wire 7361) (.wire 617152) false
  node_617154 : g.nodes ⟨617154, by omega⟩ = .linear (.wire 617101) (.wire 7362) true
  node_617155 : g.nodes ⟨617155, by omega⟩ = .product (.wire 560290) (.wire 617154)
  node_617156 : g.nodes ⟨617156, by omega⟩ = .linear (.wire 7362) (.wire 617155) false
  node_619589 : g.nodes ⟨619589, by omega⟩ = .linear (.wire 7363) (.wire 619554) true
  node_619590 : g.nodes ⟨619590, by omega⟩ = .product (.wire 560295) (.wire 619589)
  node_619591 : g.nodes ⟨619591, by omega⟩ = .linear (.wire 619554) (.wire 619590) false
  node_619592 : g.nodes ⟨619592, by omega⟩ = .linear (.wire 7364) (.wire 619565) true
  node_619593 : g.nodes ⟨619593, by omega⟩ = .product (.wire 560295) (.wire 619592)
  node_619594 : g.nodes ⟨619594, by omega⟩ = .linear (.wire 619565) (.wire 619593) false
  node_619595 : g.nodes ⟨619595, by omega⟩ = .linear (.wire 7365) (.wire 619576) true
  node_619596 : g.nodes ⟨619596, by omega⟩ = .product (.wire 560295) (.wire 619595)
  node_619597 : g.nodes ⟨619597, by omega⟩ = .linear (.wire 619576) (.wire 619596) false
  node_619598 : g.nodes ⟨619598, by omega⟩ = .linear (.wire 7366) (.wire 619587) true
  node_619599 : g.nodes ⟨619599, by omega⟩ = .product (.wire 560295) (.wire 619598)
  node_619600 : g.nodes ⟨619600, by omega⟩ = .linear (.wire 619587) (.wire 619599) false
  node_619601 : g.nodes ⟨619601, by omega⟩ = .linear (.wire 7367) (.wire 619553) true
  node_619602 : g.nodes ⟨619602, by omega⟩ = .product (.wire 560295) (.wire 619601)
  node_619603 : g.nodes ⟨619603, by omega⟩ = .linear (.wire 619553) (.wire 619602) false
  node_619604 : g.nodes ⟨619604, by omega⟩ = .linear (.wire 7368) (.wire 619564) true
  node_619605 : g.nodes ⟨619605, by omega⟩ = .product (.wire 560295) (.wire 619604)
  node_619606 : g.nodes ⟨619606, by omega⟩ = .linear (.wire 619564) (.wire 619605) false
  node_619607 : g.nodes ⟨619607, by omega⟩ = .linear (.wire 7369) (.wire 619575) true
  node_619608 : g.nodes ⟨619608, by omega⟩ = .product (.wire 560295) (.wire 619607)
  node_619609 : g.nodes ⟨619609, by omega⟩ = .linear (.wire 619575) (.wire 619608) false
  node_619610 : g.nodes ⟨619610, by omega⟩ = .linear (.wire 619554) (.wire 7363) true
  node_619611 : g.nodes ⟨619611, by omega⟩ = .product (.wire 560295) (.wire 619610)
  node_619612 : g.nodes ⟨619612, by omega⟩ = .linear (.wire 7363) (.wire 619611) false
  node_619613 : g.nodes ⟨619613, by omega⟩ = .linear (.wire 619565) (.wire 7364) true
  node_619614 : g.nodes ⟨619614, by omega⟩ = .product (.wire 560295) (.wire 619613)
  node_619615 : g.nodes ⟨619615, by omega⟩ = .linear (.wire 7364) (.wire 619614) false
  node_619616 : g.nodes ⟨619616, by omega⟩ = .linear (.wire 619576) (.wire 7365) true
  node_619617 : g.nodes ⟨619617, by omega⟩ = .product (.wire 560295) (.wire 619616)
  node_619618 : g.nodes ⟨619618, by omega⟩ = .linear (.wire 7365) (.wire 619617) false
  node_619619 : g.nodes ⟨619619, by omega⟩ = .linear (.wire 619587) (.wire 7366) true
  node_619620 : g.nodes ⟨619620, by omega⟩ = .product (.wire 560295) (.wire 619619)
  node_619621 : g.nodes ⟨619621, by omega⟩ = .linear (.wire 7366) (.wire 619620) false
  node_619622 : g.nodes ⟨619622, by omega⟩ = .linear (.wire 619553) (.wire 7367) true
  node_619623 : g.nodes ⟨619623, by omega⟩ = .product (.wire 560295) (.wire 619622)
  node_619624 : g.nodes ⟨619624, by omega⟩ = .linear (.wire 7367) (.wire 619623) false
  node_619625 : g.nodes ⟨619625, by omega⟩ = .linear (.wire 619564) (.wire 7368) true
  node_619626 : g.nodes ⟨619626, by omega⟩ = .product (.wire 560295) (.wire 619625)
  node_619627 : g.nodes ⟨619627, by omega⟩ = .linear (.wire 7368) (.wire 619626) false
  node_619628 : g.nodes ⟨619628, by omega⟩ = .linear (.wire 619575) (.wire 7369) true
  node_619629 : g.nodes ⟨619629, by omega⟩ = .product (.wire 560295) (.wire 619628)
  node_619630 : g.nodes ⟨619630, by omega⟩ = .linear (.wire 7369) (.wire 619629) false
  node_622063 : g.nodes ⟨622063, by omega⟩ = .linear (.wire 7370) (.wire 622028) true
  node_622064 : g.nodes ⟨622064, by omega⟩ = .product (.wire 560300) (.wire 622063)
  node_622065 : g.nodes ⟨622065, by omega⟩ = .linear (.wire 622028) (.wire 622064) false
  node_622066 : g.nodes ⟨622066, by omega⟩ = .linear (.wire 7371) (.wire 622039) true
  node_622067 : g.nodes ⟨622067, by omega⟩ = .product (.wire 560300) (.wire 622066)
  node_622068 : g.nodes ⟨622068, by omega⟩ = .linear (.wire 622039) (.wire 622067) false
  node_622069 : g.nodes ⟨622069, by omega⟩ = .linear (.wire 7372) (.wire 622050) true
  node_622070 : g.nodes ⟨622070, by omega⟩ = .product (.wire 560300) (.wire 622069)
  node_622071 : g.nodes ⟨622071, by omega⟩ = .linear (.wire 622050) (.wire 622070) false
  node_622072 : g.nodes ⟨622072, by omega⟩ = .linear (.wire 7373) (.wire 622061) true
  node_622073 : g.nodes ⟨622073, by omega⟩ = .product (.wire 560300) (.wire 622072)
  node_622074 : g.nodes ⟨622074, by omega⟩ = .linear (.wire 622061) (.wire 622073) false
  node_622075 : g.nodes ⟨622075, by omega⟩ = .linear (.wire 7374) (.wire 622027) true
  node_622076 : g.nodes ⟨622076, by omega⟩ = .product (.wire 560300) (.wire 622075)
  node_622077 : g.nodes ⟨622077, by omega⟩ = .linear (.wire 622027) (.wire 622076) false
  node_622078 : g.nodes ⟨622078, by omega⟩ = .linear (.wire 7375) (.wire 622038) true
  node_622079 : g.nodes ⟨622079, by omega⟩ = .product (.wire 560300) (.wire 622078)
  node_622080 : g.nodes ⟨622080, by omega⟩ = .linear (.wire 622038) (.wire 622079) false
  node_622081 : g.nodes ⟨622081, by omega⟩ = .linear (.wire 7376) (.wire 622049) true
  node_622082 : g.nodes ⟨622082, by omega⟩ = .product (.wire 560300) (.wire 622081)
  node_622083 : g.nodes ⟨622083, by omega⟩ = .linear (.wire 622049) (.wire 622082) false
  node_622084 : g.nodes ⟨622084, by omega⟩ = .linear (.wire 622028) (.wire 7370) true
  node_622085 : g.nodes ⟨622085, by omega⟩ = .product (.wire 560300) (.wire 622084)
  node_622086 : g.nodes ⟨622086, by omega⟩ = .linear (.wire 7370) (.wire 622085) false
  node_622087 : g.nodes ⟨622087, by omega⟩ = .linear (.wire 622039) (.wire 7371) true
  node_622088 : g.nodes ⟨622088, by omega⟩ = .product (.wire 560300) (.wire 622087)
  node_622089 : g.nodes ⟨622089, by omega⟩ = .linear (.wire 7371) (.wire 622088) false
  node_622090 : g.nodes ⟨622090, by omega⟩ = .linear (.wire 622050) (.wire 7372) true
  node_622091 : g.nodes ⟨622091, by omega⟩ = .product (.wire 560300) (.wire 622090)
  node_622092 : g.nodes ⟨622092, by omega⟩ = .linear (.wire 7372) (.wire 622091) false
  node_622093 : g.nodes ⟨622093, by omega⟩ = .linear (.wire 622061) (.wire 7373) true
  node_622094 : g.nodes ⟨622094, by omega⟩ = .product (.wire 560300) (.wire 622093)
  node_622095 : g.nodes ⟨622095, by omega⟩ = .linear (.wire 7373) (.wire 622094) false
  node_622096 : g.nodes ⟨622096, by omega⟩ = .linear (.wire 622027) (.wire 7374) true
  node_622097 : g.nodes ⟨622097, by omega⟩ = .product (.wire 560300) (.wire 622096)
  node_622098 : g.nodes ⟨622098, by omega⟩ = .linear (.wire 7374) (.wire 622097) false
  node_622099 : g.nodes ⟨622099, by omega⟩ = .linear (.wire 622038) (.wire 7375) true
  node_622100 : g.nodes ⟨622100, by omega⟩ = .product (.wire 560300) (.wire 622099)
  node_622101 : g.nodes ⟨622101, by omega⟩ = .linear (.wire 7375) (.wire 622100) false
  node_622102 : g.nodes ⟨622102, by omega⟩ = .linear (.wire 622049) (.wire 7376) true
  node_622103 : g.nodes ⟨622103, by omega⟩ = .product (.wire 560300) (.wire 622102)
  node_622104 : g.nodes ⟨622104, by omega⟩ = .linear (.wire 7376) (.wire 622103) false
  node_624537 : g.nodes ⟨624537, by omega⟩ = .linear (.wire 7377) (.wire 624502) true
  node_624538 : g.nodes ⟨624538, by omega⟩ = .product (.wire 560305) (.wire 624537)
  node_624539 : g.nodes ⟨624539, by omega⟩ = .linear (.wire 624502) (.wire 624538) false
  node_624540 : g.nodes ⟨624540, by omega⟩ = .linear (.wire 7378) (.wire 624513) true
  node_624541 : g.nodes ⟨624541, by omega⟩ = .product (.wire 560305) (.wire 624540)
  node_624542 : g.nodes ⟨624542, by omega⟩ = .linear (.wire 624513) (.wire 624541) false
  node_624543 : g.nodes ⟨624543, by omega⟩ = .linear (.wire 7379) (.wire 624524) true
  node_624544 : g.nodes ⟨624544, by omega⟩ = .product (.wire 560305) (.wire 624543)
  node_624545 : g.nodes ⟨624545, by omega⟩ = .linear (.wire 624524) (.wire 624544) false
  node_624546 : g.nodes ⟨624546, by omega⟩ = .linear (.wire 7380) (.wire 624535) true
  node_624547 : g.nodes ⟨624547, by omega⟩ = .product (.wire 560305) (.wire 624546)
  node_624548 : g.nodes ⟨624548, by omega⟩ = .linear (.wire 624535) (.wire 624547) false
  node_624549 : g.nodes ⟨624549, by omega⟩ = .linear (.wire 7381) (.wire 624501) true
  node_624550 : g.nodes ⟨624550, by omega⟩ = .product (.wire 560305) (.wire 624549)
  node_624551 : g.nodes ⟨624551, by omega⟩ = .linear (.wire 624501) (.wire 624550) false
  node_624552 : g.nodes ⟨624552, by omega⟩ = .linear (.wire 7382) (.wire 624512) true
  node_624553 : g.nodes ⟨624553, by omega⟩ = .product (.wire 560305) (.wire 624552)
  node_624554 : g.nodes ⟨624554, by omega⟩ = .linear (.wire 624512) (.wire 624553) false
  node_624555 : g.nodes ⟨624555, by omega⟩ = .linear (.wire 7383) (.wire 624523) true
  node_624556 : g.nodes ⟨624556, by omega⟩ = .product (.wire 560305) (.wire 624555)
  node_624557 : g.nodes ⟨624557, by omega⟩ = .linear (.wire 624523) (.wire 624556) false
  node_624558 : g.nodes ⟨624558, by omega⟩ = .linear (.wire 624502) (.wire 7377) true
  node_624559 : g.nodes ⟨624559, by omega⟩ = .product (.wire 560305) (.wire 624558)
  node_624560 : g.nodes ⟨624560, by omega⟩ = .linear (.wire 7377) (.wire 624559) false
  node_624561 : g.nodes ⟨624561, by omega⟩ = .linear (.wire 624513) (.wire 7378) true
  node_624562 : g.nodes ⟨624562, by omega⟩ = .product (.wire 560305) (.wire 624561)
  node_624563 : g.nodes ⟨624563, by omega⟩ = .linear (.wire 7378) (.wire 624562) false
  node_624564 : g.nodes ⟨624564, by omega⟩ = .linear (.wire 624524) (.wire 7379) true
  node_624565 : g.nodes ⟨624565, by omega⟩ = .product (.wire 560305) (.wire 624564)
  node_624566 : g.nodes ⟨624566, by omega⟩ = .linear (.wire 7379) (.wire 624565) false
  node_624567 : g.nodes ⟨624567, by omega⟩ = .linear (.wire 624535) (.wire 7380) true
  node_624568 : g.nodes ⟨624568, by omega⟩ = .product (.wire 560305) (.wire 624567)
  node_624569 : g.nodes ⟨624569, by omega⟩ = .linear (.wire 7380) (.wire 624568) false
  node_624570 : g.nodes ⟨624570, by omega⟩ = .linear (.wire 624501) (.wire 7381) true
  node_624571 : g.nodes ⟨624571, by omega⟩ = .product (.wire 560305) (.wire 624570)
  node_624572 : g.nodes ⟨624572, by omega⟩ = .linear (.wire 7381) (.wire 624571) false
  node_624573 : g.nodes ⟨624573, by omega⟩ = .linear (.wire 624512) (.wire 7382) true
  node_624574 : g.nodes ⟨624574, by omega⟩ = .product (.wire 560305) (.wire 624573)
  node_624575 : g.nodes ⟨624575, by omega⟩ = .linear (.wire 7382) (.wire 624574) false
  node_624576 : g.nodes ⟨624576, by omega⟩ = .linear (.wire 624523) (.wire 7383) true
  node_624577 : g.nodes ⟨624577, by omega⟩ = .product (.wire 560305) (.wire 624576)
  node_624578 : g.nodes ⟨624578, by omega⟩ = .linear (.wire 7383) (.wire 624577) false
  node_627011 : g.nodes ⟨627011, by omega⟩ = .linear (.wire 7384) (.wire 626976) true
  node_627012 : g.nodes ⟨627012, by omega⟩ = .product (.wire 560310) (.wire 627011)
  node_627013 : g.nodes ⟨627013, by omega⟩ = .linear (.wire 626976) (.wire 627012) false
  node_627014 : g.nodes ⟨627014, by omega⟩ = .linear (.wire 7385) (.wire 626987) true
  node_627015 : g.nodes ⟨627015, by omega⟩ = .product (.wire 560310) (.wire 627014)
  node_627016 : g.nodes ⟨627016, by omega⟩ = .linear (.wire 626987) (.wire 627015) false
  node_627017 : g.nodes ⟨627017, by omega⟩ = .linear (.wire 7386) (.wire 626998) true
  node_627018 : g.nodes ⟨627018, by omega⟩ = .product (.wire 560310) (.wire 627017)
  node_627019 : g.nodes ⟨627019, by omega⟩ = .linear (.wire 626998) (.wire 627018) false
  node_627020 : g.nodes ⟨627020, by omega⟩ = .linear (.wire 7387) (.wire 627009) true
  node_627021 : g.nodes ⟨627021, by omega⟩ = .product (.wire 560310) (.wire 627020)
  node_627022 : g.nodes ⟨627022, by omega⟩ = .linear (.wire 627009) (.wire 627021) false
  node_627023 : g.nodes ⟨627023, by omega⟩ = .linear (.wire 7388) (.wire 626975) true
  node_627024 : g.nodes ⟨627024, by omega⟩ = .product (.wire 560310) (.wire 627023)
  node_627025 : g.nodes ⟨627025, by omega⟩ = .linear (.wire 626975) (.wire 627024) false
  node_627026 : g.nodes ⟨627026, by omega⟩ = .linear (.wire 7389) (.wire 626986) true
  node_627027 : g.nodes ⟨627027, by omega⟩ = .product (.wire 560310) (.wire 627026)
  node_627028 : g.nodes ⟨627028, by omega⟩ = .linear (.wire 626986) (.wire 627027) false
  node_627029 : g.nodes ⟨627029, by omega⟩ = .linear (.wire 7390) (.wire 626997) true
  node_627030 : g.nodes ⟨627030, by omega⟩ = .product (.wire 560310) (.wire 627029)
  node_627031 : g.nodes ⟨627031, by omega⟩ = .linear (.wire 626997) (.wire 627030) false
  node_627032 : g.nodes ⟨627032, by omega⟩ = .linear (.wire 626976) (.wire 7384) true
  node_627033 : g.nodes ⟨627033, by omega⟩ = .product (.wire 560310) (.wire 627032)
  node_627034 : g.nodes ⟨627034, by omega⟩ = .linear (.wire 7384) (.wire 627033) false
  node_627035 : g.nodes ⟨627035, by omega⟩ = .linear (.wire 626987) (.wire 7385) true
  node_627036 : g.nodes ⟨627036, by omega⟩ = .product (.wire 560310) (.wire 627035)
  node_627037 : g.nodes ⟨627037, by omega⟩ = .linear (.wire 7385) (.wire 627036) false
  node_627038 : g.nodes ⟨627038, by omega⟩ = .linear (.wire 626998) (.wire 7386) true
  node_627039 : g.nodes ⟨627039, by omega⟩ = .product (.wire 560310) (.wire 627038)
  node_627040 : g.nodes ⟨627040, by omega⟩ = .linear (.wire 7386) (.wire 627039) false
  node_627041 : g.nodes ⟨627041, by omega⟩ = .linear (.wire 627009) (.wire 7387) true
  node_627042 : g.nodes ⟨627042, by omega⟩ = .product (.wire 560310) (.wire 627041)
  node_627043 : g.nodes ⟨627043, by omega⟩ = .linear (.wire 7387) (.wire 627042) false
  node_627044 : g.nodes ⟨627044, by omega⟩ = .linear (.wire 626975) (.wire 7388) true
  node_627045 : g.nodes ⟨627045, by omega⟩ = .product (.wire 560310) (.wire 627044)
  node_627046 : g.nodes ⟨627046, by omega⟩ = .linear (.wire 7388) (.wire 627045) false
  node_627047 : g.nodes ⟨627047, by omega⟩ = .linear (.wire 626986) (.wire 7389) true
  node_627048 : g.nodes ⟨627048, by omega⟩ = .product (.wire 560310) (.wire 627047)
  node_627049 : g.nodes ⟨627049, by omega⟩ = .linear (.wire 7389) (.wire 627048) false
  node_627050 : g.nodes ⟨627050, by omega⟩ = .linear (.wire 626997) (.wire 7390) true
  node_627051 : g.nodes ⟨627051, by omega⟩ = .product (.wire 560310) (.wire 627050)
  node_627052 : g.nodes ⟨627052, by omega⟩ = .linear (.wire 7390) (.wire 627051) false
  node_629485 : g.nodes ⟨629485, by omega⟩ = .linear (.wire 7391) (.wire 629450) true
  node_629486 : g.nodes ⟨629486, by omega⟩ = .product (.wire 560315) (.wire 629485)
  node_629487 : g.nodes ⟨629487, by omega⟩ = .linear (.wire 629450) (.wire 629486) false
  node_629488 : g.nodes ⟨629488, by omega⟩ = .linear (.wire 7392) (.wire 629461) true
  node_629489 : g.nodes ⟨629489, by omega⟩ = .product (.wire 560315) (.wire 629488)
  node_629490 : g.nodes ⟨629490, by omega⟩ = .linear (.wire 629461) (.wire 629489) false
  node_629491 : g.nodes ⟨629491, by omega⟩ = .linear (.wire 7393) (.wire 629472) true
  node_629492 : g.nodes ⟨629492, by omega⟩ = .product (.wire 560315) (.wire 629491)
  node_629493 : g.nodes ⟨629493, by omega⟩ = .linear (.wire 629472) (.wire 629492) false
  node_629494 : g.nodes ⟨629494, by omega⟩ = .linear (.wire 7394) (.wire 629483) true
  node_629495 : g.nodes ⟨629495, by omega⟩ = .product (.wire 560315) (.wire 629494)
  node_629496 : g.nodes ⟨629496, by omega⟩ = .linear (.wire 629483) (.wire 629495) false
  node_629497 : g.nodes ⟨629497, by omega⟩ = .linear (.wire 7395) (.wire 629449) true
  node_629498 : g.nodes ⟨629498, by omega⟩ = .product (.wire 560315) (.wire 629497)
  node_629499 : g.nodes ⟨629499, by omega⟩ = .linear (.wire 629449) (.wire 629498) false
  node_629500 : g.nodes ⟨629500, by omega⟩ = .linear (.wire 7396) (.wire 629460) true
  node_629501 : g.nodes ⟨629501, by omega⟩ = .product (.wire 560315) (.wire 629500)
  node_629502 : g.nodes ⟨629502, by omega⟩ = .linear (.wire 629460) (.wire 629501) false
  node_629503 : g.nodes ⟨629503, by omega⟩ = .linear (.wire 7397) (.wire 629471) true
  node_629504 : g.nodes ⟨629504, by omega⟩ = .product (.wire 560315) (.wire 629503)
  node_629505 : g.nodes ⟨629505, by omega⟩ = .linear (.wire 629471) (.wire 629504) false
  node_629506 : g.nodes ⟨629506, by omega⟩ = .linear (.wire 629450) (.wire 7391) true
  node_629507 : g.nodes ⟨629507, by omega⟩ = .product (.wire 560315) (.wire 629506)
  node_629508 : g.nodes ⟨629508, by omega⟩ = .linear (.wire 7391) (.wire 629507) false
  node_629509 : g.nodes ⟨629509, by omega⟩ = .linear (.wire 629461) (.wire 7392) true
  node_629510 : g.nodes ⟨629510, by omega⟩ = .product (.wire 560315) (.wire 629509)
  node_629511 : g.nodes ⟨629511, by omega⟩ = .linear (.wire 7392) (.wire 629510) false
  node_629512 : g.nodes ⟨629512, by omega⟩ = .linear (.wire 629472) (.wire 7393) true
  node_629513 : g.nodes ⟨629513, by omega⟩ = .product (.wire 560315) (.wire 629512)
  node_629514 : g.nodes ⟨629514, by omega⟩ = .linear (.wire 7393) (.wire 629513) false
  node_629515 : g.nodes ⟨629515, by omega⟩ = .linear (.wire 629483) (.wire 7394) true
  node_629516 : g.nodes ⟨629516, by omega⟩ = .product (.wire 560315) (.wire 629515)
  node_629517 : g.nodes ⟨629517, by omega⟩ = .linear (.wire 7394) (.wire 629516) false
  node_629518 : g.nodes ⟨629518, by omega⟩ = .linear (.wire 629449) (.wire 7395) true
  node_629519 : g.nodes ⟨629519, by omega⟩ = .product (.wire 560315) (.wire 629518)
  node_629520 : g.nodes ⟨629520, by omega⟩ = .linear (.wire 7395) (.wire 629519) false
  node_629521 : g.nodes ⟨629521, by omega⟩ = .linear (.wire 629460) (.wire 7396) true
  node_629522 : g.nodes ⟨629522, by omega⟩ = .product (.wire 560315) (.wire 629521)
  node_629523 : g.nodes ⟨629523, by omega⟩ = .linear (.wire 7396) (.wire 629522) false
  node_629524 : g.nodes ⟨629524, by omega⟩ = .linear (.wire 629471) (.wire 7397) true
  node_629525 : g.nodes ⟨629525, by omega⟩ = .product (.wire 560315) (.wire 629524)
  node_629526 : g.nodes ⟨629526, by omega⟩ = .linear (.wire 7397) (.wire 629525) false
  node_631959 : g.nodes ⟨631959, by omega⟩ = .linear (.wire 7398) (.wire 631924) true
  node_631960 : g.nodes ⟨631960, by omega⟩ = .product (.wire 560320) (.wire 631959)
  node_631961 : g.nodes ⟨631961, by omega⟩ = .linear (.wire 631924) (.wire 631960) false
  node_631962 : g.nodes ⟨631962, by omega⟩ = .linear (.wire 7399) (.wire 631935) true
  node_631963 : g.nodes ⟨631963, by omega⟩ = .product (.wire 560320) (.wire 631962)
  node_631964 : g.nodes ⟨631964, by omega⟩ = .linear (.wire 631935) (.wire 631963) false
  node_631965 : g.nodes ⟨631965, by omega⟩ = .linear (.wire 7400) (.wire 631946) true
  node_631966 : g.nodes ⟨631966, by omega⟩ = .product (.wire 560320) (.wire 631965)
  node_631967 : g.nodes ⟨631967, by omega⟩ = .linear (.wire 631946) (.wire 631966) false
  node_631968 : g.nodes ⟨631968, by omega⟩ = .linear (.wire 7401) (.wire 631957) true
  node_631969 : g.nodes ⟨631969, by omega⟩ = .product (.wire 560320) (.wire 631968)
  node_631970 : g.nodes ⟨631970, by omega⟩ = .linear (.wire 631957) (.wire 631969) false
  node_631971 : g.nodes ⟨631971, by omega⟩ = .linear (.wire 7402) (.wire 631923) true
  node_631972 : g.nodes ⟨631972, by omega⟩ = .product (.wire 560320) (.wire 631971)
  node_631973 : g.nodes ⟨631973, by omega⟩ = .linear (.wire 631923) (.wire 631972) false
  node_631974 : g.nodes ⟨631974, by omega⟩ = .linear (.wire 7403) (.wire 631934) true
  node_631975 : g.nodes ⟨631975, by omega⟩ = .product (.wire 560320) (.wire 631974)
  node_631976 : g.nodes ⟨631976, by omega⟩ = .linear (.wire 631934) (.wire 631975) false
  node_631977 : g.nodes ⟨631977, by omega⟩ = .linear (.wire 7404) (.wire 631945) true
  node_631978 : g.nodes ⟨631978, by omega⟩ = .product (.wire 560320) (.wire 631977)
  node_631979 : g.nodes ⟨631979, by omega⟩ = .linear (.wire 631945) (.wire 631978) false
  node_631980 : g.nodes ⟨631980, by omega⟩ = .linear (.wire 631924) (.wire 7398) true
  node_631981 : g.nodes ⟨631981, by omega⟩ = .product (.wire 560320) (.wire 631980)
  node_631982 : g.nodes ⟨631982, by omega⟩ = .linear (.wire 7398) (.wire 631981) false
  node_631983 : g.nodes ⟨631983, by omega⟩ = .linear (.wire 631935) (.wire 7399) true
  node_631984 : g.nodes ⟨631984, by omega⟩ = .product (.wire 560320) (.wire 631983)
  node_631985 : g.nodes ⟨631985, by omega⟩ = .linear (.wire 7399) (.wire 631984) false
  node_631986 : g.nodes ⟨631986, by omega⟩ = .linear (.wire 631946) (.wire 7400) true
  node_631987 : g.nodes ⟨631987, by omega⟩ = .product (.wire 560320) (.wire 631986)
  node_631988 : g.nodes ⟨631988, by omega⟩ = .linear (.wire 7400) (.wire 631987) false
  node_631989 : g.nodes ⟨631989, by omega⟩ = .linear (.wire 631957) (.wire 7401) true
  node_631990 : g.nodes ⟨631990, by omega⟩ = .product (.wire 560320) (.wire 631989)
  node_631991 : g.nodes ⟨631991, by omega⟩ = .linear (.wire 7401) (.wire 631990) false
  node_631992 : g.nodes ⟨631992, by omega⟩ = .linear (.wire 631923) (.wire 7402) true
  node_631993 : g.nodes ⟨631993, by omega⟩ = .product (.wire 560320) (.wire 631992)
  node_631994 : g.nodes ⟨631994, by omega⟩ = .linear (.wire 7402) (.wire 631993) false
  node_631995 : g.nodes ⟨631995, by omega⟩ = .linear (.wire 631934) (.wire 7403) true
  node_631996 : g.nodes ⟨631996, by omega⟩ = .product (.wire 560320) (.wire 631995)
  node_631997 : g.nodes ⟨631997, by omega⟩ = .linear (.wire 7403) (.wire 631996) false
  node_631998 : g.nodes ⟨631998, by omega⟩ = .linear (.wire 631945) (.wire 7404) true
  node_631999 : g.nodes ⟨631999, by omega⟩ = .product (.wire 560320) (.wire 631998)
  node_632000 : g.nodes ⟨632000, by omega⟩ = .linear (.wire 7404) (.wire 631999) false
  node_634433 : g.nodes ⟨634433, by omega⟩ = .linear (.wire 7405) (.wire 634398) true
  node_634434 : g.nodes ⟨634434, by omega⟩ = .product (.wire 560325) (.wire 634433)
  node_634435 : g.nodes ⟨634435, by omega⟩ = .linear (.wire 634398) (.wire 634434) false
  node_634436 : g.nodes ⟨634436, by omega⟩ = .linear (.wire 7406) (.wire 634409) true
  node_634437 : g.nodes ⟨634437, by omega⟩ = .product (.wire 560325) (.wire 634436)
  node_634438 : g.nodes ⟨634438, by omega⟩ = .linear (.wire 634409) (.wire 634437) false
  node_634439 : g.nodes ⟨634439, by omega⟩ = .linear (.wire 7407) (.wire 634420) true
  node_634440 : g.nodes ⟨634440, by omega⟩ = .product (.wire 560325) (.wire 634439)
  node_634441 : g.nodes ⟨634441, by omega⟩ = .linear (.wire 634420) (.wire 634440) false
  node_634442 : g.nodes ⟨634442, by omega⟩ = .linear (.wire 7408) (.wire 634431) true
  node_634443 : g.nodes ⟨634443, by omega⟩ = .product (.wire 560325) (.wire 634442)
  node_634444 : g.nodes ⟨634444, by omega⟩ = .linear (.wire 634431) (.wire 634443) false
  node_634445 : g.nodes ⟨634445, by omega⟩ = .linear (.wire 7409) (.wire 634397) true
  node_634446 : g.nodes ⟨634446, by omega⟩ = .product (.wire 560325) (.wire 634445)
  node_634447 : g.nodes ⟨634447, by omega⟩ = .linear (.wire 634397) (.wire 634446) false
  node_634448 : g.nodes ⟨634448, by omega⟩ = .linear (.wire 7410) (.wire 634408) true
  node_634449 : g.nodes ⟨634449, by omega⟩ = .product (.wire 560325) (.wire 634448)
  node_634450 : g.nodes ⟨634450, by omega⟩ = .linear (.wire 634408) (.wire 634449) false
  node_634451 : g.nodes ⟨634451, by omega⟩ = .linear (.wire 7411) (.wire 634419) true
  node_634452 : g.nodes ⟨634452, by omega⟩ = .product (.wire 560325) (.wire 634451)
  node_634453 : g.nodes ⟨634453, by omega⟩ = .linear (.wire 634419) (.wire 634452) false
  node_634454 : g.nodes ⟨634454, by omega⟩ = .linear (.wire 634398) (.wire 7405) true
  node_634455 : g.nodes ⟨634455, by omega⟩ = .product (.wire 560325) (.wire 634454)
  node_634456 : g.nodes ⟨634456, by omega⟩ = .linear (.wire 7405) (.wire 634455) false
  node_634457 : g.nodes ⟨634457, by omega⟩ = .linear (.wire 634409) (.wire 7406) true
  node_634458 : g.nodes ⟨634458, by omega⟩ = .product (.wire 560325) (.wire 634457)
  node_634459 : g.nodes ⟨634459, by omega⟩ = .linear (.wire 7406) (.wire 634458) false
  node_634460 : g.nodes ⟨634460, by omega⟩ = .linear (.wire 634420) (.wire 7407) true
  node_634461 : g.nodes ⟨634461, by omega⟩ = .product (.wire 560325) (.wire 634460)
  node_634462 : g.nodes ⟨634462, by omega⟩ = .linear (.wire 7407) (.wire 634461) false
  node_634463 : g.nodes ⟨634463, by omega⟩ = .linear (.wire 634431) (.wire 7408) true
  node_634464 : g.nodes ⟨634464, by omega⟩ = .product (.wire 560325) (.wire 634463)
  node_634465 : g.nodes ⟨634465, by omega⟩ = .linear (.wire 7408) (.wire 634464) false
  node_634466 : g.nodes ⟨634466, by omega⟩ = .linear (.wire 634397) (.wire 7409) true
  node_634467 : g.nodes ⟨634467, by omega⟩ = .product (.wire 560325) (.wire 634466)
  node_634468 : g.nodes ⟨634468, by omega⟩ = .linear (.wire 7409) (.wire 634467) false
  node_634469 : g.nodes ⟨634469, by omega⟩ = .linear (.wire 634408) (.wire 7410) true
  node_634470 : g.nodes ⟨634470, by omega⟩ = .product (.wire 560325) (.wire 634469)
  node_634471 : g.nodes ⟨634471, by omega⟩ = .linear (.wire 7410) (.wire 634470) false
  node_634472 : g.nodes ⟨634472, by omega⟩ = .linear (.wire 634419) (.wire 7411) true
  node_634473 : g.nodes ⟨634473, by omega⟩ = .product (.wire 560325) (.wire 634472)
  node_634474 : g.nodes ⟨634474, by omega⟩ = .linear (.wire 7411) (.wire 634473) false
  node_636907 : g.nodes ⟨636907, by omega⟩ = .linear (.wire 7412) (.wire 636872) true
  node_636908 : g.nodes ⟨636908, by omega⟩ = .product (.wire 560330) (.wire 636907)
  node_636909 : g.nodes ⟨636909, by omega⟩ = .linear (.wire 636872) (.wire 636908) false
  node_636910 : g.nodes ⟨636910, by omega⟩ = .linear (.wire 7413) (.wire 636883) true
  node_636911 : g.nodes ⟨636911, by omega⟩ = .product (.wire 560330) (.wire 636910)
  node_636912 : g.nodes ⟨636912, by omega⟩ = .linear (.wire 636883) (.wire 636911) false
  node_636913 : g.nodes ⟨636913, by omega⟩ = .linear (.wire 7414) (.wire 636894) true
  node_636914 : g.nodes ⟨636914, by omega⟩ = .product (.wire 560330) (.wire 636913)
  node_636915 : g.nodes ⟨636915, by omega⟩ = .linear (.wire 636894) (.wire 636914) false
  node_636916 : g.nodes ⟨636916, by omega⟩ = .linear (.wire 7415) (.wire 636905) true
  node_636917 : g.nodes ⟨636917, by omega⟩ = .product (.wire 560330) (.wire 636916)
  node_636918 : g.nodes ⟨636918, by omega⟩ = .linear (.wire 636905) (.wire 636917) false
  node_636919 : g.nodes ⟨636919, by omega⟩ = .linear (.wire 7416) (.wire 636871) true
  node_636920 : g.nodes ⟨636920, by omega⟩ = .product (.wire 560330) (.wire 636919)
  node_636921 : g.nodes ⟨636921, by omega⟩ = .linear (.wire 636871) (.wire 636920) false
  node_636922 : g.nodes ⟨636922, by omega⟩ = .linear (.wire 7417) (.wire 636882) true
  node_636923 : g.nodes ⟨636923, by omega⟩ = .product (.wire 560330) (.wire 636922)
  node_636924 : g.nodes ⟨636924, by omega⟩ = .linear (.wire 636882) (.wire 636923) false
  node_636925 : g.nodes ⟨636925, by omega⟩ = .linear (.wire 7418) (.wire 636893) true
  node_636926 : g.nodes ⟨636926, by omega⟩ = .product (.wire 560330) (.wire 636925)
  node_636927 : g.nodes ⟨636927, by omega⟩ = .linear (.wire 636893) (.wire 636926) false
  node_636928 : g.nodes ⟨636928, by omega⟩ = .linear (.wire 636872) (.wire 7412) true
  node_636929 : g.nodes ⟨636929, by omega⟩ = .product (.wire 560330) (.wire 636928)
  node_636930 : g.nodes ⟨636930, by omega⟩ = .linear (.wire 7412) (.wire 636929) false
  node_636931 : g.nodes ⟨636931, by omega⟩ = .linear (.wire 636883) (.wire 7413) true
  node_636932 : g.nodes ⟨636932, by omega⟩ = .product (.wire 560330) (.wire 636931)
  node_636933 : g.nodes ⟨636933, by omega⟩ = .linear (.wire 7413) (.wire 636932) false
  node_636934 : g.nodes ⟨636934, by omega⟩ = .linear (.wire 636894) (.wire 7414) true
  node_636935 : g.nodes ⟨636935, by omega⟩ = .product (.wire 560330) (.wire 636934)
  node_636936 : g.nodes ⟨636936, by omega⟩ = .linear (.wire 7414) (.wire 636935) false
  node_636937 : g.nodes ⟨636937, by omega⟩ = .linear (.wire 636905) (.wire 7415) true
  node_636938 : g.nodes ⟨636938, by omega⟩ = .product (.wire 560330) (.wire 636937)
  node_636939 : g.nodes ⟨636939, by omega⟩ = .linear (.wire 7415) (.wire 636938) false
  node_636940 : g.nodes ⟨636940, by omega⟩ = .linear (.wire 636871) (.wire 7416) true
  node_636941 : g.nodes ⟨636941, by omega⟩ = .product (.wire 560330) (.wire 636940)
  node_636942 : g.nodes ⟨636942, by omega⟩ = .linear (.wire 7416) (.wire 636941) false
  node_636943 : g.nodes ⟨636943, by omega⟩ = .linear (.wire 636882) (.wire 7417) true
  node_636944 : g.nodes ⟨636944, by omega⟩ = .product (.wire 560330) (.wire 636943)
  node_636945 : g.nodes ⟨636945, by omega⟩ = .linear (.wire 7417) (.wire 636944) false
  node_636946 : g.nodes ⟨636946, by omega⟩ = .linear (.wire 636893) (.wire 7418) true
  node_636947 : g.nodes ⟨636947, by omega⟩ = .product (.wire 560330) (.wire 636946)
  node_636948 : g.nodes ⟨636948, by omega⟩ = .linear (.wire 7418) (.wire 636947) false
  node_639381 : g.nodes ⟨639381, by omega⟩ = .linear (.wire 7419) (.wire 639346) true
  node_639382 : g.nodes ⟨639382, by omega⟩ = .product (.wire 560335) (.wire 639381)
  node_639383 : g.nodes ⟨639383, by omega⟩ = .linear (.wire 639346) (.wire 639382) false
  node_639384 : g.nodes ⟨639384, by omega⟩ = .linear (.wire 7420) (.wire 639357) true
  node_639385 : g.nodes ⟨639385, by omega⟩ = .product (.wire 560335) (.wire 639384)
  node_639386 : g.nodes ⟨639386, by omega⟩ = .linear (.wire 639357) (.wire 639385) false
  node_639387 : g.nodes ⟨639387, by omega⟩ = .linear (.wire 7421) (.wire 639368) true
  node_639388 : g.nodes ⟨639388, by omega⟩ = .product (.wire 560335) (.wire 639387)
  node_639389 : g.nodes ⟨639389, by omega⟩ = .linear (.wire 639368) (.wire 639388) false
  node_639390 : g.nodes ⟨639390, by omega⟩ = .linear (.wire 7422) (.wire 639379) true
  node_639391 : g.nodes ⟨639391, by omega⟩ = .product (.wire 560335) (.wire 639390)
  node_639392 : g.nodes ⟨639392, by omega⟩ = .linear (.wire 639379) (.wire 639391) false
  node_639393 : g.nodes ⟨639393, by omega⟩ = .linear (.wire 7423) (.wire 639345) true
  node_639394 : g.nodes ⟨639394, by omega⟩ = .product (.wire 560335) (.wire 639393)
  node_639395 : g.nodes ⟨639395, by omega⟩ = .linear (.wire 639345) (.wire 639394) false
  node_639396 : g.nodes ⟨639396, by omega⟩ = .linear (.wire 7424) (.wire 639356) true
  node_639397 : g.nodes ⟨639397, by omega⟩ = .product (.wire 560335) (.wire 639396)
  node_639398 : g.nodes ⟨639398, by omega⟩ = .linear (.wire 639356) (.wire 639397) false
  node_639399 : g.nodes ⟨639399, by omega⟩ = .linear (.wire 7425) (.wire 639367) true
  node_639400 : g.nodes ⟨639400, by omega⟩ = .product (.wire 560335) (.wire 639399)
  node_639401 : g.nodes ⟨639401, by omega⟩ = .linear (.wire 639367) (.wire 639400) false
  node_639402 : g.nodes ⟨639402, by omega⟩ = .linear (.wire 639346) (.wire 7419) true
  node_639403 : g.nodes ⟨639403, by omega⟩ = .product (.wire 560335) (.wire 639402)
  node_639404 : g.nodes ⟨639404, by omega⟩ = .linear (.wire 7419) (.wire 639403) false
  node_639405 : g.nodes ⟨639405, by omega⟩ = .linear (.wire 639357) (.wire 7420) true
  node_639406 : g.nodes ⟨639406, by omega⟩ = .product (.wire 560335) (.wire 639405)
  node_639407 : g.nodes ⟨639407, by omega⟩ = .linear (.wire 7420) (.wire 639406) false
  node_639408 : g.nodes ⟨639408, by omega⟩ = .linear (.wire 639368) (.wire 7421) true
  node_639409 : g.nodes ⟨639409, by omega⟩ = .product (.wire 560335) (.wire 639408)
  node_639410 : g.nodes ⟨639410, by omega⟩ = .linear (.wire 7421) (.wire 639409) false
  node_639411 : g.nodes ⟨639411, by omega⟩ = .linear (.wire 639379) (.wire 7422) true
  node_639412 : g.nodes ⟨639412, by omega⟩ = .product (.wire 560335) (.wire 639411)
  node_639413 : g.nodes ⟨639413, by omega⟩ = .linear (.wire 7422) (.wire 639412) false
  node_639414 : g.nodes ⟨639414, by omega⟩ = .linear (.wire 639345) (.wire 7423) true
  node_639415 : g.nodes ⟨639415, by omega⟩ = .product (.wire 560335) (.wire 639414)
  node_639416 : g.nodes ⟨639416, by omega⟩ = .linear (.wire 7423) (.wire 639415) false
  node_639417 : g.nodes ⟨639417, by omega⟩ = .linear (.wire 639356) (.wire 7424) true
  node_639418 : g.nodes ⟨639418, by omega⟩ = .product (.wire 560335) (.wire 639417)
  node_639419 : g.nodes ⟨639419, by omega⟩ = .linear (.wire 7424) (.wire 639418) false
  node_639420 : g.nodes ⟨639420, by omega⟩ = .linear (.wire 639367) (.wire 7425) true
  node_639421 : g.nodes ⟨639421, by omega⟩ = .product (.wire 560335) (.wire 639420)
  node_639422 : g.nodes ⟨639422, by omega⟩ = .linear (.wire 7425) (.wire 639421) false
  node_641855 : g.nodes ⟨641855, by omega⟩ = .linear (.wire 7426) (.wire 641820) true
  node_641856 : g.nodes ⟨641856, by omega⟩ = .product (.wire 560340) (.wire 641855)
  node_641857 : g.nodes ⟨641857, by omega⟩ = .linear (.wire 641820) (.wire 641856) false
  node_641858 : g.nodes ⟨641858, by omega⟩ = .linear (.wire 7427) (.wire 641831) true
  node_641859 : g.nodes ⟨641859, by omega⟩ = .product (.wire 560340) (.wire 641858)
  node_641860 : g.nodes ⟨641860, by omega⟩ = .linear (.wire 641831) (.wire 641859) false
  node_641861 : g.nodes ⟨641861, by omega⟩ = .linear (.wire 7428) (.wire 641842) true
  node_641862 : g.nodes ⟨641862, by omega⟩ = .product (.wire 560340) (.wire 641861)
  node_641863 : g.nodes ⟨641863, by omega⟩ = .linear (.wire 641842) (.wire 641862) false
  node_641864 : g.nodes ⟨641864, by omega⟩ = .linear (.wire 7429) (.wire 641853) true
  node_641865 : g.nodes ⟨641865, by omega⟩ = .product (.wire 560340) (.wire 641864)
  node_641866 : g.nodes ⟨641866, by omega⟩ = .linear (.wire 641853) (.wire 641865) false
  node_641867 : g.nodes ⟨641867, by omega⟩ = .linear (.wire 7430) (.wire 641819) true
  node_641868 : g.nodes ⟨641868, by omega⟩ = .product (.wire 560340) (.wire 641867)
  node_641869 : g.nodes ⟨641869, by omega⟩ = .linear (.wire 641819) (.wire 641868) false
  node_641870 : g.nodes ⟨641870, by omega⟩ = .linear (.wire 7431) (.wire 641830) true
  node_641871 : g.nodes ⟨641871, by omega⟩ = .product (.wire 560340) (.wire 641870)
  node_641872 : g.nodes ⟨641872, by omega⟩ = .linear (.wire 641830) (.wire 641871) false
  node_641873 : g.nodes ⟨641873, by omega⟩ = .linear (.wire 7432) (.wire 641841) true
  node_641874 : g.nodes ⟨641874, by omega⟩ = .product (.wire 560340) (.wire 641873)
  node_641875 : g.nodes ⟨641875, by omega⟩ = .linear (.wire 641841) (.wire 641874) false
  node_641876 : g.nodes ⟨641876, by omega⟩ = .linear (.wire 641820) (.wire 7426) true
  node_641877 : g.nodes ⟨641877, by omega⟩ = .product (.wire 560340) (.wire 641876)
  node_641878 : g.nodes ⟨641878, by omega⟩ = .linear (.wire 7426) (.wire 641877) false
  node_641879 : g.nodes ⟨641879, by omega⟩ = .linear (.wire 641831) (.wire 7427) true
  node_641880 : g.nodes ⟨641880, by omega⟩ = .product (.wire 560340) (.wire 641879)
  node_641881 : g.nodes ⟨641881, by omega⟩ = .linear (.wire 7427) (.wire 641880) false
  node_641882 : g.nodes ⟨641882, by omega⟩ = .linear (.wire 641842) (.wire 7428) true
  node_641883 : g.nodes ⟨641883, by omega⟩ = .product (.wire 560340) (.wire 641882)
  node_641884 : g.nodes ⟨641884, by omega⟩ = .linear (.wire 7428) (.wire 641883) false
  node_641885 : g.nodes ⟨641885, by omega⟩ = .linear (.wire 641853) (.wire 7429) true
  node_641886 : g.nodes ⟨641886, by omega⟩ = .product (.wire 560340) (.wire 641885)
  node_641887 : g.nodes ⟨641887, by omega⟩ = .linear (.wire 7429) (.wire 641886) false
  node_641888 : g.nodes ⟨641888, by omega⟩ = .linear (.wire 641819) (.wire 7430) true
  node_641889 : g.nodes ⟨641889, by omega⟩ = .product (.wire 560340) (.wire 641888)
  node_641890 : g.nodes ⟨641890, by omega⟩ = .linear (.wire 7430) (.wire 641889) false
  node_641891 : g.nodes ⟨641891, by omega⟩ = .linear (.wire 641830) (.wire 7431) true
  node_641892 : g.nodes ⟨641892, by omega⟩ = .product (.wire 560340) (.wire 641891)
  node_641893 : g.nodes ⟨641893, by omega⟩ = .linear (.wire 7431) (.wire 641892) false
  node_641894 : g.nodes ⟨641894, by omega⟩ = .linear (.wire 641841) (.wire 7432) true
  node_641895 : g.nodes ⟨641895, by omega⟩ = .product (.wire 560340) (.wire 641894)
  node_641896 : g.nodes ⟨641896, by omega⟩ = .linear (.wire 7432) (.wire 641895) false
  node_644329 : g.nodes ⟨644329, by omega⟩ = .linear (.wire 7433) (.wire 644294) true
  node_644330 : g.nodes ⟨644330, by omega⟩ = .product (.wire 560345) (.wire 644329)
  node_644331 : g.nodes ⟨644331, by omega⟩ = .linear (.wire 644294) (.wire 644330) false
  node_644332 : g.nodes ⟨644332, by omega⟩ = .linear (.wire 7434) (.wire 644305) true
  node_644333 : g.nodes ⟨644333, by omega⟩ = .product (.wire 560345) (.wire 644332)
  node_644334 : g.nodes ⟨644334, by omega⟩ = .linear (.wire 644305) (.wire 644333) false
  node_644335 : g.nodes ⟨644335, by omega⟩ = .linear (.wire 7435) (.wire 644316) true
  node_644336 : g.nodes ⟨644336, by omega⟩ = .product (.wire 560345) (.wire 644335)
  node_644337 : g.nodes ⟨644337, by omega⟩ = .linear (.wire 644316) (.wire 644336) false
  node_644338 : g.nodes ⟨644338, by omega⟩ = .linear (.wire 7436) (.wire 644327) true
  node_644339 : g.nodes ⟨644339, by omega⟩ = .product (.wire 560345) (.wire 644338)
  node_644340 : g.nodes ⟨644340, by omega⟩ = .linear (.wire 644327) (.wire 644339) false
  node_644341 : g.nodes ⟨644341, by omega⟩ = .linear (.wire 7437) (.wire 644293) true
  node_644342 : g.nodes ⟨644342, by omega⟩ = .product (.wire 560345) (.wire 644341)
  node_644343 : g.nodes ⟨644343, by omega⟩ = .linear (.wire 644293) (.wire 644342) false
  node_644344 : g.nodes ⟨644344, by omega⟩ = .linear (.wire 7438) (.wire 644304) true
  node_644345 : g.nodes ⟨644345, by omega⟩ = .product (.wire 560345) (.wire 644344)
  node_644346 : g.nodes ⟨644346, by omega⟩ = .linear (.wire 644304) (.wire 644345) false
  node_644347 : g.nodes ⟨644347, by omega⟩ = .linear (.wire 7439) (.wire 644315) true
  node_644348 : g.nodes ⟨644348, by omega⟩ = .product (.wire 560345) (.wire 644347)
  node_644349 : g.nodes ⟨644349, by omega⟩ = .linear (.wire 644315) (.wire 644348) false
  node_644350 : g.nodes ⟨644350, by omega⟩ = .linear (.wire 644294) (.wire 7433) true
  node_644351 : g.nodes ⟨644351, by omega⟩ = .product (.wire 560345) (.wire 644350)
  node_644352 : g.nodes ⟨644352, by omega⟩ = .linear (.wire 7433) (.wire 644351) false
  node_644353 : g.nodes ⟨644353, by omega⟩ = .linear (.wire 644305) (.wire 7434) true
  node_644354 : g.nodes ⟨644354, by omega⟩ = .product (.wire 560345) (.wire 644353)
  node_644355 : g.nodes ⟨644355, by omega⟩ = .linear (.wire 7434) (.wire 644354) false
  node_644356 : g.nodes ⟨644356, by omega⟩ = .linear (.wire 644316) (.wire 7435) true
  node_644357 : g.nodes ⟨644357, by omega⟩ = .product (.wire 560345) (.wire 644356)
  node_644358 : g.nodes ⟨644358, by omega⟩ = .linear (.wire 7435) (.wire 644357) false
  node_644359 : g.nodes ⟨644359, by omega⟩ = .linear (.wire 644327) (.wire 7436) true
  node_644360 : g.nodes ⟨644360, by omega⟩ = .product (.wire 560345) (.wire 644359)
  node_644361 : g.nodes ⟨644361, by omega⟩ = .linear (.wire 7436) (.wire 644360) false
  node_644362 : g.nodes ⟨644362, by omega⟩ = .linear (.wire 644293) (.wire 7437) true
  node_644363 : g.nodes ⟨644363, by omega⟩ = .product (.wire 560345) (.wire 644362)
  node_644364 : g.nodes ⟨644364, by omega⟩ = .linear (.wire 7437) (.wire 644363) false
  node_644365 : g.nodes ⟨644365, by omega⟩ = .linear (.wire 644304) (.wire 7438) true
  node_644366 : g.nodes ⟨644366, by omega⟩ = .product (.wire 560345) (.wire 644365)
  node_644367 : g.nodes ⟨644367, by omega⟩ = .linear (.wire 7438) (.wire 644366) false
  node_644368 : g.nodes ⟨644368, by omega⟩ = .linear (.wire 644315) (.wire 7439) true
  node_644369 : g.nodes ⟨644369, by omega⟩ = .product (.wire 560345) (.wire 644368)
  node_644370 : g.nodes ⟨644370, by omega⟩ = .linear (.wire 7439) (.wire 644369) false
  node_646803 : g.nodes ⟨646803, by omega⟩ = .linear (.wire 646768) (.wire 17) true
  node_646804 : g.nodes ⟨646804, by omega⟩ = .product (.wire 7195) (.wire 646803)
  node_646805 : g.nodes ⟨646805, by omega⟩ = .linear (.wire 646779) (.wire 18) true
  node_646806 : g.nodes ⟨646806, by omega⟩ = .product (.wire 7195) (.wire 646805)
  node_646807 : g.nodes ⟨646807, by omega⟩ = .linear (.wire 646790) (.wire 19) true
  node_646808 : g.nodes ⟨646808, by omega⟩ = .product (.wire 7195) (.wire 646807)
  node_646809 : g.nodes ⟨646809, by omega⟩ = .linear (.wire 646801) (.wire 20) true
  node_646810 : g.nodes ⟨646810, by omega⟩ = .product (.wire 7195) (.wire 646809)
  node_646811 : g.nodes ⟨646811, by omega⟩ = .linear (.wire 646767) (.wire 21) true
  node_646812 : g.nodes ⟨646812, by omega⟩ = .product (.wire 7195) (.wire 646811)
  node_646813 : g.nodes ⟨646813, by omega⟩ = .linear (.wire 646778) (.wire 22) true
  node_646814 : g.nodes ⟨646814, by omega⟩ = .product (.wire 7195) (.wire 646813)
  node_646815 : g.nodes ⟨646815, by omega⟩ = .linear (.wire 646789) (.wire 23) true
  node_646816 : g.nodes ⟨646816, by omega⟩ = .product (.wire 7195) (.wire 646815)
  node_656523 : g.nodes ⟨656523, by omega⟩ = .linear (.wire 651640) (.wire 656488) true
  node_656524 : g.nodes ⟨656524, by omega⟩ = .product (.wire 7195) (.wire 656523)
  node_656525 : g.nodes ⟨656525, by omega⟩ = .linear (.wire 656488) (.wire 656524) false
  node_656526 : g.nodes ⟨656526, by omega⟩ = .linear (.wire 651651) (.wire 656499) true
  node_656527 : g.nodes ⟨656527, by omega⟩ = .product (.wire 7195) (.wire 656526)
  node_656528 : g.nodes ⟨656528, by omega⟩ = .linear (.wire 656499) (.wire 656527) false
  node_656529 : g.nodes ⟨656529, by omega⟩ = .linear (.wire 651662) (.wire 656510) true
  node_656530 : g.nodes ⟨656530, by omega⟩ = .product (.wire 7195) (.wire 656529)
  node_656531 : g.nodes ⟨656531, by omega⟩ = .linear (.wire 656510) (.wire 656530) false
  node_656532 : g.nodes ⟨656532, by omega⟩ = .linear (.wire 651673) (.wire 656521) true
  node_656533 : g.nodes ⟨656533, by omega⟩ = .product (.wire 7195) (.wire 656532)
  node_656534 : g.nodes ⟨656534, by omega⟩ = .linear (.wire 656521) (.wire 656533) false
  node_656535 : g.nodes ⟨656535, by omega⟩ = .linear (.wire 651639) (.wire 656487) true
  node_656536 : g.nodes ⟨656536, by omega⟩ = .product (.wire 7195) (.wire 656535)
  node_656537 : g.nodes ⟨656537, by omega⟩ = .linear (.wire 656487) (.wire 656536) false
  node_656538 : g.nodes ⟨656538, by omega⟩ = .linear (.wire 651650) (.wire 656498) true
  node_656539 : g.nodes ⟨656539, by omega⟩ = .product (.wire 7195) (.wire 656538)
  node_656540 : g.nodes ⟨656540, by omega⟩ = .linear (.wire 656498) (.wire 656539) false
  node_656541 : g.nodes ⟨656541, by omega⟩ = .linear (.wire 651661) (.wire 656509) true
  node_656542 : g.nodes ⟨656542, by omega⟩ = .product (.wire 7195) (.wire 656541)
  node_656543 : g.nodes ⟨656543, by omega⟩ = .linear (.wire 656509) (.wire 656542) false
  node_656544 : g.nodes ⟨656544, by omega⟩ = .linear (.wire 656525) (.wire 32) true
  node_656545 : g.nodes ⟨656545, by omega⟩ = .linear (.wire 656528) (.wire 33) true
  node_656546 : g.nodes ⟨656546, by omega⟩ = .linear (.wire 656531) (.wire 34) true
  node_656547 : g.nodes ⟨656547, by omega⟩ = .linear (.wire 656534) (.wire 35) true
  node_656548 : g.nodes ⟨656548, by omega⟩ = .linear (.wire 656537) (.wire 36) true
  node_656549 : g.nodes ⟨656549, by omega⟩ = .linear (.wire 656540) (.wire 37) true
  node_656550 : g.nodes ⟨656550, by omega⟩ = .linear (.wire 656543) (.wire 38) true
  node_659253 : g.nodes ⟨659253, by omega⟩ = .linear (.wire 7464) (.wire 659218) true
  node_659254 : g.nodes ⟨659254, by omega⟩ = .product (.wire 656830) (.wire 659253)
  node_659255 : g.nodes ⟨659255, by omega⟩ = .linear (.wire 7465) (.wire 659229) true
  node_659256 : g.nodes ⟨659256, by omega⟩ = .product (.wire 656830) (.wire 659255)
  node_659257 : g.nodes ⟨659257, by omega⟩ = .linear (.wire 7466) (.wire 659240) true
  node_659258 : g.nodes ⟨659258, by omega⟩ = .product (.wire 656830) (.wire 659257)
  node_659259 : g.nodes ⟨659259, by omega⟩ = .linear (.wire 7467) (.wire 659251) true
  node_659260 : g.nodes ⟨659260, by omega⟩ = .product (.wire 656830) (.wire 659259)
  node_659261 : g.nodes ⟨659261, by omega⟩ = .linear (.wire 7460) (.wire 659217) true
  node_659262 : g.nodes ⟨659262, by omega⟩ = .product (.wire 656830) (.wire 659261)
  node_659263 : g.nodes ⟨659263, by omega⟩ = .linear (.wire 7461) (.wire 659228) true
  node_659264 : g.nodes ⟨659264, by omega⟩ = .product (.wire 656830) (.wire 659263)
  node_659265 : g.nodes ⟨659265, by omega⟩ = .linear (.wire 7462) (.wire 659239) true
  node_659266 : g.nodes ⟨659266, by omega⟩ = .product (.wire 656830) (.wire 659265)
  node_659267 : g.nodes ⟨659267, by omega⟩ = .linear (.wire 7464) (.wire 62009) true
  node_659268 : g.nodes ⟨659268, by omega⟩ = .product (.wire 6914) (.wire 659267)
  node_659269 : g.nodes ⟨659269, by omega⟩ = .linear (.wire 7465) (.wire 62020) true
  node_659270 : g.nodes ⟨659270, by omega⟩ = .product (.wire 6914) (.wire 659269)
  node_659271 : g.nodes ⟨659271, by omega⟩ = .linear (.wire 7466) (.wire 62031) true
  node_659272 : g.nodes ⟨659272, by omega⟩ = .product (.wire 6914) (.wire 659271)
  node_659273 : g.nodes ⟨659273, by omega⟩ = .linear (.wire 7467) (.wire 62042) true
  node_659274 : g.nodes ⟨659274, by omega⟩ = .product (.wire 6914) (.wire 659273)
  node_659275 : g.nodes ⟨659275, by omega⟩ = .linear (.wire 7460) (.wire 62008) true
  node_659276 : g.nodes ⟨659276, by omega⟩ = .product (.wire 6914) (.wire 659275)
  node_659277 : g.nodes ⟨659277, by omega⟩ = .linear (.wire 7461) (.wire 62019) true
  node_659278 : g.nodes ⟨659278, by omega⟩ = .product (.wire 6914) (.wire 659277)
  node_659279 : g.nodes ⟨659279, by omega⟩ = .linear (.wire 7462) (.wire 62030) true
  node_659280 : g.nodes ⟨659280, by omega⟩ = .product (.wire 6914) (.wire 659279)
  node_659282 : g.nodes ⟨659282, by omega⟩ = .linear (.wire 7464) (.wire 86901) true
  node_659283 : g.nodes ⟨659283, by omega⟩ = .product (.wire 6916) (.wire 659282)
  node_659284 : g.nodes ⟨659284, by omega⟩ = .linear (.wire 7465) (.wire 86912) true
  node_659285 : g.nodes ⟨659285, by omega⟩ = .product (.wire 6916) (.wire 659284)
  node_659286 : g.nodes ⟨659286, by omega⟩ = .linear (.wire 7466) (.wire 86923) true
  node_659287 : g.nodes ⟨659287, by omega⟩ = .product (.wire 6916) (.wire 659286)
  node_659288 : g.nodes ⟨659288, by omega⟩ = .linear (.wire 7467) (.wire 86934) true
  node_659289 : g.nodes ⟨659289, by omega⟩ = .product (.wire 6916) (.wire 659288)
  node_659290 : g.nodes ⟨659290, by omega⟩ = .linear (.wire 7460) (.wire 86900) true
  node_659291 : g.nodes ⟨659291, by omega⟩ = .product (.wire 6916) (.wire 659290)
  node_659292 : g.nodes ⟨659292, by omega⟩ = .linear (.wire 7461) (.wire 86911) true
  node_659293 : g.nodes ⟨659293, by omega⟩ = .product (.wire 6916) (.wire 659292)
  node_659294 : g.nodes ⟨659294, by omega⟩ = .linear (.wire 7462) (.wire 86922) true
  node_659295 : g.nodes ⟨659295, by omega⟩ = .product (.wire 6916) (.wire 659294)
  node_666625 : g.nodes ⟨666625, by omega⟩ = .linear (.wire 666590) (.wire 39) true
  node_666626 : g.nodes ⟨666626, by omega⟩ = .linear (.wire 666601) (.wire 40) true
  node_666627 : g.nodes ⟨666627, by omega⟩ = .linear (.wire 666612) (.wire 41) true
  node_666628 : g.nodes ⟨666628, by omega⟩ = .linear (.wire 666623) (.wire 42) true
  node_666629 : g.nodes ⟨666629, by omega⟩ = .linear (.wire 666589) (.wire 43) true
  node_666630 : g.nodes ⟨666630, by omega⟩ = .linear (.wire 666600) (.wire 44) true
  node_666631 : g.nodes ⟨666631, by omega⟩ = .linear (.wire 666611) (.wire 45) true
  node_669318 : g.nodes ⟨669318, by omega⟩ = .linear (.wire 7482) (.wire 669283) true
  node_669319 : g.nodes ⟨669319, by omega⟩ = .linear (.wire 7483) (.wire 669294) true
  node_669320 : g.nodes ⟨669320, by omega⟩ = .linear (.wire 7484) (.wire 669305) true
  node_669321 : g.nodes ⟨669321, by omega⟩ = .linear (.wire 7485) (.wire 669316) true
  node_669322 : g.nodes ⟨669322, by omega⟩ = .linear (.wire 7478) (.wire 669282) true
  node_669323 : g.nodes ⟨669323, by omega⟩ = .linear (.wire 7479) (.wire 669293) true
  node_669324 : g.nodes ⟨669324, by omega⟩ = .linear (.wire 7480) (.wire 669304) true
  node_676610 : g.nodes ⟨676610, by omega⟩ = .linear (.wire 676575) (.wire 46) true
  node_676611 : g.nodes ⟨676611, by omega⟩ = .linear (.wire 676586) (.wire 47) true
  node_676612 : g.nodes ⟨676612, by omega⟩ = .linear (.wire 676597) (.wire 48) true
  node_676613 : g.nodes ⟨676613, by omega⟩ = .linear (.wire 676608) (.wire 49) true
  node_676614 : g.nodes ⟨676614, by omega⟩ = .linear (.wire 676574) (.wire 50) true
  node_676615 : g.nodes ⟨676615, by omega⟩ = .linear (.wire 676585) (.wire 51) true
  node_676616 : g.nodes ⟨676616, by omega⟩ = .linear (.wire 676596) (.wire 52) true
  eq_0 : ((.wire 6920), (.constant (0 : K))) ∈ g.equalities
  eq_1 : ((.wire 6922), (.constant (0 : K))) ∈ g.equalities
  eq_2 : ((.wire 6924), (.constant (0 : K))) ∈ g.equalities
  eq_3 : ((.wire 6926), (.constant (0 : K))) ∈ g.equalities
  eq_4 : ((.wire 6928), (.constant (0 : K))) ∈ g.equalities
  eq_5 : ((.wire 6930), (.constant (0 : K))) ∈ g.equalities
  eq_6 : ((.wire 659254), (.constant (0 : K))) ∈ g.equalities
  eq_7 : ((.wire 659256), (.constant (0 : K))) ∈ g.equalities
  eq_8 : ((.wire 659258), (.constant (0 : K))) ∈ g.equalities
  eq_9 : ((.wire 659260), (.constant (0 : K))) ∈ g.equalities
  eq_10 : ((.wire 659262), (.constant (0 : K))) ∈ g.equalities
  eq_11 : ((.wire 659264), (.constant (0 : K))) ∈ g.equalities
  eq_12 : ((.wire 659266), (.constant (0 : K))) ∈ g.equalities
  eq_13 : ((.wire 669318), (.constant (0 : K))) ∈ g.equalities
  eq_14 : ((.wire 669319), (.constant (0 : K))) ∈ g.equalities
  eq_15 : ((.wire 669320), (.constant (0 : K))) ∈ g.equalities
  eq_16 : ((.wire 669321), (.constant (0 : K))) ∈ g.equalities
  eq_17 : ((.wire 669322), (.constant (0 : K))) ∈ g.equalities
  eq_18 : ((.wire 669323), (.constant (0 : K))) ∈ g.equalities
  eq_19 : ((.wire 669324), (.constant (0 : K))) ∈ g.equalities
  eq_20 : ((.wire 458068), (.constant (0 : K))) ∈ g.equalities
  eq_21 : ((.wire 458070), (.constant (0 : K))) ∈ g.equalities
  eq_22 : ((.wire 458072), (.constant (0 : K))) ∈ g.equalities
  eq_23 : ((.wire 458074), (.constant (0 : K))) ∈ g.equalities
  eq_24 : ((.wire 458076), (.constant (0 : K))) ∈ g.equalities
  eq_25 : ((.wire 458078), (.constant (0 : K))) ∈ g.equalities
  eq_26 : ((.wire 458080), (.constant (0 : K))) ∈ g.equalities
  eq_27 : ((.wire 659268), (.constant (0 : K))) ∈ g.equalities
  eq_28 : ((.wire 659270), (.constant (0 : K))) ∈ g.equalities
  eq_29 : ((.wire 659272), (.constant (0 : K))) ∈ g.equalities
  eq_30 : ((.wire 659274), (.constant (0 : K))) ∈ g.equalities
  eq_31 : ((.wire 659276), (.constant (0 : K))) ∈ g.equalities
  eq_32 : ((.wire 659278), (.constant (0 : K))) ∈ g.equalities
  eq_33 : ((.wire 659280), (.constant (0 : K))) ∈ g.equalities
  eq_34 : ((.wire 458082), (.constant (0 : K))) ∈ g.equalities
  eq_35 : ((.wire 458084), (.constant (0 : K))) ∈ g.equalities
  eq_36 : ((.wire 458086), (.constant (0 : K))) ∈ g.equalities
  eq_37 : ((.wire 458088), (.constant (0 : K))) ∈ g.equalities
  eq_38 : ((.wire 458090), (.constant (0 : K))) ∈ g.equalities
  eq_39 : ((.wire 458092), (.constant (0 : K))) ∈ g.equalities
  eq_40 : ((.wire 458094), (.constant (0 : K))) ∈ g.equalities
  eq_41 : ((.wire 560133), (.constant (0 : K))) ∈ g.equalities
  eq_42 : ((.wire 560135), (.constant (0 : K))) ∈ g.equalities
  eq_43 : ((.wire 560137), (.constant (0 : K))) ∈ g.equalities
  eq_44 : ((.wire 560139), (.constant (0 : K))) ∈ g.equalities
  eq_45 : ((.wire 560141), (.constant (0 : K))) ∈ g.equalities
  eq_46 : ((.wire 560143), (.constant (0 : K))) ∈ g.equalities
  eq_47 : ((.wire 560145), (.constant (0 : K))) ∈ g.equalities
  eq_48 : ((.wire 659283), (.constant (0 : K))) ∈ g.equalities
  eq_49 : ((.wire 659285), (.constant (0 : K))) ∈ g.equalities
  eq_50 : ((.wire 659287), (.constant (0 : K))) ∈ g.equalities
  eq_51 : ((.wire 659289), (.constant (0 : K))) ∈ g.equalities
  eq_52 : ((.wire 659291), (.constant (0 : K))) ∈ g.equalities
  eq_53 : ((.wire 659293), (.constant (0 : K))) ∈ g.equalities
  eq_54 : ((.wire 659295), (.constant (0 : K))) ∈ g.equalities
  eq_55 : ((.wire 458096), (.constant (0 : K))) ∈ g.equalities
  eq_56 : ((.wire 458098), (.constant (0 : K))) ∈ g.equalities
  eq_57 : ((.wire 458100), (.constant (0 : K))) ∈ g.equalities
  eq_58 : ((.wire 458102), (.constant (0 : K))) ∈ g.equalities
  eq_59 : ((.wire 458104), (.constant (0 : K))) ∈ g.equalities
  eq_60 : ((.wire 458106), (.constant (0 : K))) ∈ g.equalities
  eq_61 : ((.wire 458108), (.constant (0 : K))) ∈ g.equalities
  eq_62 : ((.wire 666625), (.constant (0 : K))) ∈ g.equalities
  eq_63 : ((.wire 666626), (.constant (0 : K))) ∈ g.equalities
  eq_64 : ((.wire 666627), (.constant (0 : K))) ∈ g.equalities
  eq_65 : ((.wire 666628), (.constant (0 : K))) ∈ g.equalities
  eq_66 : ((.wire 666629), (.constant (0 : K))) ∈ g.equalities
  eq_67 : ((.wire 666630), (.constant (0 : K))) ∈ g.equalities
  eq_68 : ((.wire 666631), (.constant (0 : K))) ∈ g.equalities
  eq_69 : ((.wire 676610), (.constant (0 : K))) ∈ g.equalities
  eq_70 : ((.wire 676611), (.constant (0 : K))) ∈ g.equalities
  eq_71 : ((.wire 676612), (.constant (0 : K))) ∈ g.equalities
  eq_72 : ((.wire 676613), (.constant (0 : K))) ∈ g.equalities
  eq_73 : ((.wire 676614), (.constant (0 : K))) ∈ g.equalities
  eq_74 : ((.wire 676615), (.constant (0 : K))) ∈ g.equalities
  eq_75 : ((.wire 676616), (.constant (0 : K))) ∈ g.equalities
  eq_76 : ((.wire 458025), (.constant (0 : K))) ∈ g.equalities
  eq_77 : ((.wire 458027), (.constant (0 : K))) ∈ g.equalities
  eq_78 : ((.wire 458029), (.constant (0 : K))) ∈ g.equalities
  eq_79 : ((.wire 458031), (.constant (0 : K))) ∈ g.equalities
  eq_80 : ((.wire 458033), (.constant (0 : K))) ∈ g.equalities
  eq_81 : ((.wire 458035), (.constant (0 : K))) ∈ g.equalities
  eq_82 : ((.wire 458037), (.constant (0 : K))) ∈ g.equalities
  eq_83 : ((.wire 554472), (.constant (0 : K))) ∈ g.equalities
  eq_84 : ((.wire 554473), (.constant (0 : K))) ∈ g.equalities
  eq_85 : ((.wire 554474), (.constant (0 : K))) ∈ g.equalities
  eq_86 : ((.wire 554475), (.constant (0 : K))) ∈ g.equalities
  eq_87 : ((.wire 554476), (.constant (0 : K))) ∈ g.equalities
  eq_88 : ((.wire 554477), (.constant (0 : K))) ∈ g.equalities
  eq_89 : ((.wire 554478), (.constant (0 : K))) ∈ g.equalities
  eq_90 : ((.wire 544722), (.constant (0 : K))) ∈ g.equalities
  eq_91 : ((.wire 544724), (.constant (0 : K))) ∈ g.equalities
  eq_92 : ((.wire 544726), (.constant (0 : K))) ∈ g.equalities
  eq_93 : ((.wire 544728), (.constant (0 : K))) ∈ g.equalities
  eq_94 : ((.wire 544730), (.constant (0 : K))) ∈ g.equalities
  eq_95 : ((.wire 544732), (.constant (0 : K))) ∈ g.equalities
  eq_96 : ((.wire 544734), (.constant (0 : K))) ∈ g.equalities
  eq_97 : ((.wire 560119), (.constant (0 : K))) ∈ g.equalities
  eq_98 : ((.wire 560121), (.constant (0 : K))) ∈ g.equalities
  eq_99 : ((.wire 560123), (.constant (0 : K))) ∈ g.equalities
  eq_100 : ((.wire 560125), (.constant (0 : K))) ∈ g.equalities
  eq_101 : ((.wire 560127), (.constant (0 : K))) ∈ g.equalities
  eq_102 : ((.wire 560129), (.constant (0 : K))) ∈ g.equalities
  eq_103 : ((.wire 560131), (.constant (0 : K))) ∈ g.equalities
  eq_104 : ((.wire 656544), (.constant (0 : K))) ∈ g.equalities
  eq_105 : ((.wire 656545), (.constant (0 : K))) ∈ g.equalities
  eq_106 : ((.wire 656546), (.constant (0 : K))) ∈ g.equalities
  eq_107 : ((.wire 656547), (.constant (0 : K))) ∈ g.equalities
  eq_108 : ((.wire 656548), (.constant (0 : K))) ∈ g.equalities
  eq_109 : ((.wire 656549), (.constant (0 : K))) ∈ g.equalities
  eq_110 : ((.wire 656550), (.constant (0 : K))) ∈ g.equalities
  eq_111 : ((.wire 646804), (.constant (0 : K))) ∈ g.equalities
  eq_112 : ((.wire 646806), (.constant (0 : K))) ∈ g.equalities
  eq_113 : ((.wire 646808), (.constant (0 : K))) ∈ g.equalities
  eq_114 : ((.wire 646810), (.constant (0 : K))) ∈ g.equalities
  eq_115 : ((.wire 646812), (.constant (0 : K))) ∈ g.equalities
  eq_116 : ((.wire 646814), (.constant (0 : K))) ∈ g.equalities
  eq_117 : ((.wire 646816), (.constant (0 : K))) ∈ g.equalities

def certificate_0 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 6913) := {
  difference := (.wire 6919)
  product := (.wire 6920)
  subtract := Or.inl ⟨⟨6919, by omega⟩, f.node_6919, rfl⟩
  multiply := Or.inl ⟨⟨6920, by omega⟩, f.node_6920, rfl⟩
  zero := f.eq_0
}

def certificate_1 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 6914) := {
  difference := (.wire 6921)
  product := (.wire 6922)
  subtract := Or.inl ⟨⟨6921, by omega⟩, f.node_6921, rfl⟩
  multiply := Or.inl ⟨⟨6922, by omega⟩, f.node_6922, rfl⟩
  zero := f.eq_1
}

def certificate_2 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 6915) := {
  difference := (.wire 6923)
  product := (.wire 6924)
  subtract := Or.inl ⟨⟨6923, by omega⟩, f.node_6923, rfl⟩
  multiply := Or.inl ⟨⟨6924, by omega⟩, f.node_6924, rfl⟩
  zero := f.eq_2
}

def certificate_3 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 6916) := {
  difference := (.wire 6925)
  product := (.wire 6926)
  subtract := Or.inl ⟨⟨6925, by omega⟩, f.node_6925, rfl⟩
  multiply := Or.inl ⟨⟨6926, by omega⟩, f.node_6926, rfl⟩
  zero := f.eq_3
}

def certificate_4 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 6917) := {
  difference := (.wire 6927)
  product := (.wire 6928)
  subtract := Or.inl ⟨⟨6927, by omega⟩, f.node_6927, rfl⟩
  multiply := Or.inl ⟨⟨6928, by omega⟩, f.node_6928, rfl⟩
  zero := f.eq_4
}

def certificate_5 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 6918) := {
  difference := (.wire 6929)
  product := (.wire 6930)
  subtract := Or.inl ⟨⟨6929, by omega⟩, f.node_6929, rfl⟩
  multiply := Or.inl ⟨⟨6930, by omega⟩, f.node_6930, rfl⟩
  zero := f.eq_5
}

def certificate_6 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 656830) (.wire 7464) (.wire 659218) := {
  difference := (.wire 659253)
  product := (.wire 659254)
  subtract := Or.inl ⟨⟨659253, by omega⟩, f.node_659253, rfl⟩
  multiply := Or.inl ⟨⟨659254, by omega⟩, f.node_659254, rfl⟩
  zero := f.eq_6
}

def certificate_7 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 656830) (.wire 7465) (.wire 659229) := {
  difference := (.wire 659255)
  product := (.wire 659256)
  subtract := Or.inl ⟨⟨659255, by omega⟩, f.node_659255, rfl⟩
  multiply := Or.inl ⟨⟨659256, by omega⟩, f.node_659256, rfl⟩
  zero := f.eq_7
}

def certificate_8 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 656830) (.wire 7466) (.wire 659240) := {
  difference := (.wire 659257)
  product := (.wire 659258)
  subtract := Or.inl ⟨⟨659257, by omega⟩, f.node_659257, rfl⟩
  multiply := Or.inl ⟨⟨659258, by omega⟩, f.node_659258, rfl⟩
  zero := f.eq_8
}

def certificate_9 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 656830) (.wire 7467) (.wire 659251) := {
  difference := (.wire 659259)
  product := (.wire 659260)
  subtract := Or.inl ⟨⟨659259, by omega⟩, f.node_659259, rfl⟩
  multiply := Or.inl ⟨⟨659260, by omega⟩, f.node_659260, rfl⟩
  zero := f.eq_9
}

def certificate_10 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 656830) (.wire 7460) (.wire 659217) := {
  difference := (.wire 659261)
  product := (.wire 659262)
  subtract := Or.inl ⟨⟨659261, by omega⟩, f.node_659261, rfl⟩
  multiply := Or.inl ⟨⟨659262, by omega⟩, f.node_659262, rfl⟩
  zero := f.eq_10
}

def certificate_11 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 656830) (.wire 7461) (.wire 659228) := {
  difference := (.wire 659263)
  product := (.wire 659264)
  subtract := Or.inl ⟨⟨659263, by omega⟩, f.node_659263, rfl⟩
  multiply := Or.inl ⟨⟨659264, by omega⟩, f.node_659264, rfl⟩
  zero := f.eq_11
}

def certificate_12 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 656830) (.wire 7462) (.wire 659239) := {
  difference := (.wire 659265)
  product := (.wire 659266)
  subtract := Or.inl ⟨⟨659265, by omega⟩, f.node_659265, rfl⟩
  multiply := Or.inl ⟨⟨659266, by omega⟩, f.node_659266, rfl⟩
  zero := f.eq_12
}

def certificate_13 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 7482) (.wire 669283) := {
  difference := (.wire 669318)
  product := (.wire 669318)
  subtract := Or.inl ⟨⟨669318, by omega⟩, f.node_669318, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_13
}

def certificate_14 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 7483) (.wire 669294) := {
  difference := (.wire 669319)
  product := (.wire 669319)
  subtract := Or.inl ⟨⟨669319, by omega⟩, f.node_669319, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_14
}

def certificate_15 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 7484) (.wire 669305) := {
  difference := (.wire 669320)
  product := (.wire 669320)
  subtract := Or.inl ⟨⟨669320, by omega⟩, f.node_669320, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_15
}

def certificate_16 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 7485) (.wire 669316) := {
  difference := (.wire 669321)
  product := (.wire 669321)
  subtract := Or.inl ⟨⟨669321, by omega⟩, f.node_669321, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_16
}

def certificate_17 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 7478) (.wire 669282) := {
  difference := (.wire 669322)
  product := (.wire 669322)
  subtract := Or.inl ⟨⟨669322, by omega⟩, f.node_669322, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_17
}

def certificate_18 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 7479) (.wire 669293) := {
  difference := (.wire 669323)
  product := (.wire 669323)
  subtract := Or.inl ⟨⟨669323, by omega⟩, f.node_669323, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_18
}

def certificate_19 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 7480) (.wire 669304) := {
  difference := (.wire 669324)
  product := (.wire 669324)
  subtract := Or.inl ⟨⟨669324, by omega⟩, f.node_669324, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_19
}

def certificate_20 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 458066) (.wire 6956) (.wire 52292) := {
  difference := (.wire 458067)
  product := (.wire 458068)
  subtract := Or.inl ⟨⟨458067, by omega⟩, f.node_458067, rfl⟩
  multiply := Or.inl ⟨⟨458068, by omega⟩, f.node_458068, rfl⟩
  zero := f.eq_20
}

def certificate_21 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 458066) (.wire 6957) (.wire 52303) := {
  difference := (.wire 458069)
  product := (.wire 458070)
  subtract := Or.inl ⟨⟨458069, by omega⟩, f.node_458069, rfl⟩
  multiply := Or.inl ⟨⟨458070, by omega⟩, f.node_458070, rfl⟩
  zero := f.eq_21
}

def certificate_22 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 458066) (.wire 6958) (.wire 52314) := {
  difference := (.wire 458071)
  product := (.wire 458072)
  subtract := Or.inl ⟨⟨458071, by omega⟩, f.node_458071, rfl⟩
  multiply := Or.inl ⟨⟨458072, by omega⟩, f.node_458072, rfl⟩
  zero := f.eq_22
}

def certificate_23 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 458066) (.wire 6959) (.wire 52325) := {
  difference := (.wire 458073)
  product := (.wire 458074)
  subtract := Or.inl ⟨⟨458073, by omega⟩, f.node_458073, rfl⟩
  multiply := Or.inl ⟨⟨458074, by omega⟩, f.node_458074, rfl⟩
  zero := f.eq_23
}

def certificate_24 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 458066) (.wire 6952) (.wire 52291) := {
  difference := (.wire 458075)
  product := (.wire 458076)
  subtract := Or.inl ⟨⟨458075, by omega⟩, f.node_458075, rfl⟩
  multiply := Or.inl ⟨⟨458076, by omega⟩, f.node_458076, rfl⟩
  zero := f.eq_24
}

def certificate_25 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 458066) (.wire 6953) (.wire 52302) := {
  difference := (.wire 458077)
  product := (.wire 458078)
  subtract := Or.inl ⟨⟨458077, by omega⟩, f.node_458077, rfl⟩
  multiply := Or.inl ⟨⟨458078, by omega⟩, f.node_458078, rfl⟩
  zero := f.eq_25
}

def certificate_26 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 458066) (.wire 6954) (.wire 52313) := {
  difference := (.wire 458079)
  product := (.wire 458080)
  subtract := Or.inl ⟨⟨458079, by omega⟩, f.node_458079, rfl⟩
  multiply := Or.inl ⟨⟨458080, by omega⟩, f.node_458080, rfl⟩
  zero := f.eq_26
}

def certificate_27 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6914) (.wire 7464) (.wire 62009) := {
  difference := (.wire 659267)
  product := (.wire 659268)
  subtract := Or.inl ⟨⟨659267, by omega⟩, f.node_659267, rfl⟩
  multiply := Or.inl ⟨⟨659268, by omega⟩, f.node_659268, rfl⟩
  zero := f.eq_27
}

def certificate_28 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6914) (.wire 7465) (.wire 62020) := {
  difference := (.wire 659269)
  product := (.wire 659270)
  subtract := Or.inl ⟨⟨659269, by omega⟩, f.node_659269, rfl⟩
  multiply := Or.inl ⟨⟨659270, by omega⟩, f.node_659270, rfl⟩
  zero := f.eq_28
}

def certificate_29 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6914) (.wire 7466) (.wire 62031) := {
  difference := (.wire 659271)
  product := (.wire 659272)
  subtract := Or.inl ⟨⟨659271, by omega⟩, f.node_659271, rfl⟩
  multiply := Or.inl ⟨⟨659272, by omega⟩, f.node_659272, rfl⟩
  zero := f.eq_29
}

def certificate_30 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6914) (.wire 7467) (.wire 62042) := {
  difference := (.wire 659273)
  product := (.wire 659274)
  subtract := Or.inl ⟨⟨659273, by omega⟩, f.node_659273, rfl⟩
  multiply := Or.inl ⟨⟨659274, by omega⟩, f.node_659274, rfl⟩
  zero := f.eq_30
}

def certificate_31 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6914) (.wire 7460) (.wire 62008) := {
  difference := (.wire 659275)
  product := (.wire 659276)
  subtract := Or.inl ⟨⟨659275, by omega⟩, f.node_659275, rfl⟩
  multiply := Or.inl ⟨⟨659276, by omega⟩, f.node_659276, rfl⟩
  zero := f.eq_31
}

def certificate_32 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6914) (.wire 7461) (.wire 62019) := {
  difference := (.wire 659277)
  product := (.wire 659278)
  subtract := Or.inl ⟨⟨659277, by omega⟩, f.node_659277, rfl⟩
  multiply := Or.inl ⟨⟨659278, by omega⟩, f.node_659278, rfl⟩
  zero := f.eq_32
}

def certificate_33 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6914) (.wire 7462) (.wire 62030) := {
  difference := (.wire 659279)
  product := (.wire 659280)
  subtract := Or.inl ⟨⟨659279, by omega⟩, f.node_659279, rfl⟩
  multiply := Or.inl ⟨⟨659280, by omega⟩, f.node_659280, rfl⟩
  zero := f.eq_33
}

def certificate_34 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6915) (.wire 6956) (.wire 66841) := {
  difference := (.wire 458081)
  product := (.wire 458082)
  subtract := Or.inl ⟨⟨458081, by omega⟩, f.node_458081, rfl⟩
  multiply := Or.inl ⟨⟨458082, by omega⟩, f.node_458082, rfl⟩
  zero := f.eq_34
}

def certificate_35 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6915) (.wire 6957) (.wire 66852) := {
  difference := (.wire 458083)
  product := (.wire 458084)
  subtract := Or.inl ⟨⟨458083, by omega⟩, f.node_458083, rfl⟩
  multiply := Or.inl ⟨⟨458084, by omega⟩, f.node_458084, rfl⟩
  zero := f.eq_35
}

def certificate_36 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6915) (.wire 6958) (.wire 66863) := {
  difference := (.wire 458085)
  product := (.wire 458086)
  subtract := Or.inl ⟨⟨458085, by omega⟩, f.node_458085, rfl⟩
  multiply := Or.inl ⟨⟨458086, by omega⟩, f.node_458086, rfl⟩
  zero := f.eq_36
}

def certificate_37 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6915) (.wire 6959) (.wire 66874) := {
  difference := (.wire 458087)
  product := (.wire 458088)
  subtract := Or.inl ⟨⟨458087, by omega⟩, f.node_458087, rfl⟩
  multiply := Or.inl ⟨⟨458088, by omega⟩, f.node_458088, rfl⟩
  zero := f.eq_37
}

def certificate_38 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6915) (.wire 6952) (.wire 66840) := {
  difference := (.wire 458089)
  product := (.wire 458090)
  subtract := Or.inl ⟨⟨458089, by omega⟩, f.node_458089, rfl⟩
  multiply := Or.inl ⟨⟨458090, by omega⟩, f.node_458090, rfl⟩
  zero := f.eq_38
}

def certificate_39 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6915) (.wire 6953) (.wire 66851) := {
  difference := (.wire 458091)
  product := (.wire 458092)
  subtract := Or.inl ⟨⟨458091, by omega⟩, f.node_458091, rfl⟩
  multiply := Or.inl ⟨⟨458092, by omega⟩, f.node_458092, rfl⟩
  zero := f.eq_39
}

def certificate_40 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6915) (.wire 6954) (.wire 66862) := {
  difference := (.wire 458093)
  product := (.wire 458094)
  subtract := Or.inl ⟨⟨458093, by omega⟩, f.node_458093, rfl⟩
  multiply := Or.inl ⟨⟨458094, by omega⟩, f.node_458094, rfl⟩
  zero := f.eq_40
}

def certificate_41 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6915) (.wire 7211) (.wire 52292) := {
  difference := (.wire 560132)
  product := (.wire 560133)
  subtract := Or.inl ⟨⟨560132, by omega⟩, f.node_560132, rfl⟩
  multiply := Or.inl ⟨⟨560133, by omega⟩, f.node_560133, rfl⟩
  zero := f.eq_41
}

def certificate_42 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6915) (.wire 7212) (.wire 52303) := {
  difference := (.wire 560134)
  product := (.wire 560135)
  subtract := Or.inl ⟨⟨560134, by omega⟩, f.node_560134, rfl⟩
  multiply := Or.inl ⟨⟨560135, by omega⟩, f.node_560135, rfl⟩
  zero := f.eq_42
}

def certificate_43 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6915) (.wire 7213) (.wire 52314) := {
  difference := (.wire 560136)
  product := (.wire 560137)
  subtract := Or.inl ⟨⟨560136, by omega⟩, f.node_560136, rfl⟩
  multiply := Or.inl ⟨⟨560137, by omega⟩, f.node_560137, rfl⟩
  zero := f.eq_43
}

def certificate_44 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6915) (.wire 7214) (.wire 52325) := {
  difference := (.wire 560138)
  product := (.wire 560139)
  subtract := Or.inl ⟨⟨560138, by omega⟩, f.node_560138, rfl⟩
  multiply := Or.inl ⟨⟨560139, by omega⟩, f.node_560139, rfl⟩
  zero := f.eq_44
}

def certificate_45 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6915) (.wire 7207) (.wire 52291) := {
  difference := (.wire 560140)
  product := (.wire 560141)
  subtract := Or.inl ⟨⟨560140, by omega⟩, f.node_560140, rfl⟩
  multiply := Or.inl ⟨⟨560141, by omega⟩, f.node_560141, rfl⟩
  zero := f.eq_45
}

def certificate_46 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6915) (.wire 7208) (.wire 52302) := {
  difference := (.wire 560142)
  product := (.wire 560143)
  subtract := Or.inl ⟨⟨560142, by omega⟩, f.node_560142, rfl⟩
  multiply := Or.inl ⟨⟨560143, by omega⟩, f.node_560143, rfl⟩
  zero := f.eq_46
}

def certificate_47 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6915) (.wire 7209) (.wire 52313) := {
  difference := (.wire 560144)
  product := (.wire 560145)
  subtract := Or.inl ⟨⟨560144, by omega⟩, f.node_560144, rfl⟩
  multiply := Or.inl ⟨⟨560145, by omega⟩, f.node_560145, rfl⟩
  zero := f.eq_47
}

def certificate_48 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6916) (.wire 7464) (.wire 86901) := {
  difference := (.wire 659282)
  product := (.wire 659283)
  subtract := Or.inl ⟨⟨659282, by omega⟩, f.node_659282, rfl⟩
  multiply := Or.inl ⟨⟨659283, by omega⟩, f.node_659283, rfl⟩
  zero := f.eq_48
}

def certificate_49 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6916) (.wire 7465) (.wire 86912) := {
  difference := (.wire 659284)
  product := (.wire 659285)
  subtract := Or.inl ⟨⟨659284, by omega⟩, f.node_659284, rfl⟩
  multiply := Or.inl ⟨⟨659285, by omega⟩, f.node_659285, rfl⟩
  zero := f.eq_49
}

def certificate_50 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6916) (.wire 7466) (.wire 86923) := {
  difference := (.wire 659286)
  product := (.wire 659287)
  subtract := Or.inl ⟨⟨659286, by omega⟩, f.node_659286, rfl⟩
  multiply := Or.inl ⟨⟨659287, by omega⟩, f.node_659287, rfl⟩
  zero := f.eq_50
}

def certificate_51 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6916) (.wire 7467) (.wire 86934) := {
  difference := (.wire 659288)
  product := (.wire 659289)
  subtract := Or.inl ⟨⟨659288, by omega⟩, f.node_659288, rfl⟩
  multiply := Or.inl ⟨⟨659289, by omega⟩, f.node_659289, rfl⟩
  zero := f.eq_51
}

def certificate_52 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6916) (.wire 7460) (.wire 86900) := {
  difference := (.wire 659290)
  product := (.wire 659291)
  subtract := Or.inl ⟨⟨659290, by omega⟩, f.node_659290, rfl⟩
  multiply := Or.inl ⟨⟨659291, by omega⟩, f.node_659291, rfl⟩
  zero := f.eq_52
}

def certificate_53 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6916) (.wire 7461) (.wire 86911) := {
  difference := (.wire 659292)
  product := (.wire 659293)
  subtract := Or.inl ⟨⟨659292, by omega⟩, f.node_659292, rfl⟩
  multiply := Or.inl ⟨⟨659293, by omega⟩, f.node_659293, rfl⟩
  zero := f.eq_53
}

def certificate_54 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6916) (.wire 7462) (.wire 86922) := {
  difference := (.wire 659294)
  product := (.wire 659295)
  subtract := Or.inl ⟨⟨659294, by omega⟩, f.node_659294, rfl⟩
  multiply := Or.inl ⟨⟨659295, by omega⟩, f.node_659295, rfl⟩
  zero := f.eq_54
}

def certificate_55 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6939) (.wire 6956) (.wire 86901) := {
  difference := (.wire 458095)
  product := (.wire 458096)
  subtract := Or.inl ⟨⟨458095, by omega⟩, f.node_458095, rfl⟩
  multiply := Or.inl ⟨⟨458096, by omega⟩, f.node_458096, rfl⟩
  zero := f.eq_55
}

def certificate_56 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6939) (.wire 6957) (.wire 86912) := {
  difference := (.wire 458097)
  product := (.wire 458098)
  subtract := Or.inl ⟨⟨458097, by omega⟩, f.node_458097, rfl⟩
  multiply := Or.inl ⟨⟨458098, by omega⟩, f.node_458098, rfl⟩
  zero := f.eq_56
}

def certificate_57 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6939) (.wire 6958) (.wire 86923) := {
  difference := (.wire 458099)
  product := (.wire 458100)
  subtract := Or.inl ⟨⟨458099, by omega⟩, f.node_458099, rfl⟩
  multiply := Or.inl ⟨⟨458100, by omega⟩, f.node_458100, rfl⟩
  zero := f.eq_57
}

def certificate_58 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6939) (.wire 6959) (.wire 86934) := {
  difference := (.wire 458101)
  product := (.wire 458102)
  subtract := Or.inl ⟨⟨458101, by omega⟩, f.node_458101, rfl⟩
  multiply := Or.inl ⟨⟨458102, by omega⟩, f.node_458102, rfl⟩
  zero := f.eq_58
}

def certificate_59 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6939) (.wire 6952) (.wire 86900) := {
  difference := (.wire 458103)
  product := (.wire 458104)
  subtract := Or.inl ⟨⟨458103, by omega⟩, f.node_458103, rfl⟩
  multiply := Or.inl ⟨⟨458104, by omega⟩, f.node_458104, rfl⟩
  zero := f.eq_59
}

def certificate_60 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6939) (.wire 6953) (.wire 86911) := {
  difference := (.wire 458105)
  product := (.wire 458106)
  subtract := Or.inl ⟨⟨458105, by omega⟩, f.node_458105, rfl⟩
  multiply := Or.inl ⟨⟨458106, by omega⟩, f.node_458106, rfl⟩
  zero := f.eq_60
}

def certificate_61 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6939) (.wire 6954) (.wire 86922) := {
  difference := (.wire 458107)
  product := (.wire 458108)
  subtract := Or.inl ⟨⟨458107, by omega⟩, f.node_458107, rfl⟩
  multiply := Or.inl ⟨⟨458108, by omega⟩, f.node_458108, rfl⟩
  zero := f.eq_61
}

def certificate_62 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 666590) (.wire 39) := {
  difference := (.wire 666625)
  product := (.wire 666625)
  subtract := Or.inl ⟨⟨666625, by omega⟩, f.node_666625, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_62
}

def certificate_63 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 666601) (.wire 40) := {
  difference := (.wire 666626)
  product := (.wire 666626)
  subtract := Or.inl ⟨⟨666626, by omega⟩, f.node_666626, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_63
}

def certificate_64 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 666612) (.wire 41) := {
  difference := (.wire 666627)
  product := (.wire 666627)
  subtract := Or.inl ⟨⟨666627, by omega⟩, f.node_666627, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_64
}

def certificate_65 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 666623) (.wire 42) := {
  difference := (.wire 666628)
  product := (.wire 666628)
  subtract := Or.inl ⟨⟨666628, by omega⟩, f.node_666628, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_65
}

def certificate_66 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 666589) (.wire 43) := {
  difference := (.wire 666629)
  product := (.wire 666629)
  subtract := Or.inl ⟨⟨666629, by omega⟩, f.node_666629, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_66
}

def certificate_67 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 666600) (.wire 44) := {
  difference := (.wire 666630)
  product := (.wire 666630)
  subtract := Or.inl ⟨⟨666630, by omega⟩, f.node_666630, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_67
}

def certificate_68 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 666611) (.wire 45) := {
  difference := (.wire 666631)
  product := (.wire 666631)
  subtract := Or.inl ⟨⟨666631, by omega⟩, f.node_666631, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_68
}

def certificate_69 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 676575) (.wire 46) := {
  difference := (.wire 676610)
  product := (.wire 676610)
  subtract := Or.inl ⟨⟨676610, by omega⟩, f.node_676610, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_69
}

def certificate_70 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 676586) (.wire 47) := {
  difference := (.wire 676611)
  product := (.wire 676611)
  subtract := Or.inl ⟨⟨676611, by omega⟩, f.node_676611, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_70
}

def certificate_71 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 676597) (.wire 48) := {
  difference := (.wire 676612)
  product := (.wire 676612)
  subtract := Or.inl ⟨⟨676612, by omega⟩, f.node_676612, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_71
}

def certificate_72 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 676608) (.wire 49) := {
  difference := (.wire 676613)
  product := (.wire 676613)
  subtract := Or.inl ⟨⟨676613, by omega⟩, f.node_676613, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_72
}

def certificate_73 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 676574) (.wire 50) := {
  difference := (.wire 676614)
  product := (.wire 676614)
  subtract := Or.inl ⟨⟨676614, by omega⟩, f.node_676614, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_73
}

def certificate_74 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 676585) (.wire 51) := {
  difference := (.wire 676615)
  product := (.wire 676615)
  subtract := Or.inl ⟨⟨676615, by omega⟩, f.node_676615, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_74
}

def certificate_75 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 676596) (.wire 52) := {
  difference := (.wire 676616)
  product := (.wire 676616)
  subtract := Or.inl ⟨⟨676616, by omega⟩, f.node_676616, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_75
}

def certificate_76 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 6941) (.wire 457968) (.wire 455560) (.wire 458005) := {
  difference := (.wire 458003)
  product := (.wire 458004)
  subtract := Or.inl ⟨⟨458003, by omega⟩, f.node_458003, rfl⟩
  multiply := Or.inl ⟨⟨458004, by omega⟩, f.node_458004, rfl⟩
  add := Or.inl ⟨⟨458005, by omega⟩, f.node_458005, rfl⟩
}

def certificate_77 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 6941) (.wire 457979) (.wire 455571) (.wire 458008) := {
  difference := (.wire 458006)
  product := (.wire 458007)
  subtract := Or.inl ⟨⟨458006, by omega⟩, f.node_458006, rfl⟩
  multiply := Or.inl ⟨⟨458007, by omega⟩, f.node_458007, rfl⟩
  add := Or.inl ⟨⟨458008, by omega⟩, f.node_458008, rfl⟩
}

def certificate_78 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 6941) (.wire 457990) (.wire 455582) (.wire 458011) := {
  difference := (.wire 458009)
  product := (.wire 458010)
  subtract := Or.inl ⟨⟨458009, by omega⟩, f.node_458009, rfl⟩
  multiply := Or.inl ⟨⟨458010, by omega⟩, f.node_458010, rfl⟩
  add := Or.inl ⟨⟨458011, by omega⟩, f.node_458011, rfl⟩
}

def certificate_79 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 6941) (.wire 458001) (.wire 455593) (.wire 458014) := {
  difference := (.wire 458012)
  product := (.wire 458013)
  subtract := Or.inl ⟨⟨458012, by omega⟩, f.node_458012, rfl⟩
  multiply := Or.inl ⟨⟨458013, by omega⟩, f.node_458013, rfl⟩
  add := Or.inl ⟨⟨458014, by omega⟩, f.node_458014, rfl⟩
}

def certificate_80 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 6941) (.wire 457967) (.wire 455559) (.wire 458017) := {
  difference := (.wire 458015)
  product := (.wire 458016)
  subtract := Or.inl ⟨⟨458015, by omega⟩, f.node_458015, rfl⟩
  multiply := Or.inl ⟨⟨458016, by omega⟩, f.node_458016, rfl⟩
  add := Or.inl ⟨⟨458017, by omega⟩, f.node_458017, rfl⟩
}

def certificate_81 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 6941) (.wire 457978) (.wire 455570) (.wire 458020) := {
  difference := (.wire 458018)
  product := (.wire 458019)
  subtract := Or.inl ⟨⟨458018, by omega⟩, f.node_458018, rfl⟩
  multiply := Or.inl ⟨⟨458019, by omega⟩, f.node_458019, rfl⟩
  add := Or.inl ⟨⟨458020, by omega⟩, f.node_458020, rfl⟩
}

def certificate_82 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 6941) (.wire 457989) (.wire 455581) (.wire 458023) := {
  difference := (.wire 458021)
  product := (.wire 458022)
  subtract := Or.inl ⟨⟨458021, by omega⟩, f.node_458021, rfl⟩
  multiply := Or.inl ⟨⟨458022, by omega⟩, f.node_458022, rfl⟩
  add := Or.inl ⟨⟨458023, by omega⟩, f.node_458023, rfl⟩
}

def certificate_83 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 453172) (.wire 6956) (.wire 458005) := {
  difference := (.wire 458024)
  product := (.wire 458025)
  subtract := Or.inl ⟨⟨458024, by omega⟩, f.node_458024, rfl⟩
  multiply := Or.inl ⟨⟨458025, by omega⟩, f.node_458025, rfl⟩
  zero := f.eq_76
}

def certificate_84 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 453172) (.wire 6957) (.wire 458008) := {
  difference := (.wire 458026)
  product := (.wire 458027)
  subtract := Or.inl ⟨⟨458026, by omega⟩, f.node_458026, rfl⟩
  multiply := Or.inl ⟨⟨458027, by omega⟩, f.node_458027, rfl⟩
  zero := f.eq_77
}

def certificate_85 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 453172) (.wire 6958) (.wire 458011) := {
  difference := (.wire 458028)
  product := (.wire 458029)
  subtract := Or.inl ⟨⟨458028, by omega⟩, f.node_458028, rfl⟩
  multiply := Or.inl ⟨⟨458029, by omega⟩, f.node_458029, rfl⟩
  zero := f.eq_78
}

def certificate_86 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 453172) (.wire 6959) (.wire 458014) := {
  difference := (.wire 458030)
  product := (.wire 458031)
  subtract := Or.inl ⟨⟨458030, by omega⟩, f.node_458030, rfl⟩
  multiply := Or.inl ⟨⟨458031, by omega⟩, f.node_458031, rfl⟩
  zero := f.eq_79
}

def certificate_87 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 453172) (.wire 6952) (.wire 458017) := {
  difference := (.wire 458032)
  product := (.wire 458033)
  subtract := Or.inl ⟨⟨458032, by omega⟩, f.node_458032, rfl⟩
  multiply := Or.inl ⟨⟨458033, by omega⟩, f.node_458033, rfl⟩
  zero := f.eq_80
}

def certificate_88 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 453172) (.wire 6953) (.wire 458020) := {
  difference := (.wire 458034)
  product := (.wire 458035)
  subtract := Or.inl ⟨⟨458034, by omega⟩, f.node_458034, rfl⟩
  multiply := Or.inl ⟨⟨458035, by omega⟩, f.node_458035, rfl⟩
  zero := f.eq_81
}

def certificate_89 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 453172) (.wire 6954) (.wire 458023) := {
  difference := (.wire 458036)
  product := (.wire 458037)
  subtract := Or.inl ⟨⟨458036, by omega⟩, f.node_458036, rfl⟩
  multiply := Or.inl ⟨⟨458037, by omega⟩, f.node_458037, rfl⟩
  zero := f.eq_82
}

def certificate_90 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 6940) (.wire 554416) (.wire 549568) (.wire 554453) := {
  difference := (.wire 554451)
  product := (.wire 554452)
  subtract := Or.inl ⟨⟨554451, by omega⟩, f.node_554451, rfl⟩
  multiply := Or.inl ⟨⟨554452, by omega⟩, f.node_554452, rfl⟩
  add := Or.inl ⟨⟨554453, by omega⟩, f.node_554453, rfl⟩
}

def certificate_91 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 6940) (.wire 554427) (.wire 549579) (.wire 554456) := {
  difference := (.wire 554454)
  product := (.wire 554455)
  subtract := Or.inl ⟨⟨554454, by omega⟩, f.node_554454, rfl⟩
  multiply := Or.inl ⟨⟨554455, by omega⟩, f.node_554455, rfl⟩
  add := Or.inl ⟨⟨554456, by omega⟩, f.node_554456, rfl⟩
}

def certificate_92 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 6940) (.wire 554438) (.wire 549590) (.wire 554459) := {
  difference := (.wire 554457)
  product := (.wire 554458)
  subtract := Or.inl ⟨⟨554457, by omega⟩, f.node_554457, rfl⟩
  multiply := Or.inl ⟨⟨554458, by omega⟩, f.node_554458, rfl⟩
  add := Or.inl ⟨⟨554459, by omega⟩, f.node_554459, rfl⟩
}

def certificate_93 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 6940) (.wire 554449) (.wire 549601) (.wire 554462) := {
  difference := (.wire 554460)
  product := (.wire 554461)
  subtract := Or.inl ⟨⟨554460, by omega⟩, f.node_554460, rfl⟩
  multiply := Or.inl ⟨⟨554461, by omega⟩, f.node_554461, rfl⟩
  add := Or.inl ⟨⟨554462, by omega⟩, f.node_554462, rfl⟩
}

def certificate_94 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 6940) (.wire 554415) (.wire 549567) (.wire 554465) := {
  difference := (.wire 554463)
  product := (.wire 554464)
  subtract := Or.inl ⟨⟨554463, by omega⟩, f.node_554463, rfl⟩
  multiply := Or.inl ⟨⟨554464, by omega⟩, f.node_554464, rfl⟩
  add := Or.inl ⟨⟨554465, by omega⟩, f.node_554465, rfl⟩
}

def certificate_95 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 6940) (.wire 554426) (.wire 549578) (.wire 554468) := {
  difference := (.wire 554466)
  product := (.wire 554467)
  subtract := Or.inl ⟨⟨554466, by omega⟩, f.node_554466, rfl⟩
  multiply := Or.inl ⟨⟨554467, by omega⟩, f.node_554467, rfl⟩
  add := Or.inl ⟨⟨554468, by omega⟩, f.node_554468, rfl⟩
}

def certificate_96 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 6940) (.wire 554437) (.wire 549589) (.wire 554471) := {
  difference := (.wire 554469)
  product := (.wire 554470)
  subtract := Or.inl ⟨⟨554469, by omega⟩, f.node_554469, rfl⟩
  multiply := Or.inl ⟨⟨554470, by omega⟩, f.node_554470, rfl⟩
  add := Or.inl ⟨⟨554471, by omega⟩, f.node_554471, rfl⟩
}

def certificate_97 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 554453) (.wire 25) := {
  difference := (.wire 554472)
  product := (.wire 554472)
  subtract := Or.inl ⟨⟨554472, by omega⟩, f.node_554472, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_83
}

def certificate_98 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 554456) (.wire 26) := {
  difference := (.wire 554473)
  product := (.wire 554473)
  subtract := Or.inl ⟨⟨554473, by omega⟩, f.node_554473, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_84
}

def certificate_99 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 554459) (.wire 27) := {
  difference := (.wire 554474)
  product := (.wire 554474)
  subtract := Or.inl ⟨⟨554474, by omega⟩, f.node_554474, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_85
}

def certificate_100 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 554462) (.wire 28) := {
  difference := (.wire 554475)
  product := (.wire 554475)
  subtract := Or.inl ⟨⟨554475, by omega⟩, f.node_554475, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_86
}

def certificate_101 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 554465) (.wire 29) := {
  difference := (.wire 554476)
  product := (.wire 554476)
  subtract := Or.inl ⟨⟨554476, by omega⟩, f.node_554476, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_87
}

def certificate_102 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 554468) (.wire 30) := {
  difference := (.wire 554477)
  product := (.wire 554477)
  subtract := Or.inl ⟨⟨554477, by omega⟩, f.node_554477, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_88
}

def certificate_103 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 554471) (.wire 31) := {
  difference := (.wire 554478)
  product := (.wire 554478)
  subtract := Or.inl ⟨⟨554478, by omega⟩, f.node_554478, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_89
}

def certificate_104 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458110) (.wire 465518) (.wire 6961) (.wire 465555) := {
  difference := (.wire 465553)
  product := (.wire 465554)
  subtract := Or.inl ⟨⟨465553, by omega⟩, f.node_465553, rfl⟩
  multiply := Or.inl ⟨⟨465554, by omega⟩, f.node_465554, rfl⟩
  add := Or.inl ⟨⟨465555, by omega⟩, f.node_465555, rfl⟩
}

def certificate_105 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458110) (.wire 465529) (.wire 6962) (.wire 465558) := {
  difference := (.wire 465556)
  product := (.wire 465557)
  subtract := Or.inl ⟨⟨465556, by omega⟩, f.node_465556, rfl⟩
  multiply := Or.inl ⟨⟨465557, by omega⟩, f.node_465557, rfl⟩
  add := Or.inl ⟨⟨465558, by omega⟩, f.node_465558, rfl⟩
}

def certificate_106 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458110) (.wire 465540) (.wire 6963) (.wire 465561) := {
  difference := (.wire 465559)
  product := (.wire 465560)
  subtract := Or.inl ⟨⟨465559, by omega⟩, f.node_465559, rfl⟩
  multiply := Or.inl ⟨⟨465560, by omega⟩, f.node_465560, rfl⟩
  add := Or.inl ⟨⟨465561, by omega⟩, f.node_465561, rfl⟩
}

def certificate_107 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458110) (.wire 465551) (.wire 6964) (.wire 465564) := {
  difference := (.wire 465562)
  product := (.wire 465563)
  subtract := Or.inl ⟨⟨465562, by omega⟩, f.node_465562, rfl⟩
  multiply := Or.inl ⟨⟨465563, by omega⟩, f.node_465563, rfl⟩
  add := Or.inl ⟨⟨465564, by omega⟩, f.node_465564, rfl⟩
}

def certificate_108 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458110) (.wire 465517) (.wire 6965) (.wire 465567) := {
  difference := (.wire 465565)
  product := (.wire 465566)
  subtract := Or.inl ⟨⟨465565, by omega⟩, f.node_465565, rfl⟩
  multiply := Or.inl ⟨⟨465566, by omega⟩, f.node_465566, rfl⟩
  add := Or.inl ⟨⟨465567, by omega⟩, f.node_465567, rfl⟩
}

def certificate_109 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458110) (.wire 465528) (.wire 6966) (.wire 465570) := {
  difference := (.wire 465568)
  product := (.wire 465569)
  subtract := Or.inl ⟨⟨465568, by omega⟩, f.node_465568, rfl⟩
  multiply := Or.inl ⟨⟨465569, by omega⟩, f.node_465569, rfl⟩
  add := Or.inl ⟨⟨465570, by omega⟩, f.node_465570, rfl⟩
}

def certificate_110 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458110) (.wire 465539) (.wire 6967) (.wire 465573) := {
  difference := (.wire 465571)
  product := (.wire 465572)
  subtract := Or.inl ⟨⟨465571, by omega⟩, f.node_465571, rfl⟩
  multiply := Or.inl ⟨⟨465572, by omega⟩, f.node_465572, rfl⟩
  add := Or.inl ⟨⟨465573, by omega⟩, f.node_465573, rfl⟩
}

def certificate_111 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458110) (.wire 6961) (.wire 465518) (.wire 465576) := {
  difference := (.wire 465574)
  product := (.wire 465575)
  subtract := Or.inl ⟨⟨465574, by omega⟩, f.node_465574, rfl⟩
  multiply := Or.inl ⟨⟨465575, by omega⟩, f.node_465575, rfl⟩
  add := Or.inl ⟨⟨465576, by omega⟩, f.node_465576, rfl⟩
}

def certificate_112 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458110) (.wire 6962) (.wire 465529) (.wire 465579) := {
  difference := (.wire 465577)
  product := (.wire 465578)
  subtract := Or.inl ⟨⟨465577, by omega⟩, f.node_465577, rfl⟩
  multiply := Or.inl ⟨⟨465578, by omega⟩, f.node_465578, rfl⟩
  add := Or.inl ⟨⟨465579, by omega⟩, f.node_465579, rfl⟩
}

def certificate_113 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458110) (.wire 6963) (.wire 465540) (.wire 465582) := {
  difference := (.wire 465580)
  product := (.wire 465581)
  subtract := Or.inl ⟨⟨465580, by omega⟩, f.node_465580, rfl⟩
  multiply := Or.inl ⟨⟨465581, by omega⟩, f.node_465581, rfl⟩
  add := Or.inl ⟨⟨465582, by omega⟩, f.node_465582, rfl⟩
}

def certificate_114 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458110) (.wire 6964) (.wire 465551) (.wire 465585) := {
  difference := (.wire 465583)
  product := (.wire 465584)
  subtract := Or.inl ⟨⟨465583, by omega⟩, f.node_465583, rfl⟩
  multiply := Or.inl ⟨⟨465584, by omega⟩, f.node_465584, rfl⟩
  add := Or.inl ⟨⟨465585, by omega⟩, f.node_465585, rfl⟩
}

def certificate_115 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458110) (.wire 6965) (.wire 465517) (.wire 465588) := {
  difference := (.wire 465586)
  product := (.wire 465587)
  subtract := Or.inl ⟨⟨465586, by omega⟩, f.node_465586, rfl⟩
  multiply := Or.inl ⟨⟨465587, by omega⟩, f.node_465587, rfl⟩
  add := Or.inl ⟨⟨465588, by omega⟩, f.node_465588, rfl⟩
}

def certificate_116 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458110) (.wire 6966) (.wire 465528) (.wire 465591) := {
  difference := (.wire 465589)
  product := (.wire 465590)
  subtract := Or.inl ⟨⟨465589, by omega⟩, f.node_465589, rfl⟩
  multiply := Or.inl ⟨⟨465590, by omega⟩, f.node_465590, rfl⟩
  add := Or.inl ⟨⟨465591, by omega⟩, f.node_465591, rfl⟩
}

def certificate_117 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458110) (.wire 6967) (.wire 465539) (.wire 465594) := {
  difference := (.wire 465592)
  product := (.wire 465593)
  subtract := Or.inl ⟨⟨465592, by omega⟩, f.node_465592, rfl⟩
  multiply := Or.inl ⟨⟨465593, by omega⟩, f.node_465593, rfl⟩
  add := Or.inl ⟨⟨465594, by omega⟩, f.node_465594, rfl⟩
}

def certificate_118 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458113) (.wire 467992) (.wire 6968) (.wire 468029) := {
  difference := (.wire 468027)
  product := (.wire 468028)
  subtract := Or.inl ⟨⟨468027, by omega⟩, f.node_468027, rfl⟩
  multiply := Or.inl ⟨⟨468028, by omega⟩, f.node_468028, rfl⟩
  add := Or.inl ⟨⟨468029, by omega⟩, f.node_468029, rfl⟩
}

def certificate_119 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458113) (.wire 468003) (.wire 6969) (.wire 468032) := {
  difference := (.wire 468030)
  product := (.wire 468031)
  subtract := Or.inl ⟨⟨468030, by omega⟩, f.node_468030, rfl⟩
  multiply := Or.inl ⟨⟨468031, by omega⟩, f.node_468031, rfl⟩
  add := Or.inl ⟨⟨468032, by omega⟩, f.node_468032, rfl⟩
}

def certificate_120 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458113) (.wire 468014) (.wire 6970) (.wire 468035) := {
  difference := (.wire 468033)
  product := (.wire 468034)
  subtract := Or.inl ⟨⟨468033, by omega⟩, f.node_468033, rfl⟩
  multiply := Or.inl ⟨⟨468034, by omega⟩, f.node_468034, rfl⟩
  add := Or.inl ⟨⟨468035, by omega⟩, f.node_468035, rfl⟩
}

def certificate_121 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458113) (.wire 468025) (.wire 6971) (.wire 468038) := {
  difference := (.wire 468036)
  product := (.wire 468037)
  subtract := Or.inl ⟨⟨468036, by omega⟩, f.node_468036, rfl⟩
  multiply := Or.inl ⟨⟨468037, by omega⟩, f.node_468037, rfl⟩
  add := Or.inl ⟨⟨468038, by omega⟩, f.node_468038, rfl⟩
}

def certificate_122 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458113) (.wire 467991) (.wire 6972) (.wire 468041) := {
  difference := (.wire 468039)
  product := (.wire 468040)
  subtract := Or.inl ⟨⟨468039, by omega⟩, f.node_468039, rfl⟩
  multiply := Or.inl ⟨⟨468040, by omega⟩, f.node_468040, rfl⟩
  add := Or.inl ⟨⟨468041, by omega⟩, f.node_468041, rfl⟩
}

def certificate_123 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458113) (.wire 468002) (.wire 6973) (.wire 468044) := {
  difference := (.wire 468042)
  product := (.wire 468043)
  subtract := Or.inl ⟨⟨468042, by omega⟩, f.node_468042, rfl⟩
  multiply := Or.inl ⟨⟨468043, by omega⟩, f.node_468043, rfl⟩
  add := Or.inl ⟨⟨468044, by omega⟩, f.node_468044, rfl⟩
}

def certificate_124 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458113) (.wire 468013) (.wire 6974) (.wire 468047) := {
  difference := (.wire 468045)
  product := (.wire 468046)
  subtract := Or.inl ⟨⟨468045, by omega⟩, f.node_468045, rfl⟩
  multiply := Or.inl ⟨⟨468046, by omega⟩, f.node_468046, rfl⟩
  add := Or.inl ⟨⟨468047, by omega⟩, f.node_468047, rfl⟩
}

def certificate_125 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458113) (.wire 6968) (.wire 467992) (.wire 468050) := {
  difference := (.wire 468048)
  product := (.wire 468049)
  subtract := Or.inl ⟨⟨468048, by omega⟩, f.node_468048, rfl⟩
  multiply := Or.inl ⟨⟨468049, by omega⟩, f.node_468049, rfl⟩
  add := Or.inl ⟨⟨468050, by omega⟩, f.node_468050, rfl⟩
}

def certificate_126 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458113) (.wire 6969) (.wire 468003) (.wire 468053) := {
  difference := (.wire 468051)
  product := (.wire 468052)
  subtract := Or.inl ⟨⟨468051, by omega⟩, f.node_468051, rfl⟩
  multiply := Or.inl ⟨⟨468052, by omega⟩, f.node_468052, rfl⟩
  add := Or.inl ⟨⟨468053, by omega⟩, f.node_468053, rfl⟩
}

def certificate_127 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458113) (.wire 6970) (.wire 468014) (.wire 468056) := {
  difference := (.wire 468054)
  product := (.wire 468055)
  subtract := Or.inl ⟨⟨468054, by omega⟩, f.node_468054, rfl⟩
  multiply := Or.inl ⟨⟨468055, by omega⟩, f.node_468055, rfl⟩
  add := Or.inl ⟨⟨468056, by omega⟩, f.node_468056, rfl⟩
}

def certificate_128 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458113) (.wire 6971) (.wire 468025) (.wire 468059) := {
  difference := (.wire 468057)
  product := (.wire 468058)
  subtract := Or.inl ⟨⟨468057, by omega⟩, f.node_468057, rfl⟩
  multiply := Or.inl ⟨⟨468058, by omega⟩, f.node_468058, rfl⟩
  add := Or.inl ⟨⟨468059, by omega⟩, f.node_468059, rfl⟩
}

def certificate_129 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458113) (.wire 6972) (.wire 467991) (.wire 468062) := {
  difference := (.wire 468060)
  product := (.wire 468061)
  subtract := Or.inl ⟨⟨468060, by omega⟩, f.node_468060, rfl⟩
  multiply := Or.inl ⟨⟨468061, by omega⟩, f.node_468061, rfl⟩
  add := Or.inl ⟨⟨468062, by omega⟩, f.node_468062, rfl⟩
}

def certificate_130 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458113) (.wire 6973) (.wire 468002) (.wire 468065) := {
  difference := (.wire 468063)
  product := (.wire 468064)
  subtract := Or.inl ⟨⟨468063, by omega⟩, f.node_468063, rfl⟩
  multiply := Or.inl ⟨⟨468064, by omega⟩, f.node_468064, rfl⟩
  add := Or.inl ⟨⟨468065, by omega⟩, f.node_468065, rfl⟩
}

def certificate_131 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458113) (.wire 6974) (.wire 468013) (.wire 468068) := {
  difference := (.wire 468066)
  product := (.wire 468067)
  subtract := Or.inl ⟨⟨468066, by omega⟩, f.node_468066, rfl⟩
  multiply := Or.inl ⟨⟨468067, by omega⟩, f.node_468067, rfl⟩
  add := Or.inl ⟨⟨468068, by omega⟩, f.node_468068, rfl⟩
}

def certificate_132 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458118) (.wire 470466) (.wire 6975) (.wire 470503) := {
  difference := (.wire 470501)
  product := (.wire 470502)
  subtract := Or.inl ⟨⟨470501, by omega⟩, f.node_470501, rfl⟩
  multiply := Or.inl ⟨⟨470502, by omega⟩, f.node_470502, rfl⟩
  add := Or.inl ⟨⟨470503, by omega⟩, f.node_470503, rfl⟩
}

def certificate_133 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458118) (.wire 470477) (.wire 6976) (.wire 470506) := {
  difference := (.wire 470504)
  product := (.wire 470505)
  subtract := Or.inl ⟨⟨470504, by omega⟩, f.node_470504, rfl⟩
  multiply := Or.inl ⟨⟨470505, by omega⟩, f.node_470505, rfl⟩
  add := Or.inl ⟨⟨470506, by omega⟩, f.node_470506, rfl⟩
}

def certificate_134 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458118) (.wire 470488) (.wire 6977) (.wire 470509) := {
  difference := (.wire 470507)
  product := (.wire 470508)
  subtract := Or.inl ⟨⟨470507, by omega⟩, f.node_470507, rfl⟩
  multiply := Or.inl ⟨⟨470508, by omega⟩, f.node_470508, rfl⟩
  add := Or.inl ⟨⟨470509, by omega⟩, f.node_470509, rfl⟩
}

def certificate_135 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458118) (.wire 470499) (.wire 6978) (.wire 470512) := {
  difference := (.wire 470510)
  product := (.wire 470511)
  subtract := Or.inl ⟨⟨470510, by omega⟩, f.node_470510, rfl⟩
  multiply := Or.inl ⟨⟨470511, by omega⟩, f.node_470511, rfl⟩
  add := Or.inl ⟨⟨470512, by omega⟩, f.node_470512, rfl⟩
}

def certificate_136 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458118) (.wire 470465) (.wire 6979) (.wire 470515) := {
  difference := (.wire 470513)
  product := (.wire 470514)
  subtract := Or.inl ⟨⟨470513, by omega⟩, f.node_470513, rfl⟩
  multiply := Or.inl ⟨⟨470514, by omega⟩, f.node_470514, rfl⟩
  add := Or.inl ⟨⟨470515, by omega⟩, f.node_470515, rfl⟩
}

def certificate_137 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458118) (.wire 470476) (.wire 6980) (.wire 470518) := {
  difference := (.wire 470516)
  product := (.wire 470517)
  subtract := Or.inl ⟨⟨470516, by omega⟩, f.node_470516, rfl⟩
  multiply := Or.inl ⟨⟨470517, by omega⟩, f.node_470517, rfl⟩
  add := Or.inl ⟨⟨470518, by omega⟩, f.node_470518, rfl⟩
}

def certificate_138 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458118) (.wire 470487) (.wire 6981) (.wire 470521) := {
  difference := (.wire 470519)
  product := (.wire 470520)
  subtract := Or.inl ⟨⟨470519, by omega⟩, f.node_470519, rfl⟩
  multiply := Or.inl ⟨⟨470520, by omega⟩, f.node_470520, rfl⟩
  add := Or.inl ⟨⟨470521, by omega⟩, f.node_470521, rfl⟩
}

def certificate_139 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458118) (.wire 6975) (.wire 470466) (.wire 470524) := {
  difference := (.wire 470522)
  product := (.wire 470523)
  subtract := Or.inl ⟨⟨470522, by omega⟩, f.node_470522, rfl⟩
  multiply := Or.inl ⟨⟨470523, by omega⟩, f.node_470523, rfl⟩
  add := Or.inl ⟨⟨470524, by omega⟩, f.node_470524, rfl⟩
}

def certificate_140 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458118) (.wire 6976) (.wire 470477) (.wire 470527) := {
  difference := (.wire 470525)
  product := (.wire 470526)
  subtract := Or.inl ⟨⟨470525, by omega⟩, f.node_470525, rfl⟩
  multiply := Or.inl ⟨⟨470526, by omega⟩, f.node_470526, rfl⟩
  add := Or.inl ⟨⟨470527, by omega⟩, f.node_470527, rfl⟩
}

def certificate_141 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458118) (.wire 6977) (.wire 470488) (.wire 470530) := {
  difference := (.wire 470528)
  product := (.wire 470529)
  subtract := Or.inl ⟨⟨470528, by omega⟩, f.node_470528, rfl⟩
  multiply := Or.inl ⟨⟨470529, by omega⟩, f.node_470529, rfl⟩
  add := Or.inl ⟨⟨470530, by omega⟩, f.node_470530, rfl⟩
}

def certificate_142 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458118) (.wire 6978) (.wire 470499) (.wire 470533) := {
  difference := (.wire 470531)
  product := (.wire 470532)
  subtract := Or.inl ⟨⟨470531, by omega⟩, f.node_470531, rfl⟩
  multiply := Or.inl ⟨⟨470532, by omega⟩, f.node_470532, rfl⟩
  add := Or.inl ⟨⟨470533, by omega⟩, f.node_470533, rfl⟩
}

def certificate_143 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458118) (.wire 6979) (.wire 470465) (.wire 470536) := {
  difference := (.wire 470534)
  product := (.wire 470535)
  subtract := Or.inl ⟨⟨470534, by omega⟩, f.node_470534, rfl⟩
  multiply := Or.inl ⟨⟨470535, by omega⟩, f.node_470535, rfl⟩
  add := Or.inl ⟨⟨470536, by omega⟩, f.node_470536, rfl⟩
}

def certificate_144 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458118) (.wire 6980) (.wire 470476) (.wire 470539) := {
  difference := (.wire 470537)
  product := (.wire 470538)
  subtract := Or.inl ⟨⟨470537, by omega⟩, f.node_470537, rfl⟩
  multiply := Or.inl ⟨⟨470538, by omega⟩, f.node_470538, rfl⟩
  add := Or.inl ⟨⟨470539, by omega⟩, f.node_470539, rfl⟩
}

def certificate_145 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458118) (.wire 6981) (.wire 470487) (.wire 470542) := {
  difference := (.wire 470540)
  product := (.wire 470541)
  subtract := Or.inl ⟨⟨470540, by omega⟩, f.node_470540, rfl⟩
  multiply := Or.inl ⟨⟨470541, by omega⟩, f.node_470541, rfl⟩
  add := Or.inl ⟨⟨470542, by omega⟩, f.node_470542, rfl⟩
}

def certificate_146 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458123) (.wire 472940) (.wire 6982) (.wire 472977) := {
  difference := (.wire 472975)
  product := (.wire 472976)
  subtract := Or.inl ⟨⟨472975, by omega⟩, f.node_472975, rfl⟩
  multiply := Or.inl ⟨⟨472976, by omega⟩, f.node_472976, rfl⟩
  add := Or.inl ⟨⟨472977, by omega⟩, f.node_472977, rfl⟩
}

def certificate_147 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458123) (.wire 472951) (.wire 6983) (.wire 472980) := {
  difference := (.wire 472978)
  product := (.wire 472979)
  subtract := Or.inl ⟨⟨472978, by omega⟩, f.node_472978, rfl⟩
  multiply := Or.inl ⟨⟨472979, by omega⟩, f.node_472979, rfl⟩
  add := Or.inl ⟨⟨472980, by omega⟩, f.node_472980, rfl⟩
}

def certificate_148 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458123) (.wire 472962) (.wire 6984) (.wire 472983) := {
  difference := (.wire 472981)
  product := (.wire 472982)
  subtract := Or.inl ⟨⟨472981, by omega⟩, f.node_472981, rfl⟩
  multiply := Or.inl ⟨⟨472982, by omega⟩, f.node_472982, rfl⟩
  add := Or.inl ⟨⟨472983, by omega⟩, f.node_472983, rfl⟩
}

def certificate_149 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458123) (.wire 472973) (.wire 6985) (.wire 472986) := {
  difference := (.wire 472984)
  product := (.wire 472985)
  subtract := Or.inl ⟨⟨472984, by omega⟩, f.node_472984, rfl⟩
  multiply := Or.inl ⟨⟨472985, by omega⟩, f.node_472985, rfl⟩
  add := Or.inl ⟨⟨472986, by omega⟩, f.node_472986, rfl⟩
}

def certificate_150 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458123) (.wire 472939) (.wire 6986) (.wire 472989) := {
  difference := (.wire 472987)
  product := (.wire 472988)
  subtract := Or.inl ⟨⟨472987, by omega⟩, f.node_472987, rfl⟩
  multiply := Or.inl ⟨⟨472988, by omega⟩, f.node_472988, rfl⟩
  add := Or.inl ⟨⟨472989, by omega⟩, f.node_472989, rfl⟩
}

def certificate_151 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458123) (.wire 472950) (.wire 6987) (.wire 472992) := {
  difference := (.wire 472990)
  product := (.wire 472991)
  subtract := Or.inl ⟨⟨472990, by omega⟩, f.node_472990, rfl⟩
  multiply := Or.inl ⟨⟨472991, by omega⟩, f.node_472991, rfl⟩
  add := Or.inl ⟨⟨472992, by omega⟩, f.node_472992, rfl⟩
}

def certificate_152 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458123) (.wire 472961) (.wire 6988) (.wire 472995) := {
  difference := (.wire 472993)
  product := (.wire 472994)
  subtract := Or.inl ⟨⟨472993, by omega⟩, f.node_472993, rfl⟩
  multiply := Or.inl ⟨⟨472994, by omega⟩, f.node_472994, rfl⟩
  add := Or.inl ⟨⟨472995, by omega⟩, f.node_472995, rfl⟩
}

def certificate_153 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458123) (.wire 6982) (.wire 472940) (.wire 472998) := {
  difference := (.wire 472996)
  product := (.wire 472997)
  subtract := Or.inl ⟨⟨472996, by omega⟩, f.node_472996, rfl⟩
  multiply := Or.inl ⟨⟨472997, by omega⟩, f.node_472997, rfl⟩
  add := Or.inl ⟨⟨472998, by omega⟩, f.node_472998, rfl⟩
}

def certificate_154 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458123) (.wire 6983) (.wire 472951) (.wire 473001) := {
  difference := (.wire 472999)
  product := (.wire 473000)
  subtract := Or.inl ⟨⟨472999, by omega⟩, f.node_472999, rfl⟩
  multiply := Or.inl ⟨⟨473000, by omega⟩, f.node_473000, rfl⟩
  add := Or.inl ⟨⟨473001, by omega⟩, f.node_473001, rfl⟩
}

def certificate_155 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458123) (.wire 6984) (.wire 472962) (.wire 473004) := {
  difference := (.wire 473002)
  product := (.wire 473003)
  subtract := Or.inl ⟨⟨473002, by omega⟩, f.node_473002, rfl⟩
  multiply := Or.inl ⟨⟨473003, by omega⟩, f.node_473003, rfl⟩
  add := Or.inl ⟨⟨473004, by omega⟩, f.node_473004, rfl⟩
}

def certificate_156 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458123) (.wire 6985) (.wire 472973) (.wire 473007) := {
  difference := (.wire 473005)
  product := (.wire 473006)
  subtract := Or.inl ⟨⟨473005, by omega⟩, f.node_473005, rfl⟩
  multiply := Or.inl ⟨⟨473006, by omega⟩, f.node_473006, rfl⟩
  add := Or.inl ⟨⟨473007, by omega⟩, f.node_473007, rfl⟩
}

def certificate_157 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458123) (.wire 6986) (.wire 472939) (.wire 473010) := {
  difference := (.wire 473008)
  product := (.wire 473009)
  subtract := Or.inl ⟨⟨473008, by omega⟩, f.node_473008, rfl⟩
  multiply := Or.inl ⟨⟨473009, by omega⟩, f.node_473009, rfl⟩
  add := Or.inl ⟨⟨473010, by omega⟩, f.node_473010, rfl⟩
}

def certificate_158 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458123) (.wire 6987) (.wire 472950) (.wire 473013) := {
  difference := (.wire 473011)
  product := (.wire 473012)
  subtract := Or.inl ⟨⟨473011, by omega⟩, f.node_473011, rfl⟩
  multiply := Or.inl ⟨⟨473012, by omega⟩, f.node_473012, rfl⟩
  add := Or.inl ⟨⟨473013, by omega⟩, f.node_473013, rfl⟩
}

def certificate_159 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458123) (.wire 6988) (.wire 472961) (.wire 473016) := {
  difference := (.wire 473014)
  product := (.wire 473015)
  subtract := Or.inl ⟨⟨473014, by omega⟩, f.node_473014, rfl⟩
  multiply := Or.inl ⟨⟨473015, by omega⟩, f.node_473015, rfl⟩
  add := Or.inl ⟨⟨473016, by omega⟩, f.node_473016, rfl⟩
}

def certificate_160 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458128) (.wire 475414) (.wire 6989) (.wire 475451) := {
  difference := (.wire 475449)
  product := (.wire 475450)
  subtract := Or.inl ⟨⟨475449, by omega⟩, f.node_475449, rfl⟩
  multiply := Or.inl ⟨⟨475450, by omega⟩, f.node_475450, rfl⟩
  add := Or.inl ⟨⟨475451, by omega⟩, f.node_475451, rfl⟩
}

def certificate_161 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458128) (.wire 475425) (.wire 6990) (.wire 475454) := {
  difference := (.wire 475452)
  product := (.wire 475453)
  subtract := Or.inl ⟨⟨475452, by omega⟩, f.node_475452, rfl⟩
  multiply := Or.inl ⟨⟨475453, by omega⟩, f.node_475453, rfl⟩
  add := Or.inl ⟨⟨475454, by omega⟩, f.node_475454, rfl⟩
}

def certificate_162 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458128) (.wire 475436) (.wire 6991) (.wire 475457) := {
  difference := (.wire 475455)
  product := (.wire 475456)
  subtract := Or.inl ⟨⟨475455, by omega⟩, f.node_475455, rfl⟩
  multiply := Or.inl ⟨⟨475456, by omega⟩, f.node_475456, rfl⟩
  add := Or.inl ⟨⟨475457, by omega⟩, f.node_475457, rfl⟩
}

def certificate_163 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458128) (.wire 475447) (.wire 6992) (.wire 475460) := {
  difference := (.wire 475458)
  product := (.wire 475459)
  subtract := Or.inl ⟨⟨475458, by omega⟩, f.node_475458, rfl⟩
  multiply := Or.inl ⟨⟨475459, by omega⟩, f.node_475459, rfl⟩
  add := Or.inl ⟨⟨475460, by omega⟩, f.node_475460, rfl⟩
}

def certificate_164 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458128) (.wire 475413) (.wire 6993) (.wire 475463) := {
  difference := (.wire 475461)
  product := (.wire 475462)
  subtract := Or.inl ⟨⟨475461, by omega⟩, f.node_475461, rfl⟩
  multiply := Or.inl ⟨⟨475462, by omega⟩, f.node_475462, rfl⟩
  add := Or.inl ⟨⟨475463, by omega⟩, f.node_475463, rfl⟩
}

def certificate_165 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458128) (.wire 475424) (.wire 6994) (.wire 475466) := {
  difference := (.wire 475464)
  product := (.wire 475465)
  subtract := Or.inl ⟨⟨475464, by omega⟩, f.node_475464, rfl⟩
  multiply := Or.inl ⟨⟨475465, by omega⟩, f.node_475465, rfl⟩
  add := Or.inl ⟨⟨475466, by omega⟩, f.node_475466, rfl⟩
}

def certificate_166 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458128) (.wire 475435) (.wire 6995) (.wire 475469) := {
  difference := (.wire 475467)
  product := (.wire 475468)
  subtract := Or.inl ⟨⟨475467, by omega⟩, f.node_475467, rfl⟩
  multiply := Or.inl ⟨⟨475468, by omega⟩, f.node_475468, rfl⟩
  add := Or.inl ⟨⟨475469, by omega⟩, f.node_475469, rfl⟩
}

def certificate_167 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458128) (.wire 6989) (.wire 475414) (.wire 475472) := {
  difference := (.wire 475470)
  product := (.wire 475471)
  subtract := Or.inl ⟨⟨475470, by omega⟩, f.node_475470, rfl⟩
  multiply := Or.inl ⟨⟨475471, by omega⟩, f.node_475471, rfl⟩
  add := Or.inl ⟨⟨475472, by omega⟩, f.node_475472, rfl⟩
}

def certificate_168 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458128) (.wire 6990) (.wire 475425) (.wire 475475) := {
  difference := (.wire 475473)
  product := (.wire 475474)
  subtract := Or.inl ⟨⟨475473, by omega⟩, f.node_475473, rfl⟩
  multiply := Or.inl ⟨⟨475474, by omega⟩, f.node_475474, rfl⟩
  add := Or.inl ⟨⟨475475, by omega⟩, f.node_475475, rfl⟩
}

def certificate_169 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458128) (.wire 6991) (.wire 475436) (.wire 475478) := {
  difference := (.wire 475476)
  product := (.wire 475477)
  subtract := Or.inl ⟨⟨475476, by omega⟩, f.node_475476, rfl⟩
  multiply := Or.inl ⟨⟨475477, by omega⟩, f.node_475477, rfl⟩
  add := Or.inl ⟨⟨475478, by omega⟩, f.node_475478, rfl⟩
}

def certificate_170 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458128) (.wire 6992) (.wire 475447) (.wire 475481) := {
  difference := (.wire 475479)
  product := (.wire 475480)
  subtract := Or.inl ⟨⟨475479, by omega⟩, f.node_475479, rfl⟩
  multiply := Or.inl ⟨⟨475480, by omega⟩, f.node_475480, rfl⟩
  add := Or.inl ⟨⟨475481, by omega⟩, f.node_475481, rfl⟩
}

def certificate_171 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458128) (.wire 6993) (.wire 475413) (.wire 475484) := {
  difference := (.wire 475482)
  product := (.wire 475483)
  subtract := Or.inl ⟨⟨475482, by omega⟩, f.node_475482, rfl⟩
  multiply := Or.inl ⟨⟨475483, by omega⟩, f.node_475483, rfl⟩
  add := Or.inl ⟨⟨475484, by omega⟩, f.node_475484, rfl⟩
}

def certificate_172 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458128) (.wire 6994) (.wire 475424) (.wire 475487) := {
  difference := (.wire 475485)
  product := (.wire 475486)
  subtract := Or.inl ⟨⟨475485, by omega⟩, f.node_475485, rfl⟩
  multiply := Or.inl ⟨⟨475486, by omega⟩, f.node_475486, rfl⟩
  add := Or.inl ⟨⟨475487, by omega⟩, f.node_475487, rfl⟩
}

def certificate_173 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458128) (.wire 6995) (.wire 475435) (.wire 475490) := {
  difference := (.wire 475488)
  product := (.wire 475489)
  subtract := Or.inl ⟨⟨475488, by omega⟩, f.node_475488, rfl⟩
  multiply := Or.inl ⟨⟨475489, by omega⟩, f.node_475489, rfl⟩
  add := Or.inl ⟨⟨475490, by omega⟩, f.node_475490, rfl⟩
}

def certificate_174 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458133) (.wire 477888) (.wire 6996) (.wire 477925) := {
  difference := (.wire 477923)
  product := (.wire 477924)
  subtract := Or.inl ⟨⟨477923, by omega⟩, f.node_477923, rfl⟩
  multiply := Or.inl ⟨⟨477924, by omega⟩, f.node_477924, rfl⟩
  add := Or.inl ⟨⟨477925, by omega⟩, f.node_477925, rfl⟩
}

def certificate_175 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458133) (.wire 477899) (.wire 6997) (.wire 477928) := {
  difference := (.wire 477926)
  product := (.wire 477927)
  subtract := Or.inl ⟨⟨477926, by omega⟩, f.node_477926, rfl⟩
  multiply := Or.inl ⟨⟨477927, by omega⟩, f.node_477927, rfl⟩
  add := Or.inl ⟨⟨477928, by omega⟩, f.node_477928, rfl⟩
}

def certificate_176 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458133) (.wire 477910) (.wire 6998) (.wire 477931) := {
  difference := (.wire 477929)
  product := (.wire 477930)
  subtract := Or.inl ⟨⟨477929, by omega⟩, f.node_477929, rfl⟩
  multiply := Or.inl ⟨⟨477930, by omega⟩, f.node_477930, rfl⟩
  add := Or.inl ⟨⟨477931, by omega⟩, f.node_477931, rfl⟩
}

def certificate_177 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458133) (.wire 477921) (.wire 6999) (.wire 477934) := {
  difference := (.wire 477932)
  product := (.wire 477933)
  subtract := Or.inl ⟨⟨477932, by omega⟩, f.node_477932, rfl⟩
  multiply := Or.inl ⟨⟨477933, by omega⟩, f.node_477933, rfl⟩
  add := Or.inl ⟨⟨477934, by omega⟩, f.node_477934, rfl⟩
}

def certificate_178 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458133) (.wire 477887) (.wire 7000) (.wire 477937) := {
  difference := (.wire 477935)
  product := (.wire 477936)
  subtract := Or.inl ⟨⟨477935, by omega⟩, f.node_477935, rfl⟩
  multiply := Or.inl ⟨⟨477936, by omega⟩, f.node_477936, rfl⟩
  add := Or.inl ⟨⟨477937, by omega⟩, f.node_477937, rfl⟩
}

def certificate_179 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458133) (.wire 477898) (.wire 7001) (.wire 477940) := {
  difference := (.wire 477938)
  product := (.wire 477939)
  subtract := Or.inl ⟨⟨477938, by omega⟩, f.node_477938, rfl⟩
  multiply := Or.inl ⟨⟨477939, by omega⟩, f.node_477939, rfl⟩
  add := Or.inl ⟨⟨477940, by omega⟩, f.node_477940, rfl⟩
}

def certificate_180 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458133) (.wire 477909) (.wire 7002) (.wire 477943) := {
  difference := (.wire 477941)
  product := (.wire 477942)
  subtract := Or.inl ⟨⟨477941, by omega⟩, f.node_477941, rfl⟩
  multiply := Or.inl ⟨⟨477942, by omega⟩, f.node_477942, rfl⟩
  add := Or.inl ⟨⟨477943, by omega⟩, f.node_477943, rfl⟩
}

def certificate_181 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458133) (.wire 6996) (.wire 477888) (.wire 477946) := {
  difference := (.wire 477944)
  product := (.wire 477945)
  subtract := Or.inl ⟨⟨477944, by omega⟩, f.node_477944, rfl⟩
  multiply := Or.inl ⟨⟨477945, by omega⟩, f.node_477945, rfl⟩
  add := Or.inl ⟨⟨477946, by omega⟩, f.node_477946, rfl⟩
}

def certificate_182 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458133) (.wire 6997) (.wire 477899) (.wire 477949) := {
  difference := (.wire 477947)
  product := (.wire 477948)
  subtract := Or.inl ⟨⟨477947, by omega⟩, f.node_477947, rfl⟩
  multiply := Or.inl ⟨⟨477948, by omega⟩, f.node_477948, rfl⟩
  add := Or.inl ⟨⟨477949, by omega⟩, f.node_477949, rfl⟩
}

def certificate_183 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458133) (.wire 6998) (.wire 477910) (.wire 477952) := {
  difference := (.wire 477950)
  product := (.wire 477951)
  subtract := Or.inl ⟨⟨477950, by omega⟩, f.node_477950, rfl⟩
  multiply := Or.inl ⟨⟨477951, by omega⟩, f.node_477951, rfl⟩
  add := Or.inl ⟨⟨477952, by omega⟩, f.node_477952, rfl⟩
}

def certificate_184 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458133) (.wire 6999) (.wire 477921) (.wire 477955) := {
  difference := (.wire 477953)
  product := (.wire 477954)
  subtract := Or.inl ⟨⟨477953, by omega⟩, f.node_477953, rfl⟩
  multiply := Or.inl ⟨⟨477954, by omega⟩, f.node_477954, rfl⟩
  add := Or.inl ⟨⟨477955, by omega⟩, f.node_477955, rfl⟩
}

def certificate_185 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458133) (.wire 7000) (.wire 477887) (.wire 477958) := {
  difference := (.wire 477956)
  product := (.wire 477957)
  subtract := Or.inl ⟨⟨477956, by omega⟩, f.node_477956, rfl⟩
  multiply := Or.inl ⟨⟨477957, by omega⟩, f.node_477957, rfl⟩
  add := Or.inl ⟨⟨477958, by omega⟩, f.node_477958, rfl⟩
}

def certificate_186 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458133) (.wire 7001) (.wire 477898) (.wire 477961) := {
  difference := (.wire 477959)
  product := (.wire 477960)
  subtract := Or.inl ⟨⟨477959, by omega⟩, f.node_477959, rfl⟩
  multiply := Or.inl ⟨⟨477960, by omega⟩, f.node_477960, rfl⟩
  add := Or.inl ⟨⟨477961, by omega⟩, f.node_477961, rfl⟩
}

def certificate_187 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458133) (.wire 7002) (.wire 477909) (.wire 477964) := {
  difference := (.wire 477962)
  product := (.wire 477963)
  subtract := Or.inl ⟨⟨477962, by omega⟩, f.node_477962, rfl⟩
  multiply := Or.inl ⟨⟨477963, by omega⟩, f.node_477963, rfl⟩
  add := Or.inl ⟨⟨477964, by omega⟩, f.node_477964, rfl⟩
}

def certificate_188 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458138) (.wire 480362) (.wire 7003) (.wire 480399) := {
  difference := (.wire 480397)
  product := (.wire 480398)
  subtract := Or.inl ⟨⟨480397, by omega⟩, f.node_480397, rfl⟩
  multiply := Or.inl ⟨⟨480398, by omega⟩, f.node_480398, rfl⟩
  add := Or.inl ⟨⟨480399, by omega⟩, f.node_480399, rfl⟩
}

def certificate_189 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458138) (.wire 480373) (.wire 7004) (.wire 480402) := {
  difference := (.wire 480400)
  product := (.wire 480401)
  subtract := Or.inl ⟨⟨480400, by omega⟩, f.node_480400, rfl⟩
  multiply := Or.inl ⟨⟨480401, by omega⟩, f.node_480401, rfl⟩
  add := Or.inl ⟨⟨480402, by omega⟩, f.node_480402, rfl⟩
}

def certificate_190 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458138) (.wire 480384) (.wire 7005) (.wire 480405) := {
  difference := (.wire 480403)
  product := (.wire 480404)
  subtract := Or.inl ⟨⟨480403, by omega⟩, f.node_480403, rfl⟩
  multiply := Or.inl ⟨⟨480404, by omega⟩, f.node_480404, rfl⟩
  add := Or.inl ⟨⟨480405, by omega⟩, f.node_480405, rfl⟩
}

def certificate_191 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458138) (.wire 480395) (.wire 7006) (.wire 480408) := {
  difference := (.wire 480406)
  product := (.wire 480407)
  subtract := Or.inl ⟨⟨480406, by omega⟩, f.node_480406, rfl⟩
  multiply := Or.inl ⟨⟨480407, by omega⟩, f.node_480407, rfl⟩
  add := Or.inl ⟨⟨480408, by omega⟩, f.node_480408, rfl⟩
}

def certificate_192 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458138) (.wire 480361) (.wire 7007) (.wire 480411) := {
  difference := (.wire 480409)
  product := (.wire 480410)
  subtract := Or.inl ⟨⟨480409, by omega⟩, f.node_480409, rfl⟩
  multiply := Or.inl ⟨⟨480410, by omega⟩, f.node_480410, rfl⟩
  add := Or.inl ⟨⟨480411, by omega⟩, f.node_480411, rfl⟩
}

def certificate_193 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458138) (.wire 480372) (.wire 7008) (.wire 480414) := {
  difference := (.wire 480412)
  product := (.wire 480413)
  subtract := Or.inl ⟨⟨480412, by omega⟩, f.node_480412, rfl⟩
  multiply := Or.inl ⟨⟨480413, by omega⟩, f.node_480413, rfl⟩
  add := Or.inl ⟨⟨480414, by omega⟩, f.node_480414, rfl⟩
}

def certificate_194 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458138) (.wire 480383) (.wire 7009) (.wire 480417) := {
  difference := (.wire 480415)
  product := (.wire 480416)
  subtract := Or.inl ⟨⟨480415, by omega⟩, f.node_480415, rfl⟩
  multiply := Or.inl ⟨⟨480416, by omega⟩, f.node_480416, rfl⟩
  add := Or.inl ⟨⟨480417, by omega⟩, f.node_480417, rfl⟩
}

def certificate_195 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458138) (.wire 7003) (.wire 480362) (.wire 480420) := {
  difference := (.wire 480418)
  product := (.wire 480419)
  subtract := Or.inl ⟨⟨480418, by omega⟩, f.node_480418, rfl⟩
  multiply := Or.inl ⟨⟨480419, by omega⟩, f.node_480419, rfl⟩
  add := Or.inl ⟨⟨480420, by omega⟩, f.node_480420, rfl⟩
}

def certificate_196 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458138) (.wire 7004) (.wire 480373) (.wire 480423) := {
  difference := (.wire 480421)
  product := (.wire 480422)
  subtract := Or.inl ⟨⟨480421, by omega⟩, f.node_480421, rfl⟩
  multiply := Or.inl ⟨⟨480422, by omega⟩, f.node_480422, rfl⟩
  add := Or.inl ⟨⟨480423, by omega⟩, f.node_480423, rfl⟩
}

def certificate_197 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458138) (.wire 7005) (.wire 480384) (.wire 480426) := {
  difference := (.wire 480424)
  product := (.wire 480425)
  subtract := Or.inl ⟨⟨480424, by omega⟩, f.node_480424, rfl⟩
  multiply := Or.inl ⟨⟨480425, by omega⟩, f.node_480425, rfl⟩
  add := Or.inl ⟨⟨480426, by omega⟩, f.node_480426, rfl⟩
}

def certificate_198 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458138) (.wire 7006) (.wire 480395) (.wire 480429) := {
  difference := (.wire 480427)
  product := (.wire 480428)
  subtract := Or.inl ⟨⟨480427, by omega⟩, f.node_480427, rfl⟩
  multiply := Or.inl ⟨⟨480428, by omega⟩, f.node_480428, rfl⟩
  add := Or.inl ⟨⟨480429, by omega⟩, f.node_480429, rfl⟩
}

def certificate_199 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458138) (.wire 7007) (.wire 480361) (.wire 480432) := {
  difference := (.wire 480430)
  product := (.wire 480431)
  subtract := Or.inl ⟨⟨480430, by omega⟩, f.node_480430, rfl⟩
  multiply := Or.inl ⟨⟨480431, by omega⟩, f.node_480431, rfl⟩
  add := Or.inl ⟨⟨480432, by omega⟩, f.node_480432, rfl⟩
}

def certificate_200 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458138) (.wire 7008) (.wire 480372) (.wire 480435) := {
  difference := (.wire 480433)
  product := (.wire 480434)
  subtract := Or.inl ⟨⟨480433, by omega⟩, f.node_480433, rfl⟩
  multiply := Or.inl ⟨⟨480434, by omega⟩, f.node_480434, rfl⟩
  add := Or.inl ⟨⟨480435, by omega⟩, f.node_480435, rfl⟩
}

def certificate_201 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458138) (.wire 7009) (.wire 480383) (.wire 480438) := {
  difference := (.wire 480436)
  product := (.wire 480437)
  subtract := Or.inl ⟨⟨480436, by omega⟩, f.node_480436, rfl⟩
  multiply := Or.inl ⟨⟨480437, by omega⟩, f.node_480437, rfl⟩
  add := Or.inl ⟨⟨480438, by omega⟩, f.node_480438, rfl⟩
}

def certificate_202 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458143) (.wire 482836) (.wire 7010) (.wire 482873) := {
  difference := (.wire 482871)
  product := (.wire 482872)
  subtract := Or.inl ⟨⟨482871, by omega⟩, f.node_482871, rfl⟩
  multiply := Or.inl ⟨⟨482872, by omega⟩, f.node_482872, rfl⟩
  add := Or.inl ⟨⟨482873, by omega⟩, f.node_482873, rfl⟩
}

def certificate_203 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458143) (.wire 482847) (.wire 7011) (.wire 482876) := {
  difference := (.wire 482874)
  product := (.wire 482875)
  subtract := Or.inl ⟨⟨482874, by omega⟩, f.node_482874, rfl⟩
  multiply := Or.inl ⟨⟨482875, by omega⟩, f.node_482875, rfl⟩
  add := Or.inl ⟨⟨482876, by omega⟩, f.node_482876, rfl⟩
}

def certificate_204 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458143) (.wire 482858) (.wire 7012) (.wire 482879) := {
  difference := (.wire 482877)
  product := (.wire 482878)
  subtract := Or.inl ⟨⟨482877, by omega⟩, f.node_482877, rfl⟩
  multiply := Or.inl ⟨⟨482878, by omega⟩, f.node_482878, rfl⟩
  add := Or.inl ⟨⟨482879, by omega⟩, f.node_482879, rfl⟩
}

def certificate_205 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458143) (.wire 482869) (.wire 7013) (.wire 482882) := {
  difference := (.wire 482880)
  product := (.wire 482881)
  subtract := Or.inl ⟨⟨482880, by omega⟩, f.node_482880, rfl⟩
  multiply := Or.inl ⟨⟨482881, by omega⟩, f.node_482881, rfl⟩
  add := Or.inl ⟨⟨482882, by omega⟩, f.node_482882, rfl⟩
}

def certificate_206 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458143) (.wire 482835) (.wire 7014) (.wire 482885) := {
  difference := (.wire 482883)
  product := (.wire 482884)
  subtract := Or.inl ⟨⟨482883, by omega⟩, f.node_482883, rfl⟩
  multiply := Or.inl ⟨⟨482884, by omega⟩, f.node_482884, rfl⟩
  add := Or.inl ⟨⟨482885, by omega⟩, f.node_482885, rfl⟩
}

def certificate_207 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458143) (.wire 482846) (.wire 7015) (.wire 482888) := {
  difference := (.wire 482886)
  product := (.wire 482887)
  subtract := Or.inl ⟨⟨482886, by omega⟩, f.node_482886, rfl⟩
  multiply := Or.inl ⟨⟨482887, by omega⟩, f.node_482887, rfl⟩
  add := Or.inl ⟨⟨482888, by omega⟩, f.node_482888, rfl⟩
}

def certificate_208 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458143) (.wire 482857) (.wire 7016) (.wire 482891) := {
  difference := (.wire 482889)
  product := (.wire 482890)
  subtract := Or.inl ⟨⟨482889, by omega⟩, f.node_482889, rfl⟩
  multiply := Or.inl ⟨⟨482890, by omega⟩, f.node_482890, rfl⟩
  add := Or.inl ⟨⟨482891, by omega⟩, f.node_482891, rfl⟩
}

def certificate_209 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458143) (.wire 7010) (.wire 482836) (.wire 482894) := {
  difference := (.wire 482892)
  product := (.wire 482893)
  subtract := Or.inl ⟨⟨482892, by omega⟩, f.node_482892, rfl⟩
  multiply := Or.inl ⟨⟨482893, by omega⟩, f.node_482893, rfl⟩
  add := Or.inl ⟨⟨482894, by omega⟩, f.node_482894, rfl⟩
}

def certificate_210 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458143) (.wire 7011) (.wire 482847) (.wire 482897) := {
  difference := (.wire 482895)
  product := (.wire 482896)
  subtract := Or.inl ⟨⟨482895, by omega⟩, f.node_482895, rfl⟩
  multiply := Or.inl ⟨⟨482896, by omega⟩, f.node_482896, rfl⟩
  add := Or.inl ⟨⟨482897, by omega⟩, f.node_482897, rfl⟩
}

def certificate_211 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458143) (.wire 7012) (.wire 482858) (.wire 482900) := {
  difference := (.wire 482898)
  product := (.wire 482899)
  subtract := Or.inl ⟨⟨482898, by omega⟩, f.node_482898, rfl⟩
  multiply := Or.inl ⟨⟨482899, by omega⟩, f.node_482899, rfl⟩
  add := Or.inl ⟨⟨482900, by omega⟩, f.node_482900, rfl⟩
}

def certificate_212 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458143) (.wire 7013) (.wire 482869) (.wire 482903) := {
  difference := (.wire 482901)
  product := (.wire 482902)
  subtract := Or.inl ⟨⟨482901, by omega⟩, f.node_482901, rfl⟩
  multiply := Or.inl ⟨⟨482902, by omega⟩, f.node_482902, rfl⟩
  add := Or.inl ⟨⟨482903, by omega⟩, f.node_482903, rfl⟩
}

def certificate_213 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458143) (.wire 7014) (.wire 482835) (.wire 482906) := {
  difference := (.wire 482904)
  product := (.wire 482905)
  subtract := Or.inl ⟨⟨482904, by omega⟩, f.node_482904, rfl⟩
  multiply := Or.inl ⟨⟨482905, by omega⟩, f.node_482905, rfl⟩
  add := Or.inl ⟨⟨482906, by omega⟩, f.node_482906, rfl⟩
}

def certificate_214 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458143) (.wire 7015) (.wire 482846) (.wire 482909) := {
  difference := (.wire 482907)
  product := (.wire 482908)
  subtract := Or.inl ⟨⟨482907, by omega⟩, f.node_482907, rfl⟩
  multiply := Or.inl ⟨⟨482908, by omega⟩, f.node_482908, rfl⟩
  add := Or.inl ⟨⟨482909, by omega⟩, f.node_482909, rfl⟩
}

def certificate_215 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458143) (.wire 7016) (.wire 482857) (.wire 482912) := {
  difference := (.wire 482910)
  product := (.wire 482911)
  subtract := Or.inl ⟨⟨482910, by omega⟩, f.node_482910, rfl⟩
  multiply := Or.inl ⟨⟨482911, by omega⟩, f.node_482911, rfl⟩
  add := Or.inl ⟨⟨482912, by omega⟩, f.node_482912, rfl⟩
}

def certificate_216 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458148) (.wire 485310) (.wire 7017) (.wire 485347) := {
  difference := (.wire 485345)
  product := (.wire 485346)
  subtract := Or.inl ⟨⟨485345, by omega⟩, f.node_485345, rfl⟩
  multiply := Or.inl ⟨⟨485346, by omega⟩, f.node_485346, rfl⟩
  add := Or.inl ⟨⟨485347, by omega⟩, f.node_485347, rfl⟩
}

def certificate_217 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458148) (.wire 485321) (.wire 7018) (.wire 485350) := {
  difference := (.wire 485348)
  product := (.wire 485349)
  subtract := Or.inl ⟨⟨485348, by omega⟩, f.node_485348, rfl⟩
  multiply := Or.inl ⟨⟨485349, by omega⟩, f.node_485349, rfl⟩
  add := Or.inl ⟨⟨485350, by omega⟩, f.node_485350, rfl⟩
}

def certificate_218 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458148) (.wire 485332) (.wire 7019) (.wire 485353) := {
  difference := (.wire 485351)
  product := (.wire 485352)
  subtract := Or.inl ⟨⟨485351, by omega⟩, f.node_485351, rfl⟩
  multiply := Or.inl ⟨⟨485352, by omega⟩, f.node_485352, rfl⟩
  add := Or.inl ⟨⟨485353, by omega⟩, f.node_485353, rfl⟩
}

def certificate_219 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458148) (.wire 485343) (.wire 7020) (.wire 485356) := {
  difference := (.wire 485354)
  product := (.wire 485355)
  subtract := Or.inl ⟨⟨485354, by omega⟩, f.node_485354, rfl⟩
  multiply := Or.inl ⟨⟨485355, by omega⟩, f.node_485355, rfl⟩
  add := Or.inl ⟨⟨485356, by omega⟩, f.node_485356, rfl⟩
}

def certificate_220 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458148) (.wire 485309) (.wire 7021) (.wire 485359) := {
  difference := (.wire 485357)
  product := (.wire 485358)
  subtract := Or.inl ⟨⟨485357, by omega⟩, f.node_485357, rfl⟩
  multiply := Or.inl ⟨⟨485358, by omega⟩, f.node_485358, rfl⟩
  add := Or.inl ⟨⟨485359, by omega⟩, f.node_485359, rfl⟩
}

def certificate_221 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458148) (.wire 485320) (.wire 7022) (.wire 485362) := {
  difference := (.wire 485360)
  product := (.wire 485361)
  subtract := Or.inl ⟨⟨485360, by omega⟩, f.node_485360, rfl⟩
  multiply := Or.inl ⟨⟨485361, by omega⟩, f.node_485361, rfl⟩
  add := Or.inl ⟨⟨485362, by omega⟩, f.node_485362, rfl⟩
}

def certificate_222 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458148) (.wire 485331) (.wire 7023) (.wire 485365) := {
  difference := (.wire 485363)
  product := (.wire 485364)
  subtract := Or.inl ⟨⟨485363, by omega⟩, f.node_485363, rfl⟩
  multiply := Or.inl ⟨⟨485364, by omega⟩, f.node_485364, rfl⟩
  add := Or.inl ⟨⟨485365, by omega⟩, f.node_485365, rfl⟩
}

def certificate_223 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458148) (.wire 7017) (.wire 485310) (.wire 485368) := {
  difference := (.wire 485366)
  product := (.wire 485367)
  subtract := Or.inl ⟨⟨485366, by omega⟩, f.node_485366, rfl⟩
  multiply := Or.inl ⟨⟨485367, by omega⟩, f.node_485367, rfl⟩
  add := Or.inl ⟨⟨485368, by omega⟩, f.node_485368, rfl⟩
}

def certificate_224 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458148) (.wire 7018) (.wire 485321) (.wire 485371) := {
  difference := (.wire 485369)
  product := (.wire 485370)
  subtract := Or.inl ⟨⟨485369, by omega⟩, f.node_485369, rfl⟩
  multiply := Or.inl ⟨⟨485370, by omega⟩, f.node_485370, rfl⟩
  add := Or.inl ⟨⟨485371, by omega⟩, f.node_485371, rfl⟩
}

def certificate_225 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458148) (.wire 7019) (.wire 485332) (.wire 485374) := {
  difference := (.wire 485372)
  product := (.wire 485373)
  subtract := Or.inl ⟨⟨485372, by omega⟩, f.node_485372, rfl⟩
  multiply := Or.inl ⟨⟨485373, by omega⟩, f.node_485373, rfl⟩
  add := Or.inl ⟨⟨485374, by omega⟩, f.node_485374, rfl⟩
}

def certificate_226 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458148) (.wire 7020) (.wire 485343) (.wire 485377) := {
  difference := (.wire 485375)
  product := (.wire 485376)
  subtract := Or.inl ⟨⟨485375, by omega⟩, f.node_485375, rfl⟩
  multiply := Or.inl ⟨⟨485376, by omega⟩, f.node_485376, rfl⟩
  add := Or.inl ⟨⟨485377, by omega⟩, f.node_485377, rfl⟩
}

def certificate_227 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458148) (.wire 7021) (.wire 485309) (.wire 485380) := {
  difference := (.wire 485378)
  product := (.wire 485379)
  subtract := Or.inl ⟨⟨485378, by omega⟩, f.node_485378, rfl⟩
  multiply := Or.inl ⟨⟨485379, by omega⟩, f.node_485379, rfl⟩
  add := Or.inl ⟨⟨485380, by omega⟩, f.node_485380, rfl⟩
}

def certificate_228 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458148) (.wire 7022) (.wire 485320) (.wire 485383) := {
  difference := (.wire 485381)
  product := (.wire 485382)
  subtract := Or.inl ⟨⟨485381, by omega⟩, f.node_485381, rfl⟩
  multiply := Or.inl ⟨⟨485382, by omega⟩, f.node_485382, rfl⟩
  add := Or.inl ⟨⟨485383, by omega⟩, f.node_485383, rfl⟩
}

def certificate_229 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458148) (.wire 7023) (.wire 485331) (.wire 485386) := {
  difference := (.wire 485384)
  product := (.wire 485385)
  subtract := Or.inl ⟨⟨485384, by omega⟩, f.node_485384, rfl⟩
  multiply := Or.inl ⟨⟨485385, by omega⟩, f.node_485385, rfl⟩
  add := Or.inl ⟨⟨485386, by omega⟩, f.node_485386, rfl⟩
}

def certificate_230 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458153) (.wire 487784) (.wire 7024) (.wire 487821) := {
  difference := (.wire 487819)
  product := (.wire 487820)
  subtract := Or.inl ⟨⟨487819, by omega⟩, f.node_487819, rfl⟩
  multiply := Or.inl ⟨⟨487820, by omega⟩, f.node_487820, rfl⟩
  add := Or.inl ⟨⟨487821, by omega⟩, f.node_487821, rfl⟩
}

def certificate_231 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458153) (.wire 487795) (.wire 7025) (.wire 487824) := {
  difference := (.wire 487822)
  product := (.wire 487823)
  subtract := Or.inl ⟨⟨487822, by omega⟩, f.node_487822, rfl⟩
  multiply := Or.inl ⟨⟨487823, by omega⟩, f.node_487823, rfl⟩
  add := Or.inl ⟨⟨487824, by omega⟩, f.node_487824, rfl⟩
}

def certificate_232 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458153) (.wire 487806) (.wire 7026) (.wire 487827) := {
  difference := (.wire 487825)
  product := (.wire 487826)
  subtract := Or.inl ⟨⟨487825, by omega⟩, f.node_487825, rfl⟩
  multiply := Or.inl ⟨⟨487826, by omega⟩, f.node_487826, rfl⟩
  add := Or.inl ⟨⟨487827, by omega⟩, f.node_487827, rfl⟩
}

def certificate_233 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458153) (.wire 487817) (.wire 7027) (.wire 487830) := {
  difference := (.wire 487828)
  product := (.wire 487829)
  subtract := Or.inl ⟨⟨487828, by omega⟩, f.node_487828, rfl⟩
  multiply := Or.inl ⟨⟨487829, by omega⟩, f.node_487829, rfl⟩
  add := Or.inl ⟨⟨487830, by omega⟩, f.node_487830, rfl⟩
}

def certificate_234 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458153) (.wire 487783) (.wire 7028) (.wire 487833) := {
  difference := (.wire 487831)
  product := (.wire 487832)
  subtract := Or.inl ⟨⟨487831, by omega⟩, f.node_487831, rfl⟩
  multiply := Or.inl ⟨⟨487832, by omega⟩, f.node_487832, rfl⟩
  add := Or.inl ⟨⟨487833, by omega⟩, f.node_487833, rfl⟩
}

def certificate_235 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458153) (.wire 487794) (.wire 7029) (.wire 487836) := {
  difference := (.wire 487834)
  product := (.wire 487835)
  subtract := Or.inl ⟨⟨487834, by omega⟩, f.node_487834, rfl⟩
  multiply := Or.inl ⟨⟨487835, by omega⟩, f.node_487835, rfl⟩
  add := Or.inl ⟨⟨487836, by omega⟩, f.node_487836, rfl⟩
}

def certificate_236 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458153) (.wire 487805) (.wire 7030) (.wire 487839) := {
  difference := (.wire 487837)
  product := (.wire 487838)
  subtract := Or.inl ⟨⟨487837, by omega⟩, f.node_487837, rfl⟩
  multiply := Or.inl ⟨⟨487838, by omega⟩, f.node_487838, rfl⟩
  add := Or.inl ⟨⟨487839, by omega⟩, f.node_487839, rfl⟩
}

def certificate_237 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458153) (.wire 7024) (.wire 487784) (.wire 487842) := {
  difference := (.wire 487840)
  product := (.wire 487841)
  subtract := Or.inl ⟨⟨487840, by omega⟩, f.node_487840, rfl⟩
  multiply := Or.inl ⟨⟨487841, by omega⟩, f.node_487841, rfl⟩
  add := Or.inl ⟨⟨487842, by omega⟩, f.node_487842, rfl⟩
}

def certificate_238 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458153) (.wire 7025) (.wire 487795) (.wire 487845) := {
  difference := (.wire 487843)
  product := (.wire 487844)
  subtract := Or.inl ⟨⟨487843, by omega⟩, f.node_487843, rfl⟩
  multiply := Or.inl ⟨⟨487844, by omega⟩, f.node_487844, rfl⟩
  add := Or.inl ⟨⟨487845, by omega⟩, f.node_487845, rfl⟩
}

def certificate_239 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458153) (.wire 7026) (.wire 487806) (.wire 487848) := {
  difference := (.wire 487846)
  product := (.wire 487847)
  subtract := Or.inl ⟨⟨487846, by omega⟩, f.node_487846, rfl⟩
  multiply := Or.inl ⟨⟨487847, by omega⟩, f.node_487847, rfl⟩
  add := Or.inl ⟨⟨487848, by omega⟩, f.node_487848, rfl⟩
}

def certificate_240 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458153) (.wire 7027) (.wire 487817) (.wire 487851) := {
  difference := (.wire 487849)
  product := (.wire 487850)
  subtract := Or.inl ⟨⟨487849, by omega⟩, f.node_487849, rfl⟩
  multiply := Or.inl ⟨⟨487850, by omega⟩, f.node_487850, rfl⟩
  add := Or.inl ⟨⟨487851, by omega⟩, f.node_487851, rfl⟩
}

def certificate_241 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458153) (.wire 7028) (.wire 487783) (.wire 487854) := {
  difference := (.wire 487852)
  product := (.wire 487853)
  subtract := Or.inl ⟨⟨487852, by omega⟩, f.node_487852, rfl⟩
  multiply := Or.inl ⟨⟨487853, by omega⟩, f.node_487853, rfl⟩
  add := Or.inl ⟨⟨487854, by omega⟩, f.node_487854, rfl⟩
}

def certificate_242 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458153) (.wire 7029) (.wire 487794) (.wire 487857) := {
  difference := (.wire 487855)
  product := (.wire 487856)
  subtract := Or.inl ⟨⟨487855, by omega⟩, f.node_487855, rfl⟩
  multiply := Or.inl ⟨⟨487856, by omega⟩, f.node_487856, rfl⟩
  add := Or.inl ⟨⟨487857, by omega⟩, f.node_487857, rfl⟩
}

def certificate_243 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458153) (.wire 7030) (.wire 487805) (.wire 487860) := {
  difference := (.wire 487858)
  product := (.wire 487859)
  subtract := Or.inl ⟨⟨487858, by omega⟩, f.node_487858, rfl⟩
  multiply := Or.inl ⟨⟨487859, by omega⟩, f.node_487859, rfl⟩
  add := Or.inl ⟨⟨487860, by omega⟩, f.node_487860, rfl⟩
}

def certificate_244 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458158) (.wire 490258) (.wire 7031) (.wire 490295) := {
  difference := (.wire 490293)
  product := (.wire 490294)
  subtract := Or.inl ⟨⟨490293, by omega⟩, f.node_490293, rfl⟩
  multiply := Or.inl ⟨⟨490294, by omega⟩, f.node_490294, rfl⟩
  add := Or.inl ⟨⟨490295, by omega⟩, f.node_490295, rfl⟩
}

def certificate_245 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458158) (.wire 490269) (.wire 7032) (.wire 490298) := {
  difference := (.wire 490296)
  product := (.wire 490297)
  subtract := Or.inl ⟨⟨490296, by omega⟩, f.node_490296, rfl⟩
  multiply := Or.inl ⟨⟨490297, by omega⟩, f.node_490297, rfl⟩
  add := Or.inl ⟨⟨490298, by omega⟩, f.node_490298, rfl⟩
}

def certificate_246 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458158) (.wire 490280) (.wire 7033) (.wire 490301) := {
  difference := (.wire 490299)
  product := (.wire 490300)
  subtract := Or.inl ⟨⟨490299, by omega⟩, f.node_490299, rfl⟩
  multiply := Or.inl ⟨⟨490300, by omega⟩, f.node_490300, rfl⟩
  add := Or.inl ⟨⟨490301, by omega⟩, f.node_490301, rfl⟩
}

def certificate_247 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458158) (.wire 490291) (.wire 7034) (.wire 490304) := {
  difference := (.wire 490302)
  product := (.wire 490303)
  subtract := Or.inl ⟨⟨490302, by omega⟩, f.node_490302, rfl⟩
  multiply := Or.inl ⟨⟨490303, by omega⟩, f.node_490303, rfl⟩
  add := Or.inl ⟨⟨490304, by omega⟩, f.node_490304, rfl⟩
}

def certificate_248 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458158) (.wire 490257) (.wire 7035) (.wire 490307) := {
  difference := (.wire 490305)
  product := (.wire 490306)
  subtract := Or.inl ⟨⟨490305, by omega⟩, f.node_490305, rfl⟩
  multiply := Or.inl ⟨⟨490306, by omega⟩, f.node_490306, rfl⟩
  add := Or.inl ⟨⟨490307, by omega⟩, f.node_490307, rfl⟩
}

def certificate_249 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458158) (.wire 490268) (.wire 7036) (.wire 490310) := {
  difference := (.wire 490308)
  product := (.wire 490309)
  subtract := Or.inl ⟨⟨490308, by omega⟩, f.node_490308, rfl⟩
  multiply := Or.inl ⟨⟨490309, by omega⟩, f.node_490309, rfl⟩
  add := Or.inl ⟨⟨490310, by omega⟩, f.node_490310, rfl⟩
}

def certificate_250 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458158) (.wire 490279) (.wire 7037) (.wire 490313) := {
  difference := (.wire 490311)
  product := (.wire 490312)
  subtract := Or.inl ⟨⟨490311, by omega⟩, f.node_490311, rfl⟩
  multiply := Or.inl ⟨⟨490312, by omega⟩, f.node_490312, rfl⟩
  add := Or.inl ⟨⟨490313, by omega⟩, f.node_490313, rfl⟩
}

def certificate_251 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458158) (.wire 7031) (.wire 490258) (.wire 490316) := {
  difference := (.wire 490314)
  product := (.wire 490315)
  subtract := Or.inl ⟨⟨490314, by omega⟩, f.node_490314, rfl⟩
  multiply := Or.inl ⟨⟨490315, by omega⟩, f.node_490315, rfl⟩
  add := Or.inl ⟨⟨490316, by omega⟩, f.node_490316, rfl⟩
}

def certificate_252 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458158) (.wire 7032) (.wire 490269) (.wire 490319) := {
  difference := (.wire 490317)
  product := (.wire 490318)
  subtract := Or.inl ⟨⟨490317, by omega⟩, f.node_490317, rfl⟩
  multiply := Or.inl ⟨⟨490318, by omega⟩, f.node_490318, rfl⟩
  add := Or.inl ⟨⟨490319, by omega⟩, f.node_490319, rfl⟩
}

def certificate_253 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458158) (.wire 7033) (.wire 490280) (.wire 490322) := {
  difference := (.wire 490320)
  product := (.wire 490321)
  subtract := Or.inl ⟨⟨490320, by omega⟩, f.node_490320, rfl⟩
  multiply := Or.inl ⟨⟨490321, by omega⟩, f.node_490321, rfl⟩
  add := Or.inl ⟨⟨490322, by omega⟩, f.node_490322, rfl⟩
}

def certificate_254 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458158) (.wire 7034) (.wire 490291) (.wire 490325) := {
  difference := (.wire 490323)
  product := (.wire 490324)
  subtract := Or.inl ⟨⟨490323, by omega⟩, f.node_490323, rfl⟩
  multiply := Or.inl ⟨⟨490324, by omega⟩, f.node_490324, rfl⟩
  add := Or.inl ⟨⟨490325, by omega⟩, f.node_490325, rfl⟩
}

def certificate_255 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458158) (.wire 7035) (.wire 490257) (.wire 490328) := {
  difference := (.wire 490326)
  product := (.wire 490327)
  subtract := Or.inl ⟨⟨490326, by omega⟩, f.node_490326, rfl⟩
  multiply := Or.inl ⟨⟨490327, by omega⟩, f.node_490327, rfl⟩
  add := Or.inl ⟨⟨490328, by omega⟩, f.node_490328, rfl⟩
}

def certificate_256 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458158) (.wire 7036) (.wire 490268) (.wire 490331) := {
  difference := (.wire 490329)
  product := (.wire 490330)
  subtract := Or.inl ⟨⟨490329, by omega⟩, f.node_490329, rfl⟩
  multiply := Or.inl ⟨⟨490330, by omega⟩, f.node_490330, rfl⟩
  add := Or.inl ⟨⟨490331, by omega⟩, f.node_490331, rfl⟩
}

def certificate_257 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458158) (.wire 7037) (.wire 490279) (.wire 490334) := {
  difference := (.wire 490332)
  product := (.wire 490333)
  subtract := Or.inl ⟨⟨490332, by omega⟩, f.node_490332, rfl⟩
  multiply := Or.inl ⟨⟨490333, by omega⟩, f.node_490333, rfl⟩
  add := Or.inl ⟨⟨490334, by omega⟩, f.node_490334, rfl⟩
}

def certificate_258 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458163) (.wire 492732) (.wire 7038) (.wire 492769) := {
  difference := (.wire 492767)
  product := (.wire 492768)
  subtract := Or.inl ⟨⟨492767, by omega⟩, f.node_492767, rfl⟩
  multiply := Or.inl ⟨⟨492768, by omega⟩, f.node_492768, rfl⟩
  add := Or.inl ⟨⟨492769, by omega⟩, f.node_492769, rfl⟩
}

def certificate_259 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458163) (.wire 492743) (.wire 7039) (.wire 492772) := {
  difference := (.wire 492770)
  product := (.wire 492771)
  subtract := Or.inl ⟨⟨492770, by omega⟩, f.node_492770, rfl⟩
  multiply := Or.inl ⟨⟨492771, by omega⟩, f.node_492771, rfl⟩
  add := Or.inl ⟨⟨492772, by omega⟩, f.node_492772, rfl⟩
}

def certificate_260 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458163) (.wire 492754) (.wire 7040) (.wire 492775) := {
  difference := (.wire 492773)
  product := (.wire 492774)
  subtract := Or.inl ⟨⟨492773, by omega⟩, f.node_492773, rfl⟩
  multiply := Or.inl ⟨⟨492774, by omega⟩, f.node_492774, rfl⟩
  add := Or.inl ⟨⟨492775, by omega⟩, f.node_492775, rfl⟩
}

def certificate_261 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458163) (.wire 492765) (.wire 7041) (.wire 492778) := {
  difference := (.wire 492776)
  product := (.wire 492777)
  subtract := Or.inl ⟨⟨492776, by omega⟩, f.node_492776, rfl⟩
  multiply := Or.inl ⟨⟨492777, by omega⟩, f.node_492777, rfl⟩
  add := Or.inl ⟨⟨492778, by omega⟩, f.node_492778, rfl⟩
}

def certificate_262 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458163) (.wire 492731) (.wire 7042) (.wire 492781) := {
  difference := (.wire 492779)
  product := (.wire 492780)
  subtract := Or.inl ⟨⟨492779, by omega⟩, f.node_492779, rfl⟩
  multiply := Or.inl ⟨⟨492780, by omega⟩, f.node_492780, rfl⟩
  add := Or.inl ⟨⟨492781, by omega⟩, f.node_492781, rfl⟩
}

def certificate_263 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458163) (.wire 492742) (.wire 7043) (.wire 492784) := {
  difference := (.wire 492782)
  product := (.wire 492783)
  subtract := Or.inl ⟨⟨492782, by omega⟩, f.node_492782, rfl⟩
  multiply := Or.inl ⟨⟨492783, by omega⟩, f.node_492783, rfl⟩
  add := Or.inl ⟨⟨492784, by omega⟩, f.node_492784, rfl⟩
}

def certificate_264 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458163) (.wire 492753) (.wire 7044) (.wire 492787) := {
  difference := (.wire 492785)
  product := (.wire 492786)
  subtract := Or.inl ⟨⟨492785, by omega⟩, f.node_492785, rfl⟩
  multiply := Or.inl ⟨⟨492786, by omega⟩, f.node_492786, rfl⟩
  add := Or.inl ⟨⟨492787, by omega⟩, f.node_492787, rfl⟩
}

def certificate_265 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458163) (.wire 7038) (.wire 492732) (.wire 492790) := {
  difference := (.wire 492788)
  product := (.wire 492789)
  subtract := Or.inl ⟨⟨492788, by omega⟩, f.node_492788, rfl⟩
  multiply := Or.inl ⟨⟨492789, by omega⟩, f.node_492789, rfl⟩
  add := Or.inl ⟨⟨492790, by omega⟩, f.node_492790, rfl⟩
}

def certificate_266 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458163) (.wire 7039) (.wire 492743) (.wire 492793) := {
  difference := (.wire 492791)
  product := (.wire 492792)
  subtract := Or.inl ⟨⟨492791, by omega⟩, f.node_492791, rfl⟩
  multiply := Or.inl ⟨⟨492792, by omega⟩, f.node_492792, rfl⟩
  add := Or.inl ⟨⟨492793, by omega⟩, f.node_492793, rfl⟩
}

def certificate_267 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458163) (.wire 7040) (.wire 492754) (.wire 492796) := {
  difference := (.wire 492794)
  product := (.wire 492795)
  subtract := Or.inl ⟨⟨492794, by omega⟩, f.node_492794, rfl⟩
  multiply := Or.inl ⟨⟨492795, by omega⟩, f.node_492795, rfl⟩
  add := Or.inl ⟨⟨492796, by omega⟩, f.node_492796, rfl⟩
}

def certificate_268 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458163) (.wire 7041) (.wire 492765) (.wire 492799) := {
  difference := (.wire 492797)
  product := (.wire 492798)
  subtract := Or.inl ⟨⟨492797, by omega⟩, f.node_492797, rfl⟩
  multiply := Or.inl ⟨⟨492798, by omega⟩, f.node_492798, rfl⟩
  add := Or.inl ⟨⟨492799, by omega⟩, f.node_492799, rfl⟩
}

def certificate_269 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458163) (.wire 7042) (.wire 492731) (.wire 492802) := {
  difference := (.wire 492800)
  product := (.wire 492801)
  subtract := Or.inl ⟨⟨492800, by omega⟩, f.node_492800, rfl⟩
  multiply := Or.inl ⟨⟨492801, by omega⟩, f.node_492801, rfl⟩
  add := Or.inl ⟨⟨492802, by omega⟩, f.node_492802, rfl⟩
}

def certificate_270 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458163) (.wire 7043) (.wire 492742) (.wire 492805) := {
  difference := (.wire 492803)
  product := (.wire 492804)
  subtract := Or.inl ⟨⟨492803, by omega⟩, f.node_492803, rfl⟩
  multiply := Or.inl ⟨⟨492804, by omega⟩, f.node_492804, rfl⟩
  add := Or.inl ⟨⟨492805, by omega⟩, f.node_492805, rfl⟩
}

def certificate_271 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458163) (.wire 7044) (.wire 492753) (.wire 492808) := {
  difference := (.wire 492806)
  product := (.wire 492807)
  subtract := Or.inl ⟨⟨492806, by omega⟩, f.node_492806, rfl⟩
  multiply := Or.inl ⟨⟨492807, by omega⟩, f.node_492807, rfl⟩
  add := Or.inl ⟨⟨492808, by omega⟩, f.node_492808, rfl⟩
}

def certificate_272 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458168) (.wire 495206) (.wire 7045) (.wire 495243) := {
  difference := (.wire 495241)
  product := (.wire 495242)
  subtract := Or.inl ⟨⟨495241, by omega⟩, f.node_495241, rfl⟩
  multiply := Or.inl ⟨⟨495242, by omega⟩, f.node_495242, rfl⟩
  add := Or.inl ⟨⟨495243, by omega⟩, f.node_495243, rfl⟩
}

def certificate_273 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458168) (.wire 495217) (.wire 7046) (.wire 495246) := {
  difference := (.wire 495244)
  product := (.wire 495245)
  subtract := Or.inl ⟨⟨495244, by omega⟩, f.node_495244, rfl⟩
  multiply := Or.inl ⟨⟨495245, by omega⟩, f.node_495245, rfl⟩
  add := Or.inl ⟨⟨495246, by omega⟩, f.node_495246, rfl⟩
}

def certificate_274 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458168) (.wire 495228) (.wire 7047) (.wire 495249) := {
  difference := (.wire 495247)
  product := (.wire 495248)
  subtract := Or.inl ⟨⟨495247, by omega⟩, f.node_495247, rfl⟩
  multiply := Or.inl ⟨⟨495248, by omega⟩, f.node_495248, rfl⟩
  add := Or.inl ⟨⟨495249, by omega⟩, f.node_495249, rfl⟩
}

def certificate_275 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458168) (.wire 495239) (.wire 7048) (.wire 495252) := {
  difference := (.wire 495250)
  product := (.wire 495251)
  subtract := Or.inl ⟨⟨495250, by omega⟩, f.node_495250, rfl⟩
  multiply := Or.inl ⟨⟨495251, by omega⟩, f.node_495251, rfl⟩
  add := Or.inl ⟨⟨495252, by omega⟩, f.node_495252, rfl⟩
}

def certificate_276 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458168) (.wire 495205) (.wire 7049) (.wire 495255) := {
  difference := (.wire 495253)
  product := (.wire 495254)
  subtract := Or.inl ⟨⟨495253, by omega⟩, f.node_495253, rfl⟩
  multiply := Or.inl ⟨⟨495254, by omega⟩, f.node_495254, rfl⟩
  add := Or.inl ⟨⟨495255, by omega⟩, f.node_495255, rfl⟩
}

def certificate_277 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458168) (.wire 495216) (.wire 7050) (.wire 495258) := {
  difference := (.wire 495256)
  product := (.wire 495257)
  subtract := Or.inl ⟨⟨495256, by omega⟩, f.node_495256, rfl⟩
  multiply := Or.inl ⟨⟨495257, by omega⟩, f.node_495257, rfl⟩
  add := Or.inl ⟨⟨495258, by omega⟩, f.node_495258, rfl⟩
}

def certificate_278 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458168) (.wire 495227) (.wire 7051) (.wire 495261) := {
  difference := (.wire 495259)
  product := (.wire 495260)
  subtract := Or.inl ⟨⟨495259, by omega⟩, f.node_495259, rfl⟩
  multiply := Or.inl ⟨⟨495260, by omega⟩, f.node_495260, rfl⟩
  add := Or.inl ⟨⟨495261, by omega⟩, f.node_495261, rfl⟩
}

def certificate_279 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458168) (.wire 7045) (.wire 495206) (.wire 495264) := {
  difference := (.wire 495262)
  product := (.wire 495263)
  subtract := Or.inl ⟨⟨495262, by omega⟩, f.node_495262, rfl⟩
  multiply := Or.inl ⟨⟨495263, by omega⟩, f.node_495263, rfl⟩
  add := Or.inl ⟨⟨495264, by omega⟩, f.node_495264, rfl⟩
}

def certificate_280 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458168) (.wire 7046) (.wire 495217) (.wire 495267) := {
  difference := (.wire 495265)
  product := (.wire 495266)
  subtract := Or.inl ⟨⟨495265, by omega⟩, f.node_495265, rfl⟩
  multiply := Or.inl ⟨⟨495266, by omega⟩, f.node_495266, rfl⟩
  add := Or.inl ⟨⟨495267, by omega⟩, f.node_495267, rfl⟩
}

def certificate_281 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458168) (.wire 7047) (.wire 495228) (.wire 495270) := {
  difference := (.wire 495268)
  product := (.wire 495269)
  subtract := Or.inl ⟨⟨495268, by omega⟩, f.node_495268, rfl⟩
  multiply := Or.inl ⟨⟨495269, by omega⟩, f.node_495269, rfl⟩
  add := Or.inl ⟨⟨495270, by omega⟩, f.node_495270, rfl⟩
}

def certificate_282 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458168) (.wire 7048) (.wire 495239) (.wire 495273) := {
  difference := (.wire 495271)
  product := (.wire 495272)
  subtract := Or.inl ⟨⟨495271, by omega⟩, f.node_495271, rfl⟩
  multiply := Or.inl ⟨⟨495272, by omega⟩, f.node_495272, rfl⟩
  add := Or.inl ⟨⟨495273, by omega⟩, f.node_495273, rfl⟩
}

def certificate_283 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458168) (.wire 7049) (.wire 495205) (.wire 495276) := {
  difference := (.wire 495274)
  product := (.wire 495275)
  subtract := Or.inl ⟨⟨495274, by omega⟩, f.node_495274, rfl⟩
  multiply := Or.inl ⟨⟨495275, by omega⟩, f.node_495275, rfl⟩
  add := Or.inl ⟨⟨495276, by omega⟩, f.node_495276, rfl⟩
}

def certificate_284 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458168) (.wire 7050) (.wire 495216) (.wire 495279) := {
  difference := (.wire 495277)
  product := (.wire 495278)
  subtract := Or.inl ⟨⟨495277, by omega⟩, f.node_495277, rfl⟩
  multiply := Or.inl ⟨⟨495278, by omega⟩, f.node_495278, rfl⟩
  add := Or.inl ⟨⟨495279, by omega⟩, f.node_495279, rfl⟩
}

def certificate_285 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458168) (.wire 7051) (.wire 495227) (.wire 495282) := {
  difference := (.wire 495280)
  product := (.wire 495281)
  subtract := Or.inl ⟨⟨495280, by omega⟩, f.node_495280, rfl⟩
  multiply := Or.inl ⟨⟨495281, by omega⟩, f.node_495281, rfl⟩
  add := Or.inl ⟨⟨495282, by omega⟩, f.node_495282, rfl⟩
}

def certificate_286 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458173) (.wire 497680) (.wire 7052) (.wire 497717) := {
  difference := (.wire 497715)
  product := (.wire 497716)
  subtract := Or.inl ⟨⟨497715, by omega⟩, f.node_497715, rfl⟩
  multiply := Or.inl ⟨⟨497716, by omega⟩, f.node_497716, rfl⟩
  add := Or.inl ⟨⟨497717, by omega⟩, f.node_497717, rfl⟩
}

def certificate_287 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458173) (.wire 497691) (.wire 7053) (.wire 497720) := {
  difference := (.wire 497718)
  product := (.wire 497719)
  subtract := Or.inl ⟨⟨497718, by omega⟩, f.node_497718, rfl⟩
  multiply := Or.inl ⟨⟨497719, by omega⟩, f.node_497719, rfl⟩
  add := Or.inl ⟨⟨497720, by omega⟩, f.node_497720, rfl⟩
}

def certificate_288 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458173) (.wire 497702) (.wire 7054) (.wire 497723) := {
  difference := (.wire 497721)
  product := (.wire 497722)
  subtract := Or.inl ⟨⟨497721, by omega⟩, f.node_497721, rfl⟩
  multiply := Or.inl ⟨⟨497722, by omega⟩, f.node_497722, rfl⟩
  add := Or.inl ⟨⟨497723, by omega⟩, f.node_497723, rfl⟩
}

def certificate_289 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458173) (.wire 497713) (.wire 7055) (.wire 497726) := {
  difference := (.wire 497724)
  product := (.wire 497725)
  subtract := Or.inl ⟨⟨497724, by omega⟩, f.node_497724, rfl⟩
  multiply := Or.inl ⟨⟨497725, by omega⟩, f.node_497725, rfl⟩
  add := Or.inl ⟨⟨497726, by omega⟩, f.node_497726, rfl⟩
}

def certificate_290 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458173) (.wire 497679) (.wire 7056) (.wire 497729) := {
  difference := (.wire 497727)
  product := (.wire 497728)
  subtract := Or.inl ⟨⟨497727, by omega⟩, f.node_497727, rfl⟩
  multiply := Or.inl ⟨⟨497728, by omega⟩, f.node_497728, rfl⟩
  add := Or.inl ⟨⟨497729, by omega⟩, f.node_497729, rfl⟩
}

def certificate_291 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458173) (.wire 497690) (.wire 7057) (.wire 497732) := {
  difference := (.wire 497730)
  product := (.wire 497731)
  subtract := Or.inl ⟨⟨497730, by omega⟩, f.node_497730, rfl⟩
  multiply := Or.inl ⟨⟨497731, by omega⟩, f.node_497731, rfl⟩
  add := Or.inl ⟨⟨497732, by omega⟩, f.node_497732, rfl⟩
}

def certificate_292 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458173) (.wire 497701) (.wire 7058) (.wire 497735) := {
  difference := (.wire 497733)
  product := (.wire 497734)
  subtract := Or.inl ⟨⟨497733, by omega⟩, f.node_497733, rfl⟩
  multiply := Or.inl ⟨⟨497734, by omega⟩, f.node_497734, rfl⟩
  add := Or.inl ⟨⟨497735, by omega⟩, f.node_497735, rfl⟩
}

def certificate_293 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458173) (.wire 7052) (.wire 497680) (.wire 497738) := {
  difference := (.wire 497736)
  product := (.wire 497737)
  subtract := Or.inl ⟨⟨497736, by omega⟩, f.node_497736, rfl⟩
  multiply := Or.inl ⟨⟨497737, by omega⟩, f.node_497737, rfl⟩
  add := Or.inl ⟨⟨497738, by omega⟩, f.node_497738, rfl⟩
}

def certificate_294 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458173) (.wire 7053) (.wire 497691) (.wire 497741) := {
  difference := (.wire 497739)
  product := (.wire 497740)
  subtract := Or.inl ⟨⟨497739, by omega⟩, f.node_497739, rfl⟩
  multiply := Or.inl ⟨⟨497740, by omega⟩, f.node_497740, rfl⟩
  add := Or.inl ⟨⟨497741, by omega⟩, f.node_497741, rfl⟩
}

def certificate_295 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458173) (.wire 7054) (.wire 497702) (.wire 497744) := {
  difference := (.wire 497742)
  product := (.wire 497743)
  subtract := Or.inl ⟨⟨497742, by omega⟩, f.node_497742, rfl⟩
  multiply := Or.inl ⟨⟨497743, by omega⟩, f.node_497743, rfl⟩
  add := Or.inl ⟨⟨497744, by omega⟩, f.node_497744, rfl⟩
}

def certificate_296 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458173) (.wire 7055) (.wire 497713) (.wire 497747) := {
  difference := (.wire 497745)
  product := (.wire 497746)
  subtract := Or.inl ⟨⟨497745, by omega⟩, f.node_497745, rfl⟩
  multiply := Or.inl ⟨⟨497746, by omega⟩, f.node_497746, rfl⟩
  add := Or.inl ⟨⟨497747, by omega⟩, f.node_497747, rfl⟩
}

def certificate_297 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458173) (.wire 7056) (.wire 497679) (.wire 497750) := {
  difference := (.wire 497748)
  product := (.wire 497749)
  subtract := Or.inl ⟨⟨497748, by omega⟩, f.node_497748, rfl⟩
  multiply := Or.inl ⟨⟨497749, by omega⟩, f.node_497749, rfl⟩
  add := Or.inl ⟨⟨497750, by omega⟩, f.node_497750, rfl⟩
}

def certificate_298 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458173) (.wire 7057) (.wire 497690) (.wire 497753) := {
  difference := (.wire 497751)
  product := (.wire 497752)
  subtract := Or.inl ⟨⟨497751, by omega⟩, f.node_497751, rfl⟩
  multiply := Or.inl ⟨⟨497752, by omega⟩, f.node_497752, rfl⟩
  add := Or.inl ⟨⟨497753, by omega⟩, f.node_497753, rfl⟩
}

def certificate_299 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458173) (.wire 7058) (.wire 497701) (.wire 497756) := {
  difference := (.wire 497754)
  product := (.wire 497755)
  subtract := Or.inl ⟨⟨497754, by omega⟩, f.node_497754, rfl⟩
  multiply := Or.inl ⟨⟨497755, by omega⟩, f.node_497755, rfl⟩
  add := Or.inl ⟨⟨497756, by omega⟩, f.node_497756, rfl⟩
}

def certificate_300 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458178) (.wire 500154) (.wire 7059) (.wire 500191) := {
  difference := (.wire 500189)
  product := (.wire 500190)
  subtract := Or.inl ⟨⟨500189, by omega⟩, f.node_500189, rfl⟩
  multiply := Or.inl ⟨⟨500190, by omega⟩, f.node_500190, rfl⟩
  add := Or.inl ⟨⟨500191, by omega⟩, f.node_500191, rfl⟩
}

def certificate_301 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458178) (.wire 500165) (.wire 7060) (.wire 500194) := {
  difference := (.wire 500192)
  product := (.wire 500193)
  subtract := Or.inl ⟨⟨500192, by omega⟩, f.node_500192, rfl⟩
  multiply := Or.inl ⟨⟨500193, by omega⟩, f.node_500193, rfl⟩
  add := Or.inl ⟨⟨500194, by omega⟩, f.node_500194, rfl⟩
}

def certificate_302 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458178) (.wire 500176) (.wire 7061) (.wire 500197) := {
  difference := (.wire 500195)
  product := (.wire 500196)
  subtract := Or.inl ⟨⟨500195, by omega⟩, f.node_500195, rfl⟩
  multiply := Or.inl ⟨⟨500196, by omega⟩, f.node_500196, rfl⟩
  add := Or.inl ⟨⟨500197, by omega⟩, f.node_500197, rfl⟩
}

def certificate_303 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458178) (.wire 500187) (.wire 7062) (.wire 500200) := {
  difference := (.wire 500198)
  product := (.wire 500199)
  subtract := Or.inl ⟨⟨500198, by omega⟩, f.node_500198, rfl⟩
  multiply := Or.inl ⟨⟨500199, by omega⟩, f.node_500199, rfl⟩
  add := Or.inl ⟨⟨500200, by omega⟩, f.node_500200, rfl⟩
}

def certificate_304 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458178) (.wire 500153) (.wire 7063) (.wire 500203) := {
  difference := (.wire 500201)
  product := (.wire 500202)
  subtract := Or.inl ⟨⟨500201, by omega⟩, f.node_500201, rfl⟩
  multiply := Or.inl ⟨⟨500202, by omega⟩, f.node_500202, rfl⟩
  add := Or.inl ⟨⟨500203, by omega⟩, f.node_500203, rfl⟩
}

def certificate_305 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458178) (.wire 500164) (.wire 7064) (.wire 500206) := {
  difference := (.wire 500204)
  product := (.wire 500205)
  subtract := Or.inl ⟨⟨500204, by omega⟩, f.node_500204, rfl⟩
  multiply := Or.inl ⟨⟨500205, by omega⟩, f.node_500205, rfl⟩
  add := Or.inl ⟨⟨500206, by omega⟩, f.node_500206, rfl⟩
}

def certificate_306 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458178) (.wire 500175) (.wire 7065) (.wire 500209) := {
  difference := (.wire 500207)
  product := (.wire 500208)
  subtract := Or.inl ⟨⟨500207, by omega⟩, f.node_500207, rfl⟩
  multiply := Or.inl ⟨⟨500208, by omega⟩, f.node_500208, rfl⟩
  add := Or.inl ⟨⟨500209, by omega⟩, f.node_500209, rfl⟩
}

def certificate_307 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458178) (.wire 7059) (.wire 500154) (.wire 500212) := {
  difference := (.wire 500210)
  product := (.wire 500211)
  subtract := Or.inl ⟨⟨500210, by omega⟩, f.node_500210, rfl⟩
  multiply := Or.inl ⟨⟨500211, by omega⟩, f.node_500211, rfl⟩
  add := Or.inl ⟨⟨500212, by omega⟩, f.node_500212, rfl⟩
}

def certificate_308 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458178) (.wire 7060) (.wire 500165) (.wire 500215) := {
  difference := (.wire 500213)
  product := (.wire 500214)
  subtract := Or.inl ⟨⟨500213, by omega⟩, f.node_500213, rfl⟩
  multiply := Or.inl ⟨⟨500214, by omega⟩, f.node_500214, rfl⟩
  add := Or.inl ⟨⟨500215, by omega⟩, f.node_500215, rfl⟩
}

def certificate_309 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458178) (.wire 7061) (.wire 500176) (.wire 500218) := {
  difference := (.wire 500216)
  product := (.wire 500217)
  subtract := Or.inl ⟨⟨500216, by omega⟩, f.node_500216, rfl⟩
  multiply := Or.inl ⟨⟨500217, by omega⟩, f.node_500217, rfl⟩
  add := Or.inl ⟨⟨500218, by omega⟩, f.node_500218, rfl⟩
}

def certificate_310 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458178) (.wire 7062) (.wire 500187) (.wire 500221) := {
  difference := (.wire 500219)
  product := (.wire 500220)
  subtract := Or.inl ⟨⟨500219, by omega⟩, f.node_500219, rfl⟩
  multiply := Or.inl ⟨⟨500220, by omega⟩, f.node_500220, rfl⟩
  add := Or.inl ⟨⟨500221, by omega⟩, f.node_500221, rfl⟩
}

def certificate_311 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458178) (.wire 7063) (.wire 500153) (.wire 500224) := {
  difference := (.wire 500222)
  product := (.wire 500223)
  subtract := Or.inl ⟨⟨500222, by omega⟩, f.node_500222, rfl⟩
  multiply := Or.inl ⟨⟨500223, by omega⟩, f.node_500223, rfl⟩
  add := Or.inl ⟨⟨500224, by omega⟩, f.node_500224, rfl⟩
}

def certificate_312 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458178) (.wire 7064) (.wire 500164) (.wire 500227) := {
  difference := (.wire 500225)
  product := (.wire 500226)
  subtract := Or.inl ⟨⟨500225, by omega⟩, f.node_500225, rfl⟩
  multiply := Or.inl ⟨⟨500226, by omega⟩, f.node_500226, rfl⟩
  add := Or.inl ⟨⟨500227, by omega⟩, f.node_500227, rfl⟩
}

def certificate_313 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458178) (.wire 7065) (.wire 500175) (.wire 500230) := {
  difference := (.wire 500228)
  product := (.wire 500229)
  subtract := Or.inl ⟨⟨500228, by omega⟩, f.node_500228, rfl⟩
  multiply := Or.inl ⟨⟨500229, by omega⟩, f.node_500229, rfl⟩
  add := Or.inl ⟨⟨500230, by omega⟩, f.node_500230, rfl⟩
}

def certificate_314 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458183) (.wire 502628) (.wire 7066) (.wire 502665) := {
  difference := (.wire 502663)
  product := (.wire 502664)
  subtract := Or.inl ⟨⟨502663, by omega⟩, f.node_502663, rfl⟩
  multiply := Or.inl ⟨⟨502664, by omega⟩, f.node_502664, rfl⟩
  add := Or.inl ⟨⟨502665, by omega⟩, f.node_502665, rfl⟩
}

def certificate_315 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458183) (.wire 502639) (.wire 7067) (.wire 502668) := {
  difference := (.wire 502666)
  product := (.wire 502667)
  subtract := Or.inl ⟨⟨502666, by omega⟩, f.node_502666, rfl⟩
  multiply := Or.inl ⟨⟨502667, by omega⟩, f.node_502667, rfl⟩
  add := Or.inl ⟨⟨502668, by omega⟩, f.node_502668, rfl⟩
}

def certificate_316 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458183) (.wire 502650) (.wire 7068) (.wire 502671) := {
  difference := (.wire 502669)
  product := (.wire 502670)
  subtract := Or.inl ⟨⟨502669, by omega⟩, f.node_502669, rfl⟩
  multiply := Or.inl ⟨⟨502670, by omega⟩, f.node_502670, rfl⟩
  add := Or.inl ⟨⟨502671, by omega⟩, f.node_502671, rfl⟩
}

def certificate_317 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458183) (.wire 502661) (.wire 7069) (.wire 502674) := {
  difference := (.wire 502672)
  product := (.wire 502673)
  subtract := Or.inl ⟨⟨502672, by omega⟩, f.node_502672, rfl⟩
  multiply := Or.inl ⟨⟨502673, by omega⟩, f.node_502673, rfl⟩
  add := Or.inl ⟨⟨502674, by omega⟩, f.node_502674, rfl⟩
}

def certificate_318 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458183) (.wire 502627) (.wire 7070) (.wire 502677) := {
  difference := (.wire 502675)
  product := (.wire 502676)
  subtract := Or.inl ⟨⟨502675, by omega⟩, f.node_502675, rfl⟩
  multiply := Or.inl ⟨⟨502676, by omega⟩, f.node_502676, rfl⟩
  add := Or.inl ⟨⟨502677, by omega⟩, f.node_502677, rfl⟩
}

def certificate_319 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458183) (.wire 502638) (.wire 7071) (.wire 502680) := {
  difference := (.wire 502678)
  product := (.wire 502679)
  subtract := Or.inl ⟨⟨502678, by omega⟩, f.node_502678, rfl⟩
  multiply := Or.inl ⟨⟨502679, by omega⟩, f.node_502679, rfl⟩
  add := Or.inl ⟨⟨502680, by omega⟩, f.node_502680, rfl⟩
}

def certificate_320 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458183) (.wire 502649) (.wire 7072) (.wire 502683) := {
  difference := (.wire 502681)
  product := (.wire 502682)
  subtract := Or.inl ⟨⟨502681, by omega⟩, f.node_502681, rfl⟩
  multiply := Or.inl ⟨⟨502682, by omega⟩, f.node_502682, rfl⟩
  add := Or.inl ⟨⟨502683, by omega⟩, f.node_502683, rfl⟩
}

def certificate_321 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458183) (.wire 7066) (.wire 502628) (.wire 502686) := {
  difference := (.wire 502684)
  product := (.wire 502685)
  subtract := Or.inl ⟨⟨502684, by omega⟩, f.node_502684, rfl⟩
  multiply := Or.inl ⟨⟨502685, by omega⟩, f.node_502685, rfl⟩
  add := Or.inl ⟨⟨502686, by omega⟩, f.node_502686, rfl⟩
}

def certificate_322 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458183) (.wire 7067) (.wire 502639) (.wire 502689) := {
  difference := (.wire 502687)
  product := (.wire 502688)
  subtract := Or.inl ⟨⟨502687, by omega⟩, f.node_502687, rfl⟩
  multiply := Or.inl ⟨⟨502688, by omega⟩, f.node_502688, rfl⟩
  add := Or.inl ⟨⟨502689, by omega⟩, f.node_502689, rfl⟩
}

def certificate_323 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458183) (.wire 7068) (.wire 502650) (.wire 502692) := {
  difference := (.wire 502690)
  product := (.wire 502691)
  subtract := Or.inl ⟨⟨502690, by omega⟩, f.node_502690, rfl⟩
  multiply := Or.inl ⟨⟨502691, by omega⟩, f.node_502691, rfl⟩
  add := Or.inl ⟨⟨502692, by omega⟩, f.node_502692, rfl⟩
}

def certificate_324 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458183) (.wire 7069) (.wire 502661) (.wire 502695) := {
  difference := (.wire 502693)
  product := (.wire 502694)
  subtract := Or.inl ⟨⟨502693, by omega⟩, f.node_502693, rfl⟩
  multiply := Or.inl ⟨⟨502694, by omega⟩, f.node_502694, rfl⟩
  add := Or.inl ⟨⟨502695, by omega⟩, f.node_502695, rfl⟩
}

def certificate_325 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458183) (.wire 7070) (.wire 502627) (.wire 502698) := {
  difference := (.wire 502696)
  product := (.wire 502697)
  subtract := Or.inl ⟨⟨502696, by omega⟩, f.node_502696, rfl⟩
  multiply := Or.inl ⟨⟨502697, by omega⟩, f.node_502697, rfl⟩
  add := Or.inl ⟨⟨502698, by omega⟩, f.node_502698, rfl⟩
}

def certificate_326 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458183) (.wire 7071) (.wire 502638) (.wire 502701) := {
  difference := (.wire 502699)
  product := (.wire 502700)
  subtract := Or.inl ⟨⟨502699, by omega⟩, f.node_502699, rfl⟩
  multiply := Or.inl ⟨⟨502700, by omega⟩, f.node_502700, rfl⟩
  add := Or.inl ⟨⟨502701, by omega⟩, f.node_502701, rfl⟩
}

def certificate_327 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458183) (.wire 7072) (.wire 502649) (.wire 502704) := {
  difference := (.wire 502702)
  product := (.wire 502703)
  subtract := Or.inl ⟨⟨502702, by omega⟩, f.node_502702, rfl⟩
  multiply := Or.inl ⟨⟨502703, by omega⟩, f.node_502703, rfl⟩
  add := Or.inl ⟨⟨502704, by omega⟩, f.node_502704, rfl⟩
}

def certificate_328 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458188) (.wire 505102) (.wire 7073) (.wire 505139) := {
  difference := (.wire 505137)
  product := (.wire 505138)
  subtract := Or.inl ⟨⟨505137, by omega⟩, f.node_505137, rfl⟩
  multiply := Or.inl ⟨⟨505138, by omega⟩, f.node_505138, rfl⟩
  add := Or.inl ⟨⟨505139, by omega⟩, f.node_505139, rfl⟩
}

def certificate_329 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458188) (.wire 505113) (.wire 7074) (.wire 505142) := {
  difference := (.wire 505140)
  product := (.wire 505141)
  subtract := Or.inl ⟨⟨505140, by omega⟩, f.node_505140, rfl⟩
  multiply := Or.inl ⟨⟨505141, by omega⟩, f.node_505141, rfl⟩
  add := Or.inl ⟨⟨505142, by omega⟩, f.node_505142, rfl⟩
}

def certificate_330 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458188) (.wire 505124) (.wire 7075) (.wire 505145) := {
  difference := (.wire 505143)
  product := (.wire 505144)
  subtract := Or.inl ⟨⟨505143, by omega⟩, f.node_505143, rfl⟩
  multiply := Or.inl ⟨⟨505144, by omega⟩, f.node_505144, rfl⟩
  add := Or.inl ⟨⟨505145, by omega⟩, f.node_505145, rfl⟩
}

def certificate_331 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458188) (.wire 505135) (.wire 7076) (.wire 505148) := {
  difference := (.wire 505146)
  product := (.wire 505147)
  subtract := Or.inl ⟨⟨505146, by omega⟩, f.node_505146, rfl⟩
  multiply := Or.inl ⟨⟨505147, by omega⟩, f.node_505147, rfl⟩
  add := Or.inl ⟨⟨505148, by omega⟩, f.node_505148, rfl⟩
}

def certificate_332 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458188) (.wire 505101) (.wire 7077) (.wire 505151) := {
  difference := (.wire 505149)
  product := (.wire 505150)
  subtract := Or.inl ⟨⟨505149, by omega⟩, f.node_505149, rfl⟩
  multiply := Or.inl ⟨⟨505150, by omega⟩, f.node_505150, rfl⟩
  add := Or.inl ⟨⟨505151, by omega⟩, f.node_505151, rfl⟩
}

def certificate_333 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458188) (.wire 505112) (.wire 7078) (.wire 505154) := {
  difference := (.wire 505152)
  product := (.wire 505153)
  subtract := Or.inl ⟨⟨505152, by omega⟩, f.node_505152, rfl⟩
  multiply := Or.inl ⟨⟨505153, by omega⟩, f.node_505153, rfl⟩
  add := Or.inl ⟨⟨505154, by omega⟩, f.node_505154, rfl⟩
}

def certificate_334 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458188) (.wire 505123) (.wire 7079) (.wire 505157) := {
  difference := (.wire 505155)
  product := (.wire 505156)
  subtract := Or.inl ⟨⟨505155, by omega⟩, f.node_505155, rfl⟩
  multiply := Or.inl ⟨⟨505156, by omega⟩, f.node_505156, rfl⟩
  add := Or.inl ⟨⟨505157, by omega⟩, f.node_505157, rfl⟩
}

def certificate_335 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458188) (.wire 7073) (.wire 505102) (.wire 505160) := {
  difference := (.wire 505158)
  product := (.wire 505159)
  subtract := Or.inl ⟨⟨505158, by omega⟩, f.node_505158, rfl⟩
  multiply := Or.inl ⟨⟨505159, by omega⟩, f.node_505159, rfl⟩
  add := Or.inl ⟨⟨505160, by omega⟩, f.node_505160, rfl⟩
}

def certificate_336 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458188) (.wire 7074) (.wire 505113) (.wire 505163) := {
  difference := (.wire 505161)
  product := (.wire 505162)
  subtract := Or.inl ⟨⟨505161, by omega⟩, f.node_505161, rfl⟩
  multiply := Or.inl ⟨⟨505162, by omega⟩, f.node_505162, rfl⟩
  add := Or.inl ⟨⟨505163, by omega⟩, f.node_505163, rfl⟩
}

def certificate_337 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458188) (.wire 7075) (.wire 505124) (.wire 505166) := {
  difference := (.wire 505164)
  product := (.wire 505165)
  subtract := Or.inl ⟨⟨505164, by omega⟩, f.node_505164, rfl⟩
  multiply := Or.inl ⟨⟨505165, by omega⟩, f.node_505165, rfl⟩
  add := Or.inl ⟨⟨505166, by omega⟩, f.node_505166, rfl⟩
}

def certificate_338 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458188) (.wire 7076) (.wire 505135) (.wire 505169) := {
  difference := (.wire 505167)
  product := (.wire 505168)
  subtract := Or.inl ⟨⟨505167, by omega⟩, f.node_505167, rfl⟩
  multiply := Or.inl ⟨⟨505168, by omega⟩, f.node_505168, rfl⟩
  add := Or.inl ⟨⟨505169, by omega⟩, f.node_505169, rfl⟩
}

def certificate_339 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458188) (.wire 7077) (.wire 505101) (.wire 505172) := {
  difference := (.wire 505170)
  product := (.wire 505171)
  subtract := Or.inl ⟨⟨505170, by omega⟩, f.node_505170, rfl⟩
  multiply := Or.inl ⟨⟨505171, by omega⟩, f.node_505171, rfl⟩
  add := Or.inl ⟨⟨505172, by omega⟩, f.node_505172, rfl⟩
}

def certificate_340 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458188) (.wire 7078) (.wire 505112) (.wire 505175) := {
  difference := (.wire 505173)
  product := (.wire 505174)
  subtract := Or.inl ⟨⟨505173, by omega⟩, f.node_505173, rfl⟩
  multiply := Or.inl ⟨⟨505174, by omega⟩, f.node_505174, rfl⟩
  add := Or.inl ⟨⟨505175, by omega⟩, f.node_505175, rfl⟩
}

def certificate_341 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458188) (.wire 7079) (.wire 505123) (.wire 505178) := {
  difference := (.wire 505176)
  product := (.wire 505177)
  subtract := Or.inl ⟨⟨505176, by omega⟩, f.node_505176, rfl⟩
  multiply := Or.inl ⟨⟨505177, by omega⟩, f.node_505177, rfl⟩
  add := Or.inl ⟨⟨505178, by omega⟩, f.node_505178, rfl⟩
}

def certificate_342 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458193) (.wire 507576) (.wire 7080) (.wire 507613) := {
  difference := (.wire 507611)
  product := (.wire 507612)
  subtract := Or.inl ⟨⟨507611, by omega⟩, f.node_507611, rfl⟩
  multiply := Or.inl ⟨⟨507612, by omega⟩, f.node_507612, rfl⟩
  add := Or.inl ⟨⟨507613, by omega⟩, f.node_507613, rfl⟩
}

def certificate_343 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458193) (.wire 507587) (.wire 7081) (.wire 507616) := {
  difference := (.wire 507614)
  product := (.wire 507615)
  subtract := Or.inl ⟨⟨507614, by omega⟩, f.node_507614, rfl⟩
  multiply := Or.inl ⟨⟨507615, by omega⟩, f.node_507615, rfl⟩
  add := Or.inl ⟨⟨507616, by omega⟩, f.node_507616, rfl⟩
}

def certificate_344 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458193) (.wire 507598) (.wire 7082) (.wire 507619) := {
  difference := (.wire 507617)
  product := (.wire 507618)
  subtract := Or.inl ⟨⟨507617, by omega⟩, f.node_507617, rfl⟩
  multiply := Or.inl ⟨⟨507618, by omega⟩, f.node_507618, rfl⟩
  add := Or.inl ⟨⟨507619, by omega⟩, f.node_507619, rfl⟩
}

def certificate_345 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458193) (.wire 507609) (.wire 7083) (.wire 507622) := {
  difference := (.wire 507620)
  product := (.wire 507621)
  subtract := Or.inl ⟨⟨507620, by omega⟩, f.node_507620, rfl⟩
  multiply := Or.inl ⟨⟨507621, by omega⟩, f.node_507621, rfl⟩
  add := Or.inl ⟨⟨507622, by omega⟩, f.node_507622, rfl⟩
}

def certificate_346 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458193) (.wire 507575) (.wire 7084) (.wire 507625) := {
  difference := (.wire 507623)
  product := (.wire 507624)
  subtract := Or.inl ⟨⟨507623, by omega⟩, f.node_507623, rfl⟩
  multiply := Or.inl ⟨⟨507624, by omega⟩, f.node_507624, rfl⟩
  add := Or.inl ⟨⟨507625, by omega⟩, f.node_507625, rfl⟩
}

def certificate_347 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458193) (.wire 507586) (.wire 7085) (.wire 507628) := {
  difference := (.wire 507626)
  product := (.wire 507627)
  subtract := Or.inl ⟨⟨507626, by omega⟩, f.node_507626, rfl⟩
  multiply := Or.inl ⟨⟨507627, by omega⟩, f.node_507627, rfl⟩
  add := Or.inl ⟨⟨507628, by omega⟩, f.node_507628, rfl⟩
}

def certificate_348 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458193) (.wire 507597) (.wire 7086) (.wire 507631) := {
  difference := (.wire 507629)
  product := (.wire 507630)
  subtract := Or.inl ⟨⟨507629, by omega⟩, f.node_507629, rfl⟩
  multiply := Or.inl ⟨⟨507630, by omega⟩, f.node_507630, rfl⟩
  add := Or.inl ⟨⟨507631, by omega⟩, f.node_507631, rfl⟩
}

def certificate_349 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458193) (.wire 7080) (.wire 507576) (.wire 507634) := {
  difference := (.wire 507632)
  product := (.wire 507633)
  subtract := Or.inl ⟨⟨507632, by omega⟩, f.node_507632, rfl⟩
  multiply := Or.inl ⟨⟨507633, by omega⟩, f.node_507633, rfl⟩
  add := Or.inl ⟨⟨507634, by omega⟩, f.node_507634, rfl⟩
}

def certificate_350 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458193) (.wire 7081) (.wire 507587) (.wire 507637) := {
  difference := (.wire 507635)
  product := (.wire 507636)
  subtract := Or.inl ⟨⟨507635, by omega⟩, f.node_507635, rfl⟩
  multiply := Or.inl ⟨⟨507636, by omega⟩, f.node_507636, rfl⟩
  add := Or.inl ⟨⟨507637, by omega⟩, f.node_507637, rfl⟩
}

def certificate_351 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458193) (.wire 7082) (.wire 507598) (.wire 507640) := {
  difference := (.wire 507638)
  product := (.wire 507639)
  subtract := Or.inl ⟨⟨507638, by omega⟩, f.node_507638, rfl⟩
  multiply := Or.inl ⟨⟨507639, by omega⟩, f.node_507639, rfl⟩
  add := Or.inl ⟨⟨507640, by omega⟩, f.node_507640, rfl⟩
}

def certificate_352 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458193) (.wire 7083) (.wire 507609) (.wire 507643) := {
  difference := (.wire 507641)
  product := (.wire 507642)
  subtract := Or.inl ⟨⟨507641, by omega⟩, f.node_507641, rfl⟩
  multiply := Or.inl ⟨⟨507642, by omega⟩, f.node_507642, rfl⟩
  add := Or.inl ⟨⟨507643, by omega⟩, f.node_507643, rfl⟩
}

def certificate_353 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458193) (.wire 7084) (.wire 507575) (.wire 507646) := {
  difference := (.wire 507644)
  product := (.wire 507645)
  subtract := Or.inl ⟨⟨507644, by omega⟩, f.node_507644, rfl⟩
  multiply := Or.inl ⟨⟨507645, by omega⟩, f.node_507645, rfl⟩
  add := Or.inl ⟨⟨507646, by omega⟩, f.node_507646, rfl⟩
}

def certificate_354 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458193) (.wire 7085) (.wire 507586) (.wire 507649) := {
  difference := (.wire 507647)
  product := (.wire 507648)
  subtract := Or.inl ⟨⟨507647, by omega⟩, f.node_507647, rfl⟩
  multiply := Or.inl ⟨⟨507648, by omega⟩, f.node_507648, rfl⟩
  add := Or.inl ⟨⟨507649, by omega⟩, f.node_507649, rfl⟩
}

def certificate_355 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458193) (.wire 7086) (.wire 507597) (.wire 507652) := {
  difference := (.wire 507650)
  product := (.wire 507651)
  subtract := Or.inl ⟨⟨507650, by omega⟩, f.node_507650, rfl⟩
  multiply := Or.inl ⟨⟨507651, by omega⟩, f.node_507651, rfl⟩
  add := Or.inl ⟨⟨507652, by omega⟩, f.node_507652, rfl⟩
}

def certificate_356 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458198) (.wire 510050) (.wire 7087) (.wire 510087) := {
  difference := (.wire 510085)
  product := (.wire 510086)
  subtract := Or.inl ⟨⟨510085, by omega⟩, f.node_510085, rfl⟩
  multiply := Or.inl ⟨⟨510086, by omega⟩, f.node_510086, rfl⟩
  add := Or.inl ⟨⟨510087, by omega⟩, f.node_510087, rfl⟩
}

def certificate_357 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458198) (.wire 510061) (.wire 7088) (.wire 510090) := {
  difference := (.wire 510088)
  product := (.wire 510089)
  subtract := Or.inl ⟨⟨510088, by omega⟩, f.node_510088, rfl⟩
  multiply := Or.inl ⟨⟨510089, by omega⟩, f.node_510089, rfl⟩
  add := Or.inl ⟨⟨510090, by omega⟩, f.node_510090, rfl⟩
}

def certificate_358 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458198) (.wire 510072) (.wire 7089) (.wire 510093) := {
  difference := (.wire 510091)
  product := (.wire 510092)
  subtract := Or.inl ⟨⟨510091, by omega⟩, f.node_510091, rfl⟩
  multiply := Or.inl ⟨⟨510092, by omega⟩, f.node_510092, rfl⟩
  add := Or.inl ⟨⟨510093, by omega⟩, f.node_510093, rfl⟩
}

def certificate_359 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458198) (.wire 510083) (.wire 7090) (.wire 510096) := {
  difference := (.wire 510094)
  product := (.wire 510095)
  subtract := Or.inl ⟨⟨510094, by omega⟩, f.node_510094, rfl⟩
  multiply := Or.inl ⟨⟨510095, by omega⟩, f.node_510095, rfl⟩
  add := Or.inl ⟨⟨510096, by omega⟩, f.node_510096, rfl⟩
}

def certificate_360 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458198) (.wire 510049) (.wire 7091) (.wire 510099) := {
  difference := (.wire 510097)
  product := (.wire 510098)
  subtract := Or.inl ⟨⟨510097, by omega⟩, f.node_510097, rfl⟩
  multiply := Or.inl ⟨⟨510098, by omega⟩, f.node_510098, rfl⟩
  add := Or.inl ⟨⟨510099, by omega⟩, f.node_510099, rfl⟩
}

def certificate_361 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458198) (.wire 510060) (.wire 7092) (.wire 510102) := {
  difference := (.wire 510100)
  product := (.wire 510101)
  subtract := Or.inl ⟨⟨510100, by omega⟩, f.node_510100, rfl⟩
  multiply := Or.inl ⟨⟨510101, by omega⟩, f.node_510101, rfl⟩
  add := Or.inl ⟨⟨510102, by omega⟩, f.node_510102, rfl⟩
}

def certificate_362 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458198) (.wire 510071) (.wire 7093) (.wire 510105) := {
  difference := (.wire 510103)
  product := (.wire 510104)
  subtract := Or.inl ⟨⟨510103, by omega⟩, f.node_510103, rfl⟩
  multiply := Or.inl ⟨⟨510104, by omega⟩, f.node_510104, rfl⟩
  add := Or.inl ⟨⟨510105, by omega⟩, f.node_510105, rfl⟩
}

def certificate_363 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458198) (.wire 7087) (.wire 510050) (.wire 510108) := {
  difference := (.wire 510106)
  product := (.wire 510107)
  subtract := Or.inl ⟨⟨510106, by omega⟩, f.node_510106, rfl⟩
  multiply := Or.inl ⟨⟨510107, by omega⟩, f.node_510107, rfl⟩
  add := Or.inl ⟨⟨510108, by omega⟩, f.node_510108, rfl⟩
}

def certificate_364 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458198) (.wire 7088) (.wire 510061) (.wire 510111) := {
  difference := (.wire 510109)
  product := (.wire 510110)
  subtract := Or.inl ⟨⟨510109, by omega⟩, f.node_510109, rfl⟩
  multiply := Or.inl ⟨⟨510110, by omega⟩, f.node_510110, rfl⟩
  add := Or.inl ⟨⟨510111, by omega⟩, f.node_510111, rfl⟩
}

def certificate_365 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458198) (.wire 7089) (.wire 510072) (.wire 510114) := {
  difference := (.wire 510112)
  product := (.wire 510113)
  subtract := Or.inl ⟨⟨510112, by omega⟩, f.node_510112, rfl⟩
  multiply := Or.inl ⟨⟨510113, by omega⟩, f.node_510113, rfl⟩
  add := Or.inl ⟨⟨510114, by omega⟩, f.node_510114, rfl⟩
}

def certificate_366 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458198) (.wire 7090) (.wire 510083) (.wire 510117) := {
  difference := (.wire 510115)
  product := (.wire 510116)
  subtract := Or.inl ⟨⟨510115, by omega⟩, f.node_510115, rfl⟩
  multiply := Or.inl ⟨⟨510116, by omega⟩, f.node_510116, rfl⟩
  add := Or.inl ⟨⟨510117, by omega⟩, f.node_510117, rfl⟩
}

def certificate_367 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458198) (.wire 7091) (.wire 510049) (.wire 510120) := {
  difference := (.wire 510118)
  product := (.wire 510119)
  subtract := Or.inl ⟨⟨510118, by omega⟩, f.node_510118, rfl⟩
  multiply := Or.inl ⟨⟨510119, by omega⟩, f.node_510119, rfl⟩
  add := Or.inl ⟨⟨510120, by omega⟩, f.node_510120, rfl⟩
}

def certificate_368 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458198) (.wire 7092) (.wire 510060) (.wire 510123) := {
  difference := (.wire 510121)
  product := (.wire 510122)
  subtract := Or.inl ⟨⟨510121, by omega⟩, f.node_510121, rfl⟩
  multiply := Or.inl ⟨⟨510122, by omega⟩, f.node_510122, rfl⟩
  add := Or.inl ⟨⟨510123, by omega⟩, f.node_510123, rfl⟩
}

def certificate_369 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458198) (.wire 7093) (.wire 510071) (.wire 510126) := {
  difference := (.wire 510124)
  product := (.wire 510125)
  subtract := Or.inl ⟨⟨510124, by omega⟩, f.node_510124, rfl⟩
  multiply := Or.inl ⟨⟨510125, by omega⟩, f.node_510125, rfl⟩
  add := Or.inl ⟨⟨510126, by omega⟩, f.node_510126, rfl⟩
}

def certificate_370 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458203) (.wire 512524) (.wire 7094) (.wire 512561) := {
  difference := (.wire 512559)
  product := (.wire 512560)
  subtract := Or.inl ⟨⟨512559, by omega⟩, f.node_512559, rfl⟩
  multiply := Or.inl ⟨⟨512560, by omega⟩, f.node_512560, rfl⟩
  add := Or.inl ⟨⟨512561, by omega⟩, f.node_512561, rfl⟩
}

def certificate_371 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458203) (.wire 512535) (.wire 7095) (.wire 512564) := {
  difference := (.wire 512562)
  product := (.wire 512563)
  subtract := Or.inl ⟨⟨512562, by omega⟩, f.node_512562, rfl⟩
  multiply := Or.inl ⟨⟨512563, by omega⟩, f.node_512563, rfl⟩
  add := Or.inl ⟨⟨512564, by omega⟩, f.node_512564, rfl⟩
}

def certificate_372 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458203) (.wire 512546) (.wire 7096) (.wire 512567) := {
  difference := (.wire 512565)
  product := (.wire 512566)
  subtract := Or.inl ⟨⟨512565, by omega⟩, f.node_512565, rfl⟩
  multiply := Or.inl ⟨⟨512566, by omega⟩, f.node_512566, rfl⟩
  add := Or.inl ⟨⟨512567, by omega⟩, f.node_512567, rfl⟩
}

def certificate_373 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458203) (.wire 512557) (.wire 7097) (.wire 512570) := {
  difference := (.wire 512568)
  product := (.wire 512569)
  subtract := Or.inl ⟨⟨512568, by omega⟩, f.node_512568, rfl⟩
  multiply := Or.inl ⟨⟨512569, by omega⟩, f.node_512569, rfl⟩
  add := Or.inl ⟨⟨512570, by omega⟩, f.node_512570, rfl⟩
}

def certificate_374 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458203) (.wire 512523) (.wire 7098) (.wire 512573) := {
  difference := (.wire 512571)
  product := (.wire 512572)
  subtract := Or.inl ⟨⟨512571, by omega⟩, f.node_512571, rfl⟩
  multiply := Or.inl ⟨⟨512572, by omega⟩, f.node_512572, rfl⟩
  add := Or.inl ⟨⟨512573, by omega⟩, f.node_512573, rfl⟩
}

def certificate_375 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458203) (.wire 512534) (.wire 7099) (.wire 512576) := {
  difference := (.wire 512574)
  product := (.wire 512575)
  subtract := Or.inl ⟨⟨512574, by omega⟩, f.node_512574, rfl⟩
  multiply := Or.inl ⟨⟨512575, by omega⟩, f.node_512575, rfl⟩
  add := Or.inl ⟨⟨512576, by omega⟩, f.node_512576, rfl⟩
}

def certificate_376 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458203) (.wire 512545) (.wire 7100) (.wire 512579) := {
  difference := (.wire 512577)
  product := (.wire 512578)
  subtract := Or.inl ⟨⟨512577, by omega⟩, f.node_512577, rfl⟩
  multiply := Or.inl ⟨⟨512578, by omega⟩, f.node_512578, rfl⟩
  add := Or.inl ⟨⟨512579, by omega⟩, f.node_512579, rfl⟩
}

def certificate_377 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458203) (.wire 7094) (.wire 512524) (.wire 512582) := {
  difference := (.wire 512580)
  product := (.wire 512581)
  subtract := Or.inl ⟨⟨512580, by omega⟩, f.node_512580, rfl⟩
  multiply := Or.inl ⟨⟨512581, by omega⟩, f.node_512581, rfl⟩
  add := Or.inl ⟨⟨512582, by omega⟩, f.node_512582, rfl⟩
}

def certificate_378 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458203) (.wire 7095) (.wire 512535) (.wire 512585) := {
  difference := (.wire 512583)
  product := (.wire 512584)
  subtract := Or.inl ⟨⟨512583, by omega⟩, f.node_512583, rfl⟩
  multiply := Or.inl ⟨⟨512584, by omega⟩, f.node_512584, rfl⟩
  add := Or.inl ⟨⟨512585, by omega⟩, f.node_512585, rfl⟩
}

def certificate_379 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458203) (.wire 7096) (.wire 512546) (.wire 512588) := {
  difference := (.wire 512586)
  product := (.wire 512587)
  subtract := Or.inl ⟨⟨512586, by omega⟩, f.node_512586, rfl⟩
  multiply := Or.inl ⟨⟨512587, by omega⟩, f.node_512587, rfl⟩
  add := Or.inl ⟨⟨512588, by omega⟩, f.node_512588, rfl⟩
}

def certificate_380 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458203) (.wire 7097) (.wire 512557) (.wire 512591) := {
  difference := (.wire 512589)
  product := (.wire 512590)
  subtract := Or.inl ⟨⟨512589, by omega⟩, f.node_512589, rfl⟩
  multiply := Or.inl ⟨⟨512590, by omega⟩, f.node_512590, rfl⟩
  add := Or.inl ⟨⟨512591, by omega⟩, f.node_512591, rfl⟩
}

def certificate_381 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458203) (.wire 7098) (.wire 512523) (.wire 512594) := {
  difference := (.wire 512592)
  product := (.wire 512593)
  subtract := Or.inl ⟨⟨512592, by omega⟩, f.node_512592, rfl⟩
  multiply := Or.inl ⟨⟨512593, by omega⟩, f.node_512593, rfl⟩
  add := Or.inl ⟨⟨512594, by omega⟩, f.node_512594, rfl⟩
}

def certificate_382 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458203) (.wire 7099) (.wire 512534) (.wire 512597) := {
  difference := (.wire 512595)
  product := (.wire 512596)
  subtract := Or.inl ⟨⟨512595, by omega⟩, f.node_512595, rfl⟩
  multiply := Or.inl ⟨⟨512596, by omega⟩, f.node_512596, rfl⟩
  add := Or.inl ⟨⟨512597, by omega⟩, f.node_512597, rfl⟩
}

def certificate_383 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458203) (.wire 7100) (.wire 512545) (.wire 512600) := {
  difference := (.wire 512598)
  product := (.wire 512599)
  subtract := Or.inl ⟨⟨512598, by omega⟩, f.node_512598, rfl⟩
  multiply := Or.inl ⟨⟨512599, by omega⟩, f.node_512599, rfl⟩
  add := Or.inl ⟨⟨512600, by omega⟩, f.node_512600, rfl⟩
}

def certificate_384 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458208) (.wire 514998) (.wire 7101) (.wire 515035) := {
  difference := (.wire 515033)
  product := (.wire 515034)
  subtract := Or.inl ⟨⟨515033, by omega⟩, f.node_515033, rfl⟩
  multiply := Or.inl ⟨⟨515034, by omega⟩, f.node_515034, rfl⟩
  add := Or.inl ⟨⟨515035, by omega⟩, f.node_515035, rfl⟩
}

def certificate_385 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458208) (.wire 515009) (.wire 7102) (.wire 515038) := {
  difference := (.wire 515036)
  product := (.wire 515037)
  subtract := Or.inl ⟨⟨515036, by omega⟩, f.node_515036, rfl⟩
  multiply := Or.inl ⟨⟨515037, by omega⟩, f.node_515037, rfl⟩
  add := Or.inl ⟨⟨515038, by omega⟩, f.node_515038, rfl⟩
}

def certificate_386 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458208) (.wire 515020) (.wire 7103) (.wire 515041) := {
  difference := (.wire 515039)
  product := (.wire 515040)
  subtract := Or.inl ⟨⟨515039, by omega⟩, f.node_515039, rfl⟩
  multiply := Or.inl ⟨⟨515040, by omega⟩, f.node_515040, rfl⟩
  add := Or.inl ⟨⟨515041, by omega⟩, f.node_515041, rfl⟩
}

def certificate_387 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458208) (.wire 515031) (.wire 7104) (.wire 515044) := {
  difference := (.wire 515042)
  product := (.wire 515043)
  subtract := Or.inl ⟨⟨515042, by omega⟩, f.node_515042, rfl⟩
  multiply := Or.inl ⟨⟨515043, by omega⟩, f.node_515043, rfl⟩
  add := Or.inl ⟨⟨515044, by omega⟩, f.node_515044, rfl⟩
}

def certificate_388 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458208) (.wire 514997) (.wire 7105) (.wire 515047) := {
  difference := (.wire 515045)
  product := (.wire 515046)
  subtract := Or.inl ⟨⟨515045, by omega⟩, f.node_515045, rfl⟩
  multiply := Or.inl ⟨⟨515046, by omega⟩, f.node_515046, rfl⟩
  add := Or.inl ⟨⟨515047, by omega⟩, f.node_515047, rfl⟩
}

def certificate_389 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458208) (.wire 515008) (.wire 7106) (.wire 515050) := {
  difference := (.wire 515048)
  product := (.wire 515049)
  subtract := Or.inl ⟨⟨515048, by omega⟩, f.node_515048, rfl⟩
  multiply := Or.inl ⟨⟨515049, by omega⟩, f.node_515049, rfl⟩
  add := Or.inl ⟨⟨515050, by omega⟩, f.node_515050, rfl⟩
}

def certificate_390 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458208) (.wire 515019) (.wire 7107) (.wire 515053) := {
  difference := (.wire 515051)
  product := (.wire 515052)
  subtract := Or.inl ⟨⟨515051, by omega⟩, f.node_515051, rfl⟩
  multiply := Or.inl ⟨⟨515052, by omega⟩, f.node_515052, rfl⟩
  add := Or.inl ⟨⟨515053, by omega⟩, f.node_515053, rfl⟩
}

def certificate_391 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458208) (.wire 7101) (.wire 514998) (.wire 515056) := {
  difference := (.wire 515054)
  product := (.wire 515055)
  subtract := Or.inl ⟨⟨515054, by omega⟩, f.node_515054, rfl⟩
  multiply := Or.inl ⟨⟨515055, by omega⟩, f.node_515055, rfl⟩
  add := Or.inl ⟨⟨515056, by omega⟩, f.node_515056, rfl⟩
}

def certificate_392 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458208) (.wire 7102) (.wire 515009) (.wire 515059) := {
  difference := (.wire 515057)
  product := (.wire 515058)
  subtract := Or.inl ⟨⟨515057, by omega⟩, f.node_515057, rfl⟩
  multiply := Or.inl ⟨⟨515058, by omega⟩, f.node_515058, rfl⟩
  add := Or.inl ⟨⟨515059, by omega⟩, f.node_515059, rfl⟩
}

def certificate_393 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458208) (.wire 7103) (.wire 515020) (.wire 515062) := {
  difference := (.wire 515060)
  product := (.wire 515061)
  subtract := Or.inl ⟨⟨515060, by omega⟩, f.node_515060, rfl⟩
  multiply := Or.inl ⟨⟨515061, by omega⟩, f.node_515061, rfl⟩
  add := Or.inl ⟨⟨515062, by omega⟩, f.node_515062, rfl⟩
}

def certificate_394 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458208) (.wire 7104) (.wire 515031) (.wire 515065) := {
  difference := (.wire 515063)
  product := (.wire 515064)
  subtract := Or.inl ⟨⟨515063, by omega⟩, f.node_515063, rfl⟩
  multiply := Or.inl ⟨⟨515064, by omega⟩, f.node_515064, rfl⟩
  add := Or.inl ⟨⟨515065, by omega⟩, f.node_515065, rfl⟩
}

def certificate_395 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458208) (.wire 7105) (.wire 514997) (.wire 515068) := {
  difference := (.wire 515066)
  product := (.wire 515067)
  subtract := Or.inl ⟨⟨515066, by omega⟩, f.node_515066, rfl⟩
  multiply := Or.inl ⟨⟨515067, by omega⟩, f.node_515067, rfl⟩
  add := Or.inl ⟨⟨515068, by omega⟩, f.node_515068, rfl⟩
}

def certificate_396 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458208) (.wire 7106) (.wire 515008) (.wire 515071) := {
  difference := (.wire 515069)
  product := (.wire 515070)
  subtract := Or.inl ⟨⟨515069, by omega⟩, f.node_515069, rfl⟩
  multiply := Or.inl ⟨⟨515070, by omega⟩, f.node_515070, rfl⟩
  add := Or.inl ⟨⟨515071, by omega⟩, f.node_515071, rfl⟩
}

def certificate_397 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458208) (.wire 7107) (.wire 515019) (.wire 515074) := {
  difference := (.wire 515072)
  product := (.wire 515073)
  subtract := Or.inl ⟨⟨515072, by omega⟩, f.node_515072, rfl⟩
  multiply := Or.inl ⟨⟨515073, by omega⟩, f.node_515073, rfl⟩
  add := Or.inl ⟨⟨515074, by omega⟩, f.node_515074, rfl⟩
}

def certificate_398 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458213) (.wire 517472) (.wire 7108) (.wire 517509) := {
  difference := (.wire 517507)
  product := (.wire 517508)
  subtract := Or.inl ⟨⟨517507, by omega⟩, f.node_517507, rfl⟩
  multiply := Or.inl ⟨⟨517508, by omega⟩, f.node_517508, rfl⟩
  add := Or.inl ⟨⟨517509, by omega⟩, f.node_517509, rfl⟩
}

def certificate_399 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458213) (.wire 517483) (.wire 7109) (.wire 517512) := {
  difference := (.wire 517510)
  product := (.wire 517511)
  subtract := Or.inl ⟨⟨517510, by omega⟩, f.node_517510, rfl⟩
  multiply := Or.inl ⟨⟨517511, by omega⟩, f.node_517511, rfl⟩
  add := Or.inl ⟨⟨517512, by omega⟩, f.node_517512, rfl⟩
}

def certificate_400 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458213) (.wire 517494) (.wire 7110) (.wire 517515) := {
  difference := (.wire 517513)
  product := (.wire 517514)
  subtract := Or.inl ⟨⟨517513, by omega⟩, f.node_517513, rfl⟩
  multiply := Or.inl ⟨⟨517514, by omega⟩, f.node_517514, rfl⟩
  add := Or.inl ⟨⟨517515, by omega⟩, f.node_517515, rfl⟩
}

def certificate_401 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458213) (.wire 517505) (.wire 7111) (.wire 517518) := {
  difference := (.wire 517516)
  product := (.wire 517517)
  subtract := Or.inl ⟨⟨517516, by omega⟩, f.node_517516, rfl⟩
  multiply := Or.inl ⟨⟨517517, by omega⟩, f.node_517517, rfl⟩
  add := Or.inl ⟨⟨517518, by omega⟩, f.node_517518, rfl⟩
}

def certificate_402 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458213) (.wire 517471) (.wire 7112) (.wire 517521) := {
  difference := (.wire 517519)
  product := (.wire 517520)
  subtract := Or.inl ⟨⟨517519, by omega⟩, f.node_517519, rfl⟩
  multiply := Or.inl ⟨⟨517520, by omega⟩, f.node_517520, rfl⟩
  add := Or.inl ⟨⟨517521, by omega⟩, f.node_517521, rfl⟩
}

def certificate_403 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458213) (.wire 517482) (.wire 7113) (.wire 517524) := {
  difference := (.wire 517522)
  product := (.wire 517523)
  subtract := Or.inl ⟨⟨517522, by omega⟩, f.node_517522, rfl⟩
  multiply := Or.inl ⟨⟨517523, by omega⟩, f.node_517523, rfl⟩
  add := Or.inl ⟨⟨517524, by omega⟩, f.node_517524, rfl⟩
}

def certificate_404 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458213) (.wire 517493) (.wire 7114) (.wire 517527) := {
  difference := (.wire 517525)
  product := (.wire 517526)
  subtract := Or.inl ⟨⟨517525, by omega⟩, f.node_517525, rfl⟩
  multiply := Or.inl ⟨⟨517526, by omega⟩, f.node_517526, rfl⟩
  add := Or.inl ⟨⟨517527, by omega⟩, f.node_517527, rfl⟩
}

def certificate_405 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458213) (.wire 7108) (.wire 517472) (.wire 517530) := {
  difference := (.wire 517528)
  product := (.wire 517529)
  subtract := Or.inl ⟨⟨517528, by omega⟩, f.node_517528, rfl⟩
  multiply := Or.inl ⟨⟨517529, by omega⟩, f.node_517529, rfl⟩
  add := Or.inl ⟨⟨517530, by omega⟩, f.node_517530, rfl⟩
}

def certificate_406 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458213) (.wire 7109) (.wire 517483) (.wire 517533) := {
  difference := (.wire 517531)
  product := (.wire 517532)
  subtract := Or.inl ⟨⟨517531, by omega⟩, f.node_517531, rfl⟩
  multiply := Or.inl ⟨⟨517532, by omega⟩, f.node_517532, rfl⟩
  add := Or.inl ⟨⟨517533, by omega⟩, f.node_517533, rfl⟩
}

def certificate_407 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458213) (.wire 7110) (.wire 517494) (.wire 517536) := {
  difference := (.wire 517534)
  product := (.wire 517535)
  subtract := Or.inl ⟨⟨517534, by omega⟩, f.node_517534, rfl⟩
  multiply := Or.inl ⟨⟨517535, by omega⟩, f.node_517535, rfl⟩
  add := Or.inl ⟨⟨517536, by omega⟩, f.node_517536, rfl⟩
}

def certificate_408 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458213) (.wire 7111) (.wire 517505) (.wire 517539) := {
  difference := (.wire 517537)
  product := (.wire 517538)
  subtract := Or.inl ⟨⟨517537, by omega⟩, f.node_517537, rfl⟩
  multiply := Or.inl ⟨⟨517538, by omega⟩, f.node_517538, rfl⟩
  add := Or.inl ⟨⟨517539, by omega⟩, f.node_517539, rfl⟩
}

def certificate_409 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458213) (.wire 7112) (.wire 517471) (.wire 517542) := {
  difference := (.wire 517540)
  product := (.wire 517541)
  subtract := Or.inl ⟨⟨517540, by omega⟩, f.node_517540, rfl⟩
  multiply := Or.inl ⟨⟨517541, by omega⟩, f.node_517541, rfl⟩
  add := Or.inl ⟨⟨517542, by omega⟩, f.node_517542, rfl⟩
}

def certificate_410 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458213) (.wire 7113) (.wire 517482) (.wire 517545) := {
  difference := (.wire 517543)
  product := (.wire 517544)
  subtract := Or.inl ⟨⟨517543, by omega⟩, f.node_517543, rfl⟩
  multiply := Or.inl ⟨⟨517544, by omega⟩, f.node_517544, rfl⟩
  add := Or.inl ⟨⟨517545, by omega⟩, f.node_517545, rfl⟩
}

def certificate_411 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458213) (.wire 7114) (.wire 517493) (.wire 517548) := {
  difference := (.wire 517546)
  product := (.wire 517547)
  subtract := Or.inl ⟨⟨517546, by omega⟩, f.node_517546, rfl⟩
  multiply := Or.inl ⟨⟨517547, by omega⟩, f.node_517547, rfl⟩
  add := Or.inl ⟨⟨517548, by omega⟩, f.node_517548, rfl⟩
}

def certificate_412 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458218) (.wire 519946) (.wire 7115) (.wire 519983) := {
  difference := (.wire 519981)
  product := (.wire 519982)
  subtract := Or.inl ⟨⟨519981, by omega⟩, f.node_519981, rfl⟩
  multiply := Or.inl ⟨⟨519982, by omega⟩, f.node_519982, rfl⟩
  add := Or.inl ⟨⟨519983, by omega⟩, f.node_519983, rfl⟩
}

def certificate_413 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458218) (.wire 519957) (.wire 7116) (.wire 519986) := {
  difference := (.wire 519984)
  product := (.wire 519985)
  subtract := Or.inl ⟨⟨519984, by omega⟩, f.node_519984, rfl⟩
  multiply := Or.inl ⟨⟨519985, by omega⟩, f.node_519985, rfl⟩
  add := Or.inl ⟨⟨519986, by omega⟩, f.node_519986, rfl⟩
}

def certificate_414 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458218) (.wire 519968) (.wire 7117) (.wire 519989) := {
  difference := (.wire 519987)
  product := (.wire 519988)
  subtract := Or.inl ⟨⟨519987, by omega⟩, f.node_519987, rfl⟩
  multiply := Or.inl ⟨⟨519988, by omega⟩, f.node_519988, rfl⟩
  add := Or.inl ⟨⟨519989, by omega⟩, f.node_519989, rfl⟩
}

def certificate_415 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458218) (.wire 519979) (.wire 7118) (.wire 519992) := {
  difference := (.wire 519990)
  product := (.wire 519991)
  subtract := Or.inl ⟨⟨519990, by omega⟩, f.node_519990, rfl⟩
  multiply := Or.inl ⟨⟨519991, by omega⟩, f.node_519991, rfl⟩
  add := Or.inl ⟨⟨519992, by omega⟩, f.node_519992, rfl⟩
}

def certificate_416 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458218) (.wire 519945) (.wire 7119) (.wire 519995) := {
  difference := (.wire 519993)
  product := (.wire 519994)
  subtract := Or.inl ⟨⟨519993, by omega⟩, f.node_519993, rfl⟩
  multiply := Or.inl ⟨⟨519994, by omega⟩, f.node_519994, rfl⟩
  add := Or.inl ⟨⟨519995, by omega⟩, f.node_519995, rfl⟩
}

def certificate_417 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458218) (.wire 519956) (.wire 7120) (.wire 519998) := {
  difference := (.wire 519996)
  product := (.wire 519997)
  subtract := Or.inl ⟨⟨519996, by omega⟩, f.node_519996, rfl⟩
  multiply := Or.inl ⟨⟨519997, by omega⟩, f.node_519997, rfl⟩
  add := Or.inl ⟨⟨519998, by omega⟩, f.node_519998, rfl⟩
}

def certificate_418 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458218) (.wire 519967) (.wire 7121) (.wire 520001) := {
  difference := (.wire 519999)
  product := (.wire 520000)
  subtract := Or.inl ⟨⟨519999, by omega⟩, f.node_519999, rfl⟩
  multiply := Or.inl ⟨⟨520000, by omega⟩, f.node_520000, rfl⟩
  add := Or.inl ⟨⟨520001, by omega⟩, f.node_520001, rfl⟩
}

def certificate_419 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458218) (.wire 7115) (.wire 519946) (.wire 520004) := {
  difference := (.wire 520002)
  product := (.wire 520003)
  subtract := Or.inl ⟨⟨520002, by omega⟩, f.node_520002, rfl⟩
  multiply := Or.inl ⟨⟨520003, by omega⟩, f.node_520003, rfl⟩
  add := Or.inl ⟨⟨520004, by omega⟩, f.node_520004, rfl⟩
}

def certificate_420 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458218) (.wire 7116) (.wire 519957) (.wire 520007) := {
  difference := (.wire 520005)
  product := (.wire 520006)
  subtract := Or.inl ⟨⟨520005, by omega⟩, f.node_520005, rfl⟩
  multiply := Or.inl ⟨⟨520006, by omega⟩, f.node_520006, rfl⟩
  add := Or.inl ⟨⟨520007, by omega⟩, f.node_520007, rfl⟩
}

def certificate_421 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458218) (.wire 7117) (.wire 519968) (.wire 520010) := {
  difference := (.wire 520008)
  product := (.wire 520009)
  subtract := Or.inl ⟨⟨520008, by omega⟩, f.node_520008, rfl⟩
  multiply := Or.inl ⟨⟨520009, by omega⟩, f.node_520009, rfl⟩
  add := Or.inl ⟨⟨520010, by omega⟩, f.node_520010, rfl⟩
}

def certificate_422 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458218) (.wire 7118) (.wire 519979) (.wire 520013) := {
  difference := (.wire 520011)
  product := (.wire 520012)
  subtract := Or.inl ⟨⟨520011, by omega⟩, f.node_520011, rfl⟩
  multiply := Or.inl ⟨⟨520012, by omega⟩, f.node_520012, rfl⟩
  add := Or.inl ⟨⟨520013, by omega⟩, f.node_520013, rfl⟩
}

def certificate_423 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458218) (.wire 7119) (.wire 519945) (.wire 520016) := {
  difference := (.wire 520014)
  product := (.wire 520015)
  subtract := Or.inl ⟨⟨520014, by omega⟩, f.node_520014, rfl⟩
  multiply := Or.inl ⟨⟨520015, by omega⟩, f.node_520015, rfl⟩
  add := Or.inl ⟨⟨520016, by omega⟩, f.node_520016, rfl⟩
}

def certificate_424 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458218) (.wire 7120) (.wire 519956) (.wire 520019) := {
  difference := (.wire 520017)
  product := (.wire 520018)
  subtract := Or.inl ⟨⟨520017, by omega⟩, f.node_520017, rfl⟩
  multiply := Or.inl ⟨⟨520018, by omega⟩, f.node_520018, rfl⟩
  add := Or.inl ⟨⟨520019, by omega⟩, f.node_520019, rfl⟩
}

def certificate_425 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458218) (.wire 7121) (.wire 519967) (.wire 520022) := {
  difference := (.wire 520020)
  product := (.wire 520021)
  subtract := Or.inl ⟨⟨520020, by omega⟩, f.node_520020, rfl⟩
  multiply := Or.inl ⟨⟨520021, by omega⟩, f.node_520021, rfl⟩
  add := Or.inl ⟨⟨520022, by omega⟩, f.node_520022, rfl⟩
}

def certificate_426 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458223) (.wire 522420) (.wire 7122) (.wire 522457) := {
  difference := (.wire 522455)
  product := (.wire 522456)
  subtract := Or.inl ⟨⟨522455, by omega⟩, f.node_522455, rfl⟩
  multiply := Or.inl ⟨⟨522456, by omega⟩, f.node_522456, rfl⟩
  add := Or.inl ⟨⟨522457, by omega⟩, f.node_522457, rfl⟩
}

def certificate_427 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458223) (.wire 522431) (.wire 7123) (.wire 522460) := {
  difference := (.wire 522458)
  product := (.wire 522459)
  subtract := Or.inl ⟨⟨522458, by omega⟩, f.node_522458, rfl⟩
  multiply := Or.inl ⟨⟨522459, by omega⟩, f.node_522459, rfl⟩
  add := Or.inl ⟨⟨522460, by omega⟩, f.node_522460, rfl⟩
}

def certificate_428 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458223) (.wire 522442) (.wire 7124) (.wire 522463) := {
  difference := (.wire 522461)
  product := (.wire 522462)
  subtract := Or.inl ⟨⟨522461, by omega⟩, f.node_522461, rfl⟩
  multiply := Or.inl ⟨⟨522462, by omega⟩, f.node_522462, rfl⟩
  add := Or.inl ⟨⟨522463, by omega⟩, f.node_522463, rfl⟩
}

def certificate_429 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458223) (.wire 522453) (.wire 7125) (.wire 522466) := {
  difference := (.wire 522464)
  product := (.wire 522465)
  subtract := Or.inl ⟨⟨522464, by omega⟩, f.node_522464, rfl⟩
  multiply := Or.inl ⟨⟨522465, by omega⟩, f.node_522465, rfl⟩
  add := Or.inl ⟨⟨522466, by omega⟩, f.node_522466, rfl⟩
}

def certificate_430 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458223) (.wire 522419) (.wire 7126) (.wire 522469) := {
  difference := (.wire 522467)
  product := (.wire 522468)
  subtract := Or.inl ⟨⟨522467, by omega⟩, f.node_522467, rfl⟩
  multiply := Or.inl ⟨⟨522468, by omega⟩, f.node_522468, rfl⟩
  add := Or.inl ⟨⟨522469, by omega⟩, f.node_522469, rfl⟩
}

def certificate_431 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458223) (.wire 522430) (.wire 7127) (.wire 522472) := {
  difference := (.wire 522470)
  product := (.wire 522471)
  subtract := Or.inl ⟨⟨522470, by omega⟩, f.node_522470, rfl⟩
  multiply := Or.inl ⟨⟨522471, by omega⟩, f.node_522471, rfl⟩
  add := Or.inl ⟨⟨522472, by omega⟩, f.node_522472, rfl⟩
}

def certificate_432 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458223) (.wire 522441) (.wire 7128) (.wire 522475) := {
  difference := (.wire 522473)
  product := (.wire 522474)
  subtract := Or.inl ⟨⟨522473, by omega⟩, f.node_522473, rfl⟩
  multiply := Or.inl ⟨⟨522474, by omega⟩, f.node_522474, rfl⟩
  add := Or.inl ⟨⟨522475, by omega⟩, f.node_522475, rfl⟩
}

def certificate_433 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458223) (.wire 7122) (.wire 522420) (.wire 522478) := {
  difference := (.wire 522476)
  product := (.wire 522477)
  subtract := Or.inl ⟨⟨522476, by omega⟩, f.node_522476, rfl⟩
  multiply := Or.inl ⟨⟨522477, by omega⟩, f.node_522477, rfl⟩
  add := Or.inl ⟨⟨522478, by omega⟩, f.node_522478, rfl⟩
}

def certificate_434 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458223) (.wire 7123) (.wire 522431) (.wire 522481) := {
  difference := (.wire 522479)
  product := (.wire 522480)
  subtract := Or.inl ⟨⟨522479, by omega⟩, f.node_522479, rfl⟩
  multiply := Or.inl ⟨⟨522480, by omega⟩, f.node_522480, rfl⟩
  add := Or.inl ⟨⟨522481, by omega⟩, f.node_522481, rfl⟩
}

def certificate_435 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458223) (.wire 7124) (.wire 522442) (.wire 522484) := {
  difference := (.wire 522482)
  product := (.wire 522483)
  subtract := Or.inl ⟨⟨522482, by omega⟩, f.node_522482, rfl⟩
  multiply := Or.inl ⟨⟨522483, by omega⟩, f.node_522483, rfl⟩
  add := Or.inl ⟨⟨522484, by omega⟩, f.node_522484, rfl⟩
}

def certificate_436 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458223) (.wire 7125) (.wire 522453) (.wire 522487) := {
  difference := (.wire 522485)
  product := (.wire 522486)
  subtract := Or.inl ⟨⟨522485, by omega⟩, f.node_522485, rfl⟩
  multiply := Or.inl ⟨⟨522486, by omega⟩, f.node_522486, rfl⟩
  add := Or.inl ⟨⟨522487, by omega⟩, f.node_522487, rfl⟩
}

def certificate_437 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458223) (.wire 7126) (.wire 522419) (.wire 522490) := {
  difference := (.wire 522488)
  product := (.wire 522489)
  subtract := Or.inl ⟨⟨522488, by omega⟩, f.node_522488, rfl⟩
  multiply := Or.inl ⟨⟨522489, by omega⟩, f.node_522489, rfl⟩
  add := Or.inl ⟨⟨522490, by omega⟩, f.node_522490, rfl⟩
}

def certificate_438 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458223) (.wire 7127) (.wire 522430) (.wire 522493) := {
  difference := (.wire 522491)
  product := (.wire 522492)
  subtract := Or.inl ⟨⟨522491, by omega⟩, f.node_522491, rfl⟩
  multiply := Or.inl ⟨⟨522492, by omega⟩, f.node_522492, rfl⟩
  add := Or.inl ⟨⟨522493, by omega⟩, f.node_522493, rfl⟩
}

def certificate_439 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458223) (.wire 7128) (.wire 522441) (.wire 522496) := {
  difference := (.wire 522494)
  product := (.wire 522495)
  subtract := Or.inl ⟨⟨522494, by omega⟩, f.node_522494, rfl⟩
  multiply := Or.inl ⟨⟨522495, by omega⟩, f.node_522495, rfl⟩
  add := Or.inl ⟨⟨522496, by omega⟩, f.node_522496, rfl⟩
}

def certificate_440 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458228) (.wire 524894) (.wire 7129) (.wire 524931) := {
  difference := (.wire 524929)
  product := (.wire 524930)
  subtract := Or.inl ⟨⟨524929, by omega⟩, f.node_524929, rfl⟩
  multiply := Or.inl ⟨⟨524930, by omega⟩, f.node_524930, rfl⟩
  add := Or.inl ⟨⟨524931, by omega⟩, f.node_524931, rfl⟩
}

def certificate_441 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458228) (.wire 524905) (.wire 7130) (.wire 524934) := {
  difference := (.wire 524932)
  product := (.wire 524933)
  subtract := Or.inl ⟨⟨524932, by omega⟩, f.node_524932, rfl⟩
  multiply := Or.inl ⟨⟨524933, by omega⟩, f.node_524933, rfl⟩
  add := Or.inl ⟨⟨524934, by omega⟩, f.node_524934, rfl⟩
}

def certificate_442 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458228) (.wire 524916) (.wire 7131) (.wire 524937) := {
  difference := (.wire 524935)
  product := (.wire 524936)
  subtract := Or.inl ⟨⟨524935, by omega⟩, f.node_524935, rfl⟩
  multiply := Or.inl ⟨⟨524936, by omega⟩, f.node_524936, rfl⟩
  add := Or.inl ⟨⟨524937, by omega⟩, f.node_524937, rfl⟩
}

def certificate_443 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458228) (.wire 524927) (.wire 7132) (.wire 524940) := {
  difference := (.wire 524938)
  product := (.wire 524939)
  subtract := Or.inl ⟨⟨524938, by omega⟩, f.node_524938, rfl⟩
  multiply := Or.inl ⟨⟨524939, by omega⟩, f.node_524939, rfl⟩
  add := Or.inl ⟨⟨524940, by omega⟩, f.node_524940, rfl⟩
}

def certificate_444 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458228) (.wire 524893) (.wire 7133) (.wire 524943) := {
  difference := (.wire 524941)
  product := (.wire 524942)
  subtract := Or.inl ⟨⟨524941, by omega⟩, f.node_524941, rfl⟩
  multiply := Or.inl ⟨⟨524942, by omega⟩, f.node_524942, rfl⟩
  add := Or.inl ⟨⟨524943, by omega⟩, f.node_524943, rfl⟩
}

def certificate_445 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458228) (.wire 524904) (.wire 7134) (.wire 524946) := {
  difference := (.wire 524944)
  product := (.wire 524945)
  subtract := Or.inl ⟨⟨524944, by omega⟩, f.node_524944, rfl⟩
  multiply := Or.inl ⟨⟨524945, by omega⟩, f.node_524945, rfl⟩
  add := Or.inl ⟨⟨524946, by omega⟩, f.node_524946, rfl⟩
}

def certificate_446 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458228) (.wire 524915) (.wire 7135) (.wire 524949) := {
  difference := (.wire 524947)
  product := (.wire 524948)
  subtract := Or.inl ⟨⟨524947, by omega⟩, f.node_524947, rfl⟩
  multiply := Or.inl ⟨⟨524948, by omega⟩, f.node_524948, rfl⟩
  add := Or.inl ⟨⟨524949, by omega⟩, f.node_524949, rfl⟩
}

def certificate_447 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458228) (.wire 7129) (.wire 524894) (.wire 524952) := {
  difference := (.wire 524950)
  product := (.wire 524951)
  subtract := Or.inl ⟨⟨524950, by omega⟩, f.node_524950, rfl⟩
  multiply := Or.inl ⟨⟨524951, by omega⟩, f.node_524951, rfl⟩
  add := Or.inl ⟨⟨524952, by omega⟩, f.node_524952, rfl⟩
}

def certificate_448 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458228) (.wire 7130) (.wire 524905) (.wire 524955) := {
  difference := (.wire 524953)
  product := (.wire 524954)
  subtract := Or.inl ⟨⟨524953, by omega⟩, f.node_524953, rfl⟩
  multiply := Or.inl ⟨⟨524954, by omega⟩, f.node_524954, rfl⟩
  add := Or.inl ⟨⟨524955, by omega⟩, f.node_524955, rfl⟩
}

def certificate_449 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458228) (.wire 7131) (.wire 524916) (.wire 524958) := {
  difference := (.wire 524956)
  product := (.wire 524957)
  subtract := Or.inl ⟨⟨524956, by omega⟩, f.node_524956, rfl⟩
  multiply := Or.inl ⟨⟨524957, by omega⟩, f.node_524957, rfl⟩
  add := Or.inl ⟨⟨524958, by omega⟩, f.node_524958, rfl⟩
}

def certificate_450 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458228) (.wire 7132) (.wire 524927) (.wire 524961) := {
  difference := (.wire 524959)
  product := (.wire 524960)
  subtract := Or.inl ⟨⟨524959, by omega⟩, f.node_524959, rfl⟩
  multiply := Or.inl ⟨⟨524960, by omega⟩, f.node_524960, rfl⟩
  add := Or.inl ⟨⟨524961, by omega⟩, f.node_524961, rfl⟩
}

def certificate_451 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458228) (.wire 7133) (.wire 524893) (.wire 524964) := {
  difference := (.wire 524962)
  product := (.wire 524963)
  subtract := Or.inl ⟨⟨524962, by omega⟩, f.node_524962, rfl⟩
  multiply := Or.inl ⟨⟨524963, by omega⟩, f.node_524963, rfl⟩
  add := Or.inl ⟨⟨524964, by omega⟩, f.node_524964, rfl⟩
}

def certificate_452 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458228) (.wire 7134) (.wire 524904) (.wire 524967) := {
  difference := (.wire 524965)
  product := (.wire 524966)
  subtract := Or.inl ⟨⟨524965, by omega⟩, f.node_524965, rfl⟩
  multiply := Or.inl ⟨⟨524966, by omega⟩, f.node_524966, rfl⟩
  add := Or.inl ⟨⟨524967, by omega⟩, f.node_524967, rfl⟩
}

def certificate_453 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458228) (.wire 7135) (.wire 524915) (.wire 524970) := {
  difference := (.wire 524968)
  product := (.wire 524969)
  subtract := Or.inl ⟨⟨524968, by omega⟩, f.node_524968, rfl⟩
  multiply := Or.inl ⟨⟨524969, by omega⟩, f.node_524969, rfl⟩
  add := Or.inl ⟨⟨524970, by omega⟩, f.node_524970, rfl⟩
}

def certificate_454 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458233) (.wire 527368) (.wire 7136) (.wire 527405) := {
  difference := (.wire 527403)
  product := (.wire 527404)
  subtract := Or.inl ⟨⟨527403, by omega⟩, f.node_527403, rfl⟩
  multiply := Or.inl ⟨⟨527404, by omega⟩, f.node_527404, rfl⟩
  add := Or.inl ⟨⟨527405, by omega⟩, f.node_527405, rfl⟩
}

def certificate_455 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458233) (.wire 527379) (.wire 7137) (.wire 527408) := {
  difference := (.wire 527406)
  product := (.wire 527407)
  subtract := Or.inl ⟨⟨527406, by omega⟩, f.node_527406, rfl⟩
  multiply := Or.inl ⟨⟨527407, by omega⟩, f.node_527407, rfl⟩
  add := Or.inl ⟨⟨527408, by omega⟩, f.node_527408, rfl⟩
}

def certificate_456 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458233) (.wire 527390) (.wire 7138) (.wire 527411) := {
  difference := (.wire 527409)
  product := (.wire 527410)
  subtract := Or.inl ⟨⟨527409, by omega⟩, f.node_527409, rfl⟩
  multiply := Or.inl ⟨⟨527410, by omega⟩, f.node_527410, rfl⟩
  add := Or.inl ⟨⟨527411, by omega⟩, f.node_527411, rfl⟩
}

def certificate_457 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458233) (.wire 527401) (.wire 7139) (.wire 527414) := {
  difference := (.wire 527412)
  product := (.wire 527413)
  subtract := Or.inl ⟨⟨527412, by omega⟩, f.node_527412, rfl⟩
  multiply := Or.inl ⟨⟨527413, by omega⟩, f.node_527413, rfl⟩
  add := Or.inl ⟨⟨527414, by omega⟩, f.node_527414, rfl⟩
}

def certificate_458 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458233) (.wire 527367) (.wire 7140) (.wire 527417) := {
  difference := (.wire 527415)
  product := (.wire 527416)
  subtract := Or.inl ⟨⟨527415, by omega⟩, f.node_527415, rfl⟩
  multiply := Or.inl ⟨⟨527416, by omega⟩, f.node_527416, rfl⟩
  add := Or.inl ⟨⟨527417, by omega⟩, f.node_527417, rfl⟩
}

def certificate_459 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458233) (.wire 527378) (.wire 7141) (.wire 527420) := {
  difference := (.wire 527418)
  product := (.wire 527419)
  subtract := Or.inl ⟨⟨527418, by omega⟩, f.node_527418, rfl⟩
  multiply := Or.inl ⟨⟨527419, by omega⟩, f.node_527419, rfl⟩
  add := Or.inl ⟨⟨527420, by omega⟩, f.node_527420, rfl⟩
}

def certificate_460 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458233) (.wire 527389) (.wire 7142) (.wire 527423) := {
  difference := (.wire 527421)
  product := (.wire 527422)
  subtract := Or.inl ⟨⟨527421, by omega⟩, f.node_527421, rfl⟩
  multiply := Or.inl ⟨⟨527422, by omega⟩, f.node_527422, rfl⟩
  add := Or.inl ⟨⟨527423, by omega⟩, f.node_527423, rfl⟩
}

def certificate_461 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458233) (.wire 7136) (.wire 527368) (.wire 527426) := {
  difference := (.wire 527424)
  product := (.wire 527425)
  subtract := Or.inl ⟨⟨527424, by omega⟩, f.node_527424, rfl⟩
  multiply := Or.inl ⟨⟨527425, by omega⟩, f.node_527425, rfl⟩
  add := Or.inl ⟨⟨527426, by omega⟩, f.node_527426, rfl⟩
}

def certificate_462 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458233) (.wire 7137) (.wire 527379) (.wire 527429) := {
  difference := (.wire 527427)
  product := (.wire 527428)
  subtract := Or.inl ⟨⟨527427, by omega⟩, f.node_527427, rfl⟩
  multiply := Or.inl ⟨⟨527428, by omega⟩, f.node_527428, rfl⟩
  add := Or.inl ⟨⟨527429, by omega⟩, f.node_527429, rfl⟩
}

def certificate_463 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458233) (.wire 7138) (.wire 527390) (.wire 527432) := {
  difference := (.wire 527430)
  product := (.wire 527431)
  subtract := Or.inl ⟨⟨527430, by omega⟩, f.node_527430, rfl⟩
  multiply := Or.inl ⟨⟨527431, by omega⟩, f.node_527431, rfl⟩
  add := Or.inl ⟨⟨527432, by omega⟩, f.node_527432, rfl⟩
}

def certificate_464 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458233) (.wire 7139) (.wire 527401) (.wire 527435) := {
  difference := (.wire 527433)
  product := (.wire 527434)
  subtract := Or.inl ⟨⟨527433, by omega⟩, f.node_527433, rfl⟩
  multiply := Or.inl ⟨⟨527434, by omega⟩, f.node_527434, rfl⟩
  add := Or.inl ⟨⟨527435, by omega⟩, f.node_527435, rfl⟩
}

def certificate_465 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458233) (.wire 7140) (.wire 527367) (.wire 527438) := {
  difference := (.wire 527436)
  product := (.wire 527437)
  subtract := Or.inl ⟨⟨527436, by omega⟩, f.node_527436, rfl⟩
  multiply := Or.inl ⟨⟨527437, by omega⟩, f.node_527437, rfl⟩
  add := Or.inl ⟨⟨527438, by omega⟩, f.node_527438, rfl⟩
}

def certificate_466 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458233) (.wire 7141) (.wire 527378) (.wire 527441) := {
  difference := (.wire 527439)
  product := (.wire 527440)
  subtract := Or.inl ⟨⟨527439, by omega⟩, f.node_527439, rfl⟩
  multiply := Or.inl ⟨⟨527440, by omega⟩, f.node_527440, rfl⟩
  add := Or.inl ⟨⟨527441, by omega⟩, f.node_527441, rfl⟩
}

def certificate_467 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458233) (.wire 7142) (.wire 527389) (.wire 527444) := {
  difference := (.wire 527442)
  product := (.wire 527443)
  subtract := Or.inl ⟨⟨527442, by omega⟩, f.node_527442, rfl⟩
  multiply := Or.inl ⟨⟨527443, by omega⟩, f.node_527443, rfl⟩
  add := Or.inl ⟨⟨527444, by omega⟩, f.node_527444, rfl⟩
}

def certificate_468 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458238) (.wire 529842) (.wire 7143) (.wire 529879) := {
  difference := (.wire 529877)
  product := (.wire 529878)
  subtract := Or.inl ⟨⟨529877, by omega⟩, f.node_529877, rfl⟩
  multiply := Or.inl ⟨⟨529878, by omega⟩, f.node_529878, rfl⟩
  add := Or.inl ⟨⟨529879, by omega⟩, f.node_529879, rfl⟩
}

def certificate_469 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458238) (.wire 529853) (.wire 7144) (.wire 529882) := {
  difference := (.wire 529880)
  product := (.wire 529881)
  subtract := Or.inl ⟨⟨529880, by omega⟩, f.node_529880, rfl⟩
  multiply := Or.inl ⟨⟨529881, by omega⟩, f.node_529881, rfl⟩
  add := Or.inl ⟨⟨529882, by omega⟩, f.node_529882, rfl⟩
}

def certificate_470 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458238) (.wire 529864) (.wire 7145) (.wire 529885) := {
  difference := (.wire 529883)
  product := (.wire 529884)
  subtract := Or.inl ⟨⟨529883, by omega⟩, f.node_529883, rfl⟩
  multiply := Or.inl ⟨⟨529884, by omega⟩, f.node_529884, rfl⟩
  add := Or.inl ⟨⟨529885, by omega⟩, f.node_529885, rfl⟩
}

def certificate_471 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458238) (.wire 529875) (.wire 7146) (.wire 529888) := {
  difference := (.wire 529886)
  product := (.wire 529887)
  subtract := Or.inl ⟨⟨529886, by omega⟩, f.node_529886, rfl⟩
  multiply := Or.inl ⟨⟨529887, by omega⟩, f.node_529887, rfl⟩
  add := Or.inl ⟨⟨529888, by omega⟩, f.node_529888, rfl⟩
}

def certificate_472 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458238) (.wire 529841) (.wire 7147) (.wire 529891) := {
  difference := (.wire 529889)
  product := (.wire 529890)
  subtract := Or.inl ⟨⟨529889, by omega⟩, f.node_529889, rfl⟩
  multiply := Or.inl ⟨⟨529890, by omega⟩, f.node_529890, rfl⟩
  add := Or.inl ⟨⟨529891, by omega⟩, f.node_529891, rfl⟩
}

def certificate_473 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458238) (.wire 529852) (.wire 7148) (.wire 529894) := {
  difference := (.wire 529892)
  product := (.wire 529893)
  subtract := Or.inl ⟨⟨529892, by omega⟩, f.node_529892, rfl⟩
  multiply := Or.inl ⟨⟨529893, by omega⟩, f.node_529893, rfl⟩
  add := Or.inl ⟨⟨529894, by omega⟩, f.node_529894, rfl⟩
}

def certificate_474 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458238) (.wire 529863) (.wire 7149) (.wire 529897) := {
  difference := (.wire 529895)
  product := (.wire 529896)
  subtract := Or.inl ⟨⟨529895, by omega⟩, f.node_529895, rfl⟩
  multiply := Or.inl ⟨⟨529896, by omega⟩, f.node_529896, rfl⟩
  add := Or.inl ⟨⟨529897, by omega⟩, f.node_529897, rfl⟩
}

def certificate_475 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458238) (.wire 7143) (.wire 529842) (.wire 529900) := {
  difference := (.wire 529898)
  product := (.wire 529899)
  subtract := Or.inl ⟨⟨529898, by omega⟩, f.node_529898, rfl⟩
  multiply := Or.inl ⟨⟨529899, by omega⟩, f.node_529899, rfl⟩
  add := Or.inl ⟨⟨529900, by omega⟩, f.node_529900, rfl⟩
}

def certificate_476 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458238) (.wire 7144) (.wire 529853) (.wire 529903) := {
  difference := (.wire 529901)
  product := (.wire 529902)
  subtract := Or.inl ⟨⟨529901, by omega⟩, f.node_529901, rfl⟩
  multiply := Or.inl ⟨⟨529902, by omega⟩, f.node_529902, rfl⟩
  add := Or.inl ⟨⟨529903, by omega⟩, f.node_529903, rfl⟩
}

def certificate_477 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458238) (.wire 7145) (.wire 529864) (.wire 529906) := {
  difference := (.wire 529904)
  product := (.wire 529905)
  subtract := Or.inl ⟨⟨529904, by omega⟩, f.node_529904, rfl⟩
  multiply := Or.inl ⟨⟨529905, by omega⟩, f.node_529905, rfl⟩
  add := Or.inl ⟨⟨529906, by omega⟩, f.node_529906, rfl⟩
}

def certificate_478 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458238) (.wire 7146) (.wire 529875) (.wire 529909) := {
  difference := (.wire 529907)
  product := (.wire 529908)
  subtract := Or.inl ⟨⟨529907, by omega⟩, f.node_529907, rfl⟩
  multiply := Or.inl ⟨⟨529908, by omega⟩, f.node_529908, rfl⟩
  add := Or.inl ⟨⟨529909, by omega⟩, f.node_529909, rfl⟩
}

def certificate_479 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458238) (.wire 7147) (.wire 529841) (.wire 529912) := {
  difference := (.wire 529910)
  product := (.wire 529911)
  subtract := Or.inl ⟨⟨529910, by omega⟩, f.node_529910, rfl⟩
  multiply := Or.inl ⟨⟨529911, by omega⟩, f.node_529911, rfl⟩
  add := Or.inl ⟨⟨529912, by omega⟩, f.node_529912, rfl⟩
}

def certificate_480 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458238) (.wire 7148) (.wire 529852) (.wire 529915) := {
  difference := (.wire 529913)
  product := (.wire 529914)
  subtract := Or.inl ⟨⟨529913, by omega⟩, f.node_529913, rfl⟩
  multiply := Or.inl ⟨⟨529914, by omega⟩, f.node_529914, rfl⟩
  add := Or.inl ⟨⟨529915, by omega⟩, f.node_529915, rfl⟩
}

def certificate_481 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458238) (.wire 7149) (.wire 529863) (.wire 529918) := {
  difference := (.wire 529916)
  product := (.wire 529917)
  subtract := Or.inl ⟨⟨529916, by omega⟩, f.node_529916, rfl⟩
  multiply := Or.inl ⟨⟨529917, by omega⟩, f.node_529917, rfl⟩
  add := Or.inl ⟨⟨529918, by omega⟩, f.node_529918, rfl⟩
}

def certificate_482 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458243) (.wire 532316) (.wire 7150) (.wire 532353) := {
  difference := (.wire 532351)
  product := (.wire 532352)
  subtract := Or.inl ⟨⟨532351, by omega⟩, f.node_532351, rfl⟩
  multiply := Or.inl ⟨⟨532352, by omega⟩, f.node_532352, rfl⟩
  add := Or.inl ⟨⟨532353, by omega⟩, f.node_532353, rfl⟩
}

def certificate_483 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458243) (.wire 532327) (.wire 7151) (.wire 532356) := {
  difference := (.wire 532354)
  product := (.wire 532355)
  subtract := Or.inl ⟨⟨532354, by omega⟩, f.node_532354, rfl⟩
  multiply := Or.inl ⟨⟨532355, by omega⟩, f.node_532355, rfl⟩
  add := Or.inl ⟨⟨532356, by omega⟩, f.node_532356, rfl⟩
}

def certificate_484 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458243) (.wire 532338) (.wire 7152) (.wire 532359) := {
  difference := (.wire 532357)
  product := (.wire 532358)
  subtract := Or.inl ⟨⟨532357, by omega⟩, f.node_532357, rfl⟩
  multiply := Or.inl ⟨⟨532358, by omega⟩, f.node_532358, rfl⟩
  add := Or.inl ⟨⟨532359, by omega⟩, f.node_532359, rfl⟩
}

def certificate_485 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458243) (.wire 532349) (.wire 7153) (.wire 532362) := {
  difference := (.wire 532360)
  product := (.wire 532361)
  subtract := Or.inl ⟨⟨532360, by omega⟩, f.node_532360, rfl⟩
  multiply := Or.inl ⟨⟨532361, by omega⟩, f.node_532361, rfl⟩
  add := Or.inl ⟨⟨532362, by omega⟩, f.node_532362, rfl⟩
}

def certificate_486 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458243) (.wire 532315) (.wire 7154) (.wire 532365) := {
  difference := (.wire 532363)
  product := (.wire 532364)
  subtract := Or.inl ⟨⟨532363, by omega⟩, f.node_532363, rfl⟩
  multiply := Or.inl ⟨⟨532364, by omega⟩, f.node_532364, rfl⟩
  add := Or.inl ⟨⟨532365, by omega⟩, f.node_532365, rfl⟩
}

def certificate_487 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458243) (.wire 532326) (.wire 7155) (.wire 532368) := {
  difference := (.wire 532366)
  product := (.wire 532367)
  subtract := Or.inl ⟨⟨532366, by omega⟩, f.node_532366, rfl⟩
  multiply := Or.inl ⟨⟨532367, by omega⟩, f.node_532367, rfl⟩
  add := Or.inl ⟨⟨532368, by omega⟩, f.node_532368, rfl⟩
}

def certificate_488 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458243) (.wire 532337) (.wire 7156) (.wire 532371) := {
  difference := (.wire 532369)
  product := (.wire 532370)
  subtract := Or.inl ⟨⟨532369, by omega⟩, f.node_532369, rfl⟩
  multiply := Or.inl ⟨⟨532370, by omega⟩, f.node_532370, rfl⟩
  add := Or.inl ⟨⟨532371, by omega⟩, f.node_532371, rfl⟩
}

def certificate_489 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458243) (.wire 7150) (.wire 532316) (.wire 532374) := {
  difference := (.wire 532372)
  product := (.wire 532373)
  subtract := Or.inl ⟨⟨532372, by omega⟩, f.node_532372, rfl⟩
  multiply := Or.inl ⟨⟨532373, by omega⟩, f.node_532373, rfl⟩
  add := Or.inl ⟨⟨532374, by omega⟩, f.node_532374, rfl⟩
}

def certificate_490 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458243) (.wire 7151) (.wire 532327) (.wire 532377) := {
  difference := (.wire 532375)
  product := (.wire 532376)
  subtract := Or.inl ⟨⟨532375, by omega⟩, f.node_532375, rfl⟩
  multiply := Or.inl ⟨⟨532376, by omega⟩, f.node_532376, rfl⟩
  add := Or.inl ⟨⟨532377, by omega⟩, f.node_532377, rfl⟩
}

def certificate_491 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458243) (.wire 7152) (.wire 532338) (.wire 532380) := {
  difference := (.wire 532378)
  product := (.wire 532379)
  subtract := Or.inl ⟨⟨532378, by omega⟩, f.node_532378, rfl⟩
  multiply := Or.inl ⟨⟨532379, by omega⟩, f.node_532379, rfl⟩
  add := Or.inl ⟨⟨532380, by omega⟩, f.node_532380, rfl⟩
}

def certificate_492 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458243) (.wire 7153) (.wire 532349) (.wire 532383) := {
  difference := (.wire 532381)
  product := (.wire 532382)
  subtract := Or.inl ⟨⟨532381, by omega⟩, f.node_532381, rfl⟩
  multiply := Or.inl ⟨⟨532382, by omega⟩, f.node_532382, rfl⟩
  add := Or.inl ⟨⟨532383, by omega⟩, f.node_532383, rfl⟩
}

def certificate_493 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458243) (.wire 7154) (.wire 532315) (.wire 532386) := {
  difference := (.wire 532384)
  product := (.wire 532385)
  subtract := Or.inl ⟨⟨532384, by omega⟩, f.node_532384, rfl⟩
  multiply := Or.inl ⟨⟨532385, by omega⟩, f.node_532385, rfl⟩
  add := Or.inl ⟨⟨532386, by omega⟩, f.node_532386, rfl⟩
}

def certificate_494 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458243) (.wire 7155) (.wire 532326) (.wire 532389) := {
  difference := (.wire 532387)
  product := (.wire 532388)
  subtract := Or.inl ⟨⟨532387, by omega⟩, f.node_532387, rfl⟩
  multiply := Or.inl ⟨⟨532388, by omega⟩, f.node_532388, rfl⟩
  add := Or.inl ⟨⟨532389, by omega⟩, f.node_532389, rfl⟩
}

def certificate_495 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458243) (.wire 7156) (.wire 532337) (.wire 532392) := {
  difference := (.wire 532390)
  product := (.wire 532391)
  subtract := Or.inl ⟨⟨532390, by omega⟩, f.node_532390, rfl⟩
  multiply := Or.inl ⟨⟨532391, by omega⟩, f.node_532391, rfl⟩
  add := Or.inl ⟨⟨532392, by omega⟩, f.node_532392, rfl⟩
}

def certificate_496 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458248) (.wire 534790) (.wire 7157) (.wire 534827) := {
  difference := (.wire 534825)
  product := (.wire 534826)
  subtract := Or.inl ⟨⟨534825, by omega⟩, f.node_534825, rfl⟩
  multiply := Or.inl ⟨⟨534826, by omega⟩, f.node_534826, rfl⟩
  add := Or.inl ⟨⟨534827, by omega⟩, f.node_534827, rfl⟩
}

def certificate_497 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458248) (.wire 534801) (.wire 7158) (.wire 534830) := {
  difference := (.wire 534828)
  product := (.wire 534829)
  subtract := Or.inl ⟨⟨534828, by omega⟩, f.node_534828, rfl⟩
  multiply := Or.inl ⟨⟨534829, by omega⟩, f.node_534829, rfl⟩
  add := Or.inl ⟨⟨534830, by omega⟩, f.node_534830, rfl⟩
}

def certificate_498 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458248) (.wire 534812) (.wire 7159) (.wire 534833) := {
  difference := (.wire 534831)
  product := (.wire 534832)
  subtract := Or.inl ⟨⟨534831, by omega⟩, f.node_534831, rfl⟩
  multiply := Or.inl ⟨⟨534832, by omega⟩, f.node_534832, rfl⟩
  add := Or.inl ⟨⟨534833, by omega⟩, f.node_534833, rfl⟩
}

def certificate_499 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458248) (.wire 534823) (.wire 7160) (.wire 534836) := {
  difference := (.wire 534834)
  product := (.wire 534835)
  subtract := Or.inl ⟨⟨534834, by omega⟩, f.node_534834, rfl⟩
  multiply := Or.inl ⟨⟨534835, by omega⟩, f.node_534835, rfl⟩
  add := Or.inl ⟨⟨534836, by omega⟩, f.node_534836, rfl⟩
}

def certificate_500 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458248) (.wire 534789) (.wire 7161) (.wire 534839) := {
  difference := (.wire 534837)
  product := (.wire 534838)
  subtract := Or.inl ⟨⟨534837, by omega⟩, f.node_534837, rfl⟩
  multiply := Or.inl ⟨⟨534838, by omega⟩, f.node_534838, rfl⟩
  add := Or.inl ⟨⟨534839, by omega⟩, f.node_534839, rfl⟩
}

def certificate_501 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458248) (.wire 534800) (.wire 7162) (.wire 534842) := {
  difference := (.wire 534840)
  product := (.wire 534841)
  subtract := Or.inl ⟨⟨534840, by omega⟩, f.node_534840, rfl⟩
  multiply := Or.inl ⟨⟨534841, by omega⟩, f.node_534841, rfl⟩
  add := Or.inl ⟨⟨534842, by omega⟩, f.node_534842, rfl⟩
}

def certificate_502 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458248) (.wire 534811) (.wire 7163) (.wire 534845) := {
  difference := (.wire 534843)
  product := (.wire 534844)
  subtract := Or.inl ⟨⟨534843, by omega⟩, f.node_534843, rfl⟩
  multiply := Or.inl ⟨⟨534844, by omega⟩, f.node_534844, rfl⟩
  add := Or.inl ⟨⟨534845, by omega⟩, f.node_534845, rfl⟩
}

def certificate_503 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458248) (.wire 7157) (.wire 534790) (.wire 534848) := {
  difference := (.wire 534846)
  product := (.wire 534847)
  subtract := Or.inl ⟨⟨534846, by omega⟩, f.node_534846, rfl⟩
  multiply := Or.inl ⟨⟨534847, by omega⟩, f.node_534847, rfl⟩
  add := Or.inl ⟨⟨534848, by omega⟩, f.node_534848, rfl⟩
}

def certificate_504 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458248) (.wire 7158) (.wire 534801) (.wire 534851) := {
  difference := (.wire 534849)
  product := (.wire 534850)
  subtract := Or.inl ⟨⟨534849, by omega⟩, f.node_534849, rfl⟩
  multiply := Or.inl ⟨⟨534850, by omega⟩, f.node_534850, rfl⟩
  add := Or.inl ⟨⟨534851, by omega⟩, f.node_534851, rfl⟩
}

def certificate_505 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458248) (.wire 7159) (.wire 534812) (.wire 534854) := {
  difference := (.wire 534852)
  product := (.wire 534853)
  subtract := Or.inl ⟨⟨534852, by omega⟩, f.node_534852, rfl⟩
  multiply := Or.inl ⟨⟨534853, by omega⟩, f.node_534853, rfl⟩
  add := Or.inl ⟨⟨534854, by omega⟩, f.node_534854, rfl⟩
}

def certificate_506 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458248) (.wire 7160) (.wire 534823) (.wire 534857) := {
  difference := (.wire 534855)
  product := (.wire 534856)
  subtract := Or.inl ⟨⟨534855, by omega⟩, f.node_534855, rfl⟩
  multiply := Or.inl ⟨⟨534856, by omega⟩, f.node_534856, rfl⟩
  add := Or.inl ⟨⟨534857, by omega⟩, f.node_534857, rfl⟩
}

def certificate_507 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458248) (.wire 7161) (.wire 534789) (.wire 534860) := {
  difference := (.wire 534858)
  product := (.wire 534859)
  subtract := Or.inl ⟨⟨534858, by omega⟩, f.node_534858, rfl⟩
  multiply := Or.inl ⟨⟨534859, by omega⟩, f.node_534859, rfl⟩
  add := Or.inl ⟨⟨534860, by omega⟩, f.node_534860, rfl⟩
}

def certificate_508 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458248) (.wire 7162) (.wire 534800) (.wire 534863) := {
  difference := (.wire 534861)
  product := (.wire 534862)
  subtract := Or.inl ⟨⟨534861, by omega⟩, f.node_534861, rfl⟩
  multiply := Or.inl ⟨⟨534862, by omega⟩, f.node_534862, rfl⟩
  add := Or.inl ⟨⟨534863, by omega⟩, f.node_534863, rfl⟩
}

def certificate_509 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458248) (.wire 7163) (.wire 534811) (.wire 534866) := {
  difference := (.wire 534864)
  product := (.wire 534865)
  subtract := Or.inl ⟨⟨534864, by omega⟩, f.node_534864, rfl⟩
  multiply := Or.inl ⟨⟨534865, by omega⟩, f.node_534865, rfl⟩
  add := Or.inl ⟨⟨534866, by omega⟩, f.node_534866, rfl⟩
}

def certificate_510 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458253) (.wire 537264) (.wire 7164) (.wire 537301) := {
  difference := (.wire 537299)
  product := (.wire 537300)
  subtract := Or.inl ⟨⟨537299, by omega⟩, f.node_537299, rfl⟩
  multiply := Or.inl ⟨⟨537300, by omega⟩, f.node_537300, rfl⟩
  add := Or.inl ⟨⟨537301, by omega⟩, f.node_537301, rfl⟩
}

def certificate_511 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458253) (.wire 537275) (.wire 7165) (.wire 537304) := {
  difference := (.wire 537302)
  product := (.wire 537303)
  subtract := Or.inl ⟨⟨537302, by omega⟩, f.node_537302, rfl⟩
  multiply := Or.inl ⟨⟨537303, by omega⟩, f.node_537303, rfl⟩
  add := Or.inl ⟨⟨537304, by omega⟩, f.node_537304, rfl⟩
}

def certificate_512 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458253) (.wire 537286) (.wire 7166) (.wire 537307) := {
  difference := (.wire 537305)
  product := (.wire 537306)
  subtract := Or.inl ⟨⟨537305, by omega⟩, f.node_537305, rfl⟩
  multiply := Or.inl ⟨⟨537306, by omega⟩, f.node_537306, rfl⟩
  add := Or.inl ⟨⟨537307, by omega⟩, f.node_537307, rfl⟩
}

def certificate_513 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458253) (.wire 537297) (.wire 7167) (.wire 537310) := {
  difference := (.wire 537308)
  product := (.wire 537309)
  subtract := Or.inl ⟨⟨537308, by omega⟩, f.node_537308, rfl⟩
  multiply := Or.inl ⟨⟨537309, by omega⟩, f.node_537309, rfl⟩
  add := Or.inl ⟨⟨537310, by omega⟩, f.node_537310, rfl⟩
}

def certificate_514 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458253) (.wire 537263) (.wire 7168) (.wire 537313) := {
  difference := (.wire 537311)
  product := (.wire 537312)
  subtract := Or.inl ⟨⟨537311, by omega⟩, f.node_537311, rfl⟩
  multiply := Or.inl ⟨⟨537312, by omega⟩, f.node_537312, rfl⟩
  add := Or.inl ⟨⟨537313, by omega⟩, f.node_537313, rfl⟩
}

def certificate_515 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458253) (.wire 537274) (.wire 7169) (.wire 537316) := {
  difference := (.wire 537314)
  product := (.wire 537315)
  subtract := Or.inl ⟨⟨537314, by omega⟩, f.node_537314, rfl⟩
  multiply := Or.inl ⟨⟨537315, by omega⟩, f.node_537315, rfl⟩
  add := Or.inl ⟨⟨537316, by omega⟩, f.node_537316, rfl⟩
}

def certificate_516 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458253) (.wire 537285) (.wire 7170) (.wire 537319) := {
  difference := (.wire 537317)
  product := (.wire 537318)
  subtract := Or.inl ⟨⟨537317, by omega⟩, f.node_537317, rfl⟩
  multiply := Or.inl ⟨⟨537318, by omega⟩, f.node_537318, rfl⟩
  add := Or.inl ⟨⟨537319, by omega⟩, f.node_537319, rfl⟩
}

def certificate_517 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458253) (.wire 7164) (.wire 537264) (.wire 537322) := {
  difference := (.wire 537320)
  product := (.wire 537321)
  subtract := Or.inl ⟨⟨537320, by omega⟩, f.node_537320, rfl⟩
  multiply := Or.inl ⟨⟨537321, by omega⟩, f.node_537321, rfl⟩
  add := Or.inl ⟨⟨537322, by omega⟩, f.node_537322, rfl⟩
}

def certificate_518 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458253) (.wire 7165) (.wire 537275) (.wire 537325) := {
  difference := (.wire 537323)
  product := (.wire 537324)
  subtract := Or.inl ⟨⟨537323, by omega⟩, f.node_537323, rfl⟩
  multiply := Or.inl ⟨⟨537324, by omega⟩, f.node_537324, rfl⟩
  add := Or.inl ⟨⟨537325, by omega⟩, f.node_537325, rfl⟩
}

def certificate_519 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458253) (.wire 7166) (.wire 537286) (.wire 537328) := {
  difference := (.wire 537326)
  product := (.wire 537327)
  subtract := Or.inl ⟨⟨537326, by omega⟩, f.node_537326, rfl⟩
  multiply := Or.inl ⟨⟨537327, by omega⟩, f.node_537327, rfl⟩
  add := Or.inl ⟨⟨537328, by omega⟩, f.node_537328, rfl⟩
}

def certificate_520 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458253) (.wire 7167) (.wire 537297) (.wire 537331) := {
  difference := (.wire 537329)
  product := (.wire 537330)
  subtract := Or.inl ⟨⟨537329, by omega⟩, f.node_537329, rfl⟩
  multiply := Or.inl ⟨⟨537330, by omega⟩, f.node_537330, rfl⟩
  add := Or.inl ⟨⟨537331, by omega⟩, f.node_537331, rfl⟩
}

def certificate_521 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458253) (.wire 7168) (.wire 537263) (.wire 537334) := {
  difference := (.wire 537332)
  product := (.wire 537333)
  subtract := Or.inl ⟨⟨537332, by omega⟩, f.node_537332, rfl⟩
  multiply := Or.inl ⟨⟨537333, by omega⟩, f.node_537333, rfl⟩
  add := Or.inl ⟨⟨537334, by omega⟩, f.node_537334, rfl⟩
}

def certificate_522 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458253) (.wire 7169) (.wire 537274) (.wire 537337) := {
  difference := (.wire 537335)
  product := (.wire 537336)
  subtract := Or.inl ⟨⟨537335, by omega⟩, f.node_537335, rfl⟩
  multiply := Or.inl ⟨⟨537336, by omega⟩, f.node_537336, rfl⟩
  add := Or.inl ⟨⟨537337, by omega⟩, f.node_537337, rfl⟩
}

def certificate_523 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458253) (.wire 7170) (.wire 537285) (.wire 537340) := {
  difference := (.wire 537338)
  product := (.wire 537339)
  subtract := Or.inl ⟨⟨537338, by omega⟩, f.node_537338, rfl⟩
  multiply := Or.inl ⟨⟨537339, by omega⟩, f.node_537339, rfl⟩
  add := Or.inl ⟨⟨537340, by omega⟩, f.node_537340, rfl⟩
}

def certificate_524 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458258) (.wire 539738) (.wire 7171) (.wire 539775) := {
  difference := (.wire 539773)
  product := (.wire 539774)
  subtract := Or.inl ⟨⟨539773, by omega⟩, f.node_539773, rfl⟩
  multiply := Or.inl ⟨⟨539774, by omega⟩, f.node_539774, rfl⟩
  add := Or.inl ⟨⟨539775, by omega⟩, f.node_539775, rfl⟩
}

def certificate_525 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458258) (.wire 539749) (.wire 7172) (.wire 539778) := {
  difference := (.wire 539776)
  product := (.wire 539777)
  subtract := Or.inl ⟨⟨539776, by omega⟩, f.node_539776, rfl⟩
  multiply := Or.inl ⟨⟨539777, by omega⟩, f.node_539777, rfl⟩
  add := Or.inl ⟨⟨539778, by omega⟩, f.node_539778, rfl⟩
}

def certificate_526 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458258) (.wire 539760) (.wire 7173) (.wire 539781) := {
  difference := (.wire 539779)
  product := (.wire 539780)
  subtract := Or.inl ⟨⟨539779, by omega⟩, f.node_539779, rfl⟩
  multiply := Or.inl ⟨⟨539780, by omega⟩, f.node_539780, rfl⟩
  add := Or.inl ⟨⟨539781, by omega⟩, f.node_539781, rfl⟩
}

def certificate_527 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458258) (.wire 539771) (.wire 7174) (.wire 539784) := {
  difference := (.wire 539782)
  product := (.wire 539783)
  subtract := Or.inl ⟨⟨539782, by omega⟩, f.node_539782, rfl⟩
  multiply := Or.inl ⟨⟨539783, by omega⟩, f.node_539783, rfl⟩
  add := Or.inl ⟨⟨539784, by omega⟩, f.node_539784, rfl⟩
}

def certificate_528 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458258) (.wire 539737) (.wire 7175) (.wire 539787) := {
  difference := (.wire 539785)
  product := (.wire 539786)
  subtract := Or.inl ⟨⟨539785, by omega⟩, f.node_539785, rfl⟩
  multiply := Or.inl ⟨⟨539786, by omega⟩, f.node_539786, rfl⟩
  add := Or.inl ⟨⟨539787, by omega⟩, f.node_539787, rfl⟩
}

def certificate_529 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458258) (.wire 539748) (.wire 7176) (.wire 539790) := {
  difference := (.wire 539788)
  product := (.wire 539789)
  subtract := Or.inl ⟨⟨539788, by omega⟩, f.node_539788, rfl⟩
  multiply := Or.inl ⟨⟨539789, by omega⟩, f.node_539789, rfl⟩
  add := Or.inl ⟨⟨539790, by omega⟩, f.node_539790, rfl⟩
}

def certificate_530 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458258) (.wire 539759) (.wire 7177) (.wire 539793) := {
  difference := (.wire 539791)
  product := (.wire 539792)
  subtract := Or.inl ⟨⟨539791, by omega⟩, f.node_539791, rfl⟩
  multiply := Or.inl ⟨⟨539792, by omega⟩, f.node_539792, rfl⟩
  add := Or.inl ⟨⟨539793, by omega⟩, f.node_539793, rfl⟩
}

def certificate_531 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458258) (.wire 7171) (.wire 539738) (.wire 539796) := {
  difference := (.wire 539794)
  product := (.wire 539795)
  subtract := Or.inl ⟨⟨539794, by omega⟩, f.node_539794, rfl⟩
  multiply := Or.inl ⟨⟨539795, by omega⟩, f.node_539795, rfl⟩
  add := Or.inl ⟨⟨539796, by omega⟩, f.node_539796, rfl⟩
}

def certificate_532 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458258) (.wire 7172) (.wire 539749) (.wire 539799) := {
  difference := (.wire 539797)
  product := (.wire 539798)
  subtract := Or.inl ⟨⟨539797, by omega⟩, f.node_539797, rfl⟩
  multiply := Or.inl ⟨⟨539798, by omega⟩, f.node_539798, rfl⟩
  add := Or.inl ⟨⟨539799, by omega⟩, f.node_539799, rfl⟩
}

def certificate_533 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458258) (.wire 7173) (.wire 539760) (.wire 539802) := {
  difference := (.wire 539800)
  product := (.wire 539801)
  subtract := Or.inl ⟨⟨539800, by omega⟩, f.node_539800, rfl⟩
  multiply := Or.inl ⟨⟨539801, by omega⟩, f.node_539801, rfl⟩
  add := Or.inl ⟨⟨539802, by omega⟩, f.node_539802, rfl⟩
}

def certificate_534 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458258) (.wire 7174) (.wire 539771) (.wire 539805) := {
  difference := (.wire 539803)
  product := (.wire 539804)
  subtract := Or.inl ⟨⟨539803, by omega⟩, f.node_539803, rfl⟩
  multiply := Or.inl ⟨⟨539804, by omega⟩, f.node_539804, rfl⟩
  add := Or.inl ⟨⟨539805, by omega⟩, f.node_539805, rfl⟩
}

def certificate_535 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458258) (.wire 7175) (.wire 539737) (.wire 539808) := {
  difference := (.wire 539806)
  product := (.wire 539807)
  subtract := Or.inl ⟨⟨539806, by omega⟩, f.node_539806, rfl⟩
  multiply := Or.inl ⟨⟨539807, by omega⟩, f.node_539807, rfl⟩
  add := Or.inl ⟨⟨539808, by omega⟩, f.node_539808, rfl⟩
}

def certificate_536 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458258) (.wire 7176) (.wire 539748) (.wire 539811) := {
  difference := (.wire 539809)
  product := (.wire 539810)
  subtract := Or.inl ⟨⟨539809, by omega⟩, f.node_539809, rfl⟩
  multiply := Or.inl ⟨⟨539810, by omega⟩, f.node_539810, rfl⟩
  add := Or.inl ⟨⟨539811, by omega⟩, f.node_539811, rfl⟩
}

def certificate_537 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458258) (.wire 7177) (.wire 539759) (.wire 539814) := {
  difference := (.wire 539812)
  product := (.wire 539813)
  subtract := Or.inl ⟨⟨539812, by omega⟩, f.node_539812, rfl⟩
  multiply := Or.inl ⟨⟨539813, by omega⟩, f.node_539813, rfl⟩
  add := Or.inl ⟨⟨539814, by omega⟩, f.node_539814, rfl⟩
}

def certificate_538 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458263) (.wire 542212) (.wire 7178) (.wire 542249) := {
  difference := (.wire 542247)
  product := (.wire 542248)
  subtract := Or.inl ⟨⟨542247, by omega⟩, f.node_542247, rfl⟩
  multiply := Or.inl ⟨⟨542248, by omega⟩, f.node_542248, rfl⟩
  add := Or.inl ⟨⟨542249, by omega⟩, f.node_542249, rfl⟩
}

def certificate_539 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458263) (.wire 542223) (.wire 7179) (.wire 542252) := {
  difference := (.wire 542250)
  product := (.wire 542251)
  subtract := Or.inl ⟨⟨542250, by omega⟩, f.node_542250, rfl⟩
  multiply := Or.inl ⟨⟨542251, by omega⟩, f.node_542251, rfl⟩
  add := Or.inl ⟨⟨542252, by omega⟩, f.node_542252, rfl⟩
}

def certificate_540 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458263) (.wire 542234) (.wire 7180) (.wire 542255) := {
  difference := (.wire 542253)
  product := (.wire 542254)
  subtract := Or.inl ⟨⟨542253, by omega⟩, f.node_542253, rfl⟩
  multiply := Or.inl ⟨⟨542254, by omega⟩, f.node_542254, rfl⟩
  add := Or.inl ⟨⟨542255, by omega⟩, f.node_542255, rfl⟩
}

def certificate_541 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458263) (.wire 542245) (.wire 7181) (.wire 542258) := {
  difference := (.wire 542256)
  product := (.wire 542257)
  subtract := Or.inl ⟨⟨542256, by omega⟩, f.node_542256, rfl⟩
  multiply := Or.inl ⟨⟨542257, by omega⟩, f.node_542257, rfl⟩
  add := Or.inl ⟨⟨542258, by omega⟩, f.node_542258, rfl⟩
}

def certificate_542 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458263) (.wire 542211) (.wire 7182) (.wire 542261) := {
  difference := (.wire 542259)
  product := (.wire 542260)
  subtract := Or.inl ⟨⟨542259, by omega⟩, f.node_542259, rfl⟩
  multiply := Or.inl ⟨⟨542260, by omega⟩, f.node_542260, rfl⟩
  add := Or.inl ⟨⟨542261, by omega⟩, f.node_542261, rfl⟩
}

def certificate_543 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458263) (.wire 542222) (.wire 7183) (.wire 542264) := {
  difference := (.wire 542262)
  product := (.wire 542263)
  subtract := Or.inl ⟨⟨542262, by omega⟩, f.node_542262, rfl⟩
  multiply := Or.inl ⟨⟨542263, by omega⟩, f.node_542263, rfl⟩
  add := Or.inl ⟨⟨542264, by omega⟩, f.node_542264, rfl⟩
}

def certificate_544 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458263) (.wire 542233) (.wire 7184) (.wire 542267) := {
  difference := (.wire 542265)
  product := (.wire 542266)
  subtract := Or.inl ⟨⟨542265, by omega⟩, f.node_542265, rfl⟩
  multiply := Or.inl ⟨⟨542266, by omega⟩, f.node_542266, rfl⟩
  add := Or.inl ⟨⟨542267, by omega⟩, f.node_542267, rfl⟩
}

def certificate_545 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458263) (.wire 7178) (.wire 542212) (.wire 542270) := {
  difference := (.wire 542268)
  product := (.wire 542269)
  subtract := Or.inl ⟨⟨542268, by omega⟩, f.node_542268, rfl⟩
  multiply := Or.inl ⟨⟨542269, by omega⟩, f.node_542269, rfl⟩
  add := Or.inl ⟨⟨542270, by omega⟩, f.node_542270, rfl⟩
}

def certificate_546 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458263) (.wire 7179) (.wire 542223) (.wire 542273) := {
  difference := (.wire 542271)
  product := (.wire 542272)
  subtract := Or.inl ⟨⟨542271, by omega⟩, f.node_542271, rfl⟩
  multiply := Or.inl ⟨⟨542272, by omega⟩, f.node_542272, rfl⟩
  add := Or.inl ⟨⟨542273, by omega⟩, f.node_542273, rfl⟩
}

def certificate_547 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458263) (.wire 7180) (.wire 542234) (.wire 542276) := {
  difference := (.wire 542274)
  product := (.wire 542275)
  subtract := Or.inl ⟨⟨542274, by omega⟩, f.node_542274, rfl⟩
  multiply := Or.inl ⟨⟨542275, by omega⟩, f.node_542275, rfl⟩
  add := Or.inl ⟨⟨542276, by omega⟩, f.node_542276, rfl⟩
}

def certificate_548 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458263) (.wire 7181) (.wire 542245) (.wire 542279) := {
  difference := (.wire 542277)
  product := (.wire 542278)
  subtract := Or.inl ⟨⟨542277, by omega⟩, f.node_542277, rfl⟩
  multiply := Or.inl ⟨⟨542278, by omega⟩, f.node_542278, rfl⟩
  add := Or.inl ⟨⟨542279, by omega⟩, f.node_542279, rfl⟩
}

def certificate_549 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458263) (.wire 7182) (.wire 542211) (.wire 542282) := {
  difference := (.wire 542280)
  product := (.wire 542281)
  subtract := Or.inl ⟨⟨542280, by omega⟩, f.node_542280, rfl⟩
  multiply := Or.inl ⟨⟨542281, by omega⟩, f.node_542281, rfl⟩
  add := Or.inl ⟨⟨542282, by omega⟩, f.node_542282, rfl⟩
}

def certificate_550 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458263) (.wire 7183) (.wire 542222) (.wire 542285) := {
  difference := (.wire 542283)
  product := (.wire 542284)
  subtract := Or.inl ⟨⟨542283, by omega⟩, f.node_542283, rfl⟩
  multiply := Or.inl ⟨⟨542284, by omega⟩, f.node_542284, rfl⟩
  add := Or.inl ⟨⟨542285, by omega⟩, f.node_542285, rfl⟩
}

def certificate_551 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 458263) (.wire 7184) (.wire 542233) (.wire 542288) := {
  difference := (.wire 542286)
  product := (.wire 542287)
  subtract := Or.inl ⟨⟨542286, by omega⟩, f.node_542286, rfl⟩
  multiply := Or.inl ⟨⟨542287, by omega⟩, f.node_542287, rfl⟩
  add := Or.inl ⟨⟨542288, by omega⟩, f.node_542288, rfl⟩
}

def certificate_552 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6940) (.wire 544686) (.wire 17) := {
  difference := (.wire 544721)
  product := (.wire 544722)
  subtract := Or.inl ⟨⟨544721, by omega⟩, f.node_544721, rfl⟩
  multiply := Or.inl ⟨⟨544722, by omega⟩, f.node_544722, rfl⟩
  zero := f.eq_90
}

def certificate_553 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6940) (.wire 544697) (.wire 18) := {
  difference := (.wire 544723)
  product := (.wire 544724)
  subtract := Or.inl ⟨⟨544723, by omega⟩, f.node_544723, rfl⟩
  multiply := Or.inl ⟨⟨544724, by omega⟩, f.node_544724, rfl⟩
  zero := f.eq_91
}

def certificate_554 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6940) (.wire 544708) (.wire 19) := {
  difference := (.wire 544725)
  product := (.wire 544726)
  subtract := Or.inl ⟨⟨544725, by omega⟩, f.node_544725, rfl⟩
  multiply := Or.inl ⟨⟨544726, by omega⟩, f.node_544726, rfl⟩
  zero := f.eq_92
}

def certificate_555 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6940) (.wire 544719) (.wire 20) := {
  difference := (.wire 544727)
  product := (.wire 544728)
  subtract := Or.inl ⟨⟨544727, by omega⟩, f.node_544727, rfl⟩
  multiply := Or.inl ⟨⟨544728, by omega⟩, f.node_544728, rfl⟩
  zero := f.eq_93
}

def certificate_556 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6940) (.wire 544685) (.wire 21) := {
  difference := (.wire 544729)
  product := (.wire 544730)
  subtract := Or.inl ⟨⟨544729, by omega⟩, f.node_544729, rfl⟩
  multiply := Or.inl ⟨⟨544730, by omega⟩, f.node_544730, rfl⟩
  zero := f.eq_94
}

def certificate_557 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6940) (.wire 544696) (.wire 22) := {
  difference := (.wire 544731)
  product := (.wire 544732)
  subtract := Or.inl ⟨⟨544731, by omega⟩, f.node_544731, rfl⟩
  multiply := Or.inl ⟨⟨544732, by omega⟩, f.node_544732, rfl⟩
  zero := f.eq_95
}

def certificate_558 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 6940) (.wire 544707) (.wire 23) := {
  difference := (.wire 544733)
  product := (.wire 544734)
  subtract := Or.inl ⟨⟨544733, by omega⟩, f.node_544733, rfl⟩
  multiply := Or.inl ⟨⟨544734, by omega⟩, f.node_544734, rfl⟩
  zero := f.eq_96
}

def certificate_559 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 7196) (.wire 560062) (.wire 557654) (.wire 560099) := {
  difference := (.wire 560097)
  product := (.wire 560098)
  subtract := Or.inl ⟨⟨560097, by omega⟩, f.node_560097, rfl⟩
  multiply := Or.inl ⟨⟨560098, by omega⟩, f.node_560098, rfl⟩
  add := Or.inl ⟨⟨560099, by omega⟩, f.node_560099, rfl⟩
}

def certificate_560 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 7196) (.wire 560073) (.wire 557665) (.wire 560102) := {
  difference := (.wire 560100)
  product := (.wire 560101)
  subtract := Or.inl ⟨⟨560100, by omega⟩, f.node_560100, rfl⟩
  multiply := Or.inl ⟨⟨560101, by omega⟩, f.node_560101, rfl⟩
  add := Or.inl ⟨⟨560102, by omega⟩, f.node_560102, rfl⟩
}

def certificate_561 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 7196) (.wire 560084) (.wire 557676) (.wire 560105) := {
  difference := (.wire 560103)
  product := (.wire 560104)
  subtract := Or.inl ⟨⟨560103, by omega⟩, f.node_560103, rfl⟩
  multiply := Or.inl ⟨⟨560104, by omega⟩, f.node_560104, rfl⟩
  add := Or.inl ⟨⟨560105, by omega⟩, f.node_560105, rfl⟩
}

def certificate_562 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 7196) (.wire 560095) (.wire 557687) (.wire 560108) := {
  difference := (.wire 560106)
  product := (.wire 560107)
  subtract := Or.inl ⟨⟨560106, by omega⟩, f.node_560106, rfl⟩
  multiply := Or.inl ⟨⟨560107, by omega⟩, f.node_560107, rfl⟩
  add := Or.inl ⟨⟨560108, by omega⟩, f.node_560108, rfl⟩
}

def certificate_563 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 7196) (.wire 560061) (.wire 557653) (.wire 560111) := {
  difference := (.wire 560109)
  product := (.wire 560110)
  subtract := Or.inl ⟨⟨560109, by omega⟩, f.node_560109, rfl⟩
  multiply := Or.inl ⟨⟨560110, by omega⟩, f.node_560110, rfl⟩
  add := Or.inl ⟨⟨560111, by omega⟩, f.node_560111, rfl⟩
}

def certificate_564 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 7196) (.wire 560072) (.wire 557664) (.wire 560114) := {
  difference := (.wire 560112)
  product := (.wire 560113)
  subtract := Or.inl ⟨⟨560112, by omega⟩, f.node_560112, rfl⟩
  multiply := Or.inl ⟨⟨560113, by omega⟩, f.node_560113, rfl⟩
  add := Or.inl ⟨⟨560114, by omega⟩, f.node_560114, rfl⟩
}

def certificate_565 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 7196) (.wire 560083) (.wire 557675) (.wire 560117) := {
  difference := (.wire 560115)
  product := (.wire 560116)
  subtract := Or.inl ⟨⟨560115, by omega⟩, f.node_560115, rfl⟩
  multiply := Or.inl ⟨⟨560116, by omega⟩, f.node_560116, rfl⟩
  add := Or.inl ⟨⟨560117, by omega⟩, f.node_560117, rfl⟩
}

def certificate_566 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 555267) (.wire 7211) (.wire 560099) := {
  difference := (.wire 560118)
  product := (.wire 560119)
  subtract := Or.inl ⟨⟨560118, by omega⟩, f.node_560118, rfl⟩
  multiply := Or.inl ⟨⟨560119, by omega⟩, f.node_560119, rfl⟩
  zero := f.eq_97
}

def certificate_567 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 555267) (.wire 7212) (.wire 560102) := {
  difference := (.wire 560120)
  product := (.wire 560121)
  subtract := Or.inl ⟨⟨560120, by omega⟩, f.node_560120, rfl⟩
  multiply := Or.inl ⟨⟨560121, by omega⟩, f.node_560121, rfl⟩
  zero := f.eq_98
}

def certificate_568 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 555267) (.wire 7213) (.wire 560105) := {
  difference := (.wire 560122)
  product := (.wire 560123)
  subtract := Or.inl ⟨⟨560122, by omega⟩, f.node_560122, rfl⟩
  multiply := Or.inl ⟨⟨560123, by omega⟩, f.node_560123, rfl⟩
  zero := f.eq_99
}

def certificate_569 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 555267) (.wire 7214) (.wire 560108) := {
  difference := (.wire 560124)
  product := (.wire 560125)
  subtract := Or.inl ⟨⟨560124, by omega⟩, f.node_560124, rfl⟩
  multiply := Or.inl ⟨⟨560125, by omega⟩, f.node_560125, rfl⟩
  zero := f.eq_100
}

def certificate_570 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 555267) (.wire 7207) (.wire 560111) := {
  difference := (.wire 560126)
  product := (.wire 560127)
  subtract := Or.inl ⟨⟨560126, by omega⟩, f.node_560126, rfl⟩
  multiply := Or.inl ⟨⟨560127, by omega⟩, f.node_560127, rfl⟩
  zero := f.eq_101
}

def certificate_571 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 555267) (.wire 7208) (.wire 560114) := {
  difference := (.wire 560128)
  product := (.wire 560129)
  subtract := Or.inl ⟨⟨560128, by omega⟩, f.node_560128, rfl⟩
  multiply := Or.inl ⟨⟨560129, by omega⟩, f.node_560129, rfl⟩
  zero := f.eq_102
}

def certificate_572 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 555267) (.wire 7209) (.wire 560117) := {
  difference := (.wire 560130)
  product := (.wire 560131)
  subtract := Or.inl ⟨⟨560130, by omega⟩, f.node_560130, rfl⟩
  multiply := Or.inl ⟨⟨560131, by omega⟩, f.node_560131, rfl⟩
  zero := f.eq_103
}

def certificate_573 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 7195) (.wire 656488) (.wire 651640) (.wire 656525) := {
  difference := (.wire 656523)
  product := (.wire 656524)
  subtract := Or.inl ⟨⟨656523, by omega⟩, f.node_656523, rfl⟩
  multiply := Or.inl ⟨⟨656524, by omega⟩, f.node_656524, rfl⟩
  add := Or.inl ⟨⟨656525, by omega⟩, f.node_656525, rfl⟩
}

def certificate_574 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 7195) (.wire 656499) (.wire 651651) (.wire 656528) := {
  difference := (.wire 656526)
  product := (.wire 656527)
  subtract := Or.inl ⟨⟨656526, by omega⟩, f.node_656526, rfl⟩
  multiply := Or.inl ⟨⟨656527, by omega⟩, f.node_656527, rfl⟩
  add := Or.inl ⟨⟨656528, by omega⟩, f.node_656528, rfl⟩
}

def certificate_575 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 7195) (.wire 656510) (.wire 651662) (.wire 656531) := {
  difference := (.wire 656529)
  product := (.wire 656530)
  subtract := Or.inl ⟨⟨656529, by omega⟩, f.node_656529, rfl⟩
  multiply := Or.inl ⟨⟨656530, by omega⟩, f.node_656530, rfl⟩
  add := Or.inl ⟨⟨656531, by omega⟩, f.node_656531, rfl⟩
}

def certificate_576 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 7195) (.wire 656521) (.wire 651673) (.wire 656534) := {
  difference := (.wire 656532)
  product := (.wire 656533)
  subtract := Or.inl ⟨⟨656532, by omega⟩, f.node_656532, rfl⟩
  multiply := Or.inl ⟨⟨656533, by omega⟩, f.node_656533, rfl⟩
  add := Or.inl ⟨⟨656534, by omega⟩, f.node_656534, rfl⟩
}

def certificate_577 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 7195) (.wire 656487) (.wire 651639) (.wire 656537) := {
  difference := (.wire 656535)
  product := (.wire 656536)
  subtract := Or.inl ⟨⟨656535, by omega⟩, f.node_656535, rfl⟩
  multiply := Or.inl ⟨⟨656536, by omega⟩, f.node_656536, rfl⟩
  add := Or.inl ⟨⟨656537, by omega⟩, f.node_656537, rfl⟩
}

def certificate_578 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 7195) (.wire 656498) (.wire 651650) (.wire 656540) := {
  difference := (.wire 656538)
  product := (.wire 656539)
  subtract := Or.inl ⟨⟨656538, by omega⟩, f.node_656538, rfl⟩
  multiply := Or.inl ⟨⟨656539, by omega⟩, f.node_656539, rfl⟩
  add := Or.inl ⟨⟨656540, by omega⟩, f.node_656540, rfl⟩
}

def certificate_579 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 7195) (.wire 656509) (.wire 651661) (.wire 656543) := {
  difference := (.wire 656541)
  product := (.wire 656542)
  subtract := Or.inl ⟨⟨656541, by omega⟩, f.node_656541, rfl⟩
  multiply := Or.inl ⟨⟨656542, by omega⟩, f.node_656542, rfl⟩
  add := Or.inl ⟨⟨656543, by omega⟩, f.node_656543, rfl⟩
}

def certificate_580 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 656525) (.wire 32) := {
  difference := (.wire 656544)
  product := (.wire 656544)
  subtract := Or.inl ⟨⟨656544, by omega⟩, f.node_656544, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_104
}

def certificate_581 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 656528) (.wire 33) := {
  difference := (.wire 656545)
  product := (.wire 656545)
  subtract := Or.inl ⟨⟨656545, by omega⟩, f.node_656545, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_105
}

def certificate_582 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 656531) (.wire 34) := {
  difference := (.wire 656546)
  product := (.wire 656546)
  subtract := Or.inl ⟨⟨656546, by omega⟩, f.node_656546, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_106
}

def certificate_583 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 656534) (.wire 35) := {
  difference := (.wire 656547)
  product := (.wire 656547)
  subtract := Or.inl ⟨⟨656547, by omega⟩, f.node_656547, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_107
}

def certificate_584 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 656537) (.wire 36) := {
  difference := (.wire 656548)
  product := (.wire 656548)
  subtract := Or.inl ⟨⟨656548, by omega⟩, f.node_656548, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_108
}

def certificate_585 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 656540) (.wire 37) := {
  difference := (.wire 656549)
  product := (.wire 656549)
  subtract := Or.inl ⟨⟨656549, by omega⟩, f.node_656549, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_109
}

def certificate_586 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.constant (1 : K)) (.wire 656543) (.wire 38) := {
  difference := (.wire 656550)
  product := (.wire 656550)
  subtract := Or.inl ⟨⟨656550, by omega⟩, f.node_656550, rfl⟩
  multiply := by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus]
  zero := f.eq_110
}

def certificate_587 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560192) (.wire 567600) (.wire 7216) (.wire 567637) := {
  difference := (.wire 567635)
  product := (.wire 567636)
  subtract := Or.inl ⟨⟨567635, by omega⟩, f.node_567635, rfl⟩
  multiply := Or.inl ⟨⟨567636, by omega⟩, f.node_567636, rfl⟩
  add := Or.inl ⟨⟨567637, by omega⟩, f.node_567637, rfl⟩
}

def certificate_588 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560192) (.wire 567611) (.wire 7217) (.wire 567640) := {
  difference := (.wire 567638)
  product := (.wire 567639)
  subtract := Or.inl ⟨⟨567638, by omega⟩, f.node_567638, rfl⟩
  multiply := Or.inl ⟨⟨567639, by omega⟩, f.node_567639, rfl⟩
  add := Or.inl ⟨⟨567640, by omega⟩, f.node_567640, rfl⟩
}

def certificate_589 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560192) (.wire 567622) (.wire 7218) (.wire 567643) := {
  difference := (.wire 567641)
  product := (.wire 567642)
  subtract := Or.inl ⟨⟨567641, by omega⟩, f.node_567641, rfl⟩
  multiply := Or.inl ⟨⟨567642, by omega⟩, f.node_567642, rfl⟩
  add := Or.inl ⟨⟨567643, by omega⟩, f.node_567643, rfl⟩
}

def certificate_590 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560192) (.wire 567633) (.wire 7219) (.wire 567646) := {
  difference := (.wire 567644)
  product := (.wire 567645)
  subtract := Or.inl ⟨⟨567644, by omega⟩, f.node_567644, rfl⟩
  multiply := Or.inl ⟨⟨567645, by omega⟩, f.node_567645, rfl⟩
  add := Or.inl ⟨⟨567646, by omega⟩, f.node_567646, rfl⟩
}

def certificate_591 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560192) (.wire 567599) (.wire 7220) (.wire 567649) := {
  difference := (.wire 567647)
  product := (.wire 567648)
  subtract := Or.inl ⟨⟨567647, by omega⟩, f.node_567647, rfl⟩
  multiply := Or.inl ⟨⟨567648, by omega⟩, f.node_567648, rfl⟩
  add := Or.inl ⟨⟨567649, by omega⟩, f.node_567649, rfl⟩
}

def certificate_592 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560192) (.wire 567610) (.wire 7221) (.wire 567652) := {
  difference := (.wire 567650)
  product := (.wire 567651)
  subtract := Or.inl ⟨⟨567650, by omega⟩, f.node_567650, rfl⟩
  multiply := Or.inl ⟨⟨567651, by omega⟩, f.node_567651, rfl⟩
  add := Or.inl ⟨⟨567652, by omega⟩, f.node_567652, rfl⟩
}

def certificate_593 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560192) (.wire 567621) (.wire 7222) (.wire 567655) := {
  difference := (.wire 567653)
  product := (.wire 567654)
  subtract := Or.inl ⟨⟨567653, by omega⟩, f.node_567653, rfl⟩
  multiply := Or.inl ⟨⟨567654, by omega⟩, f.node_567654, rfl⟩
  add := Or.inl ⟨⟨567655, by omega⟩, f.node_567655, rfl⟩
}

def certificate_594 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560192) (.wire 7216) (.wire 567600) (.wire 567658) := {
  difference := (.wire 567656)
  product := (.wire 567657)
  subtract := Or.inl ⟨⟨567656, by omega⟩, f.node_567656, rfl⟩
  multiply := Or.inl ⟨⟨567657, by omega⟩, f.node_567657, rfl⟩
  add := Or.inl ⟨⟨567658, by omega⟩, f.node_567658, rfl⟩
}

def certificate_595 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560192) (.wire 7217) (.wire 567611) (.wire 567661) := {
  difference := (.wire 567659)
  product := (.wire 567660)
  subtract := Or.inl ⟨⟨567659, by omega⟩, f.node_567659, rfl⟩
  multiply := Or.inl ⟨⟨567660, by omega⟩, f.node_567660, rfl⟩
  add := Or.inl ⟨⟨567661, by omega⟩, f.node_567661, rfl⟩
}

def certificate_596 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560192) (.wire 7218) (.wire 567622) (.wire 567664) := {
  difference := (.wire 567662)
  product := (.wire 567663)
  subtract := Or.inl ⟨⟨567662, by omega⟩, f.node_567662, rfl⟩
  multiply := Or.inl ⟨⟨567663, by omega⟩, f.node_567663, rfl⟩
  add := Or.inl ⟨⟨567664, by omega⟩, f.node_567664, rfl⟩
}

def certificate_597 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560192) (.wire 7219) (.wire 567633) (.wire 567667) := {
  difference := (.wire 567665)
  product := (.wire 567666)
  subtract := Or.inl ⟨⟨567665, by omega⟩, f.node_567665, rfl⟩
  multiply := Or.inl ⟨⟨567666, by omega⟩, f.node_567666, rfl⟩
  add := Or.inl ⟨⟨567667, by omega⟩, f.node_567667, rfl⟩
}

def certificate_598 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560192) (.wire 7220) (.wire 567599) (.wire 567670) := {
  difference := (.wire 567668)
  product := (.wire 567669)
  subtract := Or.inl ⟨⟨567668, by omega⟩, f.node_567668, rfl⟩
  multiply := Or.inl ⟨⟨567669, by omega⟩, f.node_567669, rfl⟩
  add := Or.inl ⟨⟨567670, by omega⟩, f.node_567670, rfl⟩
}

def certificate_599 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560192) (.wire 7221) (.wire 567610) (.wire 567673) := {
  difference := (.wire 567671)
  product := (.wire 567672)
  subtract := Or.inl ⟨⟨567671, by omega⟩, f.node_567671, rfl⟩
  multiply := Or.inl ⟨⟨567672, by omega⟩, f.node_567672, rfl⟩
  add := Or.inl ⟨⟨567673, by omega⟩, f.node_567673, rfl⟩
}

def certificate_600 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560192) (.wire 7222) (.wire 567621) (.wire 567676) := {
  difference := (.wire 567674)
  product := (.wire 567675)
  subtract := Or.inl ⟨⟨567674, by omega⟩, f.node_567674, rfl⟩
  multiply := Or.inl ⟨⟨567675, by omega⟩, f.node_567675, rfl⟩
  add := Or.inl ⟨⟨567676, by omega⟩, f.node_567676, rfl⟩
}

def certificate_601 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560195) (.wire 570074) (.wire 7223) (.wire 570111) := {
  difference := (.wire 570109)
  product := (.wire 570110)
  subtract := Or.inl ⟨⟨570109, by omega⟩, f.node_570109, rfl⟩
  multiply := Or.inl ⟨⟨570110, by omega⟩, f.node_570110, rfl⟩
  add := Or.inl ⟨⟨570111, by omega⟩, f.node_570111, rfl⟩
}

def certificate_602 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560195) (.wire 570085) (.wire 7224) (.wire 570114) := {
  difference := (.wire 570112)
  product := (.wire 570113)
  subtract := Or.inl ⟨⟨570112, by omega⟩, f.node_570112, rfl⟩
  multiply := Or.inl ⟨⟨570113, by omega⟩, f.node_570113, rfl⟩
  add := Or.inl ⟨⟨570114, by omega⟩, f.node_570114, rfl⟩
}

def certificate_603 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560195) (.wire 570096) (.wire 7225) (.wire 570117) := {
  difference := (.wire 570115)
  product := (.wire 570116)
  subtract := Or.inl ⟨⟨570115, by omega⟩, f.node_570115, rfl⟩
  multiply := Or.inl ⟨⟨570116, by omega⟩, f.node_570116, rfl⟩
  add := Or.inl ⟨⟨570117, by omega⟩, f.node_570117, rfl⟩
}

def certificate_604 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560195) (.wire 570107) (.wire 7226) (.wire 570120) := {
  difference := (.wire 570118)
  product := (.wire 570119)
  subtract := Or.inl ⟨⟨570118, by omega⟩, f.node_570118, rfl⟩
  multiply := Or.inl ⟨⟨570119, by omega⟩, f.node_570119, rfl⟩
  add := Or.inl ⟨⟨570120, by omega⟩, f.node_570120, rfl⟩
}

def certificate_605 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560195) (.wire 570073) (.wire 7227) (.wire 570123) := {
  difference := (.wire 570121)
  product := (.wire 570122)
  subtract := Or.inl ⟨⟨570121, by omega⟩, f.node_570121, rfl⟩
  multiply := Or.inl ⟨⟨570122, by omega⟩, f.node_570122, rfl⟩
  add := Or.inl ⟨⟨570123, by omega⟩, f.node_570123, rfl⟩
}

def certificate_606 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560195) (.wire 570084) (.wire 7228) (.wire 570126) := {
  difference := (.wire 570124)
  product := (.wire 570125)
  subtract := Or.inl ⟨⟨570124, by omega⟩, f.node_570124, rfl⟩
  multiply := Or.inl ⟨⟨570125, by omega⟩, f.node_570125, rfl⟩
  add := Or.inl ⟨⟨570126, by omega⟩, f.node_570126, rfl⟩
}

def certificate_607 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560195) (.wire 570095) (.wire 7229) (.wire 570129) := {
  difference := (.wire 570127)
  product := (.wire 570128)
  subtract := Or.inl ⟨⟨570127, by omega⟩, f.node_570127, rfl⟩
  multiply := Or.inl ⟨⟨570128, by omega⟩, f.node_570128, rfl⟩
  add := Or.inl ⟨⟨570129, by omega⟩, f.node_570129, rfl⟩
}

def certificate_608 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560195) (.wire 7223) (.wire 570074) (.wire 570132) := {
  difference := (.wire 570130)
  product := (.wire 570131)
  subtract := Or.inl ⟨⟨570130, by omega⟩, f.node_570130, rfl⟩
  multiply := Or.inl ⟨⟨570131, by omega⟩, f.node_570131, rfl⟩
  add := Or.inl ⟨⟨570132, by omega⟩, f.node_570132, rfl⟩
}

def certificate_609 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560195) (.wire 7224) (.wire 570085) (.wire 570135) := {
  difference := (.wire 570133)
  product := (.wire 570134)
  subtract := Or.inl ⟨⟨570133, by omega⟩, f.node_570133, rfl⟩
  multiply := Or.inl ⟨⟨570134, by omega⟩, f.node_570134, rfl⟩
  add := Or.inl ⟨⟨570135, by omega⟩, f.node_570135, rfl⟩
}

def certificate_610 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560195) (.wire 7225) (.wire 570096) (.wire 570138) := {
  difference := (.wire 570136)
  product := (.wire 570137)
  subtract := Or.inl ⟨⟨570136, by omega⟩, f.node_570136, rfl⟩
  multiply := Or.inl ⟨⟨570137, by omega⟩, f.node_570137, rfl⟩
  add := Or.inl ⟨⟨570138, by omega⟩, f.node_570138, rfl⟩
}

def certificate_611 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560195) (.wire 7226) (.wire 570107) (.wire 570141) := {
  difference := (.wire 570139)
  product := (.wire 570140)
  subtract := Or.inl ⟨⟨570139, by omega⟩, f.node_570139, rfl⟩
  multiply := Or.inl ⟨⟨570140, by omega⟩, f.node_570140, rfl⟩
  add := Or.inl ⟨⟨570141, by omega⟩, f.node_570141, rfl⟩
}

def certificate_612 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560195) (.wire 7227) (.wire 570073) (.wire 570144) := {
  difference := (.wire 570142)
  product := (.wire 570143)
  subtract := Or.inl ⟨⟨570142, by omega⟩, f.node_570142, rfl⟩
  multiply := Or.inl ⟨⟨570143, by omega⟩, f.node_570143, rfl⟩
  add := Or.inl ⟨⟨570144, by omega⟩, f.node_570144, rfl⟩
}

def certificate_613 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560195) (.wire 7228) (.wire 570084) (.wire 570147) := {
  difference := (.wire 570145)
  product := (.wire 570146)
  subtract := Or.inl ⟨⟨570145, by omega⟩, f.node_570145, rfl⟩
  multiply := Or.inl ⟨⟨570146, by omega⟩, f.node_570146, rfl⟩
  add := Or.inl ⟨⟨570147, by omega⟩, f.node_570147, rfl⟩
}

def certificate_614 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560195) (.wire 7229) (.wire 570095) (.wire 570150) := {
  difference := (.wire 570148)
  product := (.wire 570149)
  subtract := Or.inl ⟨⟨570148, by omega⟩, f.node_570148, rfl⟩
  multiply := Or.inl ⟨⟨570149, by omega⟩, f.node_570149, rfl⟩
  add := Or.inl ⟨⟨570150, by omega⟩, f.node_570150, rfl⟩
}

def certificate_615 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560200) (.wire 572548) (.wire 7230) (.wire 572585) := {
  difference := (.wire 572583)
  product := (.wire 572584)
  subtract := Or.inl ⟨⟨572583, by omega⟩, f.node_572583, rfl⟩
  multiply := Or.inl ⟨⟨572584, by omega⟩, f.node_572584, rfl⟩
  add := Or.inl ⟨⟨572585, by omega⟩, f.node_572585, rfl⟩
}

def certificate_616 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560200) (.wire 572559) (.wire 7231) (.wire 572588) := {
  difference := (.wire 572586)
  product := (.wire 572587)
  subtract := Or.inl ⟨⟨572586, by omega⟩, f.node_572586, rfl⟩
  multiply := Or.inl ⟨⟨572587, by omega⟩, f.node_572587, rfl⟩
  add := Or.inl ⟨⟨572588, by omega⟩, f.node_572588, rfl⟩
}

def certificate_617 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560200) (.wire 572570) (.wire 7232) (.wire 572591) := {
  difference := (.wire 572589)
  product := (.wire 572590)
  subtract := Or.inl ⟨⟨572589, by omega⟩, f.node_572589, rfl⟩
  multiply := Or.inl ⟨⟨572590, by omega⟩, f.node_572590, rfl⟩
  add := Or.inl ⟨⟨572591, by omega⟩, f.node_572591, rfl⟩
}

def certificate_618 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560200) (.wire 572581) (.wire 7233) (.wire 572594) := {
  difference := (.wire 572592)
  product := (.wire 572593)
  subtract := Or.inl ⟨⟨572592, by omega⟩, f.node_572592, rfl⟩
  multiply := Or.inl ⟨⟨572593, by omega⟩, f.node_572593, rfl⟩
  add := Or.inl ⟨⟨572594, by omega⟩, f.node_572594, rfl⟩
}

def certificate_619 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560200) (.wire 572547) (.wire 7234) (.wire 572597) := {
  difference := (.wire 572595)
  product := (.wire 572596)
  subtract := Or.inl ⟨⟨572595, by omega⟩, f.node_572595, rfl⟩
  multiply := Or.inl ⟨⟨572596, by omega⟩, f.node_572596, rfl⟩
  add := Or.inl ⟨⟨572597, by omega⟩, f.node_572597, rfl⟩
}

def certificate_620 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560200) (.wire 572558) (.wire 7235) (.wire 572600) := {
  difference := (.wire 572598)
  product := (.wire 572599)
  subtract := Or.inl ⟨⟨572598, by omega⟩, f.node_572598, rfl⟩
  multiply := Or.inl ⟨⟨572599, by omega⟩, f.node_572599, rfl⟩
  add := Or.inl ⟨⟨572600, by omega⟩, f.node_572600, rfl⟩
}

def certificate_621 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560200) (.wire 572569) (.wire 7236) (.wire 572603) := {
  difference := (.wire 572601)
  product := (.wire 572602)
  subtract := Or.inl ⟨⟨572601, by omega⟩, f.node_572601, rfl⟩
  multiply := Or.inl ⟨⟨572602, by omega⟩, f.node_572602, rfl⟩
  add := Or.inl ⟨⟨572603, by omega⟩, f.node_572603, rfl⟩
}

def certificate_622 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560200) (.wire 7230) (.wire 572548) (.wire 572606) := {
  difference := (.wire 572604)
  product := (.wire 572605)
  subtract := Or.inl ⟨⟨572604, by omega⟩, f.node_572604, rfl⟩
  multiply := Or.inl ⟨⟨572605, by omega⟩, f.node_572605, rfl⟩
  add := Or.inl ⟨⟨572606, by omega⟩, f.node_572606, rfl⟩
}

def certificate_623 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560200) (.wire 7231) (.wire 572559) (.wire 572609) := {
  difference := (.wire 572607)
  product := (.wire 572608)
  subtract := Or.inl ⟨⟨572607, by omega⟩, f.node_572607, rfl⟩
  multiply := Or.inl ⟨⟨572608, by omega⟩, f.node_572608, rfl⟩
  add := Or.inl ⟨⟨572609, by omega⟩, f.node_572609, rfl⟩
}

def certificate_624 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560200) (.wire 7232) (.wire 572570) (.wire 572612) := {
  difference := (.wire 572610)
  product := (.wire 572611)
  subtract := Or.inl ⟨⟨572610, by omega⟩, f.node_572610, rfl⟩
  multiply := Or.inl ⟨⟨572611, by omega⟩, f.node_572611, rfl⟩
  add := Or.inl ⟨⟨572612, by omega⟩, f.node_572612, rfl⟩
}

def certificate_625 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560200) (.wire 7233) (.wire 572581) (.wire 572615) := {
  difference := (.wire 572613)
  product := (.wire 572614)
  subtract := Or.inl ⟨⟨572613, by omega⟩, f.node_572613, rfl⟩
  multiply := Or.inl ⟨⟨572614, by omega⟩, f.node_572614, rfl⟩
  add := Or.inl ⟨⟨572615, by omega⟩, f.node_572615, rfl⟩
}

def certificate_626 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560200) (.wire 7234) (.wire 572547) (.wire 572618) := {
  difference := (.wire 572616)
  product := (.wire 572617)
  subtract := Or.inl ⟨⟨572616, by omega⟩, f.node_572616, rfl⟩
  multiply := Or.inl ⟨⟨572617, by omega⟩, f.node_572617, rfl⟩
  add := Or.inl ⟨⟨572618, by omega⟩, f.node_572618, rfl⟩
}

def certificate_627 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560200) (.wire 7235) (.wire 572558) (.wire 572621) := {
  difference := (.wire 572619)
  product := (.wire 572620)
  subtract := Or.inl ⟨⟨572619, by omega⟩, f.node_572619, rfl⟩
  multiply := Or.inl ⟨⟨572620, by omega⟩, f.node_572620, rfl⟩
  add := Or.inl ⟨⟨572621, by omega⟩, f.node_572621, rfl⟩
}

def certificate_628 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560200) (.wire 7236) (.wire 572569) (.wire 572624) := {
  difference := (.wire 572622)
  product := (.wire 572623)
  subtract := Or.inl ⟨⟨572622, by omega⟩, f.node_572622, rfl⟩
  multiply := Or.inl ⟨⟨572623, by omega⟩, f.node_572623, rfl⟩
  add := Or.inl ⟨⟨572624, by omega⟩, f.node_572624, rfl⟩
}

def certificate_629 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560205) (.wire 575022) (.wire 7237) (.wire 575059) := {
  difference := (.wire 575057)
  product := (.wire 575058)
  subtract := Or.inl ⟨⟨575057, by omega⟩, f.node_575057, rfl⟩
  multiply := Or.inl ⟨⟨575058, by omega⟩, f.node_575058, rfl⟩
  add := Or.inl ⟨⟨575059, by omega⟩, f.node_575059, rfl⟩
}

def certificate_630 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560205) (.wire 575033) (.wire 7238) (.wire 575062) := {
  difference := (.wire 575060)
  product := (.wire 575061)
  subtract := Or.inl ⟨⟨575060, by omega⟩, f.node_575060, rfl⟩
  multiply := Or.inl ⟨⟨575061, by omega⟩, f.node_575061, rfl⟩
  add := Or.inl ⟨⟨575062, by omega⟩, f.node_575062, rfl⟩
}

def certificate_631 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560205) (.wire 575044) (.wire 7239) (.wire 575065) := {
  difference := (.wire 575063)
  product := (.wire 575064)
  subtract := Or.inl ⟨⟨575063, by omega⟩, f.node_575063, rfl⟩
  multiply := Or.inl ⟨⟨575064, by omega⟩, f.node_575064, rfl⟩
  add := Or.inl ⟨⟨575065, by omega⟩, f.node_575065, rfl⟩
}

def certificate_632 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560205) (.wire 575055) (.wire 7240) (.wire 575068) := {
  difference := (.wire 575066)
  product := (.wire 575067)
  subtract := Or.inl ⟨⟨575066, by omega⟩, f.node_575066, rfl⟩
  multiply := Or.inl ⟨⟨575067, by omega⟩, f.node_575067, rfl⟩
  add := Or.inl ⟨⟨575068, by omega⟩, f.node_575068, rfl⟩
}

def certificate_633 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560205) (.wire 575021) (.wire 7241) (.wire 575071) := {
  difference := (.wire 575069)
  product := (.wire 575070)
  subtract := Or.inl ⟨⟨575069, by omega⟩, f.node_575069, rfl⟩
  multiply := Or.inl ⟨⟨575070, by omega⟩, f.node_575070, rfl⟩
  add := Or.inl ⟨⟨575071, by omega⟩, f.node_575071, rfl⟩
}

def certificate_634 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560205) (.wire 575032) (.wire 7242) (.wire 575074) := {
  difference := (.wire 575072)
  product := (.wire 575073)
  subtract := Or.inl ⟨⟨575072, by omega⟩, f.node_575072, rfl⟩
  multiply := Or.inl ⟨⟨575073, by omega⟩, f.node_575073, rfl⟩
  add := Or.inl ⟨⟨575074, by omega⟩, f.node_575074, rfl⟩
}

def certificate_635 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560205) (.wire 575043) (.wire 7243) (.wire 575077) := {
  difference := (.wire 575075)
  product := (.wire 575076)
  subtract := Or.inl ⟨⟨575075, by omega⟩, f.node_575075, rfl⟩
  multiply := Or.inl ⟨⟨575076, by omega⟩, f.node_575076, rfl⟩
  add := Or.inl ⟨⟨575077, by omega⟩, f.node_575077, rfl⟩
}

def certificate_636 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560205) (.wire 7237) (.wire 575022) (.wire 575080) := {
  difference := (.wire 575078)
  product := (.wire 575079)
  subtract := Or.inl ⟨⟨575078, by omega⟩, f.node_575078, rfl⟩
  multiply := Or.inl ⟨⟨575079, by omega⟩, f.node_575079, rfl⟩
  add := Or.inl ⟨⟨575080, by omega⟩, f.node_575080, rfl⟩
}

def certificate_637 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560205) (.wire 7238) (.wire 575033) (.wire 575083) := {
  difference := (.wire 575081)
  product := (.wire 575082)
  subtract := Or.inl ⟨⟨575081, by omega⟩, f.node_575081, rfl⟩
  multiply := Or.inl ⟨⟨575082, by omega⟩, f.node_575082, rfl⟩
  add := Or.inl ⟨⟨575083, by omega⟩, f.node_575083, rfl⟩
}

def certificate_638 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560205) (.wire 7239) (.wire 575044) (.wire 575086) := {
  difference := (.wire 575084)
  product := (.wire 575085)
  subtract := Or.inl ⟨⟨575084, by omega⟩, f.node_575084, rfl⟩
  multiply := Or.inl ⟨⟨575085, by omega⟩, f.node_575085, rfl⟩
  add := Or.inl ⟨⟨575086, by omega⟩, f.node_575086, rfl⟩
}

def certificate_639 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560205) (.wire 7240) (.wire 575055) (.wire 575089) := {
  difference := (.wire 575087)
  product := (.wire 575088)
  subtract := Or.inl ⟨⟨575087, by omega⟩, f.node_575087, rfl⟩
  multiply := Or.inl ⟨⟨575088, by omega⟩, f.node_575088, rfl⟩
  add := Or.inl ⟨⟨575089, by omega⟩, f.node_575089, rfl⟩
}

def certificate_640 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560205) (.wire 7241) (.wire 575021) (.wire 575092) := {
  difference := (.wire 575090)
  product := (.wire 575091)
  subtract := Or.inl ⟨⟨575090, by omega⟩, f.node_575090, rfl⟩
  multiply := Or.inl ⟨⟨575091, by omega⟩, f.node_575091, rfl⟩
  add := Or.inl ⟨⟨575092, by omega⟩, f.node_575092, rfl⟩
}

def certificate_641 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560205) (.wire 7242) (.wire 575032) (.wire 575095) := {
  difference := (.wire 575093)
  product := (.wire 575094)
  subtract := Or.inl ⟨⟨575093, by omega⟩, f.node_575093, rfl⟩
  multiply := Or.inl ⟨⟨575094, by omega⟩, f.node_575094, rfl⟩
  add := Or.inl ⟨⟨575095, by omega⟩, f.node_575095, rfl⟩
}

def certificate_642 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560205) (.wire 7243) (.wire 575043) (.wire 575098) := {
  difference := (.wire 575096)
  product := (.wire 575097)
  subtract := Or.inl ⟨⟨575096, by omega⟩, f.node_575096, rfl⟩
  multiply := Or.inl ⟨⟨575097, by omega⟩, f.node_575097, rfl⟩
  add := Or.inl ⟨⟨575098, by omega⟩, f.node_575098, rfl⟩
}

def certificate_643 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560210) (.wire 577496) (.wire 7244) (.wire 577533) := {
  difference := (.wire 577531)
  product := (.wire 577532)
  subtract := Or.inl ⟨⟨577531, by omega⟩, f.node_577531, rfl⟩
  multiply := Or.inl ⟨⟨577532, by omega⟩, f.node_577532, rfl⟩
  add := Or.inl ⟨⟨577533, by omega⟩, f.node_577533, rfl⟩
}

def certificate_644 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560210) (.wire 577507) (.wire 7245) (.wire 577536) := {
  difference := (.wire 577534)
  product := (.wire 577535)
  subtract := Or.inl ⟨⟨577534, by omega⟩, f.node_577534, rfl⟩
  multiply := Or.inl ⟨⟨577535, by omega⟩, f.node_577535, rfl⟩
  add := Or.inl ⟨⟨577536, by omega⟩, f.node_577536, rfl⟩
}

def certificate_645 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560210) (.wire 577518) (.wire 7246) (.wire 577539) := {
  difference := (.wire 577537)
  product := (.wire 577538)
  subtract := Or.inl ⟨⟨577537, by omega⟩, f.node_577537, rfl⟩
  multiply := Or.inl ⟨⟨577538, by omega⟩, f.node_577538, rfl⟩
  add := Or.inl ⟨⟨577539, by omega⟩, f.node_577539, rfl⟩
}

def certificate_646 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560210) (.wire 577529) (.wire 7247) (.wire 577542) := {
  difference := (.wire 577540)
  product := (.wire 577541)
  subtract := Or.inl ⟨⟨577540, by omega⟩, f.node_577540, rfl⟩
  multiply := Or.inl ⟨⟨577541, by omega⟩, f.node_577541, rfl⟩
  add := Or.inl ⟨⟨577542, by omega⟩, f.node_577542, rfl⟩
}

def certificate_647 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560210) (.wire 577495) (.wire 7248) (.wire 577545) := {
  difference := (.wire 577543)
  product := (.wire 577544)
  subtract := Or.inl ⟨⟨577543, by omega⟩, f.node_577543, rfl⟩
  multiply := Or.inl ⟨⟨577544, by omega⟩, f.node_577544, rfl⟩
  add := Or.inl ⟨⟨577545, by omega⟩, f.node_577545, rfl⟩
}

def certificate_648 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560210) (.wire 577506) (.wire 7249) (.wire 577548) := {
  difference := (.wire 577546)
  product := (.wire 577547)
  subtract := Or.inl ⟨⟨577546, by omega⟩, f.node_577546, rfl⟩
  multiply := Or.inl ⟨⟨577547, by omega⟩, f.node_577547, rfl⟩
  add := Or.inl ⟨⟨577548, by omega⟩, f.node_577548, rfl⟩
}

def certificate_649 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560210) (.wire 577517) (.wire 7250) (.wire 577551) := {
  difference := (.wire 577549)
  product := (.wire 577550)
  subtract := Or.inl ⟨⟨577549, by omega⟩, f.node_577549, rfl⟩
  multiply := Or.inl ⟨⟨577550, by omega⟩, f.node_577550, rfl⟩
  add := Or.inl ⟨⟨577551, by omega⟩, f.node_577551, rfl⟩
}

def certificate_650 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560210) (.wire 7244) (.wire 577496) (.wire 577554) := {
  difference := (.wire 577552)
  product := (.wire 577553)
  subtract := Or.inl ⟨⟨577552, by omega⟩, f.node_577552, rfl⟩
  multiply := Or.inl ⟨⟨577553, by omega⟩, f.node_577553, rfl⟩
  add := Or.inl ⟨⟨577554, by omega⟩, f.node_577554, rfl⟩
}

def certificate_651 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560210) (.wire 7245) (.wire 577507) (.wire 577557) := {
  difference := (.wire 577555)
  product := (.wire 577556)
  subtract := Or.inl ⟨⟨577555, by omega⟩, f.node_577555, rfl⟩
  multiply := Or.inl ⟨⟨577556, by omega⟩, f.node_577556, rfl⟩
  add := Or.inl ⟨⟨577557, by omega⟩, f.node_577557, rfl⟩
}

def certificate_652 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560210) (.wire 7246) (.wire 577518) (.wire 577560) := {
  difference := (.wire 577558)
  product := (.wire 577559)
  subtract := Or.inl ⟨⟨577558, by omega⟩, f.node_577558, rfl⟩
  multiply := Or.inl ⟨⟨577559, by omega⟩, f.node_577559, rfl⟩
  add := Or.inl ⟨⟨577560, by omega⟩, f.node_577560, rfl⟩
}

def certificate_653 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560210) (.wire 7247) (.wire 577529) (.wire 577563) := {
  difference := (.wire 577561)
  product := (.wire 577562)
  subtract := Or.inl ⟨⟨577561, by omega⟩, f.node_577561, rfl⟩
  multiply := Or.inl ⟨⟨577562, by omega⟩, f.node_577562, rfl⟩
  add := Or.inl ⟨⟨577563, by omega⟩, f.node_577563, rfl⟩
}

def certificate_654 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560210) (.wire 7248) (.wire 577495) (.wire 577566) := {
  difference := (.wire 577564)
  product := (.wire 577565)
  subtract := Or.inl ⟨⟨577564, by omega⟩, f.node_577564, rfl⟩
  multiply := Or.inl ⟨⟨577565, by omega⟩, f.node_577565, rfl⟩
  add := Or.inl ⟨⟨577566, by omega⟩, f.node_577566, rfl⟩
}

def certificate_655 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560210) (.wire 7249) (.wire 577506) (.wire 577569) := {
  difference := (.wire 577567)
  product := (.wire 577568)
  subtract := Or.inl ⟨⟨577567, by omega⟩, f.node_577567, rfl⟩
  multiply := Or.inl ⟨⟨577568, by omega⟩, f.node_577568, rfl⟩
  add := Or.inl ⟨⟨577569, by omega⟩, f.node_577569, rfl⟩
}

def certificate_656 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560210) (.wire 7250) (.wire 577517) (.wire 577572) := {
  difference := (.wire 577570)
  product := (.wire 577571)
  subtract := Or.inl ⟨⟨577570, by omega⟩, f.node_577570, rfl⟩
  multiply := Or.inl ⟨⟨577571, by omega⟩, f.node_577571, rfl⟩
  add := Or.inl ⟨⟨577572, by omega⟩, f.node_577572, rfl⟩
}

def certificate_657 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560215) (.wire 579970) (.wire 7251) (.wire 580007) := {
  difference := (.wire 580005)
  product := (.wire 580006)
  subtract := Or.inl ⟨⟨580005, by omega⟩, f.node_580005, rfl⟩
  multiply := Or.inl ⟨⟨580006, by omega⟩, f.node_580006, rfl⟩
  add := Or.inl ⟨⟨580007, by omega⟩, f.node_580007, rfl⟩
}

def certificate_658 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560215) (.wire 579981) (.wire 7252) (.wire 580010) := {
  difference := (.wire 580008)
  product := (.wire 580009)
  subtract := Or.inl ⟨⟨580008, by omega⟩, f.node_580008, rfl⟩
  multiply := Or.inl ⟨⟨580009, by omega⟩, f.node_580009, rfl⟩
  add := Or.inl ⟨⟨580010, by omega⟩, f.node_580010, rfl⟩
}

def certificate_659 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560215) (.wire 579992) (.wire 7253) (.wire 580013) := {
  difference := (.wire 580011)
  product := (.wire 580012)
  subtract := Or.inl ⟨⟨580011, by omega⟩, f.node_580011, rfl⟩
  multiply := Or.inl ⟨⟨580012, by omega⟩, f.node_580012, rfl⟩
  add := Or.inl ⟨⟨580013, by omega⟩, f.node_580013, rfl⟩
}

def certificate_660 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560215) (.wire 580003) (.wire 7254) (.wire 580016) := {
  difference := (.wire 580014)
  product := (.wire 580015)
  subtract := Or.inl ⟨⟨580014, by omega⟩, f.node_580014, rfl⟩
  multiply := Or.inl ⟨⟨580015, by omega⟩, f.node_580015, rfl⟩
  add := Or.inl ⟨⟨580016, by omega⟩, f.node_580016, rfl⟩
}

def certificate_661 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560215) (.wire 579969) (.wire 7255) (.wire 580019) := {
  difference := (.wire 580017)
  product := (.wire 580018)
  subtract := Or.inl ⟨⟨580017, by omega⟩, f.node_580017, rfl⟩
  multiply := Or.inl ⟨⟨580018, by omega⟩, f.node_580018, rfl⟩
  add := Or.inl ⟨⟨580019, by omega⟩, f.node_580019, rfl⟩
}

def certificate_662 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560215) (.wire 579980) (.wire 7256) (.wire 580022) := {
  difference := (.wire 580020)
  product := (.wire 580021)
  subtract := Or.inl ⟨⟨580020, by omega⟩, f.node_580020, rfl⟩
  multiply := Or.inl ⟨⟨580021, by omega⟩, f.node_580021, rfl⟩
  add := Or.inl ⟨⟨580022, by omega⟩, f.node_580022, rfl⟩
}

def certificate_663 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560215) (.wire 579991) (.wire 7257) (.wire 580025) := {
  difference := (.wire 580023)
  product := (.wire 580024)
  subtract := Or.inl ⟨⟨580023, by omega⟩, f.node_580023, rfl⟩
  multiply := Or.inl ⟨⟨580024, by omega⟩, f.node_580024, rfl⟩
  add := Or.inl ⟨⟨580025, by omega⟩, f.node_580025, rfl⟩
}

def certificate_664 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560215) (.wire 7251) (.wire 579970) (.wire 580028) := {
  difference := (.wire 580026)
  product := (.wire 580027)
  subtract := Or.inl ⟨⟨580026, by omega⟩, f.node_580026, rfl⟩
  multiply := Or.inl ⟨⟨580027, by omega⟩, f.node_580027, rfl⟩
  add := Or.inl ⟨⟨580028, by omega⟩, f.node_580028, rfl⟩
}

def certificate_665 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560215) (.wire 7252) (.wire 579981) (.wire 580031) := {
  difference := (.wire 580029)
  product := (.wire 580030)
  subtract := Or.inl ⟨⟨580029, by omega⟩, f.node_580029, rfl⟩
  multiply := Or.inl ⟨⟨580030, by omega⟩, f.node_580030, rfl⟩
  add := Or.inl ⟨⟨580031, by omega⟩, f.node_580031, rfl⟩
}

def certificate_666 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560215) (.wire 7253) (.wire 579992) (.wire 580034) := {
  difference := (.wire 580032)
  product := (.wire 580033)
  subtract := Or.inl ⟨⟨580032, by omega⟩, f.node_580032, rfl⟩
  multiply := Or.inl ⟨⟨580033, by omega⟩, f.node_580033, rfl⟩
  add := Or.inl ⟨⟨580034, by omega⟩, f.node_580034, rfl⟩
}

def certificate_667 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560215) (.wire 7254) (.wire 580003) (.wire 580037) := {
  difference := (.wire 580035)
  product := (.wire 580036)
  subtract := Or.inl ⟨⟨580035, by omega⟩, f.node_580035, rfl⟩
  multiply := Or.inl ⟨⟨580036, by omega⟩, f.node_580036, rfl⟩
  add := Or.inl ⟨⟨580037, by omega⟩, f.node_580037, rfl⟩
}

def certificate_668 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560215) (.wire 7255) (.wire 579969) (.wire 580040) := {
  difference := (.wire 580038)
  product := (.wire 580039)
  subtract := Or.inl ⟨⟨580038, by omega⟩, f.node_580038, rfl⟩
  multiply := Or.inl ⟨⟨580039, by omega⟩, f.node_580039, rfl⟩
  add := Or.inl ⟨⟨580040, by omega⟩, f.node_580040, rfl⟩
}

def certificate_669 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560215) (.wire 7256) (.wire 579980) (.wire 580043) := {
  difference := (.wire 580041)
  product := (.wire 580042)
  subtract := Or.inl ⟨⟨580041, by omega⟩, f.node_580041, rfl⟩
  multiply := Or.inl ⟨⟨580042, by omega⟩, f.node_580042, rfl⟩
  add := Or.inl ⟨⟨580043, by omega⟩, f.node_580043, rfl⟩
}

def certificate_670 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560215) (.wire 7257) (.wire 579991) (.wire 580046) := {
  difference := (.wire 580044)
  product := (.wire 580045)
  subtract := Or.inl ⟨⟨580044, by omega⟩, f.node_580044, rfl⟩
  multiply := Or.inl ⟨⟨580045, by omega⟩, f.node_580045, rfl⟩
  add := Or.inl ⟨⟨580046, by omega⟩, f.node_580046, rfl⟩
}

def certificate_671 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560220) (.wire 582444) (.wire 7258) (.wire 582481) := {
  difference := (.wire 582479)
  product := (.wire 582480)
  subtract := Or.inl ⟨⟨582479, by omega⟩, f.node_582479, rfl⟩
  multiply := Or.inl ⟨⟨582480, by omega⟩, f.node_582480, rfl⟩
  add := Or.inl ⟨⟨582481, by omega⟩, f.node_582481, rfl⟩
}

def certificate_672 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560220) (.wire 582455) (.wire 7259) (.wire 582484) := {
  difference := (.wire 582482)
  product := (.wire 582483)
  subtract := Or.inl ⟨⟨582482, by omega⟩, f.node_582482, rfl⟩
  multiply := Or.inl ⟨⟨582483, by omega⟩, f.node_582483, rfl⟩
  add := Or.inl ⟨⟨582484, by omega⟩, f.node_582484, rfl⟩
}

def certificate_673 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560220) (.wire 582466) (.wire 7260) (.wire 582487) := {
  difference := (.wire 582485)
  product := (.wire 582486)
  subtract := Or.inl ⟨⟨582485, by omega⟩, f.node_582485, rfl⟩
  multiply := Or.inl ⟨⟨582486, by omega⟩, f.node_582486, rfl⟩
  add := Or.inl ⟨⟨582487, by omega⟩, f.node_582487, rfl⟩
}

def certificate_674 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560220) (.wire 582477) (.wire 7261) (.wire 582490) := {
  difference := (.wire 582488)
  product := (.wire 582489)
  subtract := Or.inl ⟨⟨582488, by omega⟩, f.node_582488, rfl⟩
  multiply := Or.inl ⟨⟨582489, by omega⟩, f.node_582489, rfl⟩
  add := Or.inl ⟨⟨582490, by omega⟩, f.node_582490, rfl⟩
}

def certificate_675 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560220) (.wire 582443) (.wire 7262) (.wire 582493) := {
  difference := (.wire 582491)
  product := (.wire 582492)
  subtract := Or.inl ⟨⟨582491, by omega⟩, f.node_582491, rfl⟩
  multiply := Or.inl ⟨⟨582492, by omega⟩, f.node_582492, rfl⟩
  add := Or.inl ⟨⟨582493, by omega⟩, f.node_582493, rfl⟩
}

def certificate_676 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560220) (.wire 582454) (.wire 7263) (.wire 582496) := {
  difference := (.wire 582494)
  product := (.wire 582495)
  subtract := Or.inl ⟨⟨582494, by omega⟩, f.node_582494, rfl⟩
  multiply := Or.inl ⟨⟨582495, by omega⟩, f.node_582495, rfl⟩
  add := Or.inl ⟨⟨582496, by omega⟩, f.node_582496, rfl⟩
}

def certificate_677 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560220) (.wire 582465) (.wire 7264) (.wire 582499) := {
  difference := (.wire 582497)
  product := (.wire 582498)
  subtract := Or.inl ⟨⟨582497, by omega⟩, f.node_582497, rfl⟩
  multiply := Or.inl ⟨⟨582498, by omega⟩, f.node_582498, rfl⟩
  add := Or.inl ⟨⟨582499, by omega⟩, f.node_582499, rfl⟩
}

def certificate_678 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560220) (.wire 7258) (.wire 582444) (.wire 582502) := {
  difference := (.wire 582500)
  product := (.wire 582501)
  subtract := Or.inl ⟨⟨582500, by omega⟩, f.node_582500, rfl⟩
  multiply := Or.inl ⟨⟨582501, by omega⟩, f.node_582501, rfl⟩
  add := Or.inl ⟨⟨582502, by omega⟩, f.node_582502, rfl⟩
}

def certificate_679 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560220) (.wire 7259) (.wire 582455) (.wire 582505) := {
  difference := (.wire 582503)
  product := (.wire 582504)
  subtract := Or.inl ⟨⟨582503, by omega⟩, f.node_582503, rfl⟩
  multiply := Or.inl ⟨⟨582504, by omega⟩, f.node_582504, rfl⟩
  add := Or.inl ⟨⟨582505, by omega⟩, f.node_582505, rfl⟩
}

def certificate_680 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560220) (.wire 7260) (.wire 582466) (.wire 582508) := {
  difference := (.wire 582506)
  product := (.wire 582507)
  subtract := Or.inl ⟨⟨582506, by omega⟩, f.node_582506, rfl⟩
  multiply := Or.inl ⟨⟨582507, by omega⟩, f.node_582507, rfl⟩
  add := Or.inl ⟨⟨582508, by omega⟩, f.node_582508, rfl⟩
}

def certificate_681 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560220) (.wire 7261) (.wire 582477) (.wire 582511) := {
  difference := (.wire 582509)
  product := (.wire 582510)
  subtract := Or.inl ⟨⟨582509, by omega⟩, f.node_582509, rfl⟩
  multiply := Or.inl ⟨⟨582510, by omega⟩, f.node_582510, rfl⟩
  add := Or.inl ⟨⟨582511, by omega⟩, f.node_582511, rfl⟩
}

def certificate_682 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560220) (.wire 7262) (.wire 582443) (.wire 582514) := {
  difference := (.wire 582512)
  product := (.wire 582513)
  subtract := Or.inl ⟨⟨582512, by omega⟩, f.node_582512, rfl⟩
  multiply := Or.inl ⟨⟨582513, by omega⟩, f.node_582513, rfl⟩
  add := Or.inl ⟨⟨582514, by omega⟩, f.node_582514, rfl⟩
}

def certificate_683 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560220) (.wire 7263) (.wire 582454) (.wire 582517) := {
  difference := (.wire 582515)
  product := (.wire 582516)
  subtract := Or.inl ⟨⟨582515, by omega⟩, f.node_582515, rfl⟩
  multiply := Or.inl ⟨⟨582516, by omega⟩, f.node_582516, rfl⟩
  add := Or.inl ⟨⟨582517, by omega⟩, f.node_582517, rfl⟩
}

def certificate_684 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560220) (.wire 7264) (.wire 582465) (.wire 582520) := {
  difference := (.wire 582518)
  product := (.wire 582519)
  subtract := Or.inl ⟨⟨582518, by omega⟩, f.node_582518, rfl⟩
  multiply := Or.inl ⟨⟨582519, by omega⟩, f.node_582519, rfl⟩
  add := Or.inl ⟨⟨582520, by omega⟩, f.node_582520, rfl⟩
}

def certificate_685 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560225) (.wire 584918) (.wire 7265) (.wire 584955) := {
  difference := (.wire 584953)
  product := (.wire 584954)
  subtract := Or.inl ⟨⟨584953, by omega⟩, f.node_584953, rfl⟩
  multiply := Or.inl ⟨⟨584954, by omega⟩, f.node_584954, rfl⟩
  add := Or.inl ⟨⟨584955, by omega⟩, f.node_584955, rfl⟩
}

def certificate_686 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560225) (.wire 584929) (.wire 7266) (.wire 584958) := {
  difference := (.wire 584956)
  product := (.wire 584957)
  subtract := Or.inl ⟨⟨584956, by omega⟩, f.node_584956, rfl⟩
  multiply := Or.inl ⟨⟨584957, by omega⟩, f.node_584957, rfl⟩
  add := Or.inl ⟨⟨584958, by omega⟩, f.node_584958, rfl⟩
}

def certificate_687 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560225) (.wire 584940) (.wire 7267) (.wire 584961) := {
  difference := (.wire 584959)
  product := (.wire 584960)
  subtract := Or.inl ⟨⟨584959, by omega⟩, f.node_584959, rfl⟩
  multiply := Or.inl ⟨⟨584960, by omega⟩, f.node_584960, rfl⟩
  add := Or.inl ⟨⟨584961, by omega⟩, f.node_584961, rfl⟩
}

def certificate_688 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560225) (.wire 584951) (.wire 7268) (.wire 584964) := {
  difference := (.wire 584962)
  product := (.wire 584963)
  subtract := Or.inl ⟨⟨584962, by omega⟩, f.node_584962, rfl⟩
  multiply := Or.inl ⟨⟨584963, by omega⟩, f.node_584963, rfl⟩
  add := Or.inl ⟨⟨584964, by omega⟩, f.node_584964, rfl⟩
}

def certificate_689 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560225) (.wire 584917) (.wire 7269) (.wire 584967) := {
  difference := (.wire 584965)
  product := (.wire 584966)
  subtract := Or.inl ⟨⟨584965, by omega⟩, f.node_584965, rfl⟩
  multiply := Or.inl ⟨⟨584966, by omega⟩, f.node_584966, rfl⟩
  add := Or.inl ⟨⟨584967, by omega⟩, f.node_584967, rfl⟩
}

def certificate_690 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560225) (.wire 584928) (.wire 7270) (.wire 584970) := {
  difference := (.wire 584968)
  product := (.wire 584969)
  subtract := Or.inl ⟨⟨584968, by omega⟩, f.node_584968, rfl⟩
  multiply := Or.inl ⟨⟨584969, by omega⟩, f.node_584969, rfl⟩
  add := Or.inl ⟨⟨584970, by omega⟩, f.node_584970, rfl⟩
}

def certificate_691 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560225) (.wire 584939) (.wire 7271) (.wire 584973) := {
  difference := (.wire 584971)
  product := (.wire 584972)
  subtract := Or.inl ⟨⟨584971, by omega⟩, f.node_584971, rfl⟩
  multiply := Or.inl ⟨⟨584972, by omega⟩, f.node_584972, rfl⟩
  add := Or.inl ⟨⟨584973, by omega⟩, f.node_584973, rfl⟩
}

def certificate_692 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560225) (.wire 7265) (.wire 584918) (.wire 584976) := {
  difference := (.wire 584974)
  product := (.wire 584975)
  subtract := Or.inl ⟨⟨584974, by omega⟩, f.node_584974, rfl⟩
  multiply := Or.inl ⟨⟨584975, by omega⟩, f.node_584975, rfl⟩
  add := Or.inl ⟨⟨584976, by omega⟩, f.node_584976, rfl⟩
}

def certificate_693 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560225) (.wire 7266) (.wire 584929) (.wire 584979) := {
  difference := (.wire 584977)
  product := (.wire 584978)
  subtract := Or.inl ⟨⟨584977, by omega⟩, f.node_584977, rfl⟩
  multiply := Or.inl ⟨⟨584978, by omega⟩, f.node_584978, rfl⟩
  add := Or.inl ⟨⟨584979, by omega⟩, f.node_584979, rfl⟩
}

def certificate_694 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560225) (.wire 7267) (.wire 584940) (.wire 584982) := {
  difference := (.wire 584980)
  product := (.wire 584981)
  subtract := Or.inl ⟨⟨584980, by omega⟩, f.node_584980, rfl⟩
  multiply := Or.inl ⟨⟨584981, by omega⟩, f.node_584981, rfl⟩
  add := Or.inl ⟨⟨584982, by omega⟩, f.node_584982, rfl⟩
}

def certificate_695 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560225) (.wire 7268) (.wire 584951) (.wire 584985) := {
  difference := (.wire 584983)
  product := (.wire 584984)
  subtract := Or.inl ⟨⟨584983, by omega⟩, f.node_584983, rfl⟩
  multiply := Or.inl ⟨⟨584984, by omega⟩, f.node_584984, rfl⟩
  add := Or.inl ⟨⟨584985, by omega⟩, f.node_584985, rfl⟩
}

def certificate_696 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560225) (.wire 7269) (.wire 584917) (.wire 584988) := {
  difference := (.wire 584986)
  product := (.wire 584987)
  subtract := Or.inl ⟨⟨584986, by omega⟩, f.node_584986, rfl⟩
  multiply := Or.inl ⟨⟨584987, by omega⟩, f.node_584987, rfl⟩
  add := Or.inl ⟨⟨584988, by omega⟩, f.node_584988, rfl⟩
}

def certificate_697 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560225) (.wire 7270) (.wire 584928) (.wire 584991) := {
  difference := (.wire 584989)
  product := (.wire 584990)
  subtract := Or.inl ⟨⟨584989, by omega⟩, f.node_584989, rfl⟩
  multiply := Or.inl ⟨⟨584990, by omega⟩, f.node_584990, rfl⟩
  add := Or.inl ⟨⟨584991, by omega⟩, f.node_584991, rfl⟩
}

def certificate_698 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560225) (.wire 7271) (.wire 584939) (.wire 584994) := {
  difference := (.wire 584992)
  product := (.wire 584993)
  subtract := Or.inl ⟨⟨584992, by omega⟩, f.node_584992, rfl⟩
  multiply := Or.inl ⟨⟨584993, by omega⟩, f.node_584993, rfl⟩
  add := Or.inl ⟨⟨584994, by omega⟩, f.node_584994, rfl⟩
}

def certificate_699 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560230) (.wire 587392) (.wire 7272) (.wire 587429) := {
  difference := (.wire 587427)
  product := (.wire 587428)
  subtract := Or.inl ⟨⟨587427, by omega⟩, f.node_587427, rfl⟩
  multiply := Or.inl ⟨⟨587428, by omega⟩, f.node_587428, rfl⟩
  add := Or.inl ⟨⟨587429, by omega⟩, f.node_587429, rfl⟩
}

def certificate_700 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560230) (.wire 587403) (.wire 7273) (.wire 587432) := {
  difference := (.wire 587430)
  product := (.wire 587431)
  subtract := Or.inl ⟨⟨587430, by omega⟩, f.node_587430, rfl⟩
  multiply := Or.inl ⟨⟨587431, by omega⟩, f.node_587431, rfl⟩
  add := Or.inl ⟨⟨587432, by omega⟩, f.node_587432, rfl⟩
}

def certificate_701 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560230) (.wire 587414) (.wire 7274) (.wire 587435) := {
  difference := (.wire 587433)
  product := (.wire 587434)
  subtract := Or.inl ⟨⟨587433, by omega⟩, f.node_587433, rfl⟩
  multiply := Or.inl ⟨⟨587434, by omega⟩, f.node_587434, rfl⟩
  add := Or.inl ⟨⟨587435, by omega⟩, f.node_587435, rfl⟩
}

def certificate_702 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560230) (.wire 587425) (.wire 7275) (.wire 587438) := {
  difference := (.wire 587436)
  product := (.wire 587437)
  subtract := Or.inl ⟨⟨587436, by omega⟩, f.node_587436, rfl⟩
  multiply := Or.inl ⟨⟨587437, by omega⟩, f.node_587437, rfl⟩
  add := Or.inl ⟨⟨587438, by omega⟩, f.node_587438, rfl⟩
}

def certificate_703 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560230) (.wire 587391) (.wire 7276) (.wire 587441) := {
  difference := (.wire 587439)
  product := (.wire 587440)
  subtract := Or.inl ⟨⟨587439, by omega⟩, f.node_587439, rfl⟩
  multiply := Or.inl ⟨⟨587440, by omega⟩, f.node_587440, rfl⟩
  add := Or.inl ⟨⟨587441, by omega⟩, f.node_587441, rfl⟩
}

def certificate_704 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560230) (.wire 587402) (.wire 7277) (.wire 587444) := {
  difference := (.wire 587442)
  product := (.wire 587443)
  subtract := Or.inl ⟨⟨587442, by omega⟩, f.node_587442, rfl⟩
  multiply := Or.inl ⟨⟨587443, by omega⟩, f.node_587443, rfl⟩
  add := Or.inl ⟨⟨587444, by omega⟩, f.node_587444, rfl⟩
}

def certificate_705 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560230) (.wire 587413) (.wire 7278) (.wire 587447) := {
  difference := (.wire 587445)
  product := (.wire 587446)
  subtract := Or.inl ⟨⟨587445, by omega⟩, f.node_587445, rfl⟩
  multiply := Or.inl ⟨⟨587446, by omega⟩, f.node_587446, rfl⟩
  add := Or.inl ⟨⟨587447, by omega⟩, f.node_587447, rfl⟩
}

def certificate_706 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560230) (.wire 7272) (.wire 587392) (.wire 587450) := {
  difference := (.wire 587448)
  product := (.wire 587449)
  subtract := Or.inl ⟨⟨587448, by omega⟩, f.node_587448, rfl⟩
  multiply := Or.inl ⟨⟨587449, by omega⟩, f.node_587449, rfl⟩
  add := Or.inl ⟨⟨587450, by omega⟩, f.node_587450, rfl⟩
}

def certificate_707 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560230) (.wire 7273) (.wire 587403) (.wire 587453) := {
  difference := (.wire 587451)
  product := (.wire 587452)
  subtract := Or.inl ⟨⟨587451, by omega⟩, f.node_587451, rfl⟩
  multiply := Or.inl ⟨⟨587452, by omega⟩, f.node_587452, rfl⟩
  add := Or.inl ⟨⟨587453, by omega⟩, f.node_587453, rfl⟩
}

def certificate_708 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560230) (.wire 7274) (.wire 587414) (.wire 587456) := {
  difference := (.wire 587454)
  product := (.wire 587455)
  subtract := Or.inl ⟨⟨587454, by omega⟩, f.node_587454, rfl⟩
  multiply := Or.inl ⟨⟨587455, by omega⟩, f.node_587455, rfl⟩
  add := Or.inl ⟨⟨587456, by omega⟩, f.node_587456, rfl⟩
}

def certificate_709 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560230) (.wire 7275) (.wire 587425) (.wire 587459) := {
  difference := (.wire 587457)
  product := (.wire 587458)
  subtract := Or.inl ⟨⟨587457, by omega⟩, f.node_587457, rfl⟩
  multiply := Or.inl ⟨⟨587458, by omega⟩, f.node_587458, rfl⟩
  add := Or.inl ⟨⟨587459, by omega⟩, f.node_587459, rfl⟩
}

def certificate_710 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560230) (.wire 7276) (.wire 587391) (.wire 587462) := {
  difference := (.wire 587460)
  product := (.wire 587461)
  subtract := Or.inl ⟨⟨587460, by omega⟩, f.node_587460, rfl⟩
  multiply := Or.inl ⟨⟨587461, by omega⟩, f.node_587461, rfl⟩
  add := Or.inl ⟨⟨587462, by omega⟩, f.node_587462, rfl⟩
}

def certificate_711 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560230) (.wire 7277) (.wire 587402) (.wire 587465) := {
  difference := (.wire 587463)
  product := (.wire 587464)
  subtract := Or.inl ⟨⟨587463, by omega⟩, f.node_587463, rfl⟩
  multiply := Or.inl ⟨⟨587464, by omega⟩, f.node_587464, rfl⟩
  add := Or.inl ⟨⟨587465, by omega⟩, f.node_587465, rfl⟩
}

def certificate_712 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560230) (.wire 7278) (.wire 587413) (.wire 587468) := {
  difference := (.wire 587466)
  product := (.wire 587467)
  subtract := Or.inl ⟨⟨587466, by omega⟩, f.node_587466, rfl⟩
  multiply := Or.inl ⟨⟨587467, by omega⟩, f.node_587467, rfl⟩
  add := Or.inl ⟨⟨587468, by omega⟩, f.node_587468, rfl⟩
}

def certificate_713 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560235) (.wire 589866) (.wire 7279) (.wire 589903) := {
  difference := (.wire 589901)
  product := (.wire 589902)
  subtract := Or.inl ⟨⟨589901, by omega⟩, f.node_589901, rfl⟩
  multiply := Or.inl ⟨⟨589902, by omega⟩, f.node_589902, rfl⟩
  add := Or.inl ⟨⟨589903, by omega⟩, f.node_589903, rfl⟩
}

def certificate_714 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560235) (.wire 589877) (.wire 7280) (.wire 589906) := {
  difference := (.wire 589904)
  product := (.wire 589905)
  subtract := Or.inl ⟨⟨589904, by omega⟩, f.node_589904, rfl⟩
  multiply := Or.inl ⟨⟨589905, by omega⟩, f.node_589905, rfl⟩
  add := Or.inl ⟨⟨589906, by omega⟩, f.node_589906, rfl⟩
}

def certificate_715 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560235) (.wire 589888) (.wire 7281) (.wire 589909) := {
  difference := (.wire 589907)
  product := (.wire 589908)
  subtract := Or.inl ⟨⟨589907, by omega⟩, f.node_589907, rfl⟩
  multiply := Or.inl ⟨⟨589908, by omega⟩, f.node_589908, rfl⟩
  add := Or.inl ⟨⟨589909, by omega⟩, f.node_589909, rfl⟩
}

def certificate_716 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560235) (.wire 589899) (.wire 7282) (.wire 589912) := {
  difference := (.wire 589910)
  product := (.wire 589911)
  subtract := Or.inl ⟨⟨589910, by omega⟩, f.node_589910, rfl⟩
  multiply := Or.inl ⟨⟨589911, by omega⟩, f.node_589911, rfl⟩
  add := Or.inl ⟨⟨589912, by omega⟩, f.node_589912, rfl⟩
}

def certificate_717 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560235) (.wire 589865) (.wire 7283) (.wire 589915) := {
  difference := (.wire 589913)
  product := (.wire 589914)
  subtract := Or.inl ⟨⟨589913, by omega⟩, f.node_589913, rfl⟩
  multiply := Or.inl ⟨⟨589914, by omega⟩, f.node_589914, rfl⟩
  add := Or.inl ⟨⟨589915, by omega⟩, f.node_589915, rfl⟩
}

def certificate_718 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560235) (.wire 589876) (.wire 7284) (.wire 589918) := {
  difference := (.wire 589916)
  product := (.wire 589917)
  subtract := Or.inl ⟨⟨589916, by omega⟩, f.node_589916, rfl⟩
  multiply := Or.inl ⟨⟨589917, by omega⟩, f.node_589917, rfl⟩
  add := Or.inl ⟨⟨589918, by omega⟩, f.node_589918, rfl⟩
}

def certificate_719 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560235) (.wire 589887) (.wire 7285) (.wire 589921) := {
  difference := (.wire 589919)
  product := (.wire 589920)
  subtract := Or.inl ⟨⟨589919, by omega⟩, f.node_589919, rfl⟩
  multiply := Or.inl ⟨⟨589920, by omega⟩, f.node_589920, rfl⟩
  add := Or.inl ⟨⟨589921, by omega⟩, f.node_589921, rfl⟩
}

def certificate_720 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560235) (.wire 7279) (.wire 589866) (.wire 589924) := {
  difference := (.wire 589922)
  product := (.wire 589923)
  subtract := Or.inl ⟨⟨589922, by omega⟩, f.node_589922, rfl⟩
  multiply := Or.inl ⟨⟨589923, by omega⟩, f.node_589923, rfl⟩
  add := Or.inl ⟨⟨589924, by omega⟩, f.node_589924, rfl⟩
}

def certificate_721 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560235) (.wire 7280) (.wire 589877) (.wire 589927) := {
  difference := (.wire 589925)
  product := (.wire 589926)
  subtract := Or.inl ⟨⟨589925, by omega⟩, f.node_589925, rfl⟩
  multiply := Or.inl ⟨⟨589926, by omega⟩, f.node_589926, rfl⟩
  add := Or.inl ⟨⟨589927, by omega⟩, f.node_589927, rfl⟩
}

def certificate_722 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560235) (.wire 7281) (.wire 589888) (.wire 589930) := {
  difference := (.wire 589928)
  product := (.wire 589929)
  subtract := Or.inl ⟨⟨589928, by omega⟩, f.node_589928, rfl⟩
  multiply := Or.inl ⟨⟨589929, by omega⟩, f.node_589929, rfl⟩
  add := Or.inl ⟨⟨589930, by omega⟩, f.node_589930, rfl⟩
}

def certificate_723 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560235) (.wire 7282) (.wire 589899) (.wire 589933) := {
  difference := (.wire 589931)
  product := (.wire 589932)
  subtract := Or.inl ⟨⟨589931, by omega⟩, f.node_589931, rfl⟩
  multiply := Or.inl ⟨⟨589932, by omega⟩, f.node_589932, rfl⟩
  add := Or.inl ⟨⟨589933, by omega⟩, f.node_589933, rfl⟩
}

def certificate_724 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560235) (.wire 7283) (.wire 589865) (.wire 589936) := {
  difference := (.wire 589934)
  product := (.wire 589935)
  subtract := Or.inl ⟨⟨589934, by omega⟩, f.node_589934, rfl⟩
  multiply := Or.inl ⟨⟨589935, by omega⟩, f.node_589935, rfl⟩
  add := Or.inl ⟨⟨589936, by omega⟩, f.node_589936, rfl⟩
}

def certificate_725 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560235) (.wire 7284) (.wire 589876) (.wire 589939) := {
  difference := (.wire 589937)
  product := (.wire 589938)
  subtract := Or.inl ⟨⟨589937, by omega⟩, f.node_589937, rfl⟩
  multiply := Or.inl ⟨⟨589938, by omega⟩, f.node_589938, rfl⟩
  add := Or.inl ⟨⟨589939, by omega⟩, f.node_589939, rfl⟩
}

def certificate_726 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560235) (.wire 7285) (.wire 589887) (.wire 589942) := {
  difference := (.wire 589940)
  product := (.wire 589941)
  subtract := Or.inl ⟨⟨589940, by omega⟩, f.node_589940, rfl⟩
  multiply := Or.inl ⟨⟨589941, by omega⟩, f.node_589941, rfl⟩
  add := Or.inl ⟨⟨589942, by omega⟩, f.node_589942, rfl⟩
}

def certificate_727 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560240) (.wire 592340) (.wire 7286) (.wire 592377) := {
  difference := (.wire 592375)
  product := (.wire 592376)
  subtract := Or.inl ⟨⟨592375, by omega⟩, f.node_592375, rfl⟩
  multiply := Or.inl ⟨⟨592376, by omega⟩, f.node_592376, rfl⟩
  add := Or.inl ⟨⟨592377, by omega⟩, f.node_592377, rfl⟩
}

def certificate_728 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560240) (.wire 592351) (.wire 7287) (.wire 592380) := {
  difference := (.wire 592378)
  product := (.wire 592379)
  subtract := Or.inl ⟨⟨592378, by omega⟩, f.node_592378, rfl⟩
  multiply := Or.inl ⟨⟨592379, by omega⟩, f.node_592379, rfl⟩
  add := Or.inl ⟨⟨592380, by omega⟩, f.node_592380, rfl⟩
}

def certificate_729 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560240) (.wire 592362) (.wire 7288) (.wire 592383) := {
  difference := (.wire 592381)
  product := (.wire 592382)
  subtract := Or.inl ⟨⟨592381, by omega⟩, f.node_592381, rfl⟩
  multiply := Or.inl ⟨⟨592382, by omega⟩, f.node_592382, rfl⟩
  add := Or.inl ⟨⟨592383, by omega⟩, f.node_592383, rfl⟩
}

def certificate_730 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560240) (.wire 592373) (.wire 7289) (.wire 592386) := {
  difference := (.wire 592384)
  product := (.wire 592385)
  subtract := Or.inl ⟨⟨592384, by omega⟩, f.node_592384, rfl⟩
  multiply := Or.inl ⟨⟨592385, by omega⟩, f.node_592385, rfl⟩
  add := Or.inl ⟨⟨592386, by omega⟩, f.node_592386, rfl⟩
}

def certificate_731 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560240) (.wire 592339) (.wire 7290) (.wire 592389) := {
  difference := (.wire 592387)
  product := (.wire 592388)
  subtract := Or.inl ⟨⟨592387, by omega⟩, f.node_592387, rfl⟩
  multiply := Or.inl ⟨⟨592388, by omega⟩, f.node_592388, rfl⟩
  add := Or.inl ⟨⟨592389, by omega⟩, f.node_592389, rfl⟩
}

def certificate_732 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560240) (.wire 592350) (.wire 7291) (.wire 592392) := {
  difference := (.wire 592390)
  product := (.wire 592391)
  subtract := Or.inl ⟨⟨592390, by omega⟩, f.node_592390, rfl⟩
  multiply := Or.inl ⟨⟨592391, by omega⟩, f.node_592391, rfl⟩
  add := Or.inl ⟨⟨592392, by omega⟩, f.node_592392, rfl⟩
}

def certificate_733 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560240) (.wire 592361) (.wire 7292) (.wire 592395) := {
  difference := (.wire 592393)
  product := (.wire 592394)
  subtract := Or.inl ⟨⟨592393, by omega⟩, f.node_592393, rfl⟩
  multiply := Or.inl ⟨⟨592394, by omega⟩, f.node_592394, rfl⟩
  add := Or.inl ⟨⟨592395, by omega⟩, f.node_592395, rfl⟩
}

def certificate_734 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560240) (.wire 7286) (.wire 592340) (.wire 592398) := {
  difference := (.wire 592396)
  product := (.wire 592397)
  subtract := Or.inl ⟨⟨592396, by omega⟩, f.node_592396, rfl⟩
  multiply := Or.inl ⟨⟨592397, by omega⟩, f.node_592397, rfl⟩
  add := Or.inl ⟨⟨592398, by omega⟩, f.node_592398, rfl⟩
}

def certificate_735 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560240) (.wire 7287) (.wire 592351) (.wire 592401) := {
  difference := (.wire 592399)
  product := (.wire 592400)
  subtract := Or.inl ⟨⟨592399, by omega⟩, f.node_592399, rfl⟩
  multiply := Or.inl ⟨⟨592400, by omega⟩, f.node_592400, rfl⟩
  add := Or.inl ⟨⟨592401, by omega⟩, f.node_592401, rfl⟩
}

def certificate_736 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560240) (.wire 7288) (.wire 592362) (.wire 592404) := {
  difference := (.wire 592402)
  product := (.wire 592403)
  subtract := Or.inl ⟨⟨592402, by omega⟩, f.node_592402, rfl⟩
  multiply := Or.inl ⟨⟨592403, by omega⟩, f.node_592403, rfl⟩
  add := Or.inl ⟨⟨592404, by omega⟩, f.node_592404, rfl⟩
}

def certificate_737 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560240) (.wire 7289) (.wire 592373) (.wire 592407) := {
  difference := (.wire 592405)
  product := (.wire 592406)
  subtract := Or.inl ⟨⟨592405, by omega⟩, f.node_592405, rfl⟩
  multiply := Or.inl ⟨⟨592406, by omega⟩, f.node_592406, rfl⟩
  add := Or.inl ⟨⟨592407, by omega⟩, f.node_592407, rfl⟩
}

def certificate_738 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560240) (.wire 7290) (.wire 592339) (.wire 592410) := {
  difference := (.wire 592408)
  product := (.wire 592409)
  subtract := Or.inl ⟨⟨592408, by omega⟩, f.node_592408, rfl⟩
  multiply := Or.inl ⟨⟨592409, by omega⟩, f.node_592409, rfl⟩
  add := Or.inl ⟨⟨592410, by omega⟩, f.node_592410, rfl⟩
}

def certificate_739 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560240) (.wire 7291) (.wire 592350) (.wire 592413) := {
  difference := (.wire 592411)
  product := (.wire 592412)
  subtract := Or.inl ⟨⟨592411, by omega⟩, f.node_592411, rfl⟩
  multiply := Or.inl ⟨⟨592412, by omega⟩, f.node_592412, rfl⟩
  add := Or.inl ⟨⟨592413, by omega⟩, f.node_592413, rfl⟩
}

def certificate_740 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560240) (.wire 7292) (.wire 592361) (.wire 592416) := {
  difference := (.wire 592414)
  product := (.wire 592415)
  subtract := Or.inl ⟨⟨592414, by omega⟩, f.node_592414, rfl⟩
  multiply := Or.inl ⟨⟨592415, by omega⟩, f.node_592415, rfl⟩
  add := Or.inl ⟨⟨592416, by omega⟩, f.node_592416, rfl⟩
}

def certificate_741 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560245) (.wire 594814) (.wire 7293) (.wire 594851) := {
  difference := (.wire 594849)
  product := (.wire 594850)
  subtract := Or.inl ⟨⟨594849, by omega⟩, f.node_594849, rfl⟩
  multiply := Or.inl ⟨⟨594850, by omega⟩, f.node_594850, rfl⟩
  add := Or.inl ⟨⟨594851, by omega⟩, f.node_594851, rfl⟩
}

def certificate_742 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560245) (.wire 594825) (.wire 7294) (.wire 594854) := {
  difference := (.wire 594852)
  product := (.wire 594853)
  subtract := Or.inl ⟨⟨594852, by omega⟩, f.node_594852, rfl⟩
  multiply := Or.inl ⟨⟨594853, by omega⟩, f.node_594853, rfl⟩
  add := Or.inl ⟨⟨594854, by omega⟩, f.node_594854, rfl⟩
}

def certificate_743 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560245) (.wire 594836) (.wire 7295) (.wire 594857) := {
  difference := (.wire 594855)
  product := (.wire 594856)
  subtract := Or.inl ⟨⟨594855, by omega⟩, f.node_594855, rfl⟩
  multiply := Or.inl ⟨⟨594856, by omega⟩, f.node_594856, rfl⟩
  add := Or.inl ⟨⟨594857, by omega⟩, f.node_594857, rfl⟩
}

def certificate_744 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560245) (.wire 594847) (.wire 7296) (.wire 594860) := {
  difference := (.wire 594858)
  product := (.wire 594859)
  subtract := Or.inl ⟨⟨594858, by omega⟩, f.node_594858, rfl⟩
  multiply := Or.inl ⟨⟨594859, by omega⟩, f.node_594859, rfl⟩
  add := Or.inl ⟨⟨594860, by omega⟩, f.node_594860, rfl⟩
}

def certificate_745 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560245) (.wire 594813) (.wire 7297) (.wire 594863) := {
  difference := (.wire 594861)
  product := (.wire 594862)
  subtract := Or.inl ⟨⟨594861, by omega⟩, f.node_594861, rfl⟩
  multiply := Or.inl ⟨⟨594862, by omega⟩, f.node_594862, rfl⟩
  add := Or.inl ⟨⟨594863, by omega⟩, f.node_594863, rfl⟩
}

def certificate_746 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560245) (.wire 594824) (.wire 7298) (.wire 594866) := {
  difference := (.wire 594864)
  product := (.wire 594865)
  subtract := Or.inl ⟨⟨594864, by omega⟩, f.node_594864, rfl⟩
  multiply := Or.inl ⟨⟨594865, by omega⟩, f.node_594865, rfl⟩
  add := Or.inl ⟨⟨594866, by omega⟩, f.node_594866, rfl⟩
}

def certificate_747 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560245) (.wire 594835) (.wire 7299) (.wire 594869) := {
  difference := (.wire 594867)
  product := (.wire 594868)
  subtract := Or.inl ⟨⟨594867, by omega⟩, f.node_594867, rfl⟩
  multiply := Or.inl ⟨⟨594868, by omega⟩, f.node_594868, rfl⟩
  add := Or.inl ⟨⟨594869, by omega⟩, f.node_594869, rfl⟩
}

def certificate_748 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560245) (.wire 7293) (.wire 594814) (.wire 594872) := {
  difference := (.wire 594870)
  product := (.wire 594871)
  subtract := Or.inl ⟨⟨594870, by omega⟩, f.node_594870, rfl⟩
  multiply := Or.inl ⟨⟨594871, by omega⟩, f.node_594871, rfl⟩
  add := Or.inl ⟨⟨594872, by omega⟩, f.node_594872, rfl⟩
}

def certificate_749 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560245) (.wire 7294) (.wire 594825) (.wire 594875) := {
  difference := (.wire 594873)
  product := (.wire 594874)
  subtract := Or.inl ⟨⟨594873, by omega⟩, f.node_594873, rfl⟩
  multiply := Or.inl ⟨⟨594874, by omega⟩, f.node_594874, rfl⟩
  add := Or.inl ⟨⟨594875, by omega⟩, f.node_594875, rfl⟩
}

def certificate_750 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560245) (.wire 7295) (.wire 594836) (.wire 594878) := {
  difference := (.wire 594876)
  product := (.wire 594877)
  subtract := Or.inl ⟨⟨594876, by omega⟩, f.node_594876, rfl⟩
  multiply := Or.inl ⟨⟨594877, by omega⟩, f.node_594877, rfl⟩
  add := Or.inl ⟨⟨594878, by omega⟩, f.node_594878, rfl⟩
}

def certificate_751 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560245) (.wire 7296) (.wire 594847) (.wire 594881) := {
  difference := (.wire 594879)
  product := (.wire 594880)
  subtract := Or.inl ⟨⟨594879, by omega⟩, f.node_594879, rfl⟩
  multiply := Or.inl ⟨⟨594880, by omega⟩, f.node_594880, rfl⟩
  add := Or.inl ⟨⟨594881, by omega⟩, f.node_594881, rfl⟩
}

def certificate_752 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560245) (.wire 7297) (.wire 594813) (.wire 594884) := {
  difference := (.wire 594882)
  product := (.wire 594883)
  subtract := Or.inl ⟨⟨594882, by omega⟩, f.node_594882, rfl⟩
  multiply := Or.inl ⟨⟨594883, by omega⟩, f.node_594883, rfl⟩
  add := Or.inl ⟨⟨594884, by omega⟩, f.node_594884, rfl⟩
}

def certificate_753 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560245) (.wire 7298) (.wire 594824) (.wire 594887) := {
  difference := (.wire 594885)
  product := (.wire 594886)
  subtract := Or.inl ⟨⟨594885, by omega⟩, f.node_594885, rfl⟩
  multiply := Or.inl ⟨⟨594886, by omega⟩, f.node_594886, rfl⟩
  add := Or.inl ⟨⟨594887, by omega⟩, f.node_594887, rfl⟩
}

def certificate_754 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560245) (.wire 7299) (.wire 594835) (.wire 594890) := {
  difference := (.wire 594888)
  product := (.wire 594889)
  subtract := Or.inl ⟨⟨594888, by omega⟩, f.node_594888, rfl⟩
  multiply := Or.inl ⟨⟨594889, by omega⟩, f.node_594889, rfl⟩
  add := Or.inl ⟨⟨594890, by omega⟩, f.node_594890, rfl⟩
}

def certificate_755 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560250) (.wire 597288) (.wire 7300) (.wire 597325) := {
  difference := (.wire 597323)
  product := (.wire 597324)
  subtract := Or.inl ⟨⟨597323, by omega⟩, f.node_597323, rfl⟩
  multiply := Or.inl ⟨⟨597324, by omega⟩, f.node_597324, rfl⟩
  add := Or.inl ⟨⟨597325, by omega⟩, f.node_597325, rfl⟩
}

def certificate_756 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560250) (.wire 597299) (.wire 7301) (.wire 597328) := {
  difference := (.wire 597326)
  product := (.wire 597327)
  subtract := Or.inl ⟨⟨597326, by omega⟩, f.node_597326, rfl⟩
  multiply := Or.inl ⟨⟨597327, by omega⟩, f.node_597327, rfl⟩
  add := Or.inl ⟨⟨597328, by omega⟩, f.node_597328, rfl⟩
}

def certificate_757 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560250) (.wire 597310) (.wire 7302) (.wire 597331) := {
  difference := (.wire 597329)
  product := (.wire 597330)
  subtract := Or.inl ⟨⟨597329, by omega⟩, f.node_597329, rfl⟩
  multiply := Or.inl ⟨⟨597330, by omega⟩, f.node_597330, rfl⟩
  add := Or.inl ⟨⟨597331, by omega⟩, f.node_597331, rfl⟩
}

def certificate_758 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560250) (.wire 597321) (.wire 7303) (.wire 597334) := {
  difference := (.wire 597332)
  product := (.wire 597333)
  subtract := Or.inl ⟨⟨597332, by omega⟩, f.node_597332, rfl⟩
  multiply := Or.inl ⟨⟨597333, by omega⟩, f.node_597333, rfl⟩
  add := Or.inl ⟨⟨597334, by omega⟩, f.node_597334, rfl⟩
}

def certificate_759 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560250) (.wire 597287) (.wire 7304) (.wire 597337) := {
  difference := (.wire 597335)
  product := (.wire 597336)
  subtract := Or.inl ⟨⟨597335, by omega⟩, f.node_597335, rfl⟩
  multiply := Or.inl ⟨⟨597336, by omega⟩, f.node_597336, rfl⟩
  add := Or.inl ⟨⟨597337, by omega⟩, f.node_597337, rfl⟩
}

def certificate_760 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560250) (.wire 597298) (.wire 7305) (.wire 597340) := {
  difference := (.wire 597338)
  product := (.wire 597339)
  subtract := Or.inl ⟨⟨597338, by omega⟩, f.node_597338, rfl⟩
  multiply := Or.inl ⟨⟨597339, by omega⟩, f.node_597339, rfl⟩
  add := Or.inl ⟨⟨597340, by omega⟩, f.node_597340, rfl⟩
}

def certificate_761 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560250) (.wire 597309) (.wire 7306) (.wire 597343) := {
  difference := (.wire 597341)
  product := (.wire 597342)
  subtract := Or.inl ⟨⟨597341, by omega⟩, f.node_597341, rfl⟩
  multiply := Or.inl ⟨⟨597342, by omega⟩, f.node_597342, rfl⟩
  add := Or.inl ⟨⟨597343, by omega⟩, f.node_597343, rfl⟩
}

def certificate_762 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560250) (.wire 7300) (.wire 597288) (.wire 597346) := {
  difference := (.wire 597344)
  product := (.wire 597345)
  subtract := Or.inl ⟨⟨597344, by omega⟩, f.node_597344, rfl⟩
  multiply := Or.inl ⟨⟨597345, by omega⟩, f.node_597345, rfl⟩
  add := Or.inl ⟨⟨597346, by omega⟩, f.node_597346, rfl⟩
}

def certificate_763 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560250) (.wire 7301) (.wire 597299) (.wire 597349) := {
  difference := (.wire 597347)
  product := (.wire 597348)
  subtract := Or.inl ⟨⟨597347, by omega⟩, f.node_597347, rfl⟩
  multiply := Or.inl ⟨⟨597348, by omega⟩, f.node_597348, rfl⟩
  add := Or.inl ⟨⟨597349, by omega⟩, f.node_597349, rfl⟩
}

def certificate_764 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560250) (.wire 7302) (.wire 597310) (.wire 597352) := {
  difference := (.wire 597350)
  product := (.wire 597351)
  subtract := Or.inl ⟨⟨597350, by omega⟩, f.node_597350, rfl⟩
  multiply := Or.inl ⟨⟨597351, by omega⟩, f.node_597351, rfl⟩
  add := Or.inl ⟨⟨597352, by omega⟩, f.node_597352, rfl⟩
}

def certificate_765 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560250) (.wire 7303) (.wire 597321) (.wire 597355) := {
  difference := (.wire 597353)
  product := (.wire 597354)
  subtract := Or.inl ⟨⟨597353, by omega⟩, f.node_597353, rfl⟩
  multiply := Or.inl ⟨⟨597354, by omega⟩, f.node_597354, rfl⟩
  add := Or.inl ⟨⟨597355, by omega⟩, f.node_597355, rfl⟩
}

def certificate_766 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560250) (.wire 7304) (.wire 597287) (.wire 597358) := {
  difference := (.wire 597356)
  product := (.wire 597357)
  subtract := Or.inl ⟨⟨597356, by omega⟩, f.node_597356, rfl⟩
  multiply := Or.inl ⟨⟨597357, by omega⟩, f.node_597357, rfl⟩
  add := Or.inl ⟨⟨597358, by omega⟩, f.node_597358, rfl⟩
}

def certificate_767 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560250) (.wire 7305) (.wire 597298) (.wire 597361) := {
  difference := (.wire 597359)
  product := (.wire 597360)
  subtract := Or.inl ⟨⟨597359, by omega⟩, f.node_597359, rfl⟩
  multiply := Or.inl ⟨⟨597360, by omega⟩, f.node_597360, rfl⟩
  add := Or.inl ⟨⟨597361, by omega⟩, f.node_597361, rfl⟩
}

def certificate_768 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560250) (.wire 7306) (.wire 597309) (.wire 597364) := {
  difference := (.wire 597362)
  product := (.wire 597363)
  subtract := Or.inl ⟨⟨597362, by omega⟩, f.node_597362, rfl⟩
  multiply := Or.inl ⟨⟨597363, by omega⟩, f.node_597363, rfl⟩
  add := Or.inl ⟨⟨597364, by omega⟩, f.node_597364, rfl⟩
}

def certificate_769 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560255) (.wire 599762) (.wire 7307) (.wire 599799) := {
  difference := (.wire 599797)
  product := (.wire 599798)
  subtract := Or.inl ⟨⟨599797, by omega⟩, f.node_599797, rfl⟩
  multiply := Or.inl ⟨⟨599798, by omega⟩, f.node_599798, rfl⟩
  add := Or.inl ⟨⟨599799, by omega⟩, f.node_599799, rfl⟩
}

def certificate_770 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560255) (.wire 599773) (.wire 7308) (.wire 599802) := {
  difference := (.wire 599800)
  product := (.wire 599801)
  subtract := Or.inl ⟨⟨599800, by omega⟩, f.node_599800, rfl⟩
  multiply := Or.inl ⟨⟨599801, by omega⟩, f.node_599801, rfl⟩
  add := Or.inl ⟨⟨599802, by omega⟩, f.node_599802, rfl⟩
}

def certificate_771 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560255) (.wire 599784) (.wire 7309) (.wire 599805) := {
  difference := (.wire 599803)
  product := (.wire 599804)
  subtract := Or.inl ⟨⟨599803, by omega⟩, f.node_599803, rfl⟩
  multiply := Or.inl ⟨⟨599804, by omega⟩, f.node_599804, rfl⟩
  add := Or.inl ⟨⟨599805, by omega⟩, f.node_599805, rfl⟩
}

def certificate_772 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560255) (.wire 599795) (.wire 7310) (.wire 599808) := {
  difference := (.wire 599806)
  product := (.wire 599807)
  subtract := Or.inl ⟨⟨599806, by omega⟩, f.node_599806, rfl⟩
  multiply := Or.inl ⟨⟨599807, by omega⟩, f.node_599807, rfl⟩
  add := Or.inl ⟨⟨599808, by omega⟩, f.node_599808, rfl⟩
}

def certificate_773 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560255) (.wire 599761) (.wire 7311) (.wire 599811) := {
  difference := (.wire 599809)
  product := (.wire 599810)
  subtract := Or.inl ⟨⟨599809, by omega⟩, f.node_599809, rfl⟩
  multiply := Or.inl ⟨⟨599810, by omega⟩, f.node_599810, rfl⟩
  add := Or.inl ⟨⟨599811, by omega⟩, f.node_599811, rfl⟩
}

def certificate_774 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560255) (.wire 599772) (.wire 7312) (.wire 599814) := {
  difference := (.wire 599812)
  product := (.wire 599813)
  subtract := Or.inl ⟨⟨599812, by omega⟩, f.node_599812, rfl⟩
  multiply := Or.inl ⟨⟨599813, by omega⟩, f.node_599813, rfl⟩
  add := Or.inl ⟨⟨599814, by omega⟩, f.node_599814, rfl⟩
}

def certificate_775 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560255) (.wire 599783) (.wire 7313) (.wire 599817) := {
  difference := (.wire 599815)
  product := (.wire 599816)
  subtract := Or.inl ⟨⟨599815, by omega⟩, f.node_599815, rfl⟩
  multiply := Or.inl ⟨⟨599816, by omega⟩, f.node_599816, rfl⟩
  add := Or.inl ⟨⟨599817, by omega⟩, f.node_599817, rfl⟩
}

def certificate_776 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560255) (.wire 7307) (.wire 599762) (.wire 599820) := {
  difference := (.wire 599818)
  product := (.wire 599819)
  subtract := Or.inl ⟨⟨599818, by omega⟩, f.node_599818, rfl⟩
  multiply := Or.inl ⟨⟨599819, by omega⟩, f.node_599819, rfl⟩
  add := Or.inl ⟨⟨599820, by omega⟩, f.node_599820, rfl⟩
}

def certificate_777 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560255) (.wire 7308) (.wire 599773) (.wire 599823) := {
  difference := (.wire 599821)
  product := (.wire 599822)
  subtract := Or.inl ⟨⟨599821, by omega⟩, f.node_599821, rfl⟩
  multiply := Or.inl ⟨⟨599822, by omega⟩, f.node_599822, rfl⟩
  add := Or.inl ⟨⟨599823, by omega⟩, f.node_599823, rfl⟩
}

def certificate_778 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560255) (.wire 7309) (.wire 599784) (.wire 599826) := {
  difference := (.wire 599824)
  product := (.wire 599825)
  subtract := Or.inl ⟨⟨599824, by omega⟩, f.node_599824, rfl⟩
  multiply := Or.inl ⟨⟨599825, by omega⟩, f.node_599825, rfl⟩
  add := Or.inl ⟨⟨599826, by omega⟩, f.node_599826, rfl⟩
}

def certificate_779 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560255) (.wire 7310) (.wire 599795) (.wire 599829) := {
  difference := (.wire 599827)
  product := (.wire 599828)
  subtract := Or.inl ⟨⟨599827, by omega⟩, f.node_599827, rfl⟩
  multiply := Or.inl ⟨⟨599828, by omega⟩, f.node_599828, rfl⟩
  add := Or.inl ⟨⟨599829, by omega⟩, f.node_599829, rfl⟩
}

def certificate_780 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560255) (.wire 7311) (.wire 599761) (.wire 599832) := {
  difference := (.wire 599830)
  product := (.wire 599831)
  subtract := Or.inl ⟨⟨599830, by omega⟩, f.node_599830, rfl⟩
  multiply := Or.inl ⟨⟨599831, by omega⟩, f.node_599831, rfl⟩
  add := Or.inl ⟨⟨599832, by omega⟩, f.node_599832, rfl⟩
}

def certificate_781 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560255) (.wire 7312) (.wire 599772) (.wire 599835) := {
  difference := (.wire 599833)
  product := (.wire 599834)
  subtract := Or.inl ⟨⟨599833, by omega⟩, f.node_599833, rfl⟩
  multiply := Or.inl ⟨⟨599834, by omega⟩, f.node_599834, rfl⟩
  add := Or.inl ⟨⟨599835, by omega⟩, f.node_599835, rfl⟩
}

def certificate_782 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560255) (.wire 7313) (.wire 599783) (.wire 599838) := {
  difference := (.wire 599836)
  product := (.wire 599837)
  subtract := Or.inl ⟨⟨599836, by omega⟩, f.node_599836, rfl⟩
  multiply := Or.inl ⟨⟨599837, by omega⟩, f.node_599837, rfl⟩
  add := Or.inl ⟨⟨599838, by omega⟩, f.node_599838, rfl⟩
}

def certificate_783 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560260) (.wire 602236) (.wire 7314) (.wire 602273) := {
  difference := (.wire 602271)
  product := (.wire 602272)
  subtract := Or.inl ⟨⟨602271, by omega⟩, f.node_602271, rfl⟩
  multiply := Or.inl ⟨⟨602272, by omega⟩, f.node_602272, rfl⟩
  add := Or.inl ⟨⟨602273, by omega⟩, f.node_602273, rfl⟩
}

def certificate_784 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560260) (.wire 602247) (.wire 7315) (.wire 602276) := {
  difference := (.wire 602274)
  product := (.wire 602275)
  subtract := Or.inl ⟨⟨602274, by omega⟩, f.node_602274, rfl⟩
  multiply := Or.inl ⟨⟨602275, by omega⟩, f.node_602275, rfl⟩
  add := Or.inl ⟨⟨602276, by omega⟩, f.node_602276, rfl⟩
}

def certificate_785 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560260) (.wire 602258) (.wire 7316) (.wire 602279) := {
  difference := (.wire 602277)
  product := (.wire 602278)
  subtract := Or.inl ⟨⟨602277, by omega⟩, f.node_602277, rfl⟩
  multiply := Or.inl ⟨⟨602278, by omega⟩, f.node_602278, rfl⟩
  add := Or.inl ⟨⟨602279, by omega⟩, f.node_602279, rfl⟩
}

def certificate_786 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560260) (.wire 602269) (.wire 7317) (.wire 602282) := {
  difference := (.wire 602280)
  product := (.wire 602281)
  subtract := Or.inl ⟨⟨602280, by omega⟩, f.node_602280, rfl⟩
  multiply := Or.inl ⟨⟨602281, by omega⟩, f.node_602281, rfl⟩
  add := Or.inl ⟨⟨602282, by omega⟩, f.node_602282, rfl⟩
}

def certificate_787 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560260) (.wire 602235) (.wire 7318) (.wire 602285) := {
  difference := (.wire 602283)
  product := (.wire 602284)
  subtract := Or.inl ⟨⟨602283, by omega⟩, f.node_602283, rfl⟩
  multiply := Or.inl ⟨⟨602284, by omega⟩, f.node_602284, rfl⟩
  add := Or.inl ⟨⟨602285, by omega⟩, f.node_602285, rfl⟩
}

def certificate_788 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560260) (.wire 602246) (.wire 7319) (.wire 602288) := {
  difference := (.wire 602286)
  product := (.wire 602287)
  subtract := Or.inl ⟨⟨602286, by omega⟩, f.node_602286, rfl⟩
  multiply := Or.inl ⟨⟨602287, by omega⟩, f.node_602287, rfl⟩
  add := Or.inl ⟨⟨602288, by omega⟩, f.node_602288, rfl⟩
}

def certificate_789 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560260) (.wire 602257) (.wire 7320) (.wire 602291) := {
  difference := (.wire 602289)
  product := (.wire 602290)
  subtract := Or.inl ⟨⟨602289, by omega⟩, f.node_602289, rfl⟩
  multiply := Or.inl ⟨⟨602290, by omega⟩, f.node_602290, rfl⟩
  add := Or.inl ⟨⟨602291, by omega⟩, f.node_602291, rfl⟩
}

def certificate_790 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560260) (.wire 7314) (.wire 602236) (.wire 602294) := {
  difference := (.wire 602292)
  product := (.wire 602293)
  subtract := Or.inl ⟨⟨602292, by omega⟩, f.node_602292, rfl⟩
  multiply := Or.inl ⟨⟨602293, by omega⟩, f.node_602293, rfl⟩
  add := Or.inl ⟨⟨602294, by omega⟩, f.node_602294, rfl⟩
}

def certificate_791 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560260) (.wire 7315) (.wire 602247) (.wire 602297) := {
  difference := (.wire 602295)
  product := (.wire 602296)
  subtract := Or.inl ⟨⟨602295, by omega⟩, f.node_602295, rfl⟩
  multiply := Or.inl ⟨⟨602296, by omega⟩, f.node_602296, rfl⟩
  add := Or.inl ⟨⟨602297, by omega⟩, f.node_602297, rfl⟩
}

def certificate_792 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560260) (.wire 7316) (.wire 602258) (.wire 602300) := {
  difference := (.wire 602298)
  product := (.wire 602299)
  subtract := Or.inl ⟨⟨602298, by omega⟩, f.node_602298, rfl⟩
  multiply := Or.inl ⟨⟨602299, by omega⟩, f.node_602299, rfl⟩
  add := Or.inl ⟨⟨602300, by omega⟩, f.node_602300, rfl⟩
}

def certificate_793 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560260) (.wire 7317) (.wire 602269) (.wire 602303) := {
  difference := (.wire 602301)
  product := (.wire 602302)
  subtract := Or.inl ⟨⟨602301, by omega⟩, f.node_602301, rfl⟩
  multiply := Or.inl ⟨⟨602302, by omega⟩, f.node_602302, rfl⟩
  add := Or.inl ⟨⟨602303, by omega⟩, f.node_602303, rfl⟩
}

def certificate_794 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560260) (.wire 7318) (.wire 602235) (.wire 602306) := {
  difference := (.wire 602304)
  product := (.wire 602305)
  subtract := Or.inl ⟨⟨602304, by omega⟩, f.node_602304, rfl⟩
  multiply := Or.inl ⟨⟨602305, by omega⟩, f.node_602305, rfl⟩
  add := Or.inl ⟨⟨602306, by omega⟩, f.node_602306, rfl⟩
}

def certificate_795 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560260) (.wire 7319) (.wire 602246) (.wire 602309) := {
  difference := (.wire 602307)
  product := (.wire 602308)
  subtract := Or.inl ⟨⟨602307, by omega⟩, f.node_602307, rfl⟩
  multiply := Or.inl ⟨⟨602308, by omega⟩, f.node_602308, rfl⟩
  add := Or.inl ⟨⟨602309, by omega⟩, f.node_602309, rfl⟩
}

def certificate_796 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560260) (.wire 7320) (.wire 602257) (.wire 602312) := {
  difference := (.wire 602310)
  product := (.wire 602311)
  subtract := Or.inl ⟨⟨602310, by omega⟩, f.node_602310, rfl⟩
  multiply := Or.inl ⟨⟨602311, by omega⟩, f.node_602311, rfl⟩
  add := Or.inl ⟨⟨602312, by omega⟩, f.node_602312, rfl⟩
}

def certificate_797 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560265) (.wire 604710) (.wire 7321) (.wire 604747) := {
  difference := (.wire 604745)
  product := (.wire 604746)
  subtract := Or.inl ⟨⟨604745, by omega⟩, f.node_604745, rfl⟩
  multiply := Or.inl ⟨⟨604746, by omega⟩, f.node_604746, rfl⟩
  add := Or.inl ⟨⟨604747, by omega⟩, f.node_604747, rfl⟩
}

def certificate_798 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560265) (.wire 604721) (.wire 7322) (.wire 604750) := {
  difference := (.wire 604748)
  product := (.wire 604749)
  subtract := Or.inl ⟨⟨604748, by omega⟩, f.node_604748, rfl⟩
  multiply := Or.inl ⟨⟨604749, by omega⟩, f.node_604749, rfl⟩
  add := Or.inl ⟨⟨604750, by omega⟩, f.node_604750, rfl⟩
}

def certificate_799 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560265) (.wire 604732) (.wire 7323) (.wire 604753) := {
  difference := (.wire 604751)
  product := (.wire 604752)
  subtract := Or.inl ⟨⟨604751, by omega⟩, f.node_604751, rfl⟩
  multiply := Or.inl ⟨⟨604752, by omega⟩, f.node_604752, rfl⟩
  add := Or.inl ⟨⟨604753, by omega⟩, f.node_604753, rfl⟩
}

def certificate_800 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560265) (.wire 604743) (.wire 7324) (.wire 604756) := {
  difference := (.wire 604754)
  product := (.wire 604755)
  subtract := Or.inl ⟨⟨604754, by omega⟩, f.node_604754, rfl⟩
  multiply := Or.inl ⟨⟨604755, by omega⟩, f.node_604755, rfl⟩
  add := Or.inl ⟨⟨604756, by omega⟩, f.node_604756, rfl⟩
}

def certificate_801 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560265) (.wire 604709) (.wire 7325) (.wire 604759) := {
  difference := (.wire 604757)
  product := (.wire 604758)
  subtract := Or.inl ⟨⟨604757, by omega⟩, f.node_604757, rfl⟩
  multiply := Or.inl ⟨⟨604758, by omega⟩, f.node_604758, rfl⟩
  add := Or.inl ⟨⟨604759, by omega⟩, f.node_604759, rfl⟩
}

def certificate_802 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560265) (.wire 604720) (.wire 7326) (.wire 604762) := {
  difference := (.wire 604760)
  product := (.wire 604761)
  subtract := Or.inl ⟨⟨604760, by omega⟩, f.node_604760, rfl⟩
  multiply := Or.inl ⟨⟨604761, by omega⟩, f.node_604761, rfl⟩
  add := Or.inl ⟨⟨604762, by omega⟩, f.node_604762, rfl⟩
}

def certificate_803 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560265) (.wire 604731) (.wire 7327) (.wire 604765) := {
  difference := (.wire 604763)
  product := (.wire 604764)
  subtract := Or.inl ⟨⟨604763, by omega⟩, f.node_604763, rfl⟩
  multiply := Or.inl ⟨⟨604764, by omega⟩, f.node_604764, rfl⟩
  add := Or.inl ⟨⟨604765, by omega⟩, f.node_604765, rfl⟩
}

def certificate_804 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560265) (.wire 7321) (.wire 604710) (.wire 604768) := {
  difference := (.wire 604766)
  product := (.wire 604767)
  subtract := Or.inl ⟨⟨604766, by omega⟩, f.node_604766, rfl⟩
  multiply := Or.inl ⟨⟨604767, by omega⟩, f.node_604767, rfl⟩
  add := Or.inl ⟨⟨604768, by omega⟩, f.node_604768, rfl⟩
}

def certificate_805 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560265) (.wire 7322) (.wire 604721) (.wire 604771) := {
  difference := (.wire 604769)
  product := (.wire 604770)
  subtract := Or.inl ⟨⟨604769, by omega⟩, f.node_604769, rfl⟩
  multiply := Or.inl ⟨⟨604770, by omega⟩, f.node_604770, rfl⟩
  add := Or.inl ⟨⟨604771, by omega⟩, f.node_604771, rfl⟩
}

def certificate_806 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560265) (.wire 7323) (.wire 604732) (.wire 604774) := {
  difference := (.wire 604772)
  product := (.wire 604773)
  subtract := Or.inl ⟨⟨604772, by omega⟩, f.node_604772, rfl⟩
  multiply := Or.inl ⟨⟨604773, by omega⟩, f.node_604773, rfl⟩
  add := Or.inl ⟨⟨604774, by omega⟩, f.node_604774, rfl⟩
}

def certificate_807 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560265) (.wire 7324) (.wire 604743) (.wire 604777) := {
  difference := (.wire 604775)
  product := (.wire 604776)
  subtract := Or.inl ⟨⟨604775, by omega⟩, f.node_604775, rfl⟩
  multiply := Or.inl ⟨⟨604776, by omega⟩, f.node_604776, rfl⟩
  add := Or.inl ⟨⟨604777, by omega⟩, f.node_604777, rfl⟩
}

def certificate_808 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560265) (.wire 7325) (.wire 604709) (.wire 604780) := {
  difference := (.wire 604778)
  product := (.wire 604779)
  subtract := Or.inl ⟨⟨604778, by omega⟩, f.node_604778, rfl⟩
  multiply := Or.inl ⟨⟨604779, by omega⟩, f.node_604779, rfl⟩
  add := Or.inl ⟨⟨604780, by omega⟩, f.node_604780, rfl⟩
}

def certificate_809 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560265) (.wire 7326) (.wire 604720) (.wire 604783) := {
  difference := (.wire 604781)
  product := (.wire 604782)
  subtract := Or.inl ⟨⟨604781, by omega⟩, f.node_604781, rfl⟩
  multiply := Or.inl ⟨⟨604782, by omega⟩, f.node_604782, rfl⟩
  add := Or.inl ⟨⟨604783, by omega⟩, f.node_604783, rfl⟩
}

def certificate_810 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560265) (.wire 7327) (.wire 604731) (.wire 604786) := {
  difference := (.wire 604784)
  product := (.wire 604785)
  subtract := Or.inl ⟨⟨604784, by omega⟩, f.node_604784, rfl⟩
  multiply := Or.inl ⟨⟨604785, by omega⟩, f.node_604785, rfl⟩
  add := Or.inl ⟨⟨604786, by omega⟩, f.node_604786, rfl⟩
}

def certificate_811 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560270) (.wire 607184) (.wire 7328) (.wire 607221) := {
  difference := (.wire 607219)
  product := (.wire 607220)
  subtract := Or.inl ⟨⟨607219, by omega⟩, f.node_607219, rfl⟩
  multiply := Or.inl ⟨⟨607220, by omega⟩, f.node_607220, rfl⟩
  add := Or.inl ⟨⟨607221, by omega⟩, f.node_607221, rfl⟩
}

def certificate_812 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560270) (.wire 607195) (.wire 7329) (.wire 607224) := {
  difference := (.wire 607222)
  product := (.wire 607223)
  subtract := Or.inl ⟨⟨607222, by omega⟩, f.node_607222, rfl⟩
  multiply := Or.inl ⟨⟨607223, by omega⟩, f.node_607223, rfl⟩
  add := Or.inl ⟨⟨607224, by omega⟩, f.node_607224, rfl⟩
}

def certificate_813 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560270) (.wire 607206) (.wire 7330) (.wire 607227) := {
  difference := (.wire 607225)
  product := (.wire 607226)
  subtract := Or.inl ⟨⟨607225, by omega⟩, f.node_607225, rfl⟩
  multiply := Or.inl ⟨⟨607226, by omega⟩, f.node_607226, rfl⟩
  add := Or.inl ⟨⟨607227, by omega⟩, f.node_607227, rfl⟩
}

def certificate_814 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560270) (.wire 607217) (.wire 7331) (.wire 607230) := {
  difference := (.wire 607228)
  product := (.wire 607229)
  subtract := Or.inl ⟨⟨607228, by omega⟩, f.node_607228, rfl⟩
  multiply := Or.inl ⟨⟨607229, by omega⟩, f.node_607229, rfl⟩
  add := Or.inl ⟨⟨607230, by omega⟩, f.node_607230, rfl⟩
}

def certificate_815 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560270) (.wire 607183) (.wire 7332) (.wire 607233) := {
  difference := (.wire 607231)
  product := (.wire 607232)
  subtract := Or.inl ⟨⟨607231, by omega⟩, f.node_607231, rfl⟩
  multiply := Or.inl ⟨⟨607232, by omega⟩, f.node_607232, rfl⟩
  add := Or.inl ⟨⟨607233, by omega⟩, f.node_607233, rfl⟩
}

def certificate_816 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560270) (.wire 607194) (.wire 7333) (.wire 607236) := {
  difference := (.wire 607234)
  product := (.wire 607235)
  subtract := Or.inl ⟨⟨607234, by omega⟩, f.node_607234, rfl⟩
  multiply := Or.inl ⟨⟨607235, by omega⟩, f.node_607235, rfl⟩
  add := Or.inl ⟨⟨607236, by omega⟩, f.node_607236, rfl⟩
}

def certificate_817 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560270) (.wire 607205) (.wire 7334) (.wire 607239) := {
  difference := (.wire 607237)
  product := (.wire 607238)
  subtract := Or.inl ⟨⟨607237, by omega⟩, f.node_607237, rfl⟩
  multiply := Or.inl ⟨⟨607238, by omega⟩, f.node_607238, rfl⟩
  add := Or.inl ⟨⟨607239, by omega⟩, f.node_607239, rfl⟩
}

def certificate_818 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560270) (.wire 7328) (.wire 607184) (.wire 607242) := {
  difference := (.wire 607240)
  product := (.wire 607241)
  subtract := Or.inl ⟨⟨607240, by omega⟩, f.node_607240, rfl⟩
  multiply := Or.inl ⟨⟨607241, by omega⟩, f.node_607241, rfl⟩
  add := Or.inl ⟨⟨607242, by omega⟩, f.node_607242, rfl⟩
}

def certificate_819 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560270) (.wire 7329) (.wire 607195) (.wire 607245) := {
  difference := (.wire 607243)
  product := (.wire 607244)
  subtract := Or.inl ⟨⟨607243, by omega⟩, f.node_607243, rfl⟩
  multiply := Or.inl ⟨⟨607244, by omega⟩, f.node_607244, rfl⟩
  add := Or.inl ⟨⟨607245, by omega⟩, f.node_607245, rfl⟩
}

def certificate_820 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560270) (.wire 7330) (.wire 607206) (.wire 607248) := {
  difference := (.wire 607246)
  product := (.wire 607247)
  subtract := Or.inl ⟨⟨607246, by omega⟩, f.node_607246, rfl⟩
  multiply := Or.inl ⟨⟨607247, by omega⟩, f.node_607247, rfl⟩
  add := Or.inl ⟨⟨607248, by omega⟩, f.node_607248, rfl⟩
}

def certificate_821 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560270) (.wire 7331) (.wire 607217) (.wire 607251) := {
  difference := (.wire 607249)
  product := (.wire 607250)
  subtract := Or.inl ⟨⟨607249, by omega⟩, f.node_607249, rfl⟩
  multiply := Or.inl ⟨⟨607250, by omega⟩, f.node_607250, rfl⟩
  add := Or.inl ⟨⟨607251, by omega⟩, f.node_607251, rfl⟩
}

def certificate_822 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560270) (.wire 7332) (.wire 607183) (.wire 607254) := {
  difference := (.wire 607252)
  product := (.wire 607253)
  subtract := Or.inl ⟨⟨607252, by omega⟩, f.node_607252, rfl⟩
  multiply := Or.inl ⟨⟨607253, by omega⟩, f.node_607253, rfl⟩
  add := Or.inl ⟨⟨607254, by omega⟩, f.node_607254, rfl⟩
}

def certificate_823 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560270) (.wire 7333) (.wire 607194) (.wire 607257) := {
  difference := (.wire 607255)
  product := (.wire 607256)
  subtract := Or.inl ⟨⟨607255, by omega⟩, f.node_607255, rfl⟩
  multiply := Or.inl ⟨⟨607256, by omega⟩, f.node_607256, rfl⟩
  add := Or.inl ⟨⟨607257, by omega⟩, f.node_607257, rfl⟩
}

def certificate_824 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560270) (.wire 7334) (.wire 607205) (.wire 607260) := {
  difference := (.wire 607258)
  product := (.wire 607259)
  subtract := Or.inl ⟨⟨607258, by omega⟩, f.node_607258, rfl⟩
  multiply := Or.inl ⟨⟨607259, by omega⟩, f.node_607259, rfl⟩
  add := Or.inl ⟨⟨607260, by omega⟩, f.node_607260, rfl⟩
}

def certificate_825 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560275) (.wire 609658) (.wire 7335) (.wire 609695) := {
  difference := (.wire 609693)
  product := (.wire 609694)
  subtract := Or.inl ⟨⟨609693, by omega⟩, f.node_609693, rfl⟩
  multiply := Or.inl ⟨⟨609694, by omega⟩, f.node_609694, rfl⟩
  add := Or.inl ⟨⟨609695, by omega⟩, f.node_609695, rfl⟩
}

def certificate_826 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560275) (.wire 609669) (.wire 7336) (.wire 609698) := {
  difference := (.wire 609696)
  product := (.wire 609697)
  subtract := Or.inl ⟨⟨609696, by omega⟩, f.node_609696, rfl⟩
  multiply := Or.inl ⟨⟨609697, by omega⟩, f.node_609697, rfl⟩
  add := Or.inl ⟨⟨609698, by omega⟩, f.node_609698, rfl⟩
}

def certificate_827 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560275) (.wire 609680) (.wire 7337) (.wire 609701) := {
  difference := (.wire 609699)
  product := (.wire 609700)
  subtract := Or.inl ⟨⟨609699, by omega⟩, f.node_609699, rfl⟩
  multiply := Or.inl ⟨⟨609700, by omega⟩, f.node_609700, rfl⟩
  add := Or.inl ⟨⟨609701, by omega⟩, f.node_609701, rfl⟩
}

def certificate_828 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560275) (.wire 609691) (.wire 7338) (.wire 609704) := {
  difference := (.wire 609702)
  product := (.wire 609703)
  subtract := Or.inl ⟨⟨609702, by omega⟩, f.node_609702, rfl⟩
  multiply := Or.inl ⟨⟨609703, by omega⟩, f.node_609703, rfl⟩
  add := Or.inl ⟨⟨609704, by omega⟩, f.node_609704, rfl⟩
}

def certificate_829 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560275) (.wire 609657) (.wire 7339) (.wire 609707) := {
  difference := (.wire 609705)
  product := (.wire 609706)
  subtract := Or.inl ⟨⟨609705, by omega⟩, f.node_609705, rfl⟩
  multiply := Or.inl ⟨⟨609706, by omega⟩, f.node_609706, rfl⟩
  add := Or.inl ⟨⟨609707, by omega⟩, f.node_609707, rfl⟩
}

def certificate_830 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560275) (.wire 609668) (.wire 7340) (.wire 609710) := {
  difference := (.wire 609708)
  product := (.wire 609709)
  subtract := Or.inl ⟨⟨609708, by omega⟩, f.node_609708, rfl⟩
  multiply := Or.inl ⟨⟨609709, by omega⟩, f.node_609709, rfl⟩
  add := Or.inl ⟨⟨609710, by omega⟩, f.node_609710, rfl⟩
}

def certificate_831 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560275) (.wire 609679) (.wire 7341) (.wire 609713) := {
  difference := (.wire 609711)
  product := (.wire 609712)
  subtract := Or.inl ⟨⟨609711, by omega⟩, f.node_609711, rfl⟩
  multiply := Or.inl ⟨⟨609712, by omega⟩, f.node_609712, rfl⟩
  add := Or.inl ⟨⟨609713, by omega⟩, f.node_609713, rfl⟩
}

def certificate_832 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560275) (.wire 7335) (.wire 609658) (.wire 609716) := {
  difference := (.wire 609714)
  product := (.wire 609715)
  subtract := Or.inl ⟨⟨609714, by omega⟩, f.node_609714, rfl⟩
  multiply := Or.inl ⟨⟨609715, by omega⟩, f.node_609715, rfl⟩
  add := Or.inl ⟨⟨609716, by omega⟩, f.node_609716, rfl⟩
}

def certificate_833 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560275) (.wire 7336) (.wire 609669) (.wire 609719) := {
  difference := (.wire 609717)
  product := (.wire 609718)
  subtract := Or.inl ⟨⟨609717, by omega⟩, f.node_609717, rfl⟩
  multiply := Or.inl ⟨⟨609718, by omega⟩, f.node_609718, rfl⟩
  add := Or.inl ⟨⟨609719, by omega⟩, f.node_609719, rfl⟩
}

def certificate_834 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560275) (.wire 7337) (.wire 609680) (.wire 609722) := {
  difference := (.wire 609720)
  product := (.wire 609721)
  subtract := Or.inl ⟨⟨609720, by omega⟩, f.node_609720, rfl⟩
  multiply := Or.inl ⟨⟨609721, by omega⟩, f.node_609721, rfl⟩
  add := Or.inl ⟨⟨609722, by omega⟩, f.node_609722, rfl⟩
}

def certificate_835 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560275) (.wire 7338) (.wire 609691) (.wire 609725) := {
  difference := (.wire 609723)
  product := (.wire 609724)
  subtract := Or.inl ⟨⟨609723, by omega⟩, f.node_609723, rfl⟩
  multiply := Or.inl ⟨⟨609724, by omega⟩, f.node_609724, rfl⟩
  add := Or.inl ⟨⟨609725, by omega⟩, f.node_609725, rfl⟩
}

def certificate_836 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560275) (.wire 7339) (.wire 609657) (.wire 609728) := {
  difference := (.wire 609726)
  product := (.wire 609727)
  subtract := Or.inl ⟨⟨609726, by omega⟩, f.node_609726, rfl⟩
  multiply := Or.inl ⟨⟨609727, by omega⟩, f.node_609727, rfl⟩
  add := Or.inl ⟨⟨609728, by omega⟩, f.node_609728, rfl⟩
}

def certificate_837 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560275) (.wire 7340) (.wire 609668) (.wire 609731) := {
  difference := (.wire 609729)
  product := (.wire 609730)
  subtract := Or.inl ⟨⟨609729, by omega⟩, f.node_609729, rfl⟩
  multiply := Or.inl ⟨⟨609730, by omega⟩, f.node_609730, rfl⟩
  add := Or.inl ⟨⟨609731, by omega⟩, f.node_609731, rfl⟩
}

def certificate_838 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560275) (.wire 7341) (.wire 609679) (.wire 609734) := {
  difference := (.wire 609732)
  product := (.wire 609733)
  subtract := Or.inl ⟨⟨609732, by omega⟩, f.node_609732, rfl⟩
  multiply := Or.inl ⟨⟨609733, by omega⟩, f.node_609733, rfl⟩
  add := Or.inl ⟨⟨609734, by omega⟩, f.node_609734, rfl⟩
}

def certificate_839 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560280) (.wire 612132) (.wire 7342) (.wire 612169) := {
  difference := (.wire 612167)
  product := (.wire 612168)
  subtract := Or.inl ⟨⟨612167, by omega⟩, f.node_612167, rfl⟩
  multiply := Or.inl ⟨⟨612168, by omega⟩, f.node_612168, rfl⟩
  add := Or.inl ⟨⟨612169, by omega⟩, f.node_612169, rfl⟩
}

def certificate_840 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560280) (.wire 612143) (.wire 7343) (.wire 612172) := {
  difference := (.wire 612170)
  product := (.wire 612171)
  subtract := Or.inl ⟨⟨612170, by omega⟩, f.node_612170, rfl⟩
  multiply := Or.inl ⟨⟨612171, by omega⟩, f.node_612171, rfl⟩
  add := Or.inl ⟨⟨612172, by omega⟩, f.node_612172, rfl⟩
}

def certificate_841 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560280) (.wire 612154) (.wire 7344) (.wire 612175) := {
  difference := (.wire 612173)
  product := (.wire 612174)
  subtract := Or.inl ⟨⟨612173, by omega⟩, f.node_612173, rfl⟩
  multiply := Or.inl ⟨⟨612174, by omega⟩, f.node_612174, rfl⟩
  add := Or.inl ⟨⟨612175, by omega⟩, f.node_612175, rfl⟩
}

def certificate_842 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560280) (.wire 612165) (.wire 7345) (.wire 612178) := {
  difference := (.wire 612176)
  product := (.wire 612177)
  subtract := Or.inl ⟨⟨612176, by omega⟩, f.node_612176, rfl⟩
  multiply := Or.inl ⟨⟨612177, by omega⟩, f.node_612177, rfl⟩
  add := Or.inl ⟨⟨612178, by omega⟩, f.node_612178, rfl⟩
}

def certificate_843 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560280) (.wire 612131) (.wire 7346) (.wire 612181) := {
  difference := (.wire 612179)
  product := (.wire 612180)
  subtract := Or.inl ⟨⟨612179, by omega⟩, f.node_612179, rfl⟩
  multiply := Or.inl ⟨⟨612180, by omega⟩, f.node_612180, rfl⟩
  add := Or.inl ⟨⟨612181, by omega⟩, f.node_612181, rfl⟩
}

def certificate_844 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560280) (.wire 612142) (.wire 7347) (.wire 612184) := {
  difference := (.wire 612182)
  product := (.wire 612183)
  subtract := Or.inl ⟨⟨612182, by omega⟩, f.node_612182, rfl⟩
  multiply := Or.inl ⟨⟨612183, by omega⟩, f.node_612183, rfl⟩
  add := Or.inl ⟨⟨612184, by omega⟩, f.node_612184, rfl⟩
}

def certificate_845 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560280) (.wire 612153) (.wire 7348) (.wire 612187) := {
  difference := (.wire 612185)
  product := (.wire 612186)
  subtract := Or.inl ⟨⟨612185, by omega⟩, f.node_612185, rfl⟩
  multiply := Or.inl ⟨⟨612186, by omega⟩, f.node_612186, rfl⟩
  add := Or.inl ⟨⟨612187, by omega⟩, f.node_612187, rfl⟩
}

def certificate_846 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560280) (.wire 7342) (.wire 612132) (.wire 612190) := {
  difference := (.wire 612188)
  product := (.wire 612189)
  subtract := Or.inl ⟨⟨612188, by omega⟩, f.node_612188, rfl⟩
  multiply := Or.inl ⟨⟨612189, by omega⟩, f.node_612189, rfl⟩
  add := Or.inl ⟨⟨612190, by omega⟩, f.node_612190, rfl⟩
}

def certificate_847 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560280) (.wire 7343) (.wire 612143) (.wire 612193) := {
  difference := (.wire 612191)
  product := (.wire 612192)
  subtract := Or.inl ⟨⟨612191, by omega⟩, f.node_612191, rfl⟩
  multiply := Or.inl ⟨⟨612192, by omega⟩, f.node_612192, rfl⟩
  add := Or.inl ⟨⟨612193, by omega⟩, f.node_612193, rfl⟩
}

def certificate_848 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560280) (.wire 7344) (.wire 612154) (.wire 612196) := {
  difference := (.wire 612194)
  product := (.wire 612195)
  subtract := Or.inl ⟨⟨612194, by omega⟩, f.node_612194, rfl⟩
  multiply := Or.inl ⟨⟨612195, by omega⟩, f.node_612195, rfl⟩
  add := Or.inl ⟨⟨612196, by omega⟩, f.node_612196, rfl⟩
}

def certificate_849 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560280) (.wire 7345) (.wire 612165) (.wire 612199) := {
  difference := (.wire 612197)
  product := (.wire 612198)
  subtract := Or.inl ⟨⟨612197, by omega⟩, f.node_612197, rfl⟩
  multiply := Or.inl ⟨⟨612198, by omega⟩, f.node_612198, rfl⟩
  add := Or.inl ⟨⟨612199, by omega⟩, f.node_612199, rfl⟩
}

def certificate_850 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560280) (.wire 7346) (.wire 612131) (.wire 612202) := {
  difference := (.wire 612200)
  product := (.wire 612201)
  subtract := Or.inl ⟨⟨612200, by omega⟩, f.node_612200, rfl⟩
  multiply := Or.inl ⟨⟨612201, by omega⟩, f.node_612201, rfl⟩
  add := Or.inl ⟨⟨612202, by omega⟩, f.node_612202, rfl⟩
}

def certificate_851 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560280) (.wire 7347) (.wire 612142) (.wire 612205) := {
  difference := (.wire 612203)
  product := (.wire 612204)
  subtract := Or.inl ⟨⟨612203, by omega⟩, f.node_612203, rfl⟩
  multiply := Or.inl ⟨⟨612204, by omega⟩, f.node_612204, rfl⟩
  add := Or.inl ⟨⟨612205, by omega⟩, f.node_612205, rfl⟩
}

def certificate_852 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560280) (.wire 7348) (.wire 612153) (.wire 612208) := {
  difference := (.wire 612206)
  product := (.wire 612207)
  subtract := Or.inl ⟨⟨612206, by omega⟩, f.node_612206, rfl⟩
  multiply := Or.inl ⟨⟨612207, by omega⟩, f.node_612207, rfl⟩
  add := Or.inl ⟨⟨612208, by omega⟩, f.node_612208, rfl⟩
}

def certificate_853 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560285) (.wire 614606) (.wire 7349) (.wire 614643) := {
  difference := (.wire 614641)
  product := (.wire 614642)
  subtract := Or.inl ⟨⟨614641, by omega⟩, f.node_614641, rfl⟩
  multiply := Or.inl ⟨⟨614642, by omega⟩, f.node_614642, rfl⟩
  add := Or.inl ⟨⟨614643, by omega⟩, f.node_614643, rfl⟩
}

def certificate_854 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560285) (.wire 614617) (.wire 7350) (.wire 614646) := {
  difference := (.wire 614644)
  product := (.wire 614645)
  subtract := Or.inl ⟨⟨614644, by omega⟩, f.node_614644, rfl⟩
  multiply := Or.inl ⟨⟨614645, by omega⟩, f.node_614645, rfl⟩
  add := Or.inl ⟨⟨614646, by omega⟩, f.node_614646, rfl⟩
}

def certificate_855 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560285) (.wire 614628) (.wire 7351) (.wire 614649) := {
  difference := (.wire 614647)
  product := (.wire 614648)
  subtract := Or.inl ⟨⟨614647, by omega⟩, f.node_614647, rfl⟩
  multiply := Or.inl ⟨⟨614648, by omega⟩, f.node_614648, rfl⟩
  add := Or.inl ⟨⟨614649, by omega⟩, f.node_614649, rfl⟩
}

def certificate_856 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560285) (.wire 614639) (.wire 7352) (.wire 614652) := {
  difference := (.wire 614650)
  product := (.wire 614651)
  subtract := Or.inl ⟨⟨614650, by omega⟩, f.node_614650, rfl⟩
  multiply := Or.inl ⟨⟨614651, by omega⟩, f.node_614651, rfl⟩
  add := Or.inl ⟨⟨614652, by omega⟩, f.node_614652, rfl⟩
}

def certificate_857 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560285) (.wire 614605) (.wire 7353) (.wire 614655) := {
  difference := (.wire 614653)
  product := (.wire 614654)
  subtract := Or.inl ⟨⟨614653, by omega⟩, f.node_614653, rfl⟩
  multiply := Or.inl ⟨⟨614654, by omega⟩, f.node_614654, rfl⟩
  add := Or.inl ⟨⟨614655, by omega⟩, f.node_614655, rfl⟩
}

def certificate_858 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560285) (.wire 614616) (.wire 7354) (.wire 614658) := {
  difference := (.wire 614656)
  product := (.wire 614657)
  subtract := Or.inl ⟨⟨614656, by omega⟩, f.node_614656, rfl⟩
  multiply := Or.inl ⟨⟨614657, by omega⟩, f.node_614657, rfl⟩
  add := Or.inl ⟨⟨614658, by omega⟩, f.node_614658, rfl⟩
}

def certificate_859 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560285) (.wire 614627) (.wire 7355) (.wire 614661) := {
  difference := (.wire 614659)
  product := (.wire 614660)
  subtract := Or.inl ⟨⟨614659, by omega⟩, f.node_614659, rfl⟩
  multiply := Or.inl ⟨⟨614660, by omega⟩, f.node_614660, rfl⟩
  add := Or.inl ⟨⟨614661, by omega⟩, f.node_614661, rfl⟩
}

def certificate_860 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560285) (.wire 7349) (.wire 614606) (.wire 614664) := {
  difference := (.wire 614662)
  product := (.wire 614663)
  subtract := Or.inl ⟨⟨614662, by omega⟩, f.node_614662, rfl⟩
  multiply := Or.inl ⟨⟨614663, by omega⟩, f.node_614663, rfl⟩
  add := Or.inl ⟨⟨614664, by omega⟩, f.node_614664, rfl⟩
}

def certificate_861 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560285) (.wire 7350) (.wire 614617) (.wire 614667) := {
  difference := (.wire 614665)
  product := (.wire 614666)
  subtract := Or.inl ⟨⟨614665, by omega⟩, f.node_614665, rfl⟩
  multiply := Or.inl ⟨⟨614666, by omega⟩, f.node_614666, rfl⟩
  add := Or.inl ⟨⟨614667, by omega⟩, f.node_614667, rfl⟩
}

def certificate_862 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560285) (.wire 7351) (.wire 614628) (.wire 614670) := {
  difference := (.wire 614668)
  product := (.wire 614669)
  subtract := Or.inl ⟨⟨614668, by omega⟩, f.node_614668, rfl⟩
  multiply := Or.inl ⟨⟨614669, by omega⟩, f.node_614669, rfl⟩
  add := Or.inl ⟨⟨614670, by omega⟩, f.node_614670, rfl⟩
}

def certificate_863 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560285) (.wire 7352) (.wire 614639) (.wire 614673) := {
  difference := (.wire 614671)
  product := (.wire 614672)
  subtract := Or.inl ⟨⟨614671, by omega⟩, f.node_614671, rfl⟩
  multiply := Or.inl ⟨⟨614672, by omega⟩, f.node_614672, rfl⟩
  add := Or.inl ⟨⟨614673, by omega⟩, f.node_614673, rfl⟩
}

def certificate_864 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560285) (.wire 7353) (.wire 614605) (.wire 614676) := {
  difference := (.wire 614674)
  product := (.wire 614675)
  subtract := Or.inl ⟨⟨614674, by omega⟩, f.node_614674, rfl⟩
  multiply := Or.inl ⟨⟨614675, by omega⟩, f.node_614675, rfl⟩
  add := Or.inl ⟨⟨614676, by omega⟩, f.node_614676, rfl⟩
}

def certificate_865 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560285) (.wire 7354) (.wire 614616) (.wire 614679) := {
  difference := (.wire 614677)
  product := (.wire 614678)
  subtract := Or.inl ⟨⟨614677, by omega⟩, f.node_614677, rfl⟩
  multiply := Or.inl ⟨⟨614678, by omega⟩, f.node_614678, rfl⟩
  add := Or.inl ⟨⟨614679, by omega⟩, f.node_614679, rfl⟩
}

def certificate_866 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560285) (.wire 7355) (.wire 614627) (.wire 614682) := {
  difference := (.wire 614680)
  product := (.wire 614681)
  subtract := Or.inl ⟨⟨614680, by omega⟩, f.node_614680, rfl⟩
  multiply := Or.inl ⟨⟨614681, by omega⟩, f.node_614681, rfl⟩
  add := Or.inl ⟨⟨614682, by omega⟩, f.node_614682, rfl⟩
}

def certificate_867 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560290) (.wire 617080) (.wire 7356) (.wire 617117) := {
  difference := (.wire 617115)
  product := (.wire 617116)
  subtract := Or.inl ⟨⟨617115, by omega⟩, f.node_617115, rfl⟩
  multiply := Or.inl ⟨⟨617116, by omega⟩, f.node_617116, rfl⟩
  add := Or.inl ⟨⟨617117, by omega⟩, f.node_617117, rfl⟩
}

def certificate_868 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560290) (.wire 617091) (.wire 7357) (.wire 617120) := {
  difference := (.wire 617118)
  product := (.wire 617119)
  subtract := Or.inl ⟨⟨617118, by omega⟩, f.node_617118, rfl⟩
  multiply := Or.inl ⟨⟨617119, by omega⟩, f.node_617119, rfl⟩
  add := Or.inl ⟨⟨617120, by omega⟩, f.node_617120, rfl⟩
}

def certificate_869 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560290) (.wire 617102) (.wire 7358) (.wire 617123) := {
  difference := (.wire 617121)
  product := (.wire 617122)
  subtract := Or.inl ⟨⟨617121, by omega⟩, f.node_617121, rfl⟩
  multiply := Or.inl ⟨⟨617122, by omega⟩, f.node_617122, rfl⟩
  add := Or.inl ⟨⟨617123, by omega⟩, f.node_617123, rfl⟩
}

def certificate_870 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560290) (.wire 617113) (.wire 7359) (.wire 617126) := {
  difference := (.wire 617124)
  product := (.wire 617125)
  subtract := Or.inl ⟨⟨617124, by omega⟩, f.node_617124, rfl⟩
  multiply := Or.inl ⟨⟨617125, by omega⟩, f.node_617125, rfl⟩
  add := Or.inl ⟨⟨617126, by omega⟩, f.node_617126, rfl⟩
}

def certificate_871 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560290) (.wire 617079) (.wire 7360) (.wire 617129) := {
  difference := (.wire 617127)
  product := (.wire 617128)
  subtract := Or.inl ⟨⟨617127, by omega⟩, f.node_617127, rfl⟩
  multiply := Or.inl ⟨⟨617128, by omega⟩, f.node_617128, rfl⟩
  add := Or.inl ⟨⟨617129, by omega⟩, f.node_617129, rfl⟩
}

def certificate_872 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560290) (.wire 617090) (.wire 7361) (.wire 617132) := {
  difference := (.wire 617130)
  product := (.wire 617131)
  subtract := Or.inl ⟨⟨617130, by omega⟩, f.node_617130, rfl⟩
  multiply := Or.inl ⟨⟨617131, by omega⟩, f.node_617131, rfl⟩
  add := Or.inl ⟨⟨617132, by omega⟩, f.node_617132, rfl⟩
}

def certificate_873 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560290) (.wire 617101) (.wire 7362) (.wire 617135) := {
  difference := (.wire 617133)
  product := (.wire 617134)
  subtract := Or.inl ⟨⟨617133, by omega⟩, f.node_617133, rfl⟩
  multiply := Or.inl ⟨⟨617134, by omega⟩, f.node_617134, rfl⟩
  add := Or.inl ⟨⟨617135, by omega⟩, f.node_617135, rfl⟩
}

def certificate_874 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560290) (.wire 7356) (.wire 617080) (.wire 617138) := {
  difference := (.wire 617136)
  product := (.wire 617137)
  subtract := Or.inl ⟨⟨617136, by omega⟩, f.node_617136, rfl⟩
  multiply := Or.inl ⟨⟨617137, by omega⟩, f.node_617137, rfl⟩
  add := Or.inl ⟨⟨617138, by omega⟩, f.node_617138, rfl⟩
}

def certificate_875 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560290) (.wire 7357) (.wire 617091) (.wire 617141) := {
  difference := (.wire 617139)
  product := (.wire 617140)
  subtract := Or.inl ⟨⟨617139, by omega⟩, f.node_617139, rfl⟩
  multiply := Or.inl ⟨⟨617140, by omega⟩, f.node_617140, rfl⟩
  add := Or.inl ⟨⟨617141, by omega⟩, f.node_617141, rfl⟩
}

def certificate_876 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560290) (.wire 7358) (.wire 617102) (.wire 617144) := {
  difference := (.wire 617142)
  product := (.wire 617143)
  subtract := Or.inl ⟨⟨617142, by omega⟩, f.node_617142, rfl⟩
  multiply := Or.inl ⟨⟨617143, by omega⟩, f.node_617143, rfl⟩
  add := Or.inl ⟨⟨617144, by omega⟩, f.node_617144, rfl⟩
}

def certificate_877 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560290) (.wire 7359) (.wire 617113) (.wire 617147) := {
  difference := (.wire 617145)
  product := (.wire 617146)
  subtract := Or.inl ⟨⟨617145, by omega⟩, f.node_617145, rfl⟩
  multiply := Or.inl ⟨⟨617146, by omega⟩, f.node_617146, rfl⟩
  add := Or.inl ⟨⟨617147, by omega⟩, f.node_617147, rfl⟩
}

def certificate_878 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560290) (.wire 7360) (.wire 617079) (.wire 617150) := {
  difference := (.wire 617148)
  product := (.wire 617149)
  subtract := Or.inl ⟨⟨617148, by omega⟩, f.node_617148, rfl⟩
  multiply := Or.inl ⟨⟨617149, by omega⟩, f.node_617149, rfl⟩
  add := Or.inl ⟨⟨617150, by omega⟩, f.node_617150, rfl⟩
}

def certificate_879 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560290) (.wire 7361) (.wire 617090) (.wire 617153) := {
  difference := (.wire 617151)
  product := (.wire 617152)
  subtract := Or.inl ⟨⟨617151, by omega⟩, f.node_617151, rfl⟩
  multiply := Or.inl ⟨⟨617152, by omega⟩, f.node_617152, rfl⟩
  add := Or.inl ⟨⟨617153, by omega⟩, f.node_617153, rfl⟩
}

def certificate_880 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560290) (.wire 7362) (.wire 617101) (.wire 617156) := {
  difference := (.wire 617154)
  product := (.wire 617155)
  subtract := Or.inl ⟨⟨617154, by omega⟩, f.node_617154, rfl⟩
  multiply := Or.inl ⟨⟨617155, by omega⟩, f.node_617155, rfl⟩
  add := Or.inl ⟨⟨617156, by omega⟩, f.node_617156, rfl⟩
}

def certificate_881 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560295) (.wire 619554) (.wire 7363) (.wire 619591) := {
  difference := (.wire 619589)
  product := (.wire 619590)
  subtract := Or.inl ⟨⟨619589, by omega⟩, f.node_619589, rfl⟩
  multiply := Or.inl ⟨⟨619590, by omega⟩, f.node_619590, rfl⟩
  add := Or.inl ⟨⟨619591, by omega⟩, f.node_619591, rfl⟩
}

def certificate_882 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560295) (.wire 619565) (.wire 7364) (.wire 619594) := {
  difference := (.wire 619592)
  product := (.wire 619593)
  subtract := Or.inl ⟨⟨619592, by omega⟩, f.node_619592, rfl⟩
  multiply := Or.inl ⟨⟨619593, by omega⟩, f.node_619593, rfl⟩
  add := Or.inl ⟨⟨619594, by omega⟩, f.node_619594, rfl⟩
}

def certificate_883 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560295) (.wire 619576) (.wire 7365) (.wire 619597) := {
  difference := (.wire 619595)
  product := (.wire 619596)
  subtract := Or.inl ⟨⟨619595, by omega⟩, f.node_619595, rfl⟩
  multiply := Or.inl ⟨⟨619596, by omega⟩, f.node_619596, rfl⟩
  add := Or.inl ⟨⟨619597, by omega⟩, f.node_619597, rfl⟩
}

def certificate_884 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560295) (.wire 619587) (.wire 7366) (.wire 619600) := {
  difference := (.wire 619598)
  product := (.wire 619599)
  subtract := Or.inl ⟨⟨619598, by omega⟩, f.node_619598, rfl⟩
  multiply := Or.inl ⟨⟨619599, by omega⟩, f.node_619599, rfl⟩
  add := Or.inl ⟨⟨619600, by omega⟩, f.node_619600, rfl⟩
}

def certificate_885 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560295) (.wire 619553) (.wire 7367) (.wire 619603) := {
  difference := (.wire 619601)
  product := (.wire 619602)
  subtract := Or.inl ⟨⟨619601, by omega⟩, f.node_619601, rfl⟩
  multiply := Or.inl ⟨⟨619602, by omega⟩, f.node_619602, rfl⟩
  add := Or.inl ⟨⟨619603, by omega⟩, f.node_619603, rfl⟩
}

def certificate_886 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560295) (.wire 619564) (.wire 7368) (.wire 619606) := {
  difference := (.wire 619604)
  product := (.wire 619605)
  subtract := Or.inl ⟨⟨619604, by omega⟩, f.node_619604, rfl⟩
  multiply := Or.inl ⟨⟨619605, by omega⟩, f.node_619605, rfl⟩
  add := Or.inl ⟨⟨619606, by omega⟩, f.node_619606, rfl⟩
}

def certificate_887 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560295) (.wire 619575) (.wire 7369) (.wire 619609) := {
  difference := (.wire 619607)
  product := (.wire 619608)
  subtract := Or.inl ⟨⟨619607, by omega⟩, f.node_619607, rfl⟩
  multiply := Or.inl ⟨⟨619608, by omega⟩, f.node_619608, rfl⟩
  add := Or.inl ⟨⟨619609, by omega⟩, f.node_619609, rfl⟩
}

def certificate_888 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560295) (.wire 7363) (.wire 619554) (.wire 619612) := {
  difference := (.wire 619610)
  product := (.wire 619611)
  subtract := Or.inl ⟨⟨619610, by omega⟩, f.node_619610, rfl⟩
  multiply := Or.inl ⟨⟨619611, by omega⟩, f.node_619611, rfl⟩
  add := Or.inl ⟨⟨619612, by omega⟩, f.node_619612, rfl⟩
}

def certificate_889 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560295) (.wire 7364) (.wire 619565) (.wire 619615) := {
  difference := (.wire 619613)
  product := (.wire 619614)
  subtract := Or.inl ⟨⟨619613, by omega⟩, f.node_619613, rfl⟩
  multiply := Or.inl ⟨⟨619614, by omega⟩, f.node_619614, rfl⟩
  add := Or.inl ⟨⟨619615, by omega⟩, f.node_619615, rfl⟩
}

def certificate_890 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560295) (.wire 7365) (.wire 619576) (.wire 619618) := {
  difference := (.wire 619616)
  product := (.wire 619617)
  subtract := Or.inl ⟨⟨619616, by omega⟩, f.node_619616, rfl⟩
  multiply := Or.inl ⟨⟨619617, by omega⟩, f.node_619617, rfl⟩
  add := Or.inl ⟨⟨619618, by omega⟩, f.node_619618, rfl⟩
}

def certificate_891 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560295) (.wire 7366) (.wire 619587) (.wire 619621) := {
  difference := (.wire 619619)
  product := (.wire 619620)
  subtract := Or.inl ⟨⟨619619, by omega⟩, f.node_619619, rfl⟩
  multiply := Or.inl ⟨⟨619620, by omega⟩, f.node_619620, rfl⟩
  add := Or.inl ⟨⟨619621, by omega⟩, f.node_619621, rfl⟩
}

def certificate_892 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560295) (.wire 7367) (.wire 619553) (.wire 619624) := {
  difference := (.wire 619622)
  product := (.wire 619623)
  subtract := Or.inl ⟨⟨619622, by omega⟩, f.node_619622, rfl⟩
  multiply := Or.inl ⟨⟨619623, by omega⟩, f.node_619623, rfl⟩
  add := Or.inl ⟨⟨619624, by omega⟩, f.node_619624, rfl⟩
}

def certificate_893 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560295) (.wire 7368) (.wire 619564) (.wire 619627) := {
  difference := (.wire 619625)
  product := (.wire 619626)
  subtract := Or.inl ⟨⟨619625, by omega⟩, f.node_619625, rfl⟩
  multiply := Or.inl ⟨⟨619626, by omega⟩, f.node_619626, rfl⟩
  add := Or.inl ⟨⟨619627, by omega⟩, f.node_619627, rfl⟩
}

def certificate_894 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560295) (.wire 7369) (.wire 619575) (.wire 619630) := {
  difference := (.wire 619628)
  product := (.wire 619629)
  subtract := Or.inl ⟨⟨619628, by omega⟩, f.node_619628, rfl⟩
  multiply := Or.inl ⟨⟨619629, by omega⟩, f.node_619629, rfl⟩
  add := Or.inl ⟨⟨619630, by omega⟩, f.node_619630, rfl⟩
}

def certificate_895 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560300) (.wire 622028) (.wire 7370) (.wire 622065) := {
  difference := (.wire 622063)
  product := (.wire 622064)
  subtract := Or.inl ⟨⟨622063, by omega⟩, f.node_622063, rfl⟩
  multiply := Or.inl ⟨⟨622064, by omega⟩, f.node_622064, rfl⟩
  add := Or.inl ⟨⟨622065, by omega⟩, f.node_622065, rfl⟩
}

def certificate_896 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560300) (.wire 622039) (.wire 7371) (.wire 622068) := {
  difference := (.wire 622066)
  product := (.wire 622067)
  subtract := Or.inl ⟨⟨622066, by omega⟩, f.node_622066, rfl⟩
  multiply := Or.inl ⟨⟨622067, by omega⟩, f.node_622067, rfl⟩
  add := Or.inl ⟨⟨622068, by omega⟩, f.node_622068, rfl⟩
}

def certificate_897 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560300) (.wire 622050) (.wire 7372) (.wire 622071) := {
  difference := (.wire 622069)
  product := (.wire 622070)
  subtract := Or.inl ⟨⟨622069, by omega⟩, f.node_622069, rfl⟩
  multiply := Or.inl ⟨⟨622070, by omega⟩, f.node_622070, rfl⟩
  add := Or.inl ⟨⟨622071, by omega⟩, f.node_622071, rfl⟩
}

def certificate_898 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560300) (.wire 622061) (.wire 7373) (.wire 622074) := {
  difference := (.wire 622072)
  product := (.wire 622073)
  subtract := Or.inl ⟨⟨622072, by omega⟩, f.node_622072, rfl⟩
  multiply := Or.inl ⟨⟨622073, by omega⟩, f.node_622073, rfl⟩
  add := Or.inl ⟨⟨622074, by omega⟩, f.node_622074, rfl⟩
}

def certificate_899 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560300) (.wire 622027) (.wire 7374) (.wire 622077) := {
  difference := (.wire 622075)
  product := (.wire 622076)
  subtract := Or.inl ⟨⟨622075, by omega⟩, f.node_622075, rfl⟩
  multiply := Or.inl ⟨⟨622076, by omega⟩, f.node_622076, rfl⟩
  add := Or.inl ⟨⟨622077, by omega⟩, f.node_622077, rfl⟩
}

def certificate_900 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560300) (.wire 622038) (.wire 7375) (.wire 622080) := {
  difference := (.wire 622078)
  product := (.wire 622079)
  subtract := Or.inl ⟨⟨622078, by omega⟩, f.node_622078, rfl⟩
  multiply := Or.inl ⟨⟨622079, by omega⟩, f.node_622079, rfl⟩
  add := Or.inl ⟨⟨622080, by omega⟩, f.node_622080, rfl⟩
}

def certificate_901 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560300) (.wire 622049) (.wire 7376) (.wire 622083) := {
  difference := (.wire 622081)
  product := (.wire 622082)
  subtract := Or.inl ⟨⟨622081, by omega⟩, f.node_622081, rfl⟩
  multiply := Or.inl ⟨⟨622082, by omega⟩, f.node_622082, rfl⟩
  add := Or.inl ⟨⟨622083, by omega⟩, f.node_622083, rfl⟩
}

def certificate_902 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560300) (.wire 7370) (.wire 622028) (.wire 622086) := {
  difference := (.wire 622084)
  product := (.wire 622085)
  subtract := Or.inl ⟨⟨622084, by omega⟩, f.node_622084, rfl⟩
  multiply := Or.inl ⟨⟨622085, by omega⟩, f.node_622085, rfl⟩
  add := Or.inl ⟨⟨622086, by omega⟩, f.node_622086, rfl⟩
}

def certificate_903 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560300) (.wire 7371) (.wire 622039) (.wire 622089) := {
  difference := (.wire 622087)
  product := (.wire 622088)
  subtract := Or.inl ⟨⟨622087, by omega⟩, f.node_622087, rfl⟩
  multiply := Or.inl ⟨⟨622088, by omega⟩, f.node_622088, rfl⟩
  add := Or.inl ⟨⟨622089, by omega⟩, f.node_622089, rfl⟩
}

def certificate_904 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560300) (.wire 7372) (.wire 622050) (.wire 622092) := {
  difference := (.wire 622090)
  product := (.wire 622091)
  subtract := Or.inl ⟨⟨622090, by omega⟩, f.node_622090, rfl⟩
  multiply := Or.inl ⟨⟨622091, by omega⟩, f.node_622091, rfl⟩
  add := Or.inl ⟨⟨622092, by omega⟩, f.node_622092, rfl⟩
}

def certificate_905 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560300) (.wire 7373) (.wire 622061) (.wire 622095) := {
  difference := (.wire 622093)
  product := (.wire 622094)
  subtract := Or.inl ⟨⟨622093, by omega⟩, f.node_622093, rfl⟩
  multiply := Or.inl ⟨⟨622094, by omega⟩, f.node_622094, rfl⟩
  add := Or.inl ⟨⟨622095, by omega⟩, f.node_622095, rfl⟩
}

def certificate_906 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560300) (.wire 7374) (.wire 622027) (.wire 622098) := {
  difference := (.wire 622096)
  product := (.wire 622097)
  subtract := Or.inl ⟨⟨622096, by omega⟩, f.node_622096, rfl⟩
  multiply := Or.inl ⟨⟨622097, by omega⟩, f.node_622097, rfl⟩
  add := Or.inl ⟨⟨622098, by omega⟩, f.node_622098, rfl⟩
}

def certificate_907 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560300) (.wire 7375) (.wire 622038) (.wire 622101) := {
  difference := (.wire 622099)
  product := (.wire 622100)
  subtract := Or.inl ⟨⟨622099, by omega⟩, f.node_622099, rfl⟩
  multiply := Or.inl ⟨⟨622100, by omega⟩, f.node_622100, rfl⟩
  add := Or.inl ⟨⟨622101, by omega⟩, f.node_622101, rfl⟩
}

def certificate_908 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560300) (.wire 7376) (.wire 622049) (.wire 622104) := {
  difference := (.wire 622102)
  product := (.wire 622103)
  subtract := Or.inl ⟨⟨622102, by omega⟩, f.node_622102, rfl⟩
  multiply := Or.inl ⟨⟨622103, by omega⟩, f.node_622103, rfl⟩
  add := Or.inl ⟨⟨622104, by omega⟩, f.node_622104, rfl⟩
}

def certificate_909 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560305) (.wire 624502) (.wire 7377) (.wire 624539) := {
  difference := (.wire 624537)
  product := (.wire 624538)
  subtract := Or.inl ⟨⟨624537, by omega⟩, f.node_624537, rfl⟩
  multiply := Or.inl ⟨⟨624538, by omega⟩, f.node_624538, rfl⟩
  add := Or.inl ⟨⟨624539, by omega⟩, f.node_624539, rfl⟩
}

def certificate_910 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560305) (.wire 624513) (.wire 7378) (.wire 624542) := {
  difference := (.wire 624540)
  product := (.wire 624541)
  subtract := Or.inl ⟨⟨624540, by omega⟩, f.node_624540, rfl⟩
  multiply := Or.inl ⟨⟨624541, by omega⟩, f.node_624541, rfl⟩
  add := Or.inl ⟨⟨624542, by omega⟩, f.node_624542, rfl⟩
}

def certificate_911 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560305) (.wire 624524) (.wire 7379) (.wire 624545) := {
  difference := (.wire 624543)
  product := (.wire 624544)
  subtract := Or.inl ⟨⟨624543, by omega⟩, f.node_624543, rfl⟩
  multiply := Or.inl ⟨⟨624544, by omega⟩, f.node_624544, rfl⟩
  add := Or.inl ⟨⟨624545, by omega⟩, f.node_624545, rfl⟩
}

def certificate_912 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560305) (.wire 624535) (.wire 7380) (.wire 624548) := {
  difference := (.wire 624546)
  product := (.wire 624547)
  subtract := Or.inl ⟨⟨624546, by omega⟩, f.node_624546, rfl⟩
  multiply := Or.inl ⟨⟨624547, by omega⟩, f.node_624547, rfl⟩
  add := Or.inl ⟨⟨624548, by omega⟩, f.node_624548, rfl⟩
}

def certificate_913 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560305) (.wire 624501) (.wire 7381) (.wire 624551) := {
  difference := (.wire 624549)
  product := (.wire 624550)
  subtract := Or.inl ⟨⟨624549, by omega⟩, f.node_624549, rfl⟩
  multiply := Or.inl ⟨⟨624550, by omega⟩, f.node_624550, rfl⟩
  add := Or.inl ⟨⟨624551, by omega⟩, f.node_624551, rfl⟩
}

def certificate_914 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560305) (.wire 624512) (.wire 7382) (.wire 624554) := {
  difference := (.wire 624552)
  product := (.wire 624553)
  subtract := Or.inl ⟨⟨624552, by omega⟩, f.node_624552, rfl⟩
  multiply := Or.inl ⟨⟨624553, by omega⟩, f.node_624553, rfl⟩
  add := Or.inl ⟨⟨624554, by omega⟩, f.node_624554, rfl⟩
}

def certificate_915 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560305) (.wire 624523) (.wire 7383) (.wire 624557) := {
  difference := (.wire 624555)
  product := (.wire 624556)
  subtract := Or.inl ⟨⟨624555, by omega⟩, f.node_624555, rfl⟩
  multiply := Or.inl ⟨⟨624556, by omega⟩, f.node_624556, rfl⟩
  add := Or.inl ⟨⟨624557, by omega⟩, f.node_624557, rfl⟩
}

def certificate_916 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560305) (.wire 7377) (.wire 624502) (.wire 624560) := {
  difference := (.wire 624558)
  product := (.wire 624559)
  subtract := Or.inl ⟨⟨624558, by omega⟩, f.node_624558, rfl⟩
  multiply := Or.inl ⟨⟨624559, by omega⟩, f.node_624559, rfl⟩
  add := Or.inl ⟨⟨624560, by omega⟩, f.node_624560, rfl⟩
}

def certificate_917 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560305) (.wire 7378) (.wire 624513) (.wire 624563) := {
  difference := (.wire 624561)
  product := (.wire 624562)
  subtract := Or.inl ⟨⟨624561, by omega⟩, f.node_624561, rfl⟩
  multiply := Or.inl ⟨⟨624562, by omega⟩, f.node_624562, rfl⟩
  add := Or.inl ⟨⟨624563, by omega⟩, f.node_624563, rfl⟩
}

def certificate_918 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560305) (.wire 7379) (.wire 624524) (.wire 624566) := {
  difference := (.wire 624564)
  product := (.wire 624565)
  subtract := Or.inl ⟨⟨624564, by omega⟩, f.node_624564, rfl⟩
  multiply := Or.inl ⟨⟨624565, by omega⟩, f.node_624565, rfl⟩
  add := Or.inl ⟨⟨624566, by omega⟩, f.node_624566, rfl⟩
}

def certificate_919 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560305) (.wire 7380) (.wire 624535) (.wire 624569) := {
  difference := (.wire 624567)
  product := (.wire 624568)
  subtract := Or.inl ⟨⟨624567, by omega⟩, f.node_624567, rfl⟩
  multiply := Or.inl ⟨⟨624568, by omega⟩, f.node_624568, rfl⟩
  add := Or.inl ⟨⟨624569, by omega⟩, f.node_624569, rfl⟩
}

def certificate_920 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560305) (.wire 7381) (.wire 624501) (.wire 624572) := {
  difference := (.wire 624570)
  product := (.wire 624571)
  subtract := Or.inl ⟨⟨624570, by omega⟩, f.node_624570, rfl⟩
  multiply := Or.inl ⟨⟨624571, by omega⟩, f.node_624571, rfl⟩
  add := Or.inl ⟨⟨624572, by omega⟩, f.node_624572, rfl⟩
}

def certificate_921 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560305) (.wire 7382) (.wire 624512) (.wire 624575) := {
  difference := (.wire 624573)
  product := (.wire 624574)
  subtract := Or.inl ⟨⟨624573, by omega⟩, f.node_624573, rfl⟩
  multiply := Or.inl ⟨⟨624574, by omega⟩, f.node_624574, rfl⟩
  add := Or.inl ⟨⟨624575, by omega⟩, f.node_624575, rfl⟩
}

def certificate_922 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560305) (.wire 7383) (.wire 624523) (.wire 624578) := {
  difference := (.wire 624576)
  product := (.wire 624577)
  subtract := Or.inl ⟨⟨624576, by omega⟩, f.node_624576, rfl⟩
  multiply := Or.inl ⟨⟨624577, by omega⟩, f.node_624577, rfl⟩
  add := Or.inl ⟨⟨624578, by omega⟩, f.node_624578, rfl⟩
}

def certificate_923 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560310) (.wire 626976) (.wire 7384) (.wire 627013) := {
  difference := (.wire 627011)
  product := (.wire 627012)
  subtract := Or.inl ⟨⟨627011, by omega⟩, f.node_627011, rfl⟩
  multiply := Or.inl ⟨⟨627012, by omega⟩, f.node_627012, rfl⟩
  add := Or.inl ⟨⟨627013, by omega⟩, f.node_627013, rfl⟩
}

def certificate_924 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560310) (.wire 626987) (.wire 7385) (.wire 627016) := {
  difference := (.wire 627014)
  product := (.wire 627015)
  subtract := Or.inl ⟨⟨627014, by omega⟩, f.node_627014, rfl⟩
  multiply := Or.inl ⟨⟨627015, by omega⟩, f.node_627015, rfl⟩
  add := Or.inl ⟨⟨627016, by omega⟩, f.node_627016, rfl⟩
}

def certificate_925 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560310) (.wire 626998) (.wire 7386) (.wire 627019) := {
  difference := (.wire 627017)
  product := (.wire 627018)
  subtract := Or.inl ⟨⟨627017, by omega⟩, f.node_627017, rfl⟩
  multiply := Or.inl ⟨⟨627018, by omega⟩, f.node_627018, rfl⟩
  add := Or.inl ⟨⟨627019, by omega⟩, f.node_627019, rfl⟩
}

def certificate_926 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560310) (.wire 627009) (.wire 7387) (.wire 627022) := {
  difference := (.wire 627020)
  product := (.wire 627021)
  subtract := Or.inl ⟨⟨627020, by omega⟩, f.node_627020, rfl⟩
  multiply := Or.inl ⟨⟨627021, by omega⟩, f.node_627021, rfl⟩
  add := Or.inl ⟨⟨627022, by omega⟩, f.node_627022, rfl⟩
}

def certificate_927 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560310) (.wire 626975) (.wire 7388) (.wire 627025) := {
  difference := (.wire 627023)
  product := (.wire 627024)
  subtract := Or.inl ⟨⟨627023, by omega⟩, f.node_627023, rfl⟩
  multiply := Or.inl ⟨⟨627024, by omega⟩, f.node_627024, rfl⟩
  add := Or.inl ⟨⟨627025, by omega⟩, f.node_627025, rfl⟩
}

def certificate_928 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560310) (.wire 626986) (.wire 7389) (.wire 627028) := {
  difference := (.wire 627026)
  product := (.wire 627027)
  subtract := Or.inl ⟨⟨627026, by omega⟩, f.node_627026, rfl⟩
  multiply := Or.inl ⟨⟨627027, by omega⟩, f.node_627027, rfl⟩
  add := Or.inl ⟨⟨627028, by omega⟩, f.node_627028, rfl⟩
}

def certificate_929 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560310) (.wire 626997) (.wire 7390) (.wire 627031) := {
  difference := (.wire 627029)
  product := (.wire 627030)
  subtract := Or.inl ⟨⟨627029, by omega⟩, f.node_627029, rfl⟩
  multiply := Or.inl ⟨⟨627030, by omega⟩, f.node_627030, rfl⟩
  add := Or.inl ⟨⟨627031, by omega⟩, f.node_627031, rfl⟩
}

def certificate_930 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560310) (.wire 7384) (.wire 626976) (.wire 627034) := {
  difference := (.wire 627032)
  product := (.wire 627033)
  subtract := Or.inl ⟨⟨627032, by omega⟩, f.node_627032, rfl⟩
  multiply := Or.inl ⟨⟨627033, by omega⟩, f.node_627033, rfl⟩
  add := Or.inl ⟨⟨627034, by omega⟩, f.node_627034, rfl⟩
}

def certificate_931 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560310) (.wire 7385) (.wire 626987) (.wire 627037) := {
  difference := (.wire 627035)
  product := (.wire 627036)
  subtract := Or.inl ⟨⟨627035, by omega⟩, f.node_627035, rfl⟩
  multiply := Or.inl ⟨⟨627036, by omega⟩, f.node_627036, rfl⟩
  add := Or.inl ⟨⟨627037, by omega⟩, f.node_627037, rfl⟩
}

def certificate_932 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560310) (.wire 7386) (.wire 626998) (.wire 627040) := {
  difference := (.wire 627038)
  product := (.wire 627039)
  subtract := Or.inl ⟨⟨627038, by omega⟩, f.node_627038, rfl⟩
  multiply := Or.inl ⟨⟨627039, by omega⟩, f.node_627039, rfl⟩
  add := Or.inl ⟨⟨627040, by omega⟩, f.node_627040, rfl⟩
}

def certificate_933 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560310) (.wire 7387) (.wire 627009) (.wire 627043) := {
  difference := (.wire 627041)
  product := (.wire 627042)
  subtract := Or.inl ⟨⟨627041, by omega⟩, f.node_627041, rfl⟩
  multiply := Or.inl ⟨⟨627042, by omega⟩, f.node_627042, rfl⟩
  add := Or.inl ⟨⟨627043, by omega⟩, f.node_627043, rfl⟩
}

def certificate_934 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560310) (.wire 7388) (.wire 626975) (.wire 627046) := {
  difference := (.wire 627044)
  product := (.wire 627045)
  subtract := Or.inl ⟨⟨627044, by omega⟩, f.node_627044, rfl⟩
  multiply := Or.inl ⟨⟨627045, by omega⟩, f.node_627045, rfl⟩
  add := Or.inl ⟨⟨627046, by omega⟩, f.node_627046, rfl⟩
}

def certificate_935 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560310) (.wire 7389) (.wire 626986) (.wire 627049) := {
  difference := (.wire 627047)
  product := (.wire 627048)
  subtract := Or.inl ⟨⟨627047, by omega⟩, f.node_627047, rfl⟩
  multiply := Or.inl ⟨⟨627048, by omega⟩, f.node_627048, rfl⟩
  add := Or.inl ⟨⟨627049, by omega⟩, f.node_627049, rfl⟩
}

def certificate_936 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560310) (.wire 7390) (.wire 626997) (.wire 627052) := {
  difference := (.wire 627050)
  product := (.wire 627051)
  subtract := Or.inl ⟨⟨627050, by omega⟩, f.node_627050, rfl⟩
  multiply := Or.inl ⟨⟨627051, by omega⟩, f.node_627051, rfl⟩
  add := Or.inl ⟨⟨627052, by omega⟩, f.node_627052, rfl⟩
}

def certificate_937 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560315) (.wire 629450) (.wire 7391) (.wire 629487) := {
  difference := (.wire 629485)
  product := (.wire 629486)
  subtract := Or.inl ⟨⟨629485, by omega⟩, f.node_629485, rfl⟩
  multiply := Or.inl ⟨⟨629486, by omega⟩, f.node_629486, rfl⟩
  add := Or.inl ⟨⟨629487, by omega⟩, f.node_629487, rfl⟩
}

def certificate_938 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560315) (.wire 629461) (.wire 7392) (.wire 629490) := {
  difference := (.wire 629488)
  product := (.wire 629489)
  subtract := Or.inl ⟨⟨629488, by omega⟩, f.node_629488, rfl⟩
  multiply := Or.inl ⟨⟨629489, by omega⟩, f.node_629489, rfl⟩
  add := Or.inl ⟨⟨629490, by omega⟩, f.node_629490, rfl⟩
}

def certificate_939 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560315) (.wire 629472) (.wire 7393) (.wire 629493) := {
  difference := (.wire 629491)
  product := (.wire 629492)
  subtract := Or.inl ⟨⟨629491, by omega⟩, f.node_629491, rfl⟩
  multiply := Or.inl ⟨⟨629492, by omega⟩, f.node_629492, rfl⟩
  add := Or.inl ⟨⟨629493, by omega⟩, f.node_629493, rfl⟩
}

def certificate_940 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560315) (.wire 629483) (.wire 7394) (.wire 629496) := {
  difference := (.wire 629494)
  product := (.wire 629495)
  subtract := Or.inl ⟨⟨629494, by omega⟩, f.node_629494, rfl⟩
  multiply := Or.inl ⟨⟨629495, by omega⟩, f.node_629495, rfl⟩
  add := Or.inl ⟨⟨629496, by omega⟩, f.node_629496, rfl⟩
}

def certificate_941 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560315) (.wire 629449) (.wire 7395) (.wire 629499) := {
  difference := (.wire 629497)
  product := (.wire 629498)
  subtract := Or.inl ⟨⟨629497, by omega⟩, f.node_629497, rfl⟩
  multiply := Or.inl ⟨⟨629498, by omega⟩, f.node_629498, rfl⟩
  add := Or.inl ⟨⟨629499, by omega⟩, f.node_629499, rfl⟩
}

def certificate_942 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560315) (.wire 629460) (.wire 7396) (.wire 629502) := {
  difference := (.wire 629500)
  product := (.wire 629501)
  subtract := Or.inl ⟨⟨629500, by omega⟩, f.node_629500, rfl⟩
  multiply := Or.inl ⟨⟨629501, by omega⟩, f.node_629501, rfl⟩
  add := Or.inl ⟨⟨629502, by omega⟩, f.node_629502, rfl⟩
}

def certificate_943 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560315) (.wire 629471) (.wire 7397) (.wire 629505) := {
  difference := (.wire 629503)
  product := (.wire 629504)
  subtract := Or.inl ⟨⟨629503, by omega⟩, f.node_629503, rfl⟩
  multiply := Or.inl ⟨⟨629504, by omega⟩, f.node_629504, rfl⟩
  add := Or.inl ⟨⟨629505, by omega⟩, f.node_629505, rfl⟩
}

def certificate_944 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560315) (.wire 7391) (.wire 629450) (.wire 629508) := {
  difference := (.wire 629506)
  product := (.wire 629507)
  subtract := Or.inl ⟨⟨629506, by omega⟩, f.node_629506, rfl⟩
  multiply := Or.inl ⟨⟨629507, by omega⟩, f.node_629507, rfl⟩
  add := Or.inl ⟨⟨629508, by omega⟩, f.node_629508, rfl⟩
}

def certificate_945 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560315) (.wire 7392) (.wire 629461) (.wire 629511) := {
  difference := (.wire 629509)
  product := (.wire 629510)
  subtract := Or.inl ⟨⟨629509, by omega⟩, f.node_629509, rfl⟩
  multiply := Or.inl ⟨⟨629510, by omega⟩, f.node_629510, rfl⟩
  add := Or.inl ⟨⟨629511, by omega⟩, f.node_629511, rfl⟩
}

def certificate_946 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560315) (.wire 7393) (.wire 629472) (.wire 629514) := {
  difference := (.wire 629512)
  product := (.wire 629513)
  subtract := Or.inl ⟨⟨629512, by omega⟩, f.node_629512, rfl⟩
  multiply := Or.inl ⟨⟨629513, by omega⟩, f.node_629513, rfl⟩
  add := Or.inl ⟨⟨629514, by omega⟩, f.node_629514, rfl⟩
}

def certificate_947 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560315) (.wire 7394) (.wire 629483) (.wire 629517) := {
  difference := (.wire 629515)
  product := (.wire 629516)
  subtract := Or.inl ⟨⟨629515, by omega⟩, f.node_629515, rfl⟩
  multiply := Or.inl ⟨⟨629516, by omega⟩, f.node_629516, rfl⟩
  add := Or.inl ⟨⟨629517, by omega⟩, f.node_629517, rfl⟩
}

def certificate_948 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560315) (.wire 7395) (.wire 629449) (.wire 629520) := {
  difference := (.wire 629518)
  product := (.wire 629519)
  subtract := Or.inl ⟨⟨629518, by omega⟩, f.node_629518, rfl⟩
  multiply := Or.inl ⟨⟨629519, by omega⟩, f.node_629519, rfl⟩
  add := Or.inl ⟨⟨629520, by omega⟩, f.node_629520, rfl⟩
}

def certificate_949 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560315) (.wire 7396) (.wire 629460) (.wire 629523) := {
  difference := (.wire 629521)
  product := (.wire 629522)
  subtract := Or.inl ⟨⟨629521, by omega⟩, f.node_629521, rfl⟩
  multiply := Or.inl ⟨⟨629522, by omega⟩, f.node_629522, rfl⟩
  add := Or.inl ⟨⟨629523, by omega⟩, f.node_629523, rfl⟩
}

def certificate_950 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560315) (.wire 7397) (.wire 629471) (.wire 629526) := {
  difference := (.wire 629524)
  product := (.wire 629525)
  subtract := Or.inl ⟨⟨629524, by omega⟩, f.node_629524, rfl⟩
  multiply := Or.inl ⟨⟨629525, by omega⟩, f.node_629525, rfl⟩
  add := Or.inl ⟨⟨629526, by omega⟩, f.node_629526, rfl⟩
}

def certificate_951 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560320) (.wire 631924) (.wire 7398) (.wire 631961) := {
  difference := (.wire 631959)
  product := (.wire 631960)
  subtract := Or.inl ⟨⟨631959, by omega⟩, f.node_631959, rfl⟩
  multiply := Or.inl ⟨⟨631960, by omega⟩, f.node_631960, rfl⟩
  add := Or.inl ⟨⟨631961, by omega⟩, f.node_631961, rfl⟩
}

def certificate_952 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560320) (.wire 631935) (.wire 7399) (.wire 631964) := {
  difference := (.wire 631962)
  product := (.wire 631963)
  subtract := Or.inl ⟨⟨631962, by omega⟩, f.node_631962, rfl⟩
  multiply := Or.inl ⟨⟨631963, by omega⟩, f.node_631963, rfl⟩
  add := Or.inl ⟨⟨631964, by omega⟩, f.node_631964, rfl⟩
}

def certificate_953 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560320) (.wire 631946) (.wire 7400) (.wire 631967) := {
  difference := (.wire 631965)
  product := (.wire 631966)
  subtract := Or.inl ⟨⟨631965, by omega⟩, f.node_631965, rfl⟩
  multiply := Or.inl ⟨⟨631966, by omega⟩, f.node_631966, rfl⟩
  add := Or.inl ⟨⟨631967, by omega⟩, f.node_631967, rfl⟩
}

def certificate_954 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560320) (.wire 631957) (.wire 7401) (.wire 631970) := {
  difference := (.wire 631968)
  product := (.wire 631969)
  subtract := Or.inl ⟨⟨631968, by omega⟩, f.node_631968, rfl⟩
  multiply := Or.inl ⟨⟨631969, by omega⟩, f.node_631969, rfl⟩
  add := Or.inl ⟨⟨631970, by omega⟩, f.node_631970, rfl⟩
}

def certificate_955 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560320) (.wire 631923) (.wire 7402) (.wire 631973) := {
  difference := (.wire 631971)
  product := (.wire 631972)
  subtract := Or.inl ⟨⟨631971, by omega⟩, f.node_631971, rfl⟩
  multiply := Or.inl ⟨⟨631972, by omega⟩, f.node_631972, rfl⟩
  add := Or.inl ⟨⟨631973, by omega⟩, f.node_631973, rfl⟩
}

def certificate_956 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560320) (.wire 631934) (.wire 7403) (.wire 631976) := {
  difference := (.wire 631974)
  product := (.wire 631975)
  subtract := Or.inl ⟨⟨631974, by omega⟩, f.node_631974, rfl⟩
  multiply := Or.inl ⟨⟨631975, by omega⟩, f.node_631975, rfl⟩
  add := Or.inl ⟨⟨631976, by omega⟩, f.node_631976, rfl⟩
}

def certificate_957 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560320) (.wire 631945) (.wire 7404) (.wire 631979) := {
  difference := (.wire 631977)
  product := (.wire 631978)
  subtract := Or.inl ⟨⟨631977, by omega⟩, f.node_631977, rfl⟩
  multiply := Or.inl ⟨⟨631978, by omega⟩, f.node_631978, rfl⟩
  add := Or.inl ⟨⟨631979, by omega⟩, f.node_631979, rfl⟩
}

def certificate_958 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560320) (.wire 7398) (.wire 631924) (.wire 631982) := {
  difference := (.wire 631980)
  product := (.wire 631981)
  subtract := Or.inl ⟨⟨631980, by omega⟩, f.node_631980, rfl⟩
  multiply := Or.inl ⟨⟨631981, by omega⟩, f.node_631981, rfl⟩
  add := Or.inl ⟨⟨631982, by omega⟩, f.node_631982, rfl⟩
}

def certificate_959 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560320) (.wire 7399) (.wire 631935) (.wire 631985) := {
  difference := (.wire 631983)
  product := (.wire 631984)
  subtract := Or.inl ⟨⟨631983, by omega⟩, f.node_631983, rfl⟩
  multiply := Or.inl ⟨⟨631984, by omega⟩, f.node_631984, rfl⟩
  add := Or.inl ⟨⟨631985, by omega⟩, f.node_631985, rfl⟩
}

def certificate_960 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560320) (.wire 7400) (.wire 631946) (.wire 631988) := {
  difference := (.wire 631986)
  product := (.wire 631987)
  subtract := Or.inl ⟨⟨631986, by omega⟩, f.node_631986, rfl⟩
  multiply := Or.inl ⟨⟨631987, by omega⟩, f.node_631987, rfl⟩
  add := Or.inl ⟨⟨631988, by omega⟩, f.node_631988, rfl⟩
}

def certificate_961 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560320) (.wire 7401) (.wire 631957) (.wire 631991) := {
  difference := (.wire 631989)
  product := (.wire 631990)
  subtract := Or.inl ⟨⟨631989, by omega⟩, f.node_631989, rfl⟩
  multiply := Or.inl ⟨⟨631990, by omega⟩, f.node_631990, rfl⟩
  add := Or.inl ⟨⟨631991, by omega⟩, f.node_631991, rfl⟩
}

def certificate_962 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560320) (.wire 7402) (.wire 631923) (.wire 631994) := {
  difference := (.wire 631992)
  product := (.wire 631993)
  subtract := Or.inl ⟨⟨631992, by omega⟩, f.node_631992, rfl⟩
  multiply := Or.inl ⟨⟨631993, by omega⟩, f.node_631993, rfl⟩
  add := Or.inl ⟨⟨631994, by omega⟩, f.node_631994, rfl⟩
}

def certificate_963 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560320) (.wire 7403) (.wire 631934) (.wire 631997) := {
  difference := (.wire 631995)
  product := (.wire 631996)
  subtract := Or.inl ⟨⟨631995, by omega⟩, f.node_631995, rfl⟩
  multiply := Or.inl ⟨⟨631996, by omega⟩, f.node_631996, rfl⟩
  add := Or.inl ⟨⟨631997, by omega⟩, f.node_631997, rfl⟩
}

def certificate_964 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560320) (.wire 7404) (.wire 631945) (.wire 632000) := {
  difference := (.wire 631998)
  product := (.wire 631999)
  subtract := Or.inl ⟨⟨631998, by omega⟩, f.node_631998, rfl⟩
  multiply := Or.inl ⟨⟨631999, by omega⟩, f.node_631999, rfl⟩
  add := Or.inl ⟨⟨632000, by omega⟩, f.node_632000, rfl⟩
}

def certificate_965 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560325) (.wire 634398) (.wire 7405) (.wire 634435) := {
  difference := (.wire 634433)
  product := (.wire 634434)
  subtract := Or.inl ⟨⟨634433, by omega⟩, f.node_634433, rfl⟩
  multiply := Or.inl ⟨⟨634434, by omega⟩, f.node_634434, rfl⟩
  add := Or.inl ⟨⟨634435, by omega⟩, f.node_634435, rfl⟩
}

def certificate_966 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560325) (.wire 634409) (.wire 7406) (.wire 634438) := {
  difference := (.wire 634436)
  product := (.wire 634437)
  subtract := Or.inl ⟨⟨634436, by omega⟩, f.node_634436, rfl⟩
  multiply := Or.inl ⟨⟨634437, by omega⟩, f.node_634437, rfl⟩
  add := Or.inl ⟨⟨634438, by omega⟩, f.node_634438, rfl⟩
}

def certificate_967 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560325) (.wire 634420) (.wire 7407) (.wire 634441) := {
  difference := (.wire 634439)
  product := (.wire 634440)
  subtract := Or.inl ⟨⟨634439, by omega⟩, f.node_634439, rfl⟩
  multiply := Or.inl ⟨⟨634440, by omega⟩, f.node_634440, rfl⟩
  add := Or.inl ⟨⟨634441, by omega⟩, f.node_634441, rfl⟩
}

def certificate_968 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560325) (.wire 634431) (.wire 7408) (.wire 634444) := {
  difference := (.wire 634442)
  product := (.wire 634443)
  subtract := Or.inl ⟨⟨634442, by omega⟩, f.node_634442, rfl⟩
  multiply := Or.inl ⟨⟨634443, by omega⟩, f.node_634443, rfl⟩
  add := Or.inl ⟨⟨634444, by omega⟩, f.node_634444, rfl⟩
}

def certificate_969 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560325) (.wire 634397) (.wire 7409) (.wire 634447) := {
  difference := (.wire 634445)
  product := (.wire 634446)
  subtract := Or.inl ⟨⟨634445, by omega⟩, f.node_634445, rfl⟩
  multiply := Or.inl ⟨⟨634446, by omega⟩, f.node_634446, rfl⟩
  add := Or.inl ⟨⟨634447, by omega⟩, f.node_634447, rfl⟩
}

def certificate_970 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560325) (.wire 634408) (.wire 7410) (.wire 634450) := {
  difference := (.wire 634448)
  product := (.wire 634449)
  subtract := Or.inl ⟨⟨634448, by omega⟩, f.node_634448, rfl⟩
  multiply := Or.inl ⟨⟨634449, by omega⟩, f.node_634449, rfl⟩
  add := Or.inl ⟨⟨634450, by omega⟩, f.node_634450, rfl⟩
}

def certificate_971 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560325) (.wire 634419) (.wire 7411) (.wire 634453) := {
  difference := (.wire 634451)
  product := (.wire 634452)
  subtract := Or.inl ⟨⟨634451, by omega⟩, f.node_634451, rfl⟩
  multiply := Or.inl ⟨⟨634452, by omega⟩, f.node_634452, rfl⟩
  add := Or.inl ⟨⟨634453, by omega⟩, f.node_634453, rfl⟩
}

def certificate_972 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560325) (.wire 7405) (.wire 634398) (.wire 634456) := {
  difference := (.wire 634454)
  product := (.wire 634455)
  subtract := Or.inl ⟨⟨634454, by omega⟩, f.node_634454, rfl⟩
  multiply := Or.inl ⟨⟨634455, by omega⟩, f.node_634455, rfl⟩
  add := Or.inl ⟨⟨634456, by omega⟩, f.node_634456, rfl⟩
}

def certificate_973 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560325) (.wire 7406) (.wire 634409) (.wire 634459) := {
  difference := (.wire 634457)
  product := (.wire 634458)
  subtract := Or.inl ⟨⟨634457, by omega⟩, f.node_634457, rfl⟩
  multiply := Or.inl ⟨⟨634458, by omega⟩, f.node_634458, rfl⟩
  add := Or.inl ⟨⟨634459, by omega⟩, f.node_634459, rfl⟩
}

def certificate_974 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560325) (.wire 7407) (.wire 634420) (.wire 634462) := {
  difference := (.wire 634460)
  product := (.wire 634461)
  subtract := Or.inl ⟨⟨634460, by omega⟩, f.node_634460, rfl⟩
  multiply := Or.inl ⟨⟨634461, by omega⟩, f.node_634461, rfl⟩
  add := Or.inl ⟨⟨634462, by omega⟩, f.node_634462, rfl⟩
}

def certificate_975 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560325) (.wire 7408) (.wire 634431) (.wire 634465) := {
  difference := (.wire 634463)
  product := (.wire 634464)
  subtract := Or.inl ⟨⟨634463, by omega⟩, f.node_634463, rfl⟩
  multiply := Or.inl ⟨⟨634464, by omega⟩, f.node_634464, rfl⟩
  add := Or.inl ⟨⟨634465, by omega⟩, f.node_634465, rfl⟩
}

def certificate_976 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560325) (.wire 7409) (.wire 634397) (.wire 634468) := {
  difference := (.wire 634466)
  product := (.wire 634467)
  subtract := Or.inl ⟨⟨634466, by omega⟩, f.node_634466, rfl⟩
  multiply := Or.inl ⟨⟨634467, by omega⟩, f.node_634467, rfl⟩
  add := Or.inl ⟨⟨634468, by omega⟩, f.node_634468, rfl⟩
}

def certificate_977 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560325) (.wire 7410) (.wire 634408) (.wire 634471) := {
  difference := (.wire 634469)
  product := (.wire 634470)
  subtract := Or.inl ⟨⟨634469, by omega⟩, f.node_634469, rfl⟩
  multiply := Or.inl ⟨⟨634470, by omega⟩, f.node_634470, rfl⟩
  add := Or.inl ⟨⟨634471, by omega⟩, f.node_634471, rfl⟩
}

def certificate_978 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560325) (.wire 7411) (.wire 634419) (.wire 634474) := {
  difference := (.wire 634472)
  product := (.wire 634473)
  subtract := Or.inl ⟨⟨634472, by omega⟩, f.node_634472, rfl⟩
  multiply := Or.inl ⟨⟨634473, by omega⟩, f.node_634473, rfl⟩
  add := Or.inl ⟨⟨634474, by omega⟩, f.node_634474, rfl⟩
}

def certificate_979 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560330) (.wire 636872) (.wire 7412) (.wire 636909) := {
  difference := (.wire 636907)
  product := (.wire 636908)
  subtract := Or.inl ⟨⟨636907, by omega⟩, f.node_636907, rfl⟩
  multiply := Or.inl ⟨⟨636908, by omega⟩, f.node_636908, rfl⟩
  add := Or.inl ⟨⟨636909, by omega⟩, f.node_636909, rfl⟩
}

def certificate_980 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560330) (.wire 636883) (.wire 7413) (.wire 636912) := {
  difference := (.wire 636910)
  product := (.wire 636911)
  subtract := Or.inl ⟨⟨636910, by omega⟩, f.node_636910, rfl⟩
  multiply := Or.inl ⟨⟨636911, by omega⟩, f.node_636911, rfl⟩
  add := Or.inl ⟨⟨636912, by omega⟩, f.node_636912, rfl⟩
}

def certificate_981 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560330) (.wire 636894) (.wire 7414) (.wire 636915) := {
  difference := (.wire 636913)
  product := (.wire 636914)
  subtract := Or.inl ⟨⟨636913, by omega⟩, f.node_636913, rfl⟩
  multiply := Or.inl ⟨⟨636914, by omega⟩, f.node_636914, rfl⟩
  add := Or.inl ⟨⟨636915, by omega⟩, f.node_636915, rfl⟩
}

def certificate_982 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560330) (.wire 636905) (.wire 7415) (.wire 636918) := {
  difference := (.wire 636916)
  product := (.wire 636917)
  subtract := Or.inl ⟨⟨636916, by omega⟩, f.node_636916, rfl⟩
  multiply := Or.inl ⟨⟨636917, by omega⟩, f.node_636917, rfl⟩
  add := Or.inl ⟨⟨636918, by omega⟩, f.node_636918, rfl⟩
}

def certificate_983 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560330) (.wire 636871) (.wire 7416) (.wire 636921) := {
  difference := (.wire 636919)
  product := (.wire 636920)
  subtract := Or.inl ⟨⟨636919, by omega⟩, f.node_636919, rfl⟩
  multiply := Or.inl ⟨⟨636920, by omega⟩, f.node_636920, rfl⟩
  add := Or.inl ⟨⟨636921, by omega⟩, f.node_636921, rfl⟩
}

def certificate_984 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560330) (.wire 636882) (.wire 7417) (.wire 636924) := {
  difference := (.wire 636922)
  product := (.wire 636923)
  subtract := Or.inl ⟨⟨636922, by omega⟩, f.node_636922, rfl⟩
  multiply := Or.inl ⟨⟨636923, by omega⟩, f.node_636923, rfl⟩
  add := Or.inl ⟨⟨636924, by omega⟩, f.node_636924, rfl⟩
}

def certificate_985 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560330) (.wire 636893) (.wire 7418) (.wire 636927) := {
  difference := (.wire 636925)
  product := (.wire 636926)
  subtract := Or.inl ⟨⟨636925, by omega⟩, f.node_636925, rfl⟩
  multiply := Or.inl ⟨⟨636926, by omega⟩, f.node_636926, rfl⟩
  add := Or.inl ⟨⟨636927, by omega⟩, f.node_636927, rfl⟩
}

def certificate_986 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560330) (.wire 7412) (.wire 636872) (.wire 636930) := {
  difference := (.wire 636928)
  product := (.wire 636929)
  subtract := Or.inl ⟨⟨636928, by omega⟩, f.node_636928, rfl⟩
  multiply := Or.inl ⟨⟨636929, by omega⟩, f.node_636929, rfl⟩
  add := Or.inl ⟨⟨636930, by omega⟩, f.node_636930, rfl⟩
}

def certificate_987 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560330) (.wire 7413) (.wire 636883) (.wire 636933) := {
  difference := (.wire 636931)
  product := (.wire 636932)
  subtract := Or.inl ⟨⟨636931, by omega⟩, f.node_636931, rfl⟩
  multiply := Or.inl ⟨⟨636932, by omega⟩, f.node_636932, rfl⟩
  add := Or.inl ⟨⟨636933, by omega⟩, f.node_636933, rfl⟩
}

def certificate_988 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560330) (.wire 7414) (.wire 636894) (.wire 636936) := {
  difference := (.wire 636934)
  product := (.wire 636935)
  subtract := Or.inl ⟨⟨636934, by omega⟩, f.node_636934, rfl⟩
  multiply := Or.inl ⟨⟨636935, by omega⟩, f.node_636935, rfl⟩
  add := Or.inl ⟨⟨636936, by omega⟩, f.node_636936, rfl⟩
}

def certificate_989 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560330) (.wire 7415) (.wire 636905) (.wire 636939) := {
  difference := (.wire 636937)
  product := (.wire 636938)
  subtract := Or.inl ⟨⟨636937, by omega⟩, f.node_636937, rfl⟩
  multiply := Or.inl ⟨⟨636938, by omega⟩, f.node_636938, rfl⟩
  add := Or.inl ⟨⟨636939, by omega⟩, f.node_636939, rfl⟩
}

def certificate_990 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560330) (.wire 7416) (.wire 636871) (.wire 636942) := {
  difference := (.wire 636940)
  product := (.wire 636941)
  subtract := Or.inl ⟨⟨636940, by omega⟩, f.node_636940, rfl⟩
  multiply := Or.inl ⟨⟨636941, by omega⟩, f.node_636941, rfl⟩
  add := Or.inl ⟨⟨636942, by omega⟩, f.node_636942, rfl⟩
}

def certificate_991 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560330) (.wire 7417) (.wire 636882) (.wire 636945) := {
  difference := (.wire 636943)
  product := (.wire 636944)
  subtract := Or.inl ⟨⟨636943, by omega⟩, f.node_636943, rfl⟩
  multiply := Or.inl ⟨⟨636944, by omega⟩, f.node_636944, rfl⟩
  add := Or.inl ⟨⟨636945, by omega⟩, f.node_636945, rfl⟩
}

def certificate_992 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560330) (.wire 7418) (.wire 636893) (.wire 636948) := {
  difference := (.wire 636946)
  product := (.wire 636947)
  subtract := Or.inl ⟨⟨636946, by omega⟩, f.node_636946, rfl⟩
  multiply := Or.inl ⟨⟨636947, by omega⟩, f.node_636947, rfl⟩
  add := Or.inl ⟨⟨636948, by omega⟩, f.node_636948, rfl⟩
}

def certificate_993 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560335) (.wire 639346) (.wire 7419) (.wire 639383) := {
  difference := (.wire 639381)
  product := (.wire 639382)
  subtract := Or.inl ⟨⟨639381, by omega⟩, f.node_639381, rfl⟩
  multiply := Or.inl ⟨⟨639382, by omega⟩, f.node_639382, rfl⟩
  add := Or.inl ⟨⟨639383, by omega⟩, f.node_639383, rfl⟩
}

def certificate_994 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560335) (.wire 639357) (.wire 7420) (.wire 639386) := {
  difference := (.wire 639384)
  product := (.wire 639385)
  subtract := Or.inl ⟨⟨639384, by omega⟩, f.node_639384, rfl⟩
  multiply := Or.inl ⟨⟨639385, by omega⟩, f.node_639385, rfl⟩
  add := Or.inl ⟨⟨639386, by omega⟩, f.node_639386, rfl⟩
}

def certificate_995 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560335) (.wire 639368) (.wire 7421) (.wire 639389) := {
  difference := (.wire 639387)
  product := (.wire 639388)
  subtract := Or.inl ⟨⟨639387, by omega⟩, f.node_639387, rfl⟩
  multiply := Or.inl ⟨⟨639388, by omega⟩, f.node_639388, rfl⟩
  add := Or.inl ⟨⟨639389, by omega⟩, f.node_639389, rfl⟩
}

def certificate_996 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560335) (.wire 639379) (.wire 7422) (.wire 639392) := {
  difference := (.wire 639390)
  product := (.wire 639391)
  subtract := Or.inl ⟨⟨639390, by omega⟩, f.node_639390, rfl⟩
  multiply := Or.inl ⟨⟨639391, by omega⟩, f.node_639391, rfl⟩
  add := Or.inl ⟨⟨639392, by omega⟩, f.node_639392, rfl⟩
}

def certificate_997 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560335) (.wire 639345) (.wire 7423) (.wire 639395) := {
  difference := (.wire 639393)
  product := (.wire 639394)
  subtract := Or.inl ⟨⟨639393, by omega⟩, f.node_639393, rfl⟩
  multiply := Or.inl ⟨⟨639394, by omega⟩, f.node_639394, rfl⟩
  add := Or.inl ⟨⟨639395, by omega⟩, f.node_639395, rfl⟩
}

def certificate_998 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560335) (.wire 639356) (.wire 7424) (.wire 639398) := {
  difference := (.wire 639396)
  product := (.wire 639397)
  subtract := Or.inl ⟨⟨639396, by omega⟩, f.node_639396, rfl⟩
  multiply := Or.inl ⟨⟨639397, by omega⟩, f.node_639397, rfl⟩
  add := Or.inl ⟨⟨639398, by omega⟩, f.node_639398, rfl⟩
}

def certificate_999 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560335) (.wire 639367) (.wire 7425) (.wire 639401) := {
  difference := (.wire 639399)
  product := (.wire 639400)
  subtract := Or.inl ⟨⟨639399, by omega⟩, f.node_639399, rfl⟩
  multiply := Or.inl ⟨⟨639400, by omega⟩, f.node_639400, rfl⟩
  add := Or.inl ⟨⟨639401, by omega⟩, f.node_639401, rfl⟩
}

def certificate_1000 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560335) (.wire 7419) (.wire 639346) (.wire 639404) := {
  difference := (.wire 639402)
  product := (.wire 639403)
  subtract := Or.inl ⟨⟨639402, by omega⟩, f.node_639402, rfl⟩
  multiply := Or.inl ⟨⟨639403, by omega⟩, f.node_639403, rfl⟩
  add := Or.inl ⟨⟨639404, by omega⟩, f.node_639404, rfl⟩
}

def certificate_1001 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560335) (.wire 7420) (.wire 639357) (.wire 639407) := {
  difference := (.wire 639405)
  product := (.wire 639406)
  subtract := Or.inl ⟨⟨639405, by omega⟩, f.node_639405, rfl⟩
  multiply := Or.inl ⟨⟨639406, by omega⟩, f.node_639406, rfl⟩
  add := Or.inl ⟨⟨639407, by omega⟩, f.node_639407, rfl⟩
}

def certificate_1002 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560335) (.wire 7421) (.wire 639368) (.wire 639410) := {
  difference := (.wire 639408)
  product := (.wire 639409)
  subtract := Or.inl ⟨⟨639408, by omega⟩, f.node_639408, rfl⟩
  multiply := Or.inl ⟨⟨639409, by omega⟩, f.node_639409, rfl⟩
  add := Or.inl ⟨⟨639410, by omega⟩, f.node_639410, rfl⟩
}

def certificate_1003 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560335) (.wire 7422) (.wire 639379) (.wire 639413) := {
  difference := (.wire 639411)
  product := (.wire 639412)
  subtract := Or.inl ⟨⟨639411, by omega⟩, f.node_639411, rfl⟩
  multiply := Or.inl ⟨⟨639412, by omega⟩, f.node_639412, rfl⟩
  add := Or.inl ⟨⟨639413, by omega⟩, f.node_639413, rfl⟩
}

def certificate_1004 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560335) (.wire 7423) (.wire 639345) (.wire 639416) := {
  difference := (.wire 639414)
  product := (.wire 639415)
  subtract := Or.inl ⟨⟨639414, by omega⟩, f.node_639414, rfl⟩
  multiply := Or.inl ⟨⟨639415, by omega⟩, f.node_639415, rfl⟩
  add := Or.inl ⟨⟨639416, by omega⟩, f.node_639416, rfl⟩
}

def certificate_1005 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560335) (.wire 7424) (.wire 639356) (.wire 639419) := {
  difference := (.wire 639417)
  product := (.wire 639418)
  subtract := Or.inl ⟨⟨639417, by omega⟩, f.node_639417, rfl⟩
  multiply := Or.inl ⟨⟨639418, by omega⟩, f.node_639418, rfl⟩
  add := Or.inl ⟨⟨639419, by omega⟩, f.node_639419, rfl⟩
}

def certificate_1006 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560335) (.wire 7425) (.wire 639367) (.wire 639422) := {
  difference := (.wire 639420)
  product := (.wire 639421)
  subtract := Or.inl ⟨⟨639420, by omega⟩, f.node_639420, rfl⟩
  multiply := Or.inl ⟨⟨639421, by omega⟩, f.node_639421, rfl⟩
  add := Or.inl ⟨⟨639422, by omega⟩, f.node_639422, rfl⟩
}

def certificate_1007 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560340) (.wire 641820) (.wire 7426) (.wire 641857) := {
  difference := (.wire 641855)
  product := (.wire 641856)
  subtract := Or.inl ⟨⟨641855, by omega⟩, f.node_641855, rfl⟩
  multiply := Or.inl ⟨⟨641856, by omega⟩, f.node_641856, rfl⟩
  add := Or.inl ⟨⟨641857, by omega⟩, f.node_641857, rfl⟩
}

def certificate_1008 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560340) (.wire 641831) (.wire 7427) (.wire 641860) := {
  difference := (.wire 641858)
  product := (.wire 641859)
  subtract := Or.inl ⟨⟨641858, by omega⟩, f.node_641858, rfl⟩
  multiply := Or.inl ⟨⟨641859, by omega⟩, f.node_641859, rfl⟩
  add := Or.inl ⟨⟨641860, by omega⟩, f.node_641860, rfl⟩
}

def certificate_1009 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560340) (.wire 641842) (.wire 7428) (.wire 641863) := {
  difference := (.wire 641861)
  product := (.wire 641862)
  subtract := Or.inl ⟨⟨641861, by omega⟩, f.node_641861, rfl⟩
  multiply := Or.inl ⟨⟨641862, by omega⟩, f.node_641862, rfl⟩
  add := Or.inl ⟨⟨641863, by omega⟩, f.node_641863, rfl⟩
}

def certificate_1010 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560340) (.wire 641853) (.wire 7429) (.wire 641866) := {
  difference := (.wire 641864)
  product := (.wire 641865)
  subtract := Or.inl ⟨⟨641864, by omega⟩, f.node_641864, rfl⟩
  multiply := Or.inl ⟨⟨641865, by omega⟩, f.node_641865, rfl⟩
  add := Or.inl ⟨⟨641866, by omega⟩, f.node_641866, rfl⟩
}

def certificate_1011 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560340) (.wire 641819) (.wire 7430) (.wire 641869) := {
  difference := (.wire 641867)
  product := (.wire 641868)
  subtract := Or.inl ⟨⟨641867, by omega⟩, f.node_641867, rfl⟩
  multiply := Or.inl ⟨⟨641868, by omega⟩, f.node_641868, rfl⟩
  add := Or.inl ⟨⟨641869, by omega⟩, f.node_641869, rfl⟩
}

def certificate_1012 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560340) (.wire 641830) (.wire 7431) (.wire 641872) := {
  difference := (.wire 641870)
  product := (.wire 641871)
  subtract := Or.inl ⟨⟨641870, by omega⟩, f.node_641870, rfl⟩
  multiply := Or.inl ⟨⟨641871, by omega⟩, f.node_641871, rfl⟩
  add := Or.inl ⟨⟨641872, by omega⟩, f.node_641872, rfl⟩
}

def certificate_1013 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560340) (.wire 641841) (.wire 7432) (.wire 641875) := {
  difference := (.wire 641873)
  product := (.wire 641874)
  subtract := Or.inl ⟨⟨641873, by omega⟩, f.node_641873, rfl⟩
  multiply := Or.inl ⟨⟨641874, by omega⟩, f.node_641874, rfl⟩
  add := Or.inl ⟨⟨641875, by omega⟩, f.node_641875, rfl⟩
}

def certificate_1014 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560340) (.wire 7426) (.wire 641820) (.wire 641878) := {
  difference := (.wire 641876)
  product := (.wire 641877)
  subtract := Or.inl ⟨⟨641876, by omega⟩, f.node_641876, rfl⟩
  multiply := Or.inl ⟨⟨641877, by omega⟩, f.node_641877, rfl⟩
  add := Or.inl ⟨⟨641878, by omega⟩, f.node_641878, rfl⟩
}

def certificate_1015 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560340) (.wire 7427) (.wire 641831) (.wire 641881) := {
  difference := (.wire 641879)
  product := (.wire 641880)
  subtract := Or.inl ⟨⟨641879, by omega⟩, f.node_641879, rfl⟩
  multiply := Or.inl ⟨⟨641880, by omega⟩, f.node_641880, rfl⟩
  add := Or.inl ⟨⟨641881, by omega⟩, f.node_641881, rfl⟩
}

def certificate_1016 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560340) (.wire 7428) (.wire 641842) (.wire 641884) := {
  difference := (.wire 641882)
  product := (.wire 641883)
  subtract := Or.inl ⟨⟨641882, by omega⟩, f.node_641882, rfl⟩
  multiply := Or.inl ⟨⟨641883, by omega⟩, f.node_641883, rfl⟩
  add := Or.inl ⟨⟨641884, by omega⟩, f.node_641884, rfl⟩
}

def certificate_1017 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560340) (.wire 7429) (.wire 641853) (.wire 641887) := {
  difference := (.wire 641885)
  product := (.wire 641886)
  subtract := Or.inl ⟨⟨641885, by omega⟩, f.node_641885, rfl⟩
  multiply := Or.inl ⟨⟨641886, by omega⟩, f.node_641886, rfl⟩
  add := Or.inl ⟨⟨641887, by omega⟩, f.node_641887, rfl⟩
}

def certificate_1018 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560340) (.wire 7430) (.wire 641819) (.wire 641890) := {
  difference := (.wire 641888)
  product := (.wire 641889)
  subtract := Or.inl ⟨⟨641888, by omega⟩, f.node_641888, rfl⟩
  multiply := Or.inl ⟨⟨641889, by omega⟩, f.node_641889, rfl⟩
  add := Or.inl ⟨⟨641890, by omega⟩, f.node_641890, rfl⟩
}

def certificate_1019 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560340) (.wire 7431) (.wire 641830) (.wire 641893) := {
  difference := (.wire 641891)
  product := (.wire 641892)
  subtract := Or.inl ⟨⟨641891, by omega⟩, f.node_641891, rfl⟩
  multiply := Or.inl ⟨⟨641892, by omega⟩, f.node_641892, rfl⟩
  add := Or.inl ⟨⟨641893, by omega⟩, f.node_641893, rfl⟩
}

def certificate_1020 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560340) (.wire 7432) (.wire 641841) (.wire 641896) := {
  difference := (.wire 641894)
  product := (.wire 641895)
  subtract := Or.inl ⟨⟨641894, by omega⟩, f.node_641894, rfl⟩
  multiply := Or.inl ⟨⟨641895, by omega⟩, f.node_641895, rfl⟩
  add := Or.inl ⟨⟨641896, by omega⟩, f.node_641896, rfl⟩
}

def certificate_1021 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560345) (.wire 644294) (.wire 7433) (.wire 644331) := {
  difference := (.wire 644329)
  product := (.wire 644330)
  subtract := Or.inl ⟨⟨644329, by omega⟩, f.node_644329, rfl⟩
  multiply := Or.inl ⟨⟨644330, by omega⟩, f.node_644330, rfl⟩
  add := Or.inl ⟨⟨644331, by omega⟩, f.node_644331, rfl⟩
}

def certificate_1022 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560345) (.wire 644305) (.wire 7434) (.wire 644334) := {
  difference := (.wire 644332)
  product := (.wire 644333)
  subtract := Or.inl ⟨⟨644332, by omega⟩, f.node_644332, rfl⟩
  multiply := Or.inl ⟨⟨644333, by omega⟩, f.node_644333, rfl⟩
  add := Or.inl ⟨⟨644334, by omega⟩, f.node_644334, rfl⟩
}

def certificate_1023 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560345) (.wire 644316) (.wire 7435) (.wire 644337) := {
  difference := (.wire 644335)
  product := (.wire 644336)
  subtract := Or.inl ⟨⟨644335, by omega⟩, f.node_644335, rfl⟩
  multiply := Or.inl ⟨⟨644336, by omega⟩, f.node_644336, rfl⟩
  add := Or.inl ⟨⟨644337, by omega⟩, f.node_644337, rfl⟩
}

def certificate_1024 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560345) (.wire 644327) (.wire 7436) (.wire 644340) := {
  difference := (.wire 644338)
  product := (.wire 644339)
  subtract := Or.inl ⟨⟨644338, by omega⟩, f.node_644338, rfl⟩
  multiply := Or.inl ⟨⟨644339, by omega⟩, f.node_644339, rfl⟩
  add := Or.inl ⟨⟨644340, by omega⟩, f.node_644340, rfl⟩
}

def certificate_1025 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560345) (.wire 644293) (.wire 7437) (.wire 644343) := {
  difference := (.wire 644341)
  product := (.wire 644342)
  subtract := Or.inl ⟨⟨644341, by omega⟩, f.node_644341, rfl⟩
  multiply := Or.inl ⟨⟨644342, by omega⟩, f.node_644342, rfl⟩
  add := Or.inl ⟨⟨644343, by omega⟩, f.node_644343, rfl⟩
}

def certificate_1026 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560345) (.wire 644304) (.wire 7438) (.wire 644346) := {
  difference := (.wire 644344)
  product := (.wire 644345)
  subtract := Or.inl ⟨⟨644344, by omega⟩, f.node_644344, rfl⟩
  multiply := Or.inl ⟨⟨644345, by omega⟩, f.node_644345, rfl⟩
  add := Or.inl ⟨⟨644346, by omega⟩, f.node_644346, rfl⟩
}

def certificate_1027 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560345) (.wire 644315) (.wire 7439) (.wire 644349) := {
  difference := (.wire 644347)
  product := (.wire 644348)
  subtract := Or.inl ⟨⟨644347, by omega⟩, f.node_644347, rfl⟩
  multiply := Or.inl ⟨⟨644348, by omega⟩, f.node_644348, rfl⟩
  add := Or.inl ⟨⟨644349, by omega⟩, f.node_644349, rfl⟩
}

def certificate_1028 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560345) (.wire 7433) (.wire 644294) (.wire 644352) := {
  difference := (.wire 644350)
  product := (.wire 644351)
  subtract := Or.inl ⟨⟨644350, by omega⟩, f.node_644350, rfl⟩
  multiply := Or.inl ⟨⟨644351, by omega⟩, f.node_644351, rfl⟩
  add := Or.inl ⟨⟨644352, by omega⟩, f.node_644352, rfl⟩
}

def certificate_1029 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560345) (.wire 7434) (.wire 644305) (.wire 644355) := {
  difference := (.wire 644353)
  product := (.wire 644354)
  subtract := Or.inl ⟨⟨644353, by omega⟩, f.node_644353, rfl⟩
  multiply := Or.inl ⟨⟨644354, by omega⟩, f.node_644354, rfl⟩
  add := Or.inl ⟨⟨644355, by omega⟩, f.node_644355, rfl⟩
}

def certificate_1030 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560345) (.wire 7435) (.wire 644316) (.wire 644358) := {
  difference := (.wire 644356)
  product := (.wire 644357)
  subtract := Or.inl ⟨⟨644356, by omega⟩, f.node_644356, rfl⟩
  multiply := Or.inl ⟨⟨644357, by omega⟩, f.node_644357, rfl⟩
  add := Or.inl ⟨⟨644358, by omega⟩, f.node_644358, rfl⟩
}

def certificate_1031 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560345) (.wire 7436) (.wire 644327) (.wire 644361) := {
  difference := (.wire 644359)
  product := (.wire 644360)
  subtract := Or.inl ⟨⟨644359, by omega⟩, f.node_644359, rfl⟩
  multiply := Or.inl ⟨⟨644360, by omega⟩, f.node_644360, rfl⟩
  add := Or.inl ⟨⟨644361, by omega⟩, f.node_644361, rfl⟩
}

def certificate_1032 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560345) (.wire 7437) (.wire 644293) (.wire 644364) := {
  difference := (.wire 644362)
  product := (.wire 644363)
  subtract := Or.inl ⟨⟨644362, by omega⟩, f.node_644362, rfl⟩
  multiply := Or.inl ⟨⟨644363, by omega⟩, f.node_644363, rfl⟩
  add := Or.inl ⟨⟨644364, by omega⟩, f.node_644364, rfl⟩
}

def certificate_1033 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560345) (.wire 7438) (.wire 644304) (.wire 644367) := {
  difference := (.wire 644365)
  product := (.wire 644366)
  subtract := Or.inl ⟨⟨644365, by omega⟩, f.node_644365, rfl⟩
  multiply := Or.inl ⟨⟨644366, by omega⟩, f.node_644366, rfl⟩
  add := Or.inl ⟨⟨644367, by omega⟩, f.node_644367, rfl⟩
}

def certificate_1034 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : SelectData g (.wire 560345) (.wire 7439) (.wire 644315) (.wire 644370) := {
  difference := (.wire 644368)
  product := (.wire 644369)
  subtract := Or.inl ⟨⟨644368, by omega⟩, f.node_644368, rfl⟩
  multiply := Or.inl ⟨⟨644369, by omega⟩, f.node_644369, rfl⟩
  add := Or.inl ⟨⟨644370, by omega⟩, f.node_644370, rfl⟩
}

def certificate_1035 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 7195) (.wire 646768) (.wire 17) := {
  difference := (.wire 646803)
  product := (.wire 646804)
  subtract := Or.inl ⟨⟨646803, by omega⟩, f.node_646803, rfl⟩
  multiply := Or.inl ⟨⟨646804, by omega⟩, f.node_646804, rfl⟩
  zero := f.eq_111
}

def certificate_1036 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 7195) (.wire 646779) (.wire 18) := {
  difference := (.wire 646805)
  product := (.wire 646806)
  subtract := Or.inl ⟨⟨646805, by omega⟩, f.node_646805, rfl⟩
  multiply := Or.inl ⟨⟨646806, by omega⟩, f.node_646806, rfl⟩
  zero := f.eq_112
}

def certificate_1037 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 7195) (.wire 646790) (.wire 19) := {
  difference := (.wire 646807)
  product := (.wire 646808)
  subtract := Or.inl ⟨⟨646807, by omega⟩, f.node_646807, rfl⟩
  multiply := Or.inl ⟨⟨646808, by omega⟩, f.node_646808, rfl⟩
  zero := f.eq_113
}

def certificate_1038 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 7195) (.wire 646801) (.wire 20) := {
  difference := (.wire 646809)
  product := (.wire 646810)
  subtract := Or.inl ⟨⟨646809, by omega⟩, f.node_646809, rfl⟩
  multiply := Or.inl ⟨⟨646810, by omega⟩, f.node_646810, rfl⟩
  zero := f.eq_114
}

def certificate_1039 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 7195) (.wire 646767) (.wire 21) := {
  difference := (.wire 646811)
  product := (.wire 646812)
  subtract := Or.inl ⟨⟨646811, by omega⟩, f.node_646811, rfl⟩
  multiply := Or.inl ⟨⟨646812, by omega⟩, f.node_646812, rfl⟩
  zero := f.eq_115
}

def certificate_1040 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 7195) (.wire 646778) (.wire 22) := {
  difference := (.wire 646813)
  product := (.wire 646814)
  subtract := Or.inl ⟨⟨646813, by omega⟩, f.node_646813, rfl⟩
  multiply := Or.inl ⟨⟨646814, by omega⟩, f.node_646814, rfl⟩
  zero := f.eq_116
}

def certificate_1041 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : GateData g (.wire 7195) (.wire 646789) (.wire 23) := {
  difference := (.wire 646815)
  product := (.wire 646816)
  subtract := Or.inl ⟨⟨646815, by omega⟩, f.node_646815, rfl⟩
  multiply := Or.inl ⟨⟨646816, by omega⟩, f.node_646816, rfl⟩
  zero := f.eq_117
}

end
end HegemonCrypto.NativePrivateSpendCurrentFiniteConstructors
