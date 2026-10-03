import HegemonCrypto.SmallWoodV8Smz9SourceAuthRootClosure

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthLastInverseDAG
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership (actual_node_field_equation)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt expressionField)
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

theorem actual_root_411 (pub rows : Nat → F) :
    (exactNonlinearRoots[411]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (((rows 93 + rows 94) * ((rows 181 + (rows 180 + (rows 179 + (rows 178 + (rows 176 + rows 177))))) * (rows 181 + (rows 180 + (rows 179 + (rows 177 + rows 178)))))) * ((rows 232 * (rows 196 - rows 201)) - 1)) := by
  rw [show exactNonlinearRoots[411]? = some 1858 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e300 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[300]? = some (.witnessRow 176) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e320 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[320]? = some (.witnessRow 196) by decide)
  have e325 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[325]? = some (.witnessRow 201) by decide)
  have e356 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[356]? = some (.witnessRow 232) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1489 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1489]? = some (.add 300 301) by decide)
  have e1490 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1490]? = some (.add 302 1489) by decide)
  have e1491 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1491]? = some (.add 303 1490) by decide)
  have e1492 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1492]? = some (.add 304 1491) by decide)
  have e1493 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1493]? = some (.add 305 1492) by decide)
  have e1614 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1614]? = some (.add 301 302) by decide)
  have e1615 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1615]? = some (.add 303 1614) by decide)
  have e1616 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1616]? = some (.add 304 1615) by decide)
  have e1617 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1617]? = some (.add 305 1616) by decide)
  have e1853 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1853]? = some (.mul 1493 1617) by decide)
  have e1854 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1854]? = some (.sub 320 325) by decide)
  have e1855 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1855]? = some (.mul 1234 1853) by decide)
  have e1856 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1856]? = some (.mul 356 1854) by decide)
  have e1857 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1857]? = some (.sub 1856 1) by decide)
  have e1858 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1858]? = some (.mul 1855 1857) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e300 e301 e302 e303 e304 e305 e320 e325 e356 e1234 e1489 e1490 e1491 e1492 e1493 e1614 e1615 e1616 e1617 e1853 e1854 e1855 e1856 e1857 e1858
  rw [e1857,e1856,e1855,e1854,e1853,e1617,e1616,e1615,e1614,e1493,e1492,e1491,e1490,e1489,e1234,e356,e325,e320,e305,e304,e303,e302,e301,e300,e218,e217,e1] at e1858
  exact congrArg some e1858

theorem actual_root_412 (pub rows : Nat → F) :
    (exactNonlinearRoots[412]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 232 * ((rows 93 + rows 94) * (1 - ((rows 181 + (rows 180 + (rows 179 + (rows 178 + (rows 176 + rows 177))))) * (rows 181 + (rows 180 + (rows 179 + (rows 177 + rows 178)))))))) := by
  rw [show exactNonlinearRoots[412]? = some 1861 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e300 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[300]? = some (.witnessRow 176) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e356 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[356]? = some (.witnessRow 232) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1489 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1489]? = some (.add 300 301) by decide)
  have e1490 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1490]? = some (.add 302 1489) by decide)
  have e1491 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1491]? = some (.add 303 1490) by decide)
  have e1492 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1492]? = some (.add 304 1491) by decide)
  have e1493 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1493]? = some (.add 305 1492) by decide)
  have e1614 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1614]? = some (.add 301 302) by decide)
  have e1615 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1615]? = some (.add 303 1614) by decide)
  have e1616 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1616]? = some (.add 304 1615) by decide)
  have e1617 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1617]? = some (.add 305 1616) by decide)
  have e1853 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1853]? = some (.mul 1493 1617) by decide)
  have e1859 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1859]? = some (.sub 1 1853) by decide)
  have e1860 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1860]? = some (.mul 1234 1859) by decide)
  have e1861 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1861]? = some (.mul 356 1860) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e300 e301 e302 e303 e304 e305 e356 e1234 e1489 e1490 e1491 e1492 e1493 e1614 e1615 e1616 e1617 e1853 e1859 e1860 e1861
  rw [e1860,e1859,e1853,e1617,e1616,e1615,e1614,e1493,e1492,e1491,e1490,e1489,e1234,e356,e305,e304,e303,e302,e301,e300,e218,e217,e1] at e1861
  exact congrArg some e1861

theorem actual_root_413 (pub rows : Nat → F) :
    (exactNonlinearRoots[413]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (((rows 93 + rows 94) * ((rows 181 + (rows 180 + (rows 179 + (rows 178 + (rows 176 + rows 177))))) * (rows 181 + (rows 180 + (rows 178 + rows 179))))) * ((rows 233 * (rows 196 - rows 206)) - 1)) := by
  rw [show exactNonlinearRoots[413]? = some 1867 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e300 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[300]? = some (.witnessRow 176) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e320 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[320]? = some (.witnessRow 196) by decide)
  have e330 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[330]? = some (.witnessRow 206) by decide)
  have e357 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[357]? = some (.witnessRow 233) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1489 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1489]? = some (.add 300 301) by decide)
  have e1490 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1490]? = some (.add 302 1489) by decide)
  have e1491 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1491]? = some (.add 303 1490) by decide)
  have e1492 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1492]? = some (.add 304 1491) by decide)
  have e1493 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1493]? = some (.add 305 1492) by decide)
  have e1624 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1624]? = some (.add 302 303) by decide)
  have e1625 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1625]? = some (.add 304 1624) by decide)
  have e1626 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1626]? = some (.add 305 1625) by decide)
  have e1862 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1862]? = some (.mul 1493 1626) by decide)
  have e1863 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1863]? = some (.sub 320 330) by decide)
  have e1864 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1864]? = some (.mul 1234 1862) by decide)
  have e1865 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1865]? = some (.mul 357 1863) by decide)
  have e1866 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1866]? = some (.sub 1865 1) by decide)
  have e1867 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1867]? = some (.mul 1864 1866) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e300 e301 e302 e303 e304 e305 e320 e330 e357 e1234 e1489 e1490 e1491 e1492 e1493 e1624 e1625 e1626 e1862 e1863 e1864 e1865 e1866 e1867
  rw [e1866,e1865,e1864,e1863,e1862,e1626,e1625,e1624,e1493,e1492,e1491,e1490,e1489,e1234,e357,e330,e320,e305,e304,e303,e302,e301,e300,e218,e217,e1] at e1867
  exact congrArg some e1867

theorem actual_root_414 (pub rows : Nat → F) :
    (exactNonlinearRoots[414]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 233 * ((rows 93 + rows 94) * (1 - ((rows 181 + (rows 180 + (rows 179 + (rows 178 + (rows 176 + rows 177))))) * (rows 181 + (rows 180 + (rows 178 + rows 179))))))) := by
  rw [show exactNonlinearRoots[414]? = some 1870 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e300 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[300]? = some (.witnessRow 176) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e357 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[357]? = some (.witnessRow 233) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1489 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1489]? = some (.add 300 301) by decide)
  have e1490 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1490]? = some (.add 302 1489) by decide)
  have e1491 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1491]? = some (.add 303 1490) by decide)
  have e1492 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1492]? = some (.add 304 1491) by decide)
  have e1493 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1493]? = some (.add 305 1492) by decide)
  have e1624 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1624]? = some (.add 302 303) by decide)
  have e1625 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1625]? = some (.add 304 1624) by decide)
  have e1626 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1626]? = some (.add 305 1625) by decide)
  have e1862 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1862]? = some (.mul 1493 1626) by decide)
  have e1868 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1868]? = some (.sub 1 1862) by decide)
  have e1869 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1869]? = some (.mul 1234 1868) by decide)
  have e1870 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1870]? = some (.mul 357 1869) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e300 e301 e302 e303 e304 e305 e357 e1234 e1489 e1490 e1491 e1492 e1493 e1624 e1625 e1626 e1862 e1868 e1869 e1870
  rw [e1869,e1868,e1862,e1626,e1625,e1624,e1493,e1492,e1491,e1490,e1489,e1234,e357,e305,e304,e303,e302,e301,e300,e218,e217,e1] at e1870
  exact congrArg some e1870

theorem actual_root_415 (pub rows : Nat → F) :
    (exactNonlinearRoots[415]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (((rows 93 + rows 94) * ((rows 181 + (rows 180 + (rows 179 + (rows 178 + (rows 176 + rows 177))))) * (rows 181 + (rows 179 + rows 180)))) * ((rows 234 * (rows 196 - rows 211)) - 1)) := by
  rw [show exactNonlinearRoots[415]? = some 1876 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e300 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[300]? = some (.witnessRow 176) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e320 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[320]? = some (.witnessRow 196) by decide)
  have e335 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[335]? = some (.witnessRow 211) by decide)
  have e358 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[358]? = some (.witnessRow 234) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1489 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1489]? = some (.add 300 301) by decide)
  have e1490 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1490]? = some (.add 302 1489) by decide)
  have e1491 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1491]? = some (.add 303 1490) by decide)
  have e1492 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1492]? = some (.add 304 1491) by decide)
  have e1493 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1493]? = some (.add 305 1492) by decide)
  have e1633 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1633]? = some (.add 303 304) by decide)
  have e1634 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1634]? = some (.add 305 1633) by decide)
  have e1871 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1871]? = some (.mul 1493 1634) by decide)
  have e1872 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1872]? = some (.sub 320 335) by decide)
  have e1873 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1873]? = some (.mul 1234 1871) by decide)
  have e1874 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1874]? = some (.mul 358 1872) by decide)
  have e1875 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1875]? = some (.sub 1874 1) by decide)
  have e1876 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1876]? = some (.mul 1873 1875) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e300 e301 e302 e303 e304 e305 e320 e335 e358 e1234 e1489 e1490 e1491 e1492 e1493 e1633 e1634 e1871 e1872 e1873 e1874 e1875 e1876
  rw [e1875,e1874,e1873,e1872,e1871,e1634,e1633,e1493,e1492,e1491,e1490,e1489,e1234,e358,e335,e320,e305,e304,e303,e302,e301,e300,e218,e217,e1] at e1876
  exact congrArg some e1876

theorem actual_root_416 (pub rows : Nat → F) :
    (exactNonlinearRoots[416]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 234 * ((rows 93 + rows 94) * (1 - ((rows 181 + (rows 180 + (rows 179 + (rows 178 + (rows 176 + rows 177))))) * (rows 181 + (rows 179 + rows 180)))))) := by
  rw [show exactNonlinearRoots[416]? = some 1879 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e300 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[300]? = some (.witnessRow 176) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e358 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[358]? = some (.witnessRow 234) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1489 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1489]? = some (.add 300 301) by decide)
  have e1490 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1490]? = some (.add 302 1489) by decide)
  have e1491 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1491]? = some (.add 303 1490) by decide)
  have e1492 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1492]? = some (.add 304 1491) by decide)
  have e1493 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1493]? = some (.add 305 1492) by decide)
  have e1633 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1633]? = some (.add 303 304) by decide)
  have e1634 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1634]? = some (.add 305 1633) by decide)
  have e1871 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1871]? = some (.mul 1493 1634) by decide)
  have e1877 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1877]? = some (.sub 1 1871) by decide)
  have e1878 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1878]? = some (.mul 1234 1877) by decide)
  have e1879 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1879]? = some (.mul 358 1878) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e300 e301 e302 e303 e304 e305 e358 e1234 e1489 e1490 e1491 e1492 e1493 e1633 e1634 e1871 e1877 e1878 e1879
  rw [e1878,e1877,e1871,e1634,e1633,e1493,e1492,e1491,e1490,e1489,e1234,e358,e305,e304,e303,e302,e301,e300,e218,e217,e1] at e1879
  exact congrArg some e1879

theorem actual_root_417 (pub rows : Nat → F) :
    (exactNonlinearRoots[417]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (((rows 93 + rows 94) * ((rows 181 + (rows 180 + (rows 179 + (rows 178 + (rows 176 + rows 177))))) * (rows 180 + rows 181))) * ((rows 235 * (rows 196 - rows 216)) - 1)) := by
  rw [show exactNonlinearRoots[417]? = some 1885 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e300 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[300]? = some (.witnessRow 176) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e320 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[320]? = some (.witnessRow 196) by decide)
  have e340 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[340]? = some (.witnessRow 216) by decide)
  have e359 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[359]? = some (.witnessRow 235) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1489 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1489]? = some (.add 300 301) by decide)
  have e1490 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1490]? = some (.add 302 1489) by decide)
  have e1491 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1491]? = some (.add 303 1490) by decide)
  have e1492 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1492]? = some (.add 304 1491) by decide)
  have e1493 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1493]? = some (.add 305 1492) by decide)
  have e1641 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1641]? = some (.add 304 305) by decide)
  have e1880 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1880]? = some (.mul 1493 1641) by decide)
  have e1881 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1881]? = some (.sub 320 340) by decide)
  have e1882 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1882]? = some (.mul 1234 1880) by decide)
  have e1883 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1883]? = some (.mul 359 1881) by decide)
  have e1884 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1884]? = some (.sub 1883 1) by decide)
  have e1885 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1885]? = some (.mul 1882 1884) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e300 e301 e302 e303 e304 e305 e320 e340 e359 e1234 e1489 e1490 e1491 e1492 e1493 e1641 e1880 e1881 e1882 e1883 e1884 e1885
  rw [e1884,e1883,e1882,e1881,e1880,e1641,e1493,e1492,e1491,e1490,e1489,e1234,e359,e340,e320,e305,e304,e303,e302,e301,e300,e218,e217,e1] at e1885
  exact congrArg some e1885

theorem actual_root_418 (pub rows : Nat → F) :
    (exactNonlinearRoots[418]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 235 * ((rows 93 + rows 94) * (1 - ((rows 181 + (rows 180 + (rows 179 + (rows 178 + (rows 176 + rows 177))))) * (rows 180 + rows 181))))) := by
  rw [show exactNonlinearRoots[418]? = some 1888 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e300 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[300]? = some (.witnessRow 176) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e359 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[359]? = some (.witnessRow 235) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1489 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1489]? = some (.add 300 301) by decide)
  have e1490 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1490]? = some (.add 302 1489) by decide)
  have e1491 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1491]? = some (.add 303 1490) by decide)
  have e1492 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1492]? = some (.add 304 1491) by decide)
  have e1493 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1493]? = some (.add 305 1492) by decide)
  have e1641 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1641]? = some (.add 304 305) by decide)
  have e1880 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1880]? = some (.mul 1493 1641) by decide)
  have e1886 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1886]? = some (.sub 1 1880) by decide)
  have e1887 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1887]? = some (.mul 1234 1886) by decide)
  have e1888 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1888]? = some (.mul 359 1887) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e300 e301 e302 e303 e304 e305 e359 e1234 e1489 e1490 e1491 e1492 e1493 e1641 e1880 e1886 e1887 e1888
  rw [e1887,e1886,e1880,e1641,e1493,e1492,e1491,e1490,e1489,e1234,e359,e305,e304,e303,e302,e301,e300,e218,e217,e1] at e1888
  exact congrArg some e1888

theorem actual_root_419 (pub rows : Nat → F) :
    (exactNonlinearRoots[419]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (((rows 93 + rows 94) * (rows 181 * (rows 181 + (rows 180 + (rows 179 + (rows 178 + (rows 176 + rows 177))))))) * ((rows 236 * (rows 196 - rows 221)) - 1)) := by
  rw [show exactNonlinearRoots[419]? = some 1894 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e300 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[300]? = some (.witnessRow 176) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e320 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[320]? = some (.witnessRow 196) by decide)
  have e345 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[345]? = some (.witnessRow 221) by decide)
  have e360 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[360]? = some (.witnessRow 236) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1489 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1489]? = some (.add 300 301) by decide)
  have e1490 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1490]? = some (.add 302 1489) by decide)
  have e1491 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1491]? = some (.add 303 1490) by decide)
  have e1492 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1492]? = some (.add 304 1491) by decide)
  have e1493 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1493]? = some (.add 305 1492) by decide)
  have e1889 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1889]? = some (.mul 305 1493) by decide)
  have e1890 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1890]? = some (.sub 320 345) by decide)
  have e1891 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1891]? = some (.mul 1234 1889) by decide)
  have e1892 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1892]? = some (.mul 360 1890) by decide)
  have e1893 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1893]? = some (.sub 1892 1) by decide)
  have e1894 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1894]? = some (.mul 1891 1893) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e300 e301 e302 e303 e304 e305 e320 e345 e360 e1234 e1489 e1490 e1491 e1492 e1493 e1889 e1890 e1891 e1892 e1893 e1894
  rw [e1893,e1892,e1891,e1890,e1889,e1493,e1492,e1491,e1490,e1489,e1234,e360,e345,e320,e305,e304,e303,e302,e301,e300,e218,e217,e1] at e1894
  exact congrArg some e1894

theorem actual_root_420 (pub rows : Nat → F) :
    (exactNonlinearRoots[420]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 236 * ((rows 93 + rows 94) * (1 - (rows 181 * (rows 181 + (rows 180 + (rows 179 + (rows 178 + (rows 176 + rows 177))))))))) := by
  rw [show exactNonlinearRoots[420]? = some 1897 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e300 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[300]? = some (.witnessRow 176) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e360 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[360]? = some (.witnessRow 236) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1489 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1489]? = some (.add 300 301) by decide)
  have e1490 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1490]? = some (.add 302 1489) by decide)
  have e1491 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1491]? = some (.add 303 1490) by decide)
  have e1492 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1492]? = some (.add 304 1491) by decide)
  have e1493 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1493]? = some (.add 305 1492) by decide)
  have e1889 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1889]? = some (.mul 305 1493) by decide)
  have e1895 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1895]? = some (.sub 1 1889) by decide)
  have e1896 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1896]? = some (.mul 1234 1895) by decide)
  have e1897 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1897]? = some (.mul 360 1896) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e300 e301 e302 e303 e304 e305 e360 e1234 e1489 e1490 e1491 e1492 e1493 e1889 e1895 e1896 e1897
  rw [e1896,e1895,e1889,e1493,e1492,e1491,e1490,e1489,e1234,e360,e305,e304,e303,e302,e301,e300,e218,e217,e1] at e1897
  exact congrArg some e1897

theorem actual_root_421 (pub rows : Nat → F) :
    (exactNonlinearRoots[421]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (((rows 93 + rows 94) * ((rows 181 + (rows 180 + (rows 179 + (rows 177 + rows 178)))) * (rows 181 + (rows 180 + (rows 178 + rows 179))))) * ((rows 237 * (rows 201 - rows 206)) - 1)) := by
  rw [show exactNonlinearRoots[421]? = some 1903 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e325 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[325]? = some (.witnessRow 201) by decide)
  have e330 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[330]? = some (.witnessRow 206) by decide)
  have e361 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[361]? = some (.witnessRow 237) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1614 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1614]? = some (.add 301 302) by decide)
  have e1615 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1615]? = some (.add 303 1614) by decide)
  have e1616 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1616]? = some (.add 304 1615) by decide)
  have e1617 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1617]? = some (.add 305 1616) by decide)
  have e1624 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1624]? = some (.add 302 303) by decide)
  have e1625 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1625]? = some (.add 304 1624) by decide)
  have e1626 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1626]? = some (.add 305 1625) by decide)
  have e1898 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1898]? = some (.mul 1617 1626) by decide)
  have e1899 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1899]? = some (.sub 325 330) by decide)
  have e1900 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1900]? = some (.mul 1234 1898) by decide)
  have e1901 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1901]? = some (.mul 361 1899) by decide)
  have e1902 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1902]? = some (.sub 1901 1) by decide)
  have e1903 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1903]? = some (.mul 1900 1902) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e301 e302 e303 e304 e305 e325 e330 e361 e1234 e1614 e1615 e1616 e1617 e1624 e1625 e1626 e1898 e1899 e1900 e1901 e1902 e1903
  rw [e1902,e1901,e1900,e1899,e1898,e1626,e1625,e1624,e1617,e1616,e1615,e1614,e1234,e361,e330,e325,e305,e304,e303,e302,e301,e218,e217,e1] at e1903
  exact congrArg some e1903

theorem actual_root_422 (pub rows : Nat → F) :
    (exactNonlinearRoots[422]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 237 * ((rows 93 + rows 94) * (1 - ((rows 181 + (rows 180 + (rows 179 + (rows 177 + rows 178)))) * (rows 181 + (rows 180 + (rows 178 + rows 179))))))) := by
  rw [show exactNonlinearRoots[422]? = some 1906 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e361 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[361]? = some (.witnessRow 237) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1614 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1614]? = some (.add 301 302) by decide)
  have e1615 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1615]? = some (.add 303 1614) by decide)
  have e1616 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1616]? = some (.add 304 1615) by decide)
  have e1617 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1617]? = some (.add 305 1616) by decide)
  have e1624 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1624]? = some (.add 302 303) by decide)
  have e1625 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1625]? = some (.add 304 1624) by decide)
  have e1626 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1626]? = some (.add 305 1625) by decide)
  have e1898 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1898]? = some (.mul 1617 1626) by decide)
  have e1904 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1904]? = some (.sub 1 1898) by decide)
  have e1905 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1905]? = some (.mul 1234 1904) by decide)
  have e1906 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1906]? = some (.mul 361 1905) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e301 e302 e303 e304 e305 e361 e1234 e1614 e1615 e1616 e1617 e1624 e1625 e1626 e1898 e1904 e1905 e1906
  rw [e1905,e1904,e1898,e1626,e1625,e1624,e1617,e1616,e1615,e1614,e1234,e361,e305,e304,e303,e302,e301,e218,e217,e1] at e1906
  exact congrArg some e1906

theorem actual_root_423 (pub rows : Nat → F) :
    (exactNonlinearRoots[423]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (((rows 93 + rows 94) * ((rows 181 + (rows 180 + (rows 179 + (rows 177 + rows 178)))) * (rows 181 + (rows 179 + rows 180)))) * ((rows 238 * (rows 201 - rows 211)) - 1)) := by
  rw [show exactNonlinearRoots[423]? = some 1912 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e325 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[325]? = some (.witnessRow 201) by decide)
  have e335 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[335]? = some (.witnessRow 211) by decide)
  have e362 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[362]? = some (.witnessRow 238) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1614 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1614]? = some (.add 301 302) by decide)
  have e1615 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1615]? = some (.add 303 1614) by decide)
  have e1616 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1616]? = some (.add 304 1615) by decide)
  have e1617 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1617]? = some (.add 305 1616) by decide)
  have e1633 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1633]? = some (.add 303 304) by decide)
  have e1634 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1634]? = some (.add 305 1633) by decide)
  have e1907 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1907]? = some (.mul 1617 1634) by decide)
  have e1908 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1908]? = some (.sub 325 335) by decide)
  have e1909 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1909]? = some (.mul 1234 1907) by decide)
  have e1910 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1910]? = some (.mul 362 1908) by decide)
  have e1911 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1911]? = some (.sub 1910 1) by decide)
  have e1912 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1912]? = some (.mul 1909 1911) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e301 e302 e303 e304 e305 e325 e335 e362 e1234 e1614 e1615 e1616 e1617 e1633 e1634 e1907 e1908 e1909 e1910 e1911 e1912
  rw [e1911,e1910,e1909,e1908,e1907,e1634,e1633,e1617,e1616,e1615,e1614,e1234,e362,e335,e325,e305,e304,e303,e302,e301,e218,e217,e1] at e1912
  exact congrArg some e1912

theorem actual_root_424 (pub rows : Nat → F) :
    (exactNonlinearRoots[424]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 238 * ((rows 93 + rows 94) * (1 - ((rows 181 + (rows 180 + (rows 179 + (rows 177 + rows 178)))) * (rows 181 + (rows 179 + rows 180)))))) := by
  rw [show exactNonlinearRoots[424]? = some 1915 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e362 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[362]? = some (.witnessRow 238) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1614 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1614]? = some (.add 301 302) by decide)
  have e1615 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1615]? = some (.add 303 1614) by decide)
  have e1616 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1616]? = some (.add 304 1615) by decide)
  have e1617 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1617]? = some (.add 305 1616) by decide)
  have e1633 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1633]? = some (.add 303 304) by decide)
  have e1634 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1634]? = some (.add 305 1633) by decide)
  have e1907 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1907]? = some (.mul 1617 1634) by decide)
  have e1913 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1913]? = some (.sub 1 1907) by decide)
  have e1914 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1914]? = some (.mul 1234 1913) by decide)
  have e1915 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1915]? = some (.mul 362 1914) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e301 e302 e303 e304 e305 e362 e1234 e1614 e1615 e1616 e1617 e1633 e1634 e1907 e1913 e1914 e1915
  rw [e1914,e1913,e1907,e1634,e1633,e1617,e1616,e1615,e1614,e1234,e362,e305,e304,e303,e302,e301,e218,e217,e1] at e1915
  exact congrArg some e1915

theorem actual_root_425 (pub rows : Nat → F) :
    (exactNonlinearRoots[425]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (((rows 93 + rows 94) * ((rows 181 + (rows 180 + (rows 179 + (rows 177 + rows 178)))) * (rows 180 + rows 181))) * ((rows 239 * (rows 201 - rows 216)) - 1)) := by
  rw [show exactNonlinearRoots[425]? = some 1921 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e325 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[325]? = some (.witnessRow 201) by decide)
  have e340 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[340]? = some (.witnessRow 216) by decide)
  have e363 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[363]? = some (.witnessRow 239) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1614 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1614]? = some (.add 301 302) by decide)
  have e1615 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1615]? = some (.add 303 1614) by decide)
  have e1616 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1616]? = some (.add 304 1615) by decide)
  have e1617 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1617]? = some (.add 305 1616) by decide)
  have e1641 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1641]? = some (.add 304 305) by decide)
  have e1916 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1916]? = some (.mul 1617 1641) by decide)
  have e1917 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1917]? = some (.sub 325 340) by decide)
  have e1918 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1918]? = some (.mul 1234 1916) by decide)
  have e1919 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1919]? = some (.mul 363 1917) by decide)
  have e1920 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1920]? = some (.sub 1919 1) by decide)
  have e1921 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1921]? = some (.mul 1918 1920) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e301 e302 e303 e304 e305 e325 e340 e363 e1234 e1614 e1615 e1616 e1617 e1641 e1916 e1917 e1918 e1919 e1920 e1921
  rw [e1920,e1919,e1918,e1917,e1916,e1641,e1617,e1616,e1615,e1614,e1234,e363,e340,e325,e305,e304,e303,e302,e301,e218,e217,e1] at e1921
  exact congrArg some e1921

theorem actual_root_426 (pub rows : Nat → F) :
    (exactNonlinearRoots[426]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 239 * ((rows 93 + rows 94) * (1 - ((rows 181 + (rows 180 + (rows 179 + (rows 177 + rows 178)))) * (rows 180 + rows 181))))) := by
  rw [show exactNonlinearRoots[426]? = some 1924 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e363 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[363]? = some (.witnessRow 239) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1614 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1614]? = some (.add 301 302) by decide)
  have e1615 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1615]? = some (.add 303 1614) by decide)
  have e1616 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1616]? = some (.add 304 1615) by decide)
  have e1617 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1617]? = some (.add 305 1616) by decide)
  have e1641 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1641]? = some (.add 304 305) by decide)
  have e1916 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1916]? = some (.mul 1617 1641) by decide)
  have e1922 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1922]? = some (.sub 1 1916) by decide)
  have e1923 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1923]? = some (.mul 1234 1922) by decide)
  have e1924 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1924]? = some (.mul 363 1923) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e301 e302 e303 e304 e305 e363 e1234 e1614 e1615 e1616 e1617 e1641 e1916 e1922 e1923 e1924
  rw [e1923,e1922,e1916,e1641,e1617,e1616,e1615,e1614,e1234,e363,e305,e304,e303,e302,e301,e218,e217,e1] at e1924
  exact congrArg some e1924

theorem actual_root_427 (pub rows : Nat → F) :
    (exactNonlinearRoots[427]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (((rows 93 + rows 94) * (rows 181 * (rows 181 + (rows 180 + (rows 179 + (rows 177 + rows 178)))))) * ((rows 240 * (rows 201 - rows 221)) - 1)) := by
  rw [show exactNonlinearRoots[427]? = some 1930 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e325 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[325]? = some (.witnessRow 201) by decide)
  have e345 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[345]? = some (.witnessRow 221) by decide)
  have e364 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[364]? = some (.witnessRow 240) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1614 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1614]? = some (.add 301 302) by decide)
  have e1615 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1615]? = some (.add 303 1614) by decide)
  have e1616 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1616]? = some (.add 304 1615) by decide)
  have e1617 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1617]? = some (.add 305 1616) by decide)
  have e1925 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1925]? = some (.mul 305 1617) by decide)
  have e1926 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1926]? = some (.sub 325 345) by decide)
  have e1927 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1927]? = some (.mul 1234 1925) by decide)
  have e1928 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1928]? = some (.mul 364 1926) by decide)
  have e1929 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1929]? = some (.sub 1928 1) by decide)
  have e1930 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1930]? = some (.mul 1927 1929) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e301 e302 e303 e304 e305 e325 e345 e364 e1234 e1614 e1615 e1616 e1617 e1925 e1926 e1927 e1928 e1929 e1930
  rw [e1929,e1928,e1927,e1926,e1925,e1617,e1616,e1615,e1614,e1234,e364,e345,e325,e305,e304,e303,e302,e301,e218,e217,e1] at e1930
  exact congrArg some e1930

theorem actual_root_428 (pub rows : Nat → F) :
    (exactNonlinearRoots[428]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 240 * ((rows 93 + rows 94) * (1 - (rows 181 * (rows 181 + (rows 180 + (rows 179 + (rows 177 + rows 178)))))))) := by
  rw [show exactNonlinearRoots[428]? = some 1933 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e364 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[364]? = some (.witnessRow 240) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1614 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1614]? = some (.add 301 302) by decide)
  have e1615 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1615]? = some (.add 303 1614) by decide)
  have e1616 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1616]? = some (.add 304 1615) by decide)
  have e1617 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1617]? = some (.add 305 1616) by decide)
  have e1925 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1925]? = some (.mul 305 1617) by decide)
  have e1931 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1931]? = some (.sub 1 1925) by decide)
  have e1932 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1932]? = some (.mul 1234 1931) by decide)
  have e1933 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1933]? = some (.mul 364 1932) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e301 e302 e303 e304 e305 e364 e1234 e1614 e1615 e1616 e1617 e1925 e1931 e1932 e1933
  rw [e1932,e1931,e1925,e1617,e1616,e1615,e1614,e1234,e364,e305,e304,e303,e302,e301,e218,e217,e1] at e1933
  exact congrArg some e1933

theorem actual_root_429 (pub rows : Nat → F) :
    (exactNonlinearRoots[429]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (((rows 93 + rows 94) * ((rows 181 + (rows 180 + (rows 178 + rows 179))) * (rows 181 + (rows 179 + rows 180)))) * ((rows 241 * (rows 206 - rows 211)) - 1)) := by
  rw [show exactNonlinearRoots[429]? = some 1939 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e330 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[330]? = some (.witnessRow 206) by decide)
  have e335 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[335]? = some (.witnessRow 211) by decide)
  have e365 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[365]? = some (.witnessRow 241) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1624 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1624]? = some (.add 302 303) by decide)
  have e1625 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1625]? = some (.add 304 1624) by decide)
  have e1626 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1626]? = some (.add 305 1625) by decide)
  have e1633 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1633]? = some (.add 303 304) by decide)
  have e1634 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1634]? = some (.add 305 1633) by decide)
  have e1934 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1934]? = some (.mul 1626 1634) by decide)
  have e1935 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1935]? = some (.sub 330 335) by decide)
  have e1936 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1936]? = some (.mul 1234 1934) by decide)
  have e1937 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1937]? = some (.mul 365 1935) by decide)
  have e1938 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1938]? = some (.sub 1937 1) by decide)
  have e1939 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1939]? = some (.mul 1936 1938) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e302 e303 e304 e305 e330 e335 e365 e1234 e1624 e1625 e1626 e1633 e1634 e1934 e1935 e1936 e1937 e1938 e1939
  rw [e1938,e1937,e1936,e1935,e1934,e1634,e1633,e1626,e1625,e1624,e1234,e365,e335,e330,e305,e304,e303,e302,e218,e217,e1] at e1939
  exact congrArg some e1939

theorem actual_root_430 (pub rows : Nat → F) :
    (exactNonlinearRoots[430]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 241 * ((rows 93 + rows 94) * (1 - ((rows 181 + (rows 180 + (rows 178 + rows 179))) * (rows 181 + (rows 179 + rows 180)))))) := by
  rw [show exactNonlinearRoots[430]? = some 1942 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e365 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[365]? = some (.witnessRow 241) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1624 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1624]? = some (.add 302 303) by decide)
  have e1625 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1625]? = some (.add 304 1624) by decide)
  have e1626 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1626]? = some (.add 305 1625) by decide)
  have e1633 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1633]? = some (.add 303 304) by decide)
  have e1634 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1634]? = some (.add 305 1633) by decide)
  have e1934 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1934]? = some (.mul 1626 1634) by decide)
  have e1940 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1940]? = some (.sub 1 1934) by decide)
  have e1941 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1941]? = some (.mul 1234 1940) by decide)
  have e1942 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1942]? = some (.mul 365 1941) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e302 e303 e304 e305 e365 e1234 e1624 e1625 e1626 e1633 e1634 e1934 e1940 e1941 e1942
  rw [e1941,e1940,e1934,e1634,e1633,e1626,e1625,e1624,e1234,e365,e305,e304,e303,e302,e218,e217,e1] at e1942
  exact congrArg some e1942

theorem actual_root_431 (pub rows : Nat → F) :
    (exactNonlinearRoots[431]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (((rows 93 + rows 94) * ((rows 181 + (rows 180 + (rows 178 + rows 179))) * (rows 180 + rows 181))) * ((rows 242 * (rows 206 - rows 216)) - 1)) := by
  rw [show exactNonlinearRoots[431]? = some 1948 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e330 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[330]? = some (.witnessRow 206) by decide)
  have e340 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[340]? = some (.witnessRow 216) by decide)
  have e366 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[366]? = some (.witnessRow 242) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1624 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1624]? = some (.add 302 303) by decide)
  have e1625 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1625]? = some (.add 304 1624) by decide)
  have e1626 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1626]? = some (.add 305 1625) by decide)
  have e1641 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1641]? = some (.add 304 305) by decide)
  have e1943 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1943]? = some (.mul 1626 1641) by decide)
  have e1944 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1944]? = some (.sub 330 340) by decide)
  have e1945 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1945]? = some (.mul 1234 1943) by decide)
  have e1946 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1946]? = some (.mul 366 1944) by decide)
  have e1947 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1947]? = some (.sub 1946 1) by decide)
  have e1948 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1948]? = some (.mul 1945 1947) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e302 e303 e304 e305 e330 e340 e366 e1234 e1624 e1625 e1626 e1641 e1943 e1944 e1945 e1946 e1947 e1948
  rw [e1947,e1946,e1945,e1944,e1943,e1641,e1626,e1625,e1624,e1234,e366,e340,e330,e305,e304,e303,e302,e218,e217,e1] at e1948
  exact congrArg some e1948

theorem actual_root_432 (pub rows : Nat → F) :
    (exactNonlinearRoots[432]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 242 * ((rows 93 + rows 94) * (1 - ((rows 181 + (rows 180 + (rows 178 + rows 179))) * (rows 180 + rows 181))))) := by
  rw [show exactNonlinearRoots[432]? = some 1951 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e366 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[366]? = some (.witnessRow 242) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1624 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1624]? = some (.add 302 303) by decide)
  have e1625 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1625]? = some (.add 304 1624) by decide)
  have e1626 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1626]? = some (.add 305 1625) by decide)
  have e1641 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1641]? = some (.add 304 305) by decide)
  have e1943 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1943]? = some (.mul 1626 1641) by decide)
  have e1949 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1949]? = some (.sub 1 1943) by decide)
  have e1950 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1950]? = some (.mul 1234 1949) by decide)
  have e1951 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1951]? = some (.mul 366 1950) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e302 e303 e304 e305 e366 e1234 e1624 e1625 e1626 e1641 e1943 e1949 e1950 e1951
  rw [e1950,e1949,e1943,e1641,e1626,e1625,e1624,e1234,e366,e305,e304,e303,e302,e218,e217,e1] at e1951
  exact congrArg some e1951

theorem actual_root_433 (pub rows : Nat → F) :
    (exactNonlinearRoots[433]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (((rows 93 + rows 94) * (rows 181 * (rows 181 + (rows 180 + (rows 178 + rows 179))))) * ((rows 243 * (rows 206 - rows 221)) - 1)) := by
  rw [show exactNonlinearRoots[433]? = some 1957 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e330 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[330]? = some (.witnessRow 206) by decide)
  have e345 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[345]? = some (.witnessRow 221) by decide)
  have e367 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[367]? = some (.witnessRow 243) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1624 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1624]? = some (.add 302 303) by decide)
  have e1625 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1625]? = some (.add 304 1624) by decide)
  have e1626 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1626]? = some (.add 305 1625) by decide)
  have e1952 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1952]? = some (.mul 305 1626) by decide)
  have e1953 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1953]? = some (.sub 330 345) by decide)
  have e1954 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1954]? = some (.mul 1234 1952) by decide)
  have e1955 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1955]? = some (.mul 367 1953) by decide)
  have e1956 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1956]? = some (.sub 1955 1) by decide)
  have e1957 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1957]? = some (.mul 1954 1956) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e302 e303 e304 e305 e330 e345 e367 e1234 e1624 e1625 e1626 e1952 e1953 e1954 e1955 e1956 e1957
  rw [e1956,e1955,e1954,e1953,e1952,e1626,e1625,e1624,e1234,e367,e345,e330,e305,e304,e303,e302,e218,e217,e1] at e1957
  exact congrArg some e1957

theorem actual_root_434 (pub rows : Nat → F) :
    (exactNonlinearRoots[434]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 243 * ((rows 93 + rows 94) * (1 - (rows 181 * (rows 181 + (rows 180 + (rows 178 + rows 179))))))) := by
  rw [show exactNonlinearRoots[434]? = some 1960 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e367 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[367]? = some (.witnessRow 243) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1624 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1624]? = some (.add 302 303) by decide)
  have e1625 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1625]? = some (.add 304 1624) by decide)
  have e1626 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1626]? = some (.add 305 1625) by decide)
  have e1952 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1952]? = some (.mul 305 1626) by decide)
  have e1958 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1958]? = some (.sub 1 1952) by decide)
  have e1959 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1959]? = some (.mul 1234 1958) by decide)
  have e1960 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1960]? = some (.mul 367 1959) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e302 e303 e304 e305 e367 e1234 e1624 e1625 e1626 e1952 e1958 e1959 e1960
  rw [e1959,e1958,e1952,e1626,e1625,e1624,e1234,e367,e305,e304,e303,e302,e218,e217,e1] at e1960
  exact congrArg some e1960

theorem actual_root_435 (pub rows : Nat → F) :
    (exactNonlinearRoots[435]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (((rows 93 + rows 94) * ((rows 181 + (rows 179 + rows 180)) * (rows 180 + rows 181))) * ((rows 244 * (rows 211 - rows 216)) - 1)) := by
  rw [show exactNonlinearRoots[435]? = some 1966 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e335 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[335]? = some (.witnessRow 211) by decide)
  have e340 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[340]? = some (.witnessRow 216) by decide)
  have e368 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[368]? = some (.witnessRow 244) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1633 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1633]? = some (.add 303 304) by decide)
  have e1634 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1634]? = some (.add 305 1633) by decide)
  have e1641 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1641]? = some (.add 304 305) by decide)
  have e1961 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1961]? = some (.mul 1634 1641) by decide)
  have e1962 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1962]? = some (.sub 335 340) by decide)
  have e1963 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1963]? = some (.mul 1234 1961) by decide)
  have e1964 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1964]? = some (.mul 368 1962) by decide)
  have e1965 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1965]? = some (.sub 1964 1) by decide)
  have e1966 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1966]? = some (.mul 1963 1965) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e303 e304 e305 e335 e340 e368 e1234 e1633 e1634 e1641 e1961 e1962 e1963 e1964 e1965 e1966
  rw [e1965,e1964,e1963,e1962,e1961,e1641,e1634,e1633,e1234,e368,e340,e335,e305,e304,e303,e218,e217,e1] at e1966
  exact congrArg some e1966

theorem actual_root_436 (pub rows : Nat → F) :
    (exactNonlinearRoots[436]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 244 * ((rows 93 + rows 94) * (1 - ((rows 181 + (rows 179 + rows 180)) * (rows 180 + rows 181))))) := by
  rw [show exactNonlinearRoots[436]? = some 1969 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e368 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[368]? = some (.witnessRow 244) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1633 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1633]? = some (.add 303 304) by decide)
  have e1634 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1634]? = some (.add 305 1633) by decide)
  have e1641 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1641]? = some (.add 304 305) by decide)
  have e1961 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1961]? = some (.mul 1634 1641) by decide)
  have e1967 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1967]? = some (.sub 1 1961) by decide)
  have e1968 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1968]? = some (.mul 1234 1967) by decide)
  have e1969 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1969]? = some (.mul 368 1968) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e303 e304 e305 e368 e1234 e1633 e1634 e1641 e1961 e1967 e1968 e1969
  rw [e1968,e1967,e1961,e1641,e1634,e1633,e1234,e368,e305,e304,e303,e218,e217,e1] at e1969
  exact congrArg some e1969

theorem actual_root_437 (pub rows : Nat → F) :
    (exactNonlinearRoots[437]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (((rows 93 + rows 94) * (rows 181 * (rows 181 + (rows 179 + rows 180)))) * ((rows 245 * (rows 211 - rows 221)) - 1)) := by
  rw [show exactNonlinearRoots[437]? = some 1975 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e335 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[335]? = some (.witnessRow 211) by decide)
  have e345 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[345]? = some (.witnessRow 221) by decide)
  have e369 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[369]? = some (.witnessRow 245) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1633 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1633]? = some (.add 303 304) by decide)
  have e1634 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1634]? = some (.add 305 1633) by decide)
  have e1970 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1970]? = some (.mul 305 1634) by decide)
  have e1971 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1971]? = some (.sub 335 345) by decide)
  have e1972 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1972]? = some (.mul 1234 1970) by decide)
  have e1973 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1973]? = some (.mul 369 1971) by decide)
  have e1974 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1974]? = some (.sub 1973 1) by decide)
  have e1975 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1975]? = some (.mul 1972 1974) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e303 e304 e305 e335 e345 e369 e1234 e1633 e1634 e1970 e1971 e1972 e1973 e1974 e1975
  rw [e1974,e1973,e1972,e1971,e1970,e1634,e1633,e1234,e369,e345,e335,e305,e304,e303,e218,e217,e1] at e1975
  exact congrArg some e1975

theorem actual_root_438 (pub rows : Nat → F) :
    (exactNonlinearRoots[438]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 245 * ((rows 93 + rows 94) * (1 - (rows 181 * (rows 181 + (rows 179 + rows 180)))))) := by
  rw [show exactNonlinearRoots[438]? = some 1978 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e369 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[369]? = some (.witnessRow 245) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1633 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1633]? = some (.add 303 304) by decide)
  have e1634 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1634]? = some (.add 305 1633) by decide)
  have e1970 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1970]? = some (.mul 305 1634) by decide)
  have e1976 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1976]? = some (.sub 1 1970) by decide)
  have e1977 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1977]? = some (.mul 1234 1976) by decide)
  have e1978 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1978]? = some (.mul 369 1977) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e303 e304 e305 e369 e1234 e1633 e1634 e1970 e1976 e1977 e1978
  rw [e1977,e1976,e1970,e1634,e1633,e1234,e369,e305,e304,e303,e218,e217,e1] at e1978
  exact congrArg some e1978

theorem actual_root_439 (pub rows : Nat → F) :
    (exactNonlinearRoots[439]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (((rows 93 + rows 94) * (rows 181 * (rows 180 + rows 181))) * ((rows 246 * (rows 216 - rows 221)) - 1)) := by
  rw [show exactNonlinearRoots[439]? = some 1984 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e340 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[340]? = some (.witnessRow 216) by decide)
  have e345 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[345]? = some (.witnessRow 221) by decide)
  have e370 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[370]? = some (.witnessRow 246) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1641 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1641]? = some (.add 304 305) by decide)
  have e1979 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1979]? = some (.mul 305 1641) by decide)
  have e1980 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1980]? = some (.sub 340 345) by decide)
  have e1981 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1981]? = some (.mul 1234 1979) by decide)
  have e1982 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1982]? = some (.mul 370 1980) by decide)
  have e1983 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1983]? = some (.sub 1982 1) by decide)
  have e1984 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1984]? = some (.mul 1981 1983) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e304 e305 e340 e345 e370 e1234 e1641 e1979 e1980 e1981 e1982 e1983 e1984
  rw [e1983,e1982,e1981,e1980,e1979,e1641,e1234,e370,e345,e340,e305,e304,e218,e217,e1] at e1984
  exact congrArg some e1984

theorem actual_root_440 (pub rows : Nat → F) :
    (exactNonlinearRoots[440]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 246 * ((rows 93 + rows 94) * (1 - (rows 181 * (rows 180 + rows 181))))) := by
  rw [show exactNonlinearRoots[440]? = some 1987 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e370 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[370]? = some (.witnessRow 246) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1641 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1641]? = some (.add 304 305) by decide)
  have e1979 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1979]? = some (.mul 305 1641) by decide)
  have e1985 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1985]? = some (.sub 1 1979) by decide)
  have e1986 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1986]? = some (.mul 1234 1985) by decide)
  have e1987 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1987]? = some (.mul 370 1986) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e304 e305 e370 e1234 e1641 e1979 e1985 e1986 e1987
  rw [e1986,e1985,e1979,e1641,e1234,e370,e305,e304,e218,e217,e1] at e1987
  exact congrArg some e1987

end
end HegemonCrypto.SmallWood.V8Smz9SourceAuthLastInverseDAG

