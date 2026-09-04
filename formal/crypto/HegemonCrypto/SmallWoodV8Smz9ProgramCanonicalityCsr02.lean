import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityCsr01

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr02
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [1024, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 1024 0 1024 0 [(1041, 1), (1024, 3)] 0, attempt 1025 0 1025 0 [(1042, 1), (1024, 3)] 0, attempt 1026 0 1026 0 [(1043, 1), (1024, 3)] 0, attempt 1027 0 1027 0 [(1044, 1), (1024, 3)] 0, attempt 1028 0 1028 0 [(1045, 1), (1024, 3)] 0, attempt 1029 0 1029 0 [(1046, 1), (1024, 3)] 0, attempt 1030 0 1030 0 [(1047, 1), (1024, 3)] 0, attempt 1031 0 1031 0 [(1048, 1), (1024, 3)] 0, attempt 1032 0 1032 0 [(1049, 1), (1024, 3)] 0, attempt 1033 0 1033 0 [(1050, 1), (1024, 3)] 0, attempt 1034 0 1034 0 [(1051, 1), (1024, 3)] 0, attempt 1035 0 1035 0 [(1052, 1), (1024, 3)] 0, attempt 1036 0 1036 0 [(1053, 1), (1024, 3)] 0, attempt 1037 0 1037 0 [(1054, 1), (1024, 3)] 0, attempt 1038 0 1038 0 [(1055, 1), (1024, 3)] 0, attempt 1039 0 1039 0 [(1056, 1), (1024, 3)] 0, attempt 1040 0 1040 0 [(1057, 1), (1024, 3)] 0, attempt 1041 0 1041 0 [(1058, 1), (1024, 3)] 0, attempt 1042 0 1042 0 [(1059, 1), (1024, 3)] 0, attempt 1043 0 1043 0 [(1060, 1), (1024, 3)] 0, attempt 1044 0 1044 0 [(1061, 1), (1024, 3)] 0, attempt 1045 0 1045 0 [(1062, 1), (1024, 3)] 0, attempt 1046 0 1046 0 [(1063, 1), (1024, 3)] 0, attempt 1047 0 1047 0 [(1064, 1), (1024, 3)] 0, attempt 1048 0 1048 0 [(1065, 1), (1024, 3)] 0, attempt 1049 0 1049 0 [(1066, 1), (1024, 3)] 0, attempt 1050 0 1050 0 [(1067, 1), (1024, 3)] 0, attempt 1051 0 1051 0 [(1068, 1), (1024, 3)] 0, attempt 1052 0 1052 0 [(1069, 1), (1024, 3)] 0, attempt 1053 0 1053 0 [(1070, 1), (1024, 3)] 0, attempt 1054 0 1054 0 [(1071, 1), (1024, 3)] 0, attempt 1055 0 1055 0 [(1072, 1), (1024, 3)] 0]
def counters001 : List Nat := [1056, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1024
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 1056 0 1056 0 [(1073, 1), (1024, 3)] 0, attempt 1057 0 1057 0 [(1074, 1), (1024, 3)] 0, attempt 1058 0 1058 0 [(1075, 1), (1024, 3)] 0, attempt 1059 0 1059 0 [(1076, 1), (1024, 3)] 0, attempt 1060 0 1060 0 [(1077, 1), (1024, 3)] 0, attempt 1061 0 1061 0 [(1078, 1), (1024, 3)] 0, attempt 1062 0 1062 0 [(1079, 1), (1024, 3)] 0, attempt 1063 0 1063 0 [(1080, 1), (1024, 3)] 0, attempt 1064 0 1064 0 [(1081, 1), (1024, 3)] 0, attempt 1065 0 1065 0 [(1082, 1), (1024, 3)] 0, attempt 1066 0 1066 0 [(1083, 1), (1024, 3)] 0, attempt 1067 0 1067 0 [(1084, 1), (1024, 3)] 0, attempt 1068 0 1068 0 [(1085, 1), (1024, 3)] 0, attempt 1069 0 1069 0 [(1086, 1), (1024, 3)] 0, attempt 1070 0 1070 0 [(1087, 1), (1024, 3)] 0, attempt 1071 0 1071 0 [(1089, 1), (1088, 3)] 0, attempt 1072 0 1072 0 [(1090, 1), (1088, 3)] 0, attempt 1073 0 1073 0 [(1091, 1), (1088, 3)] 0, attempt 1074 0 1074 0 [(1092, 1), (1088, 3)] 0, attempt 1075 0 1075 0 [(1093, 1), (1088, 3)] 0, attempt 1076 0 1076 0 [(1094, 1), (1088, 3)] 0, attempt 1077 0 1077 0 [(1095, 1), (1088, 3)] 0, attempt 1078 0 1078 0 [(1096, 1), (1088, 3)] 0, attempt 1079 0 1079 0 [(1097, 1), (1088, 3)] 0, attempt 1080 0 1080 0 [(1098, 1), (1088, 3)] 0, attempt 1081 0 1081 0 [(1099, 1), (1088, 3)] 0, attempt 1082 0 1082 0 [(1100, 1), (1088, 3)] 0, attempt 1083 0 1083 0 [(1101, 1), (1088, 3)] 0, attempt 1084 0 1084 0 [(1102, 1), (1088, 3)] 0, attempt 1085 0 1085 0 [(1103, 1), (1088, 3)] 0, attempt 1086 0 1086 0 [(1104, 1), (1088, 3)] 0, attempt 1087 0 1087 0 [(1105, 1), (1088, 3)] 0]
def counters002 : List Nat := [1088, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1056
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 1088 0 1088 0 [(1106, 1), (1088, 3)] 0, attempt 1089 0 1089 0 [(1107, 1), (1088, 3)] 0, attempt 1090 0 1090 0 [(1108, 1), (1088, 3)] 0, attempt 1091 0 1091 0 [(1109, 1), (1088, 3)] 0, attempt 1092 0 1092 0 [(1110, 1), (1088, 3)] 0, attempt 1093 0 1093 0 [(1111, 1), (1088, 3)] 0, attempt 1094 0 1094 0 [(1112, 1), (1088, 3)] 0, attempt 1095 0 1095 0 [(1113, 1), (1088, 3)] 0, attempt 1096 0 1096 0 [(1114, 1), (1088, 3)] 0, attempt 1097 0 1097 0 [(1115, 1), (1088, 3)] 0, attempt 1098 0 1098 0 [(1116, 1), (1088, 3)] 0, attempt 1099 0 1099 0 [(1117, 1), (1088, 3)] 0, attempt 1100 0 1100 0 [(1118, 1), (1088, 3)] 0, attempt 1101 0 1101 0 [(1119, 1), (1088, 3)] 0, attempt 1102 0 1102 0 [(1120, 1), (1088, 3)] 0, attempt 1103 0 1103 0 [(1121, 1), (1088, 3)] 0, attempt 1104 0 1104 0 [(1122, 1), (1088, 3)] 0, attempt 1105 0 1105 0 [(1123, 1), (1088, 3)] 0, attempt 1106 0 1106 0 [(1124, 1), (1088, 3)] 0, attempt 1107 0 1107 0 [(1125, 1), (1088, 3)] 0, attempt 1108 0 1108 0 [(1126, 1), (1088, 3)] 0, attempt 1109 0 1109 0 [(1127, 1), (1088, 3)] 0, attempt 1110 0 1110 0 [(1128, 1), (1088, 3)] 0, attempt 1111 0 1111 0 [(1129, 1), (1088, 3)] 0, attempt 1112 0 1112 0 [(1130, 1), (1088, 3)] 0, attempt 1113 0 1113 0 [(1131, 1), (1088, 3)] 0, attempt 1114 0 1114 0 [(1132, 1), (1088, 3)] 0, attempt 1115 0 1115 0 [(1133, 1), (1088, 3)] 0, attempt 1116 0 1116 0 [(1134, 1), (1088, 3)] 0, attempt 1117 0 1117 0 [(1135, 1), (1088, 3)] 0, attempt 1118 0 1118 0 [(1136, 1), (1088, 3)] 0, attempt 1119 0 1119 0 [(1137, 1), (1088, 3)] 0]
def counters003 : List Nat := [1120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1088
        counters002 chunk002 = true ∧ chunk002.length = 32 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def chunk003 : List CsrExecutableAttempt :=
  [attempt 1120 0 1120 0 [(1138, 1), (1088, 3)] 0, attempt 1121 0 1121 0 [(1139, 1), (1088, 3)] 0, attempt 1122 0 1122 0 [(1140, 1), (1088, 3)] 0, attempt 1123 0 1123 0 [(1141, 1), (1088, 3)] 0, attempt 1124 0 1124 0 [(1142, 1), (1088, 3)] 0, attempt 1125 0 1125 0 [(1143, 1), (1088, 3)] 0, attempt 1126 0 1126 0 [(1144, 1), (1088, 3)] 0, attempt 1127 0 1127 0 [(1145, 1), (1088, 3)] 0, attempt 1128 0 1128 0 [(1146, 1), (1088, 3)] 0, attempt 1129 0 1129 0 [(1147, 1), (1088, 3)] 0, attempt 1130 0 1130 0 [(1148, 1), (1088, 3)] 0, attempt 1131 0 1131 0 [(1149, 1), (1088, 3)] 0, attempt 1132 0 1132 0 [(1150, 1), (1088, 3)] 0, attempt 1133 0 1133 0 [(1151, 1), (1088, 3)] 0, attempt 1134 0 1134 0 [(1153, 1), (1152, 3)] 0, attempt 1135 0 1135 0 [(1154, 1), (1152, 3)] 0, attempt 1136 0 1136 0 [(1155, 1), (1152, 3)] 0, attempt 1137 0 1137 0 [(1156, 1), (1152, 3)] 0, attempt 1138 0 1138 0 [(1157, 1), (1152, 3)] 0, attempt 1139 0 1139 0 [(1158, 1), (1152, 3)] 0, attempt 1140 0 1140 0 [(1159, 1), (1152, 3)] 0, attempt 1141 0 1141 0 [(1160, 1), (1152, 3)] 0, attempt 1142 0 1142 0 [(1161, 1), (1152, 3)] 0, attempt 1143 0 1143 0 [(1162, 1), (1152, 3)] 0, attempt 1144 0 1144 0 [(1163, 1), (1152, 3)] 0, attempt 1145 0 1145 0 [(1164, 1), (1152, 3)] 0, attempt 1146 0 1146 0 [(1165, 1), (1152, 3)] 0, attempt 1147 0 1147 0 [(1166, 1), (1152, 3)] 0, attempt 1148 0 1148 0 [(1167, 1), (1152, 3)] 0, attempt 1149 0 1149 0 [(1168, 1), (1152, 3)] 0, attempt 1150 0 1150 0 [(1169, 1), (1152, 3)] 0, attempt 1151 0 1151 0 [(1170, 1), (1152, 3)] 0]
def counters004 : List Nat := [1152, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1120
        counters003 chunk003 = true ∧ chunk003.length = 32 ∧
      advanceCsrCounters counters003 chunk003 = counters004 := by decide

def chunk004 : List CsrExecutableAttempt :=
  [attempt 1152 0 1152 0 [(1171, 1), (1152, 3)] 0, attempt 1153 0 1153 0 [(1172, 1), (1152, 3)] 0, attempt 1154 0 1154 0 [(1173, 1), (1152, 3)] 0, attempt 1155 0 1155 0 [(1174, 1), (1152, 3)] 0, attempt 1156 0 1156 0 [(1175, 1), (1152, 3)] 0, attempt 1157 0 1157 0 [(1176, 1), (1152, 3)] 0, attempt 1158 0 1158 0 [(1177, 1), (1152, 3)] 0, attempt 1159 0 1159 0 [(1178, 1), (1152, 3)] 0, attempt 1160 0 1160 0 [(1179, 1), (1152, 3)] 0, attempt 1161 0 1161 0 [(1180, 1), (1152, 3)] 0, attempt 1162 0 1162 0 [(1181, 1), (1152, 3)] 0, attempt 1163 0 1163 0 [(1182, 1), (1152, 3)] 0, attempt 1164 0 1164 0 [(1183, 1), (1152, 3)] 0, attempt 1165 0 1165 0 [(1184, 1), (1152, 3)] 0, attempt 1166 0 1166 0 [(1185, 1), (1152, 3)] 0, attempt 1167 0 1167 0 [(1186, 1), (1152, 3)] 0, attempt 1168 0 1168 0 [(1187, 1), (1152, 3)] 0, attempt 1169 0 1169 0 [(1188, 1), (1152, 3)] 0, attempt 1170 0 1170 0 [(1189, 1), (1152, 3)] 0, attempt 1171 0 1171 0 [(1190, 1), (1152, 3)] 0, attempt 1172 0 1172 0 [(1191, 1), (1152, 3)] 0, attempt 1173 0 1173 0 [(1192, 1), (1152, 3)] 0, attempt 1174 0 1174 0 [(1193, 1), (1152, 3)] 0, attempt 1175 0 1175 0 [(1194, 1), (1152, 3)] 0, attempt 1176 0 1176 0 [(1195, 1), (1152, 3)] 0, attempt 1177 0 1177 0 [(1196, 1), (1152, 3)] 0, attempt 1178 0 1178 0 [(1197, 1), (1152, 3)] 0, attempt 1179 0 1179 0 [(1198, 1), (1152, 3)] 0, attempt 1180 0 1180 0 [(1199, 1), (1152, 3)] 0, attempt 1181 0 1181 0 [(1200, 1), (1152, 3)] 0, attempt 1182 0 1182 0 [(1201, 1), (1152, 3)] 0, attempt 1183 0 1183 0 [(1202, 1), (1152, 3)] 0]
def counters005 : List Nat := [1184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1152
        counters004 chunk004 = true ∧ chunk004.length = 32 ∧
      advanceCsrCounters counters004 chunk004 = counters005 := by decide

def chunk005 : List CsrExecutableAttempt :=
  [attempt 1184 0 1184 0 [(1203, 1), (1152, 3)] 0, attempt 1185 0 1185 0 [(1204, 1), (1152, 3)] 0, attempt 1186 0 1186 0 [(1205, 1), (1152, 3)] 0, attempt 1187 0 1187 0 [(1206, 1), (1152, 3)] 0, attempt 1188 0 1188 0 [(1207, 1), (1152, 3)] 0, attempt 1189 0 1189 0 [(1208, 1), (1152, 3)] 0, attempt 1190 0 1190 0 [(1209, 1), (1152, 3)] 0, attempt 1191 0 1191 0 [(1210, 1), (1152, 3)] 0, attempt 1192 0 1192 0 [(1211, 1), (1152, 3)] 0, attempt 1193 0 1193 0 [(1212, 1), (1152, 3)] 0, attempt 1194 0 1194 0 [(1213, 1), (1152, 3)] 0, attempt 1195 0 1195 0 [(1214, 1), (1152, 3)] 0, attempt 1196 0 1196 0 [(1215, 1), (1152, 3)] 0, attempt 1197 0 1197 0 [(1217, 1), (1216, 3)] 0, attempt 1198 0 1198 0 [(1218, 1), (1216, 3)] 0, attempt 1199 0 1199 0 [(1219, 1), (1216, 3)] 0, attempt 1200 0 1200 0 [(1220, 1), (1216, 3)] 0, attempt 1201 0 1201 0 [(1221, 1), (1216, 3)] 0, attempt 1202 0 1202 0 [(1222, 1), (1216, 3)] 0, attempt 1203 0 1203 0 [(1223, 1), (1216, 3)] 0, attempt 1204 0 1204 0 [(1224, 1), (1216, 3)] 0, attempt 1205 0 1205 0 [(1225, 1), (1216, 3)] 0, attempt 1206 0 1206 0 [(1226, 1), (1216, 3)] 0, attempt 1207 0 1207 0 [(1227, 1), (1216, 3)] 0, attempt 1208 0 1208 0 [(1228, 1), (1216, 3)] 0, attempt 1209 0 1209 0 [(1229, 1), (1216, 3)] 0, attempt 1210 0 1210 0 [(1230, 1), (1216, 3)] 0, attempt 1211 0 1211 0 [(1231, 1), (1216, 3)] 0, attempt 1212 0 1212 0 [(1232, 1), (1216, 3)] 0, attempt 1213 0 1213 0 [(1233, 1), (1216, 3)] 0, attempt 1214 0 1214 0 [(1234, 1), (1216, 3)] 0, attempt 1215 0 1215 0 [(1235, 1), (1216, 3)] 0]
def counters006 : List Nat := [1216, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1184
        counters005 chunk005 = true ∧ chunk005.length = 32 ∧
      advanceCsrCounters counters005 chunk005 = counters006 := by decide

def chunk006 : List CsrExecutableAttempt :=
  [attempt 1216 0 1216 0 [(1236, 1), (1216, 3)] 0, attempt 1217 0 1217 0 [(1237, 1), (1216, 3)] 0, attempt 1218 0 1218 0 [(1238, 1), (1216, 3)] 0, attempt 1219 0 1219 0 [(1239, 1), (1216, 3)] 0, attempt 1220 0 1220 0 [(1240, 1), (1216, 3)] 0, attempt 1221 0 1221 0 [(1241, 1), (1216, 3)] 0, attempt 1222 0 1222 0 [(1242, 1), (1216, 3)] 0, attempt 1223 0 1223 0 [(1243, 1), (1216, 3)] 0, attempt 1224 0 1224 0 [(1244, 1), (1216, 3)] 0, attempt 1225 0 1225 0 [(1245, 1), (1216, 3)] 0, attempt 1226 0 1226 0 [(1246, 1), (1216, 3)] 0, attempt 1227 0 1227 0 [(1247, 1), (1216, 3)] 0, attempt 1228 0 1228 0 [(1248, 1), (1216, 3)] 0, attempt 1229 0 1229 0 [(1249, 1), (1216, 3)] 0, attempt 1230 0 1230 0 [(1250, 1), (1216, 3)] 0, attempt 1231 0 1231 0 [(1251, 1), (1216, 3)] 0, attempt 1232 0 1232 0 [(1252, 1), (1216, 3)] 0, attempt 1233 0 1233 0 [(1253, 1), (1216, 3)] 0, attempt 1234 0 1234 0 [(1254, 1), (1216, 3)] 0, attempt 1235 0 1235 0 [(1255, 1), (1216, 3)] 0, attempt 1236 0 1236 0 [(1256, 1), (1216, 3)] 0, attempt 1237 0 1237 0 [(1257, 1), (1216, 3)] 0, attempt 1238 0 1238 0 [(1258, 1), (1216, 3)] 0, attempt 1239 0 1239 0 [(1259, 1), (1216, 3)] 0, attempt 1240 0 1240 0 [(1260, 1), (1216, 3)] 0, attempt 1241 0 1241 0 [(1261, 1), (1216, 3)] 0, attempt 1242 0 1242 0 [(1262, 1), (1216, 3)] 0, attempt 1243 0 1243 0 [(1263, 1), (1216, 3)] 0, attempt 1244 0 1244 0 [(1264, 1), (1216, 3)] 0, attempt 1245 0 1245 0 [(1265, 1), (1216, 3)] 0, attempt 1246 0 1246 0 [(1266, 1), (1216, 3)] 0, attempt 1247 0 1247 0 [(1267, 1), (1216, 3)] 0]
def counters007 : List Nat := [1248, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1216
        counters006 chunk006 = true ∧ chunk006.length = 32 ∧
      advanceCsrCounters counters006 chunk006 = counters007 := by decide

def chunk007 : List CsrExecutableAttempt :=
  [attempt 1248 0 1248 0 [(1268, 1), (1216, 3)] 0, attempt 1249 0 1249 0 [(1269, 1), (1216, 3)] 0, attempt 1250 0 1250 0 [(1270, 1), (1216, 3)] 0, attempt 1251 0 1251 0 [(1271, 1), (1216, 3)] 0, attempt 1252 0 1252 0 [(1272, 1), (1216, 3)] 0, attempt 1253 0 1253 0 [(1273, 1), (1216, 3)] 0, attempt 1254 0 1254 0 [(1274, 1), (1216, 3)] 0, attempt 1255 0 1255 0 [(1275, 1), (1216, 3)] 0, attempt 1256 0 1256 0 [(1276, 1), (1216, 3)] 0, attempt 1257 0 1257 0 [(1277, 1), (1216, 3)] 0, attempt 1258 0 1258 0 [(1278, 1), (1216, 3)] 0, attempt 1259 0 1259 0 [(1279, 1), (1216, 3)] 0, attempt 1260 0 1260 0 [(1281, 1), (1280, 3)] 0, attempt 1261 0 1261 0 [(1282, 1), (1280, 3)] 0, attempt 1262 0 1262 0 [(1283, 1), (1280, 3)] 0, attempt 1263 0 1263 0 [(1284, 1), (1280, 3)] 0, attempt 1264 0 1264 0 [(1285, 1), (1280, 3)] 0, attempt 1265 0 1265 0 [(1286, 1), (1280, 3)] 0, attempt 1266 0 1266 0 [(1287, 1), (1280, 3)] 0, attempt 1267 0 1267 0 [(1288, 1), (1280, 3)] 0, attempt 1268 0 1268 0 [(1289, 1), (1280, 3)] 0, attempt 1269 0 1269 0 [(1290, 1), (1280, 3)] 0, attempt 1270 0 1270 0 [(1291, 1), (1280, 3)] 0, attempt 1271 0 1271 0 [(1292, 1), (1280, 3)] 0, attempt 1272 0 1272 0 [(1293, 1), (1280, 3)] 0, attempt 1273 0 1273 0 [(1294, 1), (1280, 3)] 0, attempt 1274 0 1274 0 [(1295, 1), (1280, 3)] 0, attempt 1275 0 1275 0 [(1296, 1), (1280, 3)] 0, attempt 1276 0 1276 0 [(1297, 1), (1280, 3)] 0, attempt 1277 0 1277 0 [(1298, 1), (1280, 3)] 0, attempt 1278 0 1278 0 [(1299, 1), (1280, 3)] 0, attempt 1279 0 1279 0 [(1300, 1), (1280, 3)] 0]
def counters008 : List Nat := [1280, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1248
        counters007 chunk007 = true ∧ chunk007.length = 32 ∧
      advanceCsrCounters counters007 chunk007 = counters008 := by decide

def chunk008 : List CsrExecutableAttempt :=
  [attempt 1280 0 1280 0 [(1301, 1), (1280, 3)] 0, attempt 1281 0 1281 0 [(1302, 1), (1280, 3)] 0, attempt 1282 0 1282 0 [(1303, 1), (1280, 3)] 0, attempt 1283 0 1283 0 [(1304, 1), (1280, 3)] 0, attempt 1284 0 1284 0 [(1305, 1), (1280, 3)] 0, attempt 1285 0 1285 0 [(1306, 1), (1280, 3)] 0, attempt 1286 0 1286 0 [(1307, 1), (1280, 3)] 0, attempt 1287 0 1287 0 [(1308, 1), (1280, 3)] 0, attempt 1288 0 1288 0 [(1309, 1), (1280, 3)] 0, attempt 1289 0 1289 0 [(1310, 1), (1280, 3)] 0, attempt 1290 0 1290 0 [(1311, 1), (1280, 3)] 0, attempt 1291 0 1291 0 [(1312, 1), (1280, 3)] 0, attempt 1292 0 1292 0 [(1313, 1), (1280, 3)] 0, attempt 1293 0 1293 0 [(1314, 1), (1280, 3)] 0, attempt 1294 0 1294 0 [(1315, 1), (1280, 3)] 0, attempt 1295 0 1295 0 [(1316, 1), (1280, 3)] 0, attempt 1296 0 1296 0 [(1317, 1), (1280, 3)] 0, attempt 1297 0 1297 0 [(1318, 1), (1280, 3)] 0, attempt 1298 0 1298 0 [(1319, 1), (1280, 3)] 0, attempt 1299 0 1299 0 [(1320, 1), (1280, 3)] 0, attempt 1300 0 1300 0 [(1321, 1), (1280, 3)] 0, attempt 1301 0 1301 0 [(1322, 1), (1280, 3)] 0, attempt 1302 0 1302 0 [(1323, 1), (1280, 3)] 0, attempt 1303 0 1303 0 [(1324, 1), (1280, 3)] 0, attempt 1304 0 1304 0 [(1325, 1), (1280, 3)] 0, attempt 1305 0 1305 0 [(1326, 1), (1280, 3)] 0, attempt 1306 0 1306 0 [(1327, 1), (1280, 3)] 0, attempt 1307 0 1307 0 [(1328, 1), (1280, 3)] 0, attempt 1308 0 1308 0 [(1329, 1), (1280, 3)] 0, attempt 1309 0 1309 0 [(1330, 1), (1280, 3)] 0, attempt 1310 0 1310 0 [(1331, 1), (1280, 3)] 0, attempt 1311 0 1311 0 [(1332, 1), (1280, 3)] 0]
def counters009 : List Nat := [1312, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1280
        counters008 chunk008 = true ∧ chunk008.length = 32 ∧
      advanceCsrCounters counters008 chunk008 = counters009 := by decide

def chunk009 : List CsrExecutableAttempt :=
  [attempt 1312 0 1312 0 [(1333, 1), (1280, 3)] 0, attempt 1313 0 1313 0 [(1334, 1), (1280, 3)] 0, attempt 1314 0 1314 0 [(1335, 1), (1280, 3)] 0, attempt 1315 0 1315 0 [(1336, 1), (1280, 3)] 0, attempt 1316 0 1316 0 [(1337, 1), (1280, 3)] 0, attempt 1317 0 1317 0 [(1338, 1), (1280, 3)] 0, attempt 1318 0 1318 0 [(1339, 1), (1280, 3)] 0, attempt 1319 0 1319 0 [(1340, 1), (1280, 3)] 0, attempt 1320 0 1320 0 [(1341, 1), (1280, 3)] 0, attempt 1321 0 1321 0 [(1342, 1), (1280, 3)] 0, attempt 1322 0 1322 0 [(1343, 1), (1280, 3)] 0, attempt 1323 0 1323 0 [(1345, 1), (1344, 3)] 0, attempt 1324 0 1324 0 [(1346, 1), (1344, 3)] 0, attempt 1325 0 1325 0 [(1347, 1), (1344, 3)] 0, attempt 1326 0 1326 0 [(1348, 1), (1344, 3)] 0, attempt 1327 0 1327 0 [(1349, 1), (1344, 3)] 0, attempt 1328 0 1328 0 [(1350, 1), (1344, 3)] 0, attempt 1329 0 1329 0 [(1351, 1), (1344, 3)] 0, attempt 1330 0 1330 0 [(1352, 1), (1344, 3)] 0, attempt 1331 0 1331 0 [(1353, 1), (1344, 3)] 0, attempt 1332 0 1332 0 [(1354, 1), (1344, 3)] 0, attempt 1333 0 1333 0 [(1355, 1), (1344, 3)] 0, attempt 1334 0 1334 0 [(1356, 1), (1344, 3)] 0, attempt 1335 0 1335 0 [(1357, 1), (1344, 3)] 0, attempt 1336 0 1336 0 [(1358, 1), (1344, 3)] 0, attempt 1337 0 1337 0 [(1359, 1), (1344, 3)] 0, attempt 1338 0 1338 0 [(1360, 1), (1344, 3)] 0, attempt 1339 0 1339 0 [(1361, 1), (1344, 3)] 0, attempt 1340 0 1340 0 [(1362, 1), (1344, 3)] 0, attempt 1341 0 1341 0 [(1363, 1), (1344, 3)] 0, attempt 1342 0 1342 0 [(1364, 1), (1344, 3)] 0, attempt 1343 0 1343 0 [(1365, 1), (1344, 3)] 0]
def counters010 : List Nat := [1344, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1312
        counters009 chunk009 = true ∧ chunk009.length = 32 ∧
      advanceCsrCounters counters009 chunk009 = counters010 := by decide

def chunk010 : List CsrExecutableAttempt :=
  [attempt 1344 0 1344 0 [(1366, 1), (1344, 3)] 0, attempt 1345 0 1345 0 [(1367, 1), (1344, 3)] 0, attempt 1346 0 1346 0 [(1368, 1), (1344, 3)] 0, attempt 1347 0 1347 0 [(1369, 1), (1344, 3)] 0, attempt 1348 0 1348 0 [(1370, 1), (1344, 3)] 0, attempt 1349 0 1349 0 [(1371, 1), (1344, 3)] 0, attempt 1350 0 1350 0 [(1372, 1), (1344, 3)] 0, attempt 1351 0 1351 0 [(1373, 1), (1344, 3)] 0, attempt 1352 0 1352 0 [(1374, 1), (1344, 3)] 0, attempt 1353 0 1353 0 [(1375, 1), (1344, 3)] 0, attempt 1354 0 1354 0 [(1376, 1), (1344, 3)] 0, attempt 1355 0 1355 0 [(1377, 1), (1344, 3)] 0, attempt 1356 0 1356 0 [(1378, 1), (1344, 3)] 0, attempt 1357 0 1357 0 [(1379, 1), (1344, 3)] 0, attempt 1358 0 1358 0 [(1380, 1), (1344, 3)] 0, attempt 1359 0 1359 0 [(1381, 1), (1344, 3)] 0, attempt 1360 0 1360 0 [(1382, 1), (1344, 3)] 0, attempt 1361 0 1361 0 [(1383, 1), (1344, 3)] 0, attempt 1362 0 1362 0 [(1384, 1), (1344, 3)] 0, attempt 1363 0 1363 0 [(1385, 1), (1344, 3)] 0, attempt 1364 0 1364 0 [(1386, 1), (1344, 3)] 0, attempt 1365 0 1365 0 [(1387, 1), (1344, 3)] 0, attempt 1366 0 1366 0 [(1388, 1), (1344, 3)] 0, attempt 1367 0 1367 0 [(1389, 1), (1344, 3)] 0, attempt 1368 0 1368 0 [(1390, 1), (1344, 3)] 0, attempt 1369 0 1369 0 [(1391, 1), (1344, 3)] 0, attempt 1370 0 1370 0 [(1392, 1), (1344, 3)] 0, attempt 1371 0 1371 0 [(1393, 1), (1344, 3)] 0, attempt 1372 0 1372 0 [(1394, 1), (1344, 3)] 0, attempt 1373 0 1373 0 [(1395, 1), (1344, 3)] 0, attempt 1374 0 1374 0 [(1396, 1), (1344, 3)] 0, attempt 1375 0 1375 0 [(1397, 1), (1344, 3)] 0]
def counters011 : List Nat := [1376, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1344
        counters010 chunk010 = true ∧ chunk010.length = 32 ∧
      advanceCsrCounters counters010 chunk010 = counters011 := by decide

def chunk011 : List CsrExecutableAttempt :=
  [attempt 1376 0 1376 0 [(1398, 1), (1344, 3)] 0, attempt 1377 0 1377 0 [(1399, 1), (1344, 3)] 0, attempt 1378 0 1378 0 [(1400, 1), (1344, 3)] 0, attempt 1379 0 1379 0 [(1401, 1), (1344, 3)] 0, attempt 1380 0 1380 0 [(1402, 1), (1344, 3)] 0, attempt 1381 0 1381 0 [(1403, 1), (1344, 3)] 0, attempt 1382 0 1382 0 [(1404, 1), (1344, 3)] 0, attempt 1383 0 1383 0 [(1405, 1), (1344, 3)] 0, attempt 1384 0 1384 0 [(1406, 1), (1344, 3)] 0, attempt 1385 0 1385 0 [(1407, 1), (1344, 3)] 0, attempt 1386 0 1386 0 [(1409, 1), (1408, 3)] 0, attempt 1387 0 1387 0 [(1410, 1), (1408, 3)] 0, attempt 1388 0 1388 0 [(1411, 1), (1408, 3)] 0, attempt 1389 0 1389 0 [(1412, 1), (1408, 3)] 0, attempt 1390 0 1390 0 [(1413, 1), (1408, 3)] 0, attempt 1391 0 1391 0 [(1414, 1), (1408, 3)] 0, attempt 1392 0 1392 0 [(1415, 1), (1408, 3)] 0, attempt 1393 0 1393 0 [(1416, 1), (1408, 3)] 0, attempt 1394 0 1394 0 [(1417, 1), (1408, 3)] 0, attempt 1395 0 1395 0 [(1418, 1), (1408, 3)] 0, attempt 1396 0 1396 0 [(1419, 1), (1408, 3)] 0, attempt 1397 0 1397 0 [(1420, 1), (1408, 3)] 0, attempt 1398 0 1398 0 [(1421, 1), (1408, 3)] 0, attempt 1399 0 1399 0 [(1422, 1), (1408, 3)] 0, attempt 1400 0 1400 0 [(1423, 1), (1408, 3)] 0, attempt 1401 0 1401 0 [(1424, 1), (1408, 3)] 0, attempt 1402 0 1402 0 [(1425, 1), (1408, 3)] 0, attempt 1403 0 1403 0 [(1426, 1), (1408, 3)] 0, attempt 1404 0 1404 0 [(1427, 1), (1408, 3)] 0, attempt 1405 0 1405 0 [(1428, 1), (1408, 3)] 0, attempt 1406 0 1406 0 [(1429, 1), (1408, 3)] 0, attempt 1407 0 1407 0 [(1430, 1), (1408, 3)] 0]
def counters012 : List Nat := [1408, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1376
        counters011 chunk011 = true ∧ chunk011.length = 32 ∧
      advanceCsrCounters counters011 chunk011 = counters012 := by decide

def chunk012 : List CsrExecutableAttempt :=
  [attempt 1408 0 1408 0 [(1431, 1), (1408, 3)] 0, attempt 1409 0 1409 0 [(1432, 1), (1408, 3)] 0, attempt 1410 0 1410 0 [(1433, 1), (1408, 3)] 0, attempt 1411 0 1411 0 [(1434, 1), (1408, 3)] 0, attempt 1412 0 1412 0 [(1435, 1), (1408, 3)] 0, attempt 1413 0 1413 0 [(1436, 1), (1408, 3)] 0, attempt 1414 0 1414 0 [(1437, 1), (1408, 3)] 0, attempt 1415 0 1415 0 [(1438, 1), (1408, 3)] 0, attempt 1416 0 1416 0 [(1439, 1), (1408, 3)] 0, attempt 1417 0 1417 0 [(1440, 1), (1408, 3)] 0, attempt 1418 0 1418 0 [(1441, 1), (1408, 3)] 0, attempt 1419 0 1419 0 [(1442, 1), (1408, 3)] 0, attempt 1420 0 1420 0 [(1443, 1), (1408, 3)] 0, attempt 1421 0 1421 0 [(1444, 1), (1408, 3)] 0, attempt 1422 0 1422 0 [(1445, 1), (1408, 3)] 0, attempt 1423 0 1423 0 [(1446, 1), (1408, 3)] 0, attempt 1424 0 1424 0 [(1447, 1), (1408, 3)] 0, attempt 1425 0 1425 0 [(1448, 1), (1408, 3)] 0, attempt 1426 0 1426 0 [(1449, 1), (1408, 3)] 0, attempt 1427 0 1427 0 [(1450, 1), (1408, 3)] 0, attempt 1428 0 1428 0 [(1451, 1), (1408, 3)] 0, attempt 1429 0 1429 0 [(1452, 1), (1408, 3)] 0, attempt 1430 0 1430 0 [(1453, 1), (1408, 3)] 0, attempt 1431 0 1431 0 [(1454, 1), (1408, 3)] 0, attempt 1432 0 1432 0 [(1455, 1), (1408, 3)] 0, attempt 1433 0 1433 0 [(1456, 1), (1408, 3)] 0, attempt 1434 0 1434 0 [(1457, 1), (1408, 3)] 0, attempt 1435 0 1435 0 [(1458, 1), (1408, 3)] 0, attempt 1436 0 1436 0 [(1459, 1), (1408, 3)] 0, attempt 1437 0 1437 0 [(1460, 1), (1408, 3)] 0, attempt 1438 0 1438 0 [(1461, 1), (1408, 3)] 0, attempt 1439 0 1439 0 [(1462, 1), (1408, 3)] 0]
def counters013 : List Nat := [1440, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1408
        counters012 chunk012 = true ∧ chunk012.length = 32 ∧
      advanceCsrCounters counters012 chunk012 = counters013 := by decide

def chunk013 : List CsrExecutableAttempt :=
  [attempt 1440 0 1440 0 [(1463, 1), (1408, 3)] 0, attempt 1441 0 1441 0 [(1464, 1), (1408, 3)] 0, attempt 1442 0 1442 0 [(1465, 1), (1408, 3)] 0, attempt 1443 0 1443 0 [(1466, 1), (1408, 3)] 0, attempt 1444 0 1444 0 [(1467, 1), (1408, 3)] 0, attempt 1445 0 1445 0 [(1468, 1), (1408, 3)] 0, attempt 1446 0 1446 0 [(1469, 1), (1408, 3)] 0, attempt 1447 0 1447 0 [(1470, 1), (1408, 3)] 0, attempt 1448 0 1448 0 [(1471, 1), (1408, 3)] 0, attempt 1449 0 1449 0 [(1473, 1), (1472, 3)] 0, attempt 1450 0 1450 0 [(1474, 1), (1472, 3)] 0, attempt 1451 0 1451 0 [(1475, 1), (1472, 3)] 0, attempt 1452 0 1452 0 [(1476, 1), (1472, 3)] 0, attempt 1453 0 1453 0 [(1477, 1), (1472, 3)] 0, attempt 1454 0 1454 0 [(1478, 1), (1472, 3)] 0, attempt 1455 0 1455 0 [(1479, 1), (1472, 3)] 0, attempt 1456 0 1456 0 [(1480, 1), (1472, 3)] 0, attempt 1457 0 1457 0 [(1481, 1), (1472, 3)] 0, attempt 1458 0 1458 0 [(1482, 1), (1472, 3)] 0, attempt 1459 0 1459 0 [(1483, 1), (1472, 3)] 0, attempt 1460 0 1460 0 [(1484, 1), (1472, 3)] 0, attempt 1461 0 1461 0 [(1485, 1), (1472, 3)] 0, attempt 1462 0 1462 0 [(1486, 1), (1472, 3)] 0, attempt 1463 0 1463 0 [(1487, 1), (1472, 3)] 0, attempt 1464 0 1464 0 [(1488, 1), (1472, 3)] 0, attempt 1465 0 1465 0 [(1489, 1), (1472, 3)] 0, attempt 1466 0 1466 0 [(1490, 1), (1472, 3)] 0, attempt 1467 0 1467 0 [(1491, 1), (1472, 3)] 0, attempt 1468 0 1468 0 [(1492, 1), (1472, 3)] 0, attempt 1469 0 1469 0 [(1493, 1), (1472, 3)] 0, attempt 1470 0 1470 0 [(1494, 1), (1472, 3)] 0, attempt 1471 0 1471 0 [(1495, 1), (1472, 3)] 0]
def counters014 : List Nat := [1472, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1440
        counters013 chunk013 = true ∧ chunk013.length = 32 ∧
      advanceCsrCounters counters013 chunk013 = counters014 := by decide

def chunk014 : List CsrExecutableAttempt :=
  [attempt 1472 0 1472 0 [(1496, 1), (1472, 3)] 0, attempt 1473 0 1473 0 [(1497, 1), (1472, 3)] 0, attempt 1474 0 1474 0 [(1498, 1), (1472, 3)] 0, attempt 1475 0 1475 0 [(1499, 1), (1472, 3)] 0, attempt 1476 0 1476 0 [(1500, 1), (1472, 3)] 0, attempt 1477 0 1477 0 [(1501, 1), (1472, 3)] 0, attempt 1478 0 1478 0 [(1502, 1), (1472, 3)] 0, attempt 1479 0 1479 0 [(1503, 1), (1472, 3)] 0, attempt 1480 0 1480 0 [(1504, 1), (1472, 3)] 0, attempt 1481 0 1481 0 [(1505, 1), (1472, 3)] 0, attempt 1482 0 1482 0 [(1506, 1), (1472, 3)] 0, attempt 1483 0 1483 0 [(1507, 1), (1472, 3)] 0, attempt 1484 0 1484 0 [(1508, 1), (1472, 3)] 0, attempt 1485 0 1485 0 [(1509, 1), (1472, 3)] 0, attempt 1486 0 1486 0 [(1510, 1), (1472, 3)] 0, attempt 1487 0 1487 0 [(1511, 1), (1472, 3)] 0, attempt 1488 0 1488 0 [(1512, 1), (1472, 3)] 0, attempt 1489 0 1489 0 [(1513, 1), (1472, 3)] 0, attempt 1490 0 1490 0 [(1514, 1), (1472, 3)] 0, attempt 1491 0 1491 0 [(1515, 1), (1472, 3)] 0, attempt 1492 0 1492 0 [(1516, 1), (1472, 3)] 0, attempt 1493 0 1493 0 [(1517, 1), (1472, 3)] 0, attempt 1494 0 1494 0 [(1518, 1), (1472, 3)] 0, attempt 1495 0 1495 0 [(1519, 1), (1472, 3)] 0, attempt 1496 0 1496 0 [(1520, 1), (1472, 3)] 0, attempt 1497 0 1497 0 [(1521, 1), (1472, 3)] 0, attempt 1498 0 1498 0 [(1522, 1), (1472, 3)] 0, attempt 1499 0 1499 0 [(1523, 1), (1472, 3)] 0, attempt 1500 0 1500 0 [(1524, 1), (1472, 3)] 0, attempt 1501 0 1501 0 [(1525, 1), (1472, 3)] 0, attempt 1502 0 1502 0 [(1526, 1), (1472, 3)] 0, attempt 1503 0 1503 0 [(1527, 1), (1472, 3)] 0]
def counters015 : List Nat := [1504, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1472
        counters014 chunk014 = true ∧ chunk014.length = 32 ∧
      advanceCsrCounters counters014 chunk014 = counters015 := by decide

def chunk015 : List CsrExecutableAttempt :=
  [attempt 1504 0 1504 0 [(1528, 1), (1472, 3)] 0, attempt 1505 0 1505 0 [(1529, 1), (1472, 3)] 0, attempt 1506 0 1506 0 [(1530, 1), (1472, 3)] 0, attempt 1507 0 1507 0 [(1531, 1), (1472, 3)] 0, attempt 1508 0 1508 0 [(1532, 1), (1472, 3)] 0, attempt 1509 0 1509 0 [(1533, 1), (1472, 3)] 0, attempt 1510 0 1510 0 [(1534, 1), (1472, 3)] 0, attempt 1511 0 1511 0 [(1535, 1), (1472, 3)] 0, attempt 1512 0 1512 0 [(1537, 1), (1536, 3)] 0, attempt 1513 0 1513 0 [(1538, 1), (1536, 3)] 0, attempt 1514 0 1514 0 [(1539, 1), (1536, 3)] 0, attempt 1515 0 1515 0 [(1540, 1), (1536, 3)] 0, attempt 1516 0 1516 0 [(1541, 1), (1536, 3)] 0, attempt 1517 0 1517 0 [(1542, 1), (1536, 3)] 0, attempt 1518 0 1518 0 [(1543, 1), (1536, 3)] 0, attempt 1519 0 1519 0 [(1544, 1), (1536, 3)] 0, attempt 1520 0 1520 0 [(1545, 1), (1536, 3)] 0, attempt 1521 0 1521 0 [(1546, 1), (1536, 3)] 0, attempt 1522 0 1522 0 [(1547, 1), (1536, 3)] 0, attempt 1523 0 1523 0 [(1548, 1), (1536, 3)] 0, attempt 1524 0 1524 0 [(1549, 1), (1536, 3)] 0, attempt 1525 0 1525 0 [(1550, 1), (1536, 3)] 0, attempt 1526 0 1526 0 [(1551, 1), (1536, 3)] 0, attempt 1527 0 1527 0 [(1552, 1), (1536, 3)] 0, attempt 1528 0 1528 0 [(1553, 1), (1536, 3)] 0, attempt 1529 0 1529 0 [(1554, 1), (1536, 3)] 0, attempt 1530 0 1530 0 [(1555, 1), (1536, 3)] 0, attempt 1531 0 1531 0 [(1556, 1), (1536, 3)] 0, attempt 1532 0 1532 0 [(1557, 1), (1536, 3)] 0, attempt 1533 0 1533 0 [(1558, 1), (1536, 3)] 0, attempt 1534 0 1534 0 [(1559, 1), (1536, 3)] 0, attempt 1535 0 1535 0 [(1560, 1), (1536, 3)] 0]
def counters016 : List Nat := [1536, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1504
        counters015 chunk015 = true ∧ chunk015.length = 32 ∧
      advanceCsrCounters counters015 chunk015 = counters016 := by decide

def suffix016 : List CsrExecutableAttempt := []
theorem suffix016_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1536
      counters016 suffix016 = true := by rfl
theorem suffix016_length : suffix016.length = 0 := by rfl
theorem suffix016_state : advanceCsrCounters counters016 suffix016 = counters016 := by rfl

def suffix015 : List CsrExecutableAttempt := chunk015 ++ suffix016
theorem suffix015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1504
      counters015 suffix015 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk015 suffix016 1504 1536 counters015 counters016
    chunk015_checked.1 (congrArg (Nat.add 1504) chunk015_checked.2.1)
    chunk015_checked.2.2 suffix016_checked
theorem suffix015_length : suffix015.length = 32 := by
  rw [suffix015, List.length_append, chunk015_checked.2.1, suffix016_length]
theorem suffix015_state : advanceCsrCounters counters015 suffix015 = counters016 := by
  rw [suffix015, advanceCsrCounters_append, chunk015_checked.2.2, suffix016_state]

def suffix014 : List CsrExecutableAttempt := chunk014 ++ suffix015
theorem suffix014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1472
      counters014 suffix014 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk014 suffix015 1472 1504 counters014 counters015
    chunk014_checked.1 (congrArg (Nat.add 1472) chunk014_checked.2.1)
    chunk014_checked.2.2 suffix015_checked
theorem suffix014_length : suffix014.length = 64 := by
  rw [suffix014, List.length_append, chunk014_checked.2.1, suffix015_length]
theorem suffix014_state : advanceCsrCounters counters014 suffix014 = counters016 := by
  rw [suffix014, advanceCsrCounters_append, chunk014_checked.2.2, suffix015_state]

def suffix013 : List CsrExecutableAttempt := chunk013 ++ suffix014
theorem suffix013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1440
      counters013 suffix013 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk013 suffix014 1440 1472 counters013 counters014
    chunk013_checked.1 (congrArg (Nat.add 1440) chunk013_checked.2.1)
    chunk013_checked.2.2 suffix014_checked
theorem suffix013_length : suffix013.length = 96 := by
  rw [suffix013, List.length_append, chunk013_checked.2.1, suffix014_length]
theorem suffix013_state : advanceCsrCounters counters013 suffix013 = counters016 := by
  rw [suffix013, advanceCsrCounters_append, chunk013_checked.2.2, suffix014_state]

def suffix012 : List CsrExecutableAttempt := chunk012 ++ suffix013
theorem suffix012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1408
      counters012 suffix012 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk012 suffix013 1408 1440 counters012 counters013
    chunk012_checked.1 (congrArg (Nat.add 1408) chunk012_checked.2.1)
    chunk012_checked.2.2 suffix013_checked
theorem suffix012_length : suffix012.length = 128 := by
  rw [suffix012, List.length_append, chunk012_checked.2.1, suffix013_length]
theorem suffix012_state : advanceCsrCounters counters012 suffix012 = counters016 := by
  rw [suffix012, advanceCsrCounters_append, chunk012_checked.2.2, suffix013_state]

def suffix011 : List CsrExecutableAttempt := chunk011 ++ suffix012
theorem suffix011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1376
      counters011 suffix011 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk011 suffix012 1376 1408 counters011 counters012
    chunk011_checked.1 (congrArg (Nat.add 1376) chunk011_checked.2.1)
    chunk011_checked.2.2 suffix012_checked
theorem suffix011_length : suffix011.length = 160 := by
  rw [suffix011, List.length_append, chunk011_checked.2.1, suffix012_length]
theorem suffix011_state : advanceCsrCounters counters011 suffix011 = counters016 := by
  rw [suffix011, advanceCsrCounters_append, chunk011_checked.2.2, suffix012_state]

def suffix010 : List CsrExecutableAttempt := chunk010 ++ suffix011
theorem suffix010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1344
      counters010 suffix010 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk010 suffix011 1344 1376 counters010 counters011
    chunk010_checked.1 (congrArg (Nat.add 1344) chunk010_checked.2.1)
    chunk010_checked.2.2 suffix011_checked
theorem suffix010_length : suffix010.length = 192 := by
  rw [suffix010, List.length_append, chunk010_checked.2.1, suffix011_length]
theorem suffix010_state : advanceCsrCounters counters010 suffix010 = counters016 := by
  rw [suffix010, advanceCsrCounters_append, chunk010_checked.2.2, suffix011_state]

def suffix009 : List CsrExecutableAttempt := chunk009 ++ suffix010
theorem suffix009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1312
      counters009 suffix009 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk009 suffix010 1312 1344 counters009 counters010
    chunk009_checked.1 (congrArg (Nat.add 1312) chunk009_checked.2.1)
    chunk009_checked.2.2 suffix010_checked
theorem suffix009_length : suffix009.length = 224 := by
  rw [suffix009, List.length_append, chunk009_checked.2.1, suffix010_length]
theorem suffix009_state : advanceCsrCounters counters009 suffix009 = counters016 := by
  rw [suffix009, advanceCsrCounters_append, chunk009_checked.2.2, suffix010_state]

def suffix008 : List CsrExecutableAttempt := chunk008 ++ suffix009
theorem suffix008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1280
      counters008 suffix008 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk008 suffix009 1280 1312 counters008 counters009
    chunk008_checked.1 (congrArg (Nat.add 1280) chunk008_checked.2.1)
    chunk008_checked.2.2 suffix009_checked
theorem suffix008_length : suffix008.length = 256 := by
  rw [suffix008, List.length_append, chunk008_checked.2.1, suffix009_length]
theorem suffix008_state : advanceCsrCounters counters008 suffix008 = counters016 := by
  rw [suffix008, advanceCsrCounters_append, chunk008_checked.2.2, suffix009_state]

def suffix007 : List CsrExecutableAttempt := chunk007 ++ suffix008
theorem suffix007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1248
      counters007 suffix007 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk007 suffix008 1248 1280 counters007 counters008
    chunk007_checked.1 (congrArg (Nat.add 1248) chunk007_checked.2.1)
    chunk007_checked.2.2 suffix008_checked
theorem suffix007_length : suffix007.length = 288 := by
  rw [suffix007, List.length_append, chunk007_checked.2.1, suffix008_length]
theorem suffix007_state : advanceCsrCounters counters007 suffix007 = counters016 := by
  rw [suffix007, advanceCsrCounters_append, chunk007_checked.2.2, suffix008_state]

def suffix006 : List CsrExecutableAttempt := chunk006 ++ suffix007
theorem suffix006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1216
      counters006 suffix006 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk006 suffix007 1216 1248 counters006 counters007
    chunk006_checked.1 (congrArg (Nat.add 1216) chunk006_checked.2.1)
    chunk006_checked.2.2 suffix007_checked
theorem suffix006_length : suffix006.length = 320 := by
  rw [suffix006, List.length_append, chunk006_checked.2.1, suffix007_length]
theorem suffix006_state : advanceCsrCounters counters006 suffix006 = counters016 := by
  rw [suffix006, advanceCsrCounters_append, chunk006_checked.2.2, suffix007_state]

def suffix005 : List CsrExecutableAttempt := chunk005 ++ suffix006
theorem suffix005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1184
      counters005 suffix005 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk005 suffix006 1184 1216 counters005 counters006
    chunk005_checked.1 (congrArg (Nat.add 1184) chunk005_checked.2.1)
    chunk005_checked.2.2 suffix006_checked
theorem suffix005_length : suffix005.length = 352 := by
  rw [suffix005, List.length_append, chunk005_checked.2.1, suffix006_length]
theorem suffix005_state : advanceCsrCounters counters005 suffix005 = counters016 := by
  rw [suffix005, advanceCsrCounters_append, chunk005_checked.2.2, suffix006_state]

def suffix004 : List CsrExecutableAttempt := chunk004 ++ suffix005
theorem suffix004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1152
      counters004 suffix004 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk004 suffix005 1152 1184 counters004 counters005
    chunk004_checked.1 (congrArg (Nat.add 1152) chunk004_checked.2.1)
    chunk004_checked.2.2 suffix005_checked
theorem suffix004_length : suffix004.length = 384 := by
  rw [suffix004, List.length_append, chunk004_checked.2.1, suffix005_length]
theorem suffix004_state : advanceCsrCounters counters004 suffix004 = counters016 := by
  rw [suffix004, advanceCsrCounters_append, chunk004_checked.2.2, suffix005_state]

def suffix003 : List CsrExecutableAttempt := chunk003 ++ suffix004
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1120
      counters003 suffix003 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk003 suffix004 1120 1152 counters003 counters004
    chunk003_checked.1 (congrArg (Nat.add 1120) chunk003_checked.2.1)
    chunk003_checked.2.2 suffix004_checked
theorem suffix003_length : suffix003.length = 416 := by
  rw [suffix003, List.length_append, chunk003_checked.2.1, suffix004_length]
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters016 := by
  rw [suffix003, advanceCsrCounters_append, chunk003_checked.2.2, suffix004_state]

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1088
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 1088 1120 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 1088) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 448 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters016 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1056
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 1056 1088 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 1056) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 480 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters016 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1024
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 1024 1056 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 1024) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 512 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters016 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002, chunk003, chunk004, chunk005, chunk006, chunk007, chunk008, chunk009, chunk010, chunk011, chunk012, chunk013, chunk014, chunk015]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, suffix004, suffix005, suffix006, suffix007, suffix008, suffix009, suffix010, suffix011, suffix012, suffix013, suffix014, suffix015, suffix016, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr02
