import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityCsr07

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr08
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [4096, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 4096 0 4096 0 [(4162, 1), (4160, 3)] 0, attempt 4097 0 4097 0 [(4163, 1), (4160, 3)] 0, attempt 4098 0 4098 0 [(4164, 1), (4160, 3)] 0, attempt 4099 0 4099 0 [(4165, 1), (4160, 3)] 0, attempt 4100 0 4100 0 [(4166, 1), (4160, 3)] 0, attempt 4101 0 4101 0 [(4167, 1), (4160, 3)] 0, attempt 4102 0 4102 0 [(4168, 1), (4160, 3)] 0, attempt 4103 0 4103 0 [(4169, 1), (4160, 3)] 0, attempt 4104 0 4104 0 [(4170, 1), (4160, 3)] 0, attempt 4105 0 4105 0 [(4171, 1), (4160, 3)] 0, attempt 4106 0 4106 0 [(4172, 1), (4160, 3)] 0, attempt 4107 0 4107 0 [(4173, 1), (4160, 3)] 0, attempt 4108 0 4108 0 [(4174, 1), (4160, 3)] 0, attempt 4109 0 4109 0 [(4175, 1), (4160, 3)] 0, attempt 4110 0 4110 0 [(4176, 1), (4160, 3)] 0, attempt 4111 0 4111 0 [(4177, 1), (4160, 3)] 0, attempt 4112 0 4112 0 [(4178, 1), (4160, 3)] 0, attempt 4113 0 4113 0 [(4179, 1), (4160, 3)] 0, attempt 4114 0 4114 0 [(4180, 1), (4160, 3)] 0, attempt 4115 0 4115 0 [(4181, 1), (4160, 3)] 0, attempt 4116 0 4116 0 [(4182, 1), (4160, 3)] 0, attempt 4117 0 4117 0 [(4183, 1), (4160, 3)] 0, attempt 4118 0 4118 0 [(4184, 1), (4160, 3)] 0, attempt 4119 0 4119 0 [(4185, 1), (4160, 3)] 0, attempt 4120 0 4120 0 [(4186, 1), (4160, 3)] 0, attempt 4121 0 4121 0 [(4187, 1), (4160, 3)] 0, attempt 4122 0 4122 0 [(4188, 1), (4160, 3)] 0, attempt 4123 0 4123 0 [(4189, 1), (4160, 3)] 0, attempt 4124 0 4124 0 [(4190, 1), (4160, 3)] 0, attempt 4125 0 4125 0 [(4191, 1), (4160, 3)] 0, attempt 4126 0 4126 0 [(4192, 1), (4160, 3)] 0, attempt 4127 0 4127 0 [(4193, 1), (4160, 3)] 0]
def counters001 : List Nat := [4128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4096
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 4128 0 4128 0 [(4194, 1), (4160, 3)] 0, attempt 4129 0 4129 0 [(4195, 1), (4160, 3)] 0, attempt 4130 0 4130 0 [(4196, 1), (4160, 3)] 0, attempt 4131 0 4131 0 [(4197, 1), (4160, 3)] 0, attempt 4132 0 4132 0 [(4198, 1), (4160, 3)] 0, attempt 4133 0 4133 0 [(4199, 1), (4160, 3)] 0, attempt 4134 0 4134 0 [(4200, 1), (4160, 3)] 0, attempt 4135 0 4135 0 [(4201, 1), (4160, 3)] 0, attempt 4136 0 4136 0 [(4202, 1), (4160, 3)] 0, attempt 4137 0 4137 0 [(4203, 1), (4160, 3)] 0, attempt 4138 0 4138 0 [(4204, 1), (4160, 3)] 0, attempt 4139 0 4139 0 [(4205, 1), (4160, 3)] 0, attempt 4140 0 4140 0 [(4206, 1), (4160, 3)] 0, attempt 4141 0 4141 0 [(4207, 1), (4160, 3)] 0, attempt 4142 0 4142 0 [(4208, 1), (4160, 3)] 0, attempt 4143 0 4143 0 [(4209, 1), (4160, 3)] 0, attempt 4144 0 4144 0 [(4210, 1), (4160, 3)] 0, attempt 4145 0 4145 0 [(4211, 1), (4160, 3)] 0, attempt 4146 0 4146 0 [(4212, 1), (4160, 3)] 0, attempt 4147 0 4147 0 [(4213, 1), (4160, 3)] 0, attempt 4148 0 4148 0 [(4214, 1), (4160, 3)] 0, attempt 4149 0 4149 0 [(4215, 1), (4160, 3)] 0, attempt 4150 0 4150 0 [(4216, 1), (4160, 3)] 0, attempt 4151 0 4151 0 [(4217, 1), (4160, 3)] 0, attempt 4152 0 4152 0 [(4218, 1), (4160, 3)] 0, attempt 4153 0 4153 0 [(4219, 1), (4160, 3)] 0, attempt 4154 0 4154 0 [(4220, 1), (4160, 3)] 0, attempt 4155 0 4155 0 [(4221, 1), (4160, 3)] 0, attempt 4156 0 4156 0 [(4222, 1), (4160, 3)] 0, attempt 4157 0 4157 0 [(4223, 1), (4160, 3)] 0, attempt 4158 0 4158 0 [(4225, 1), (4224, 3)] 0, attempt 4159 0 4159 0 [(4226, 1), (4224, 3)] 0]
def counters002 : List Nat := [4160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4128
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 4160 0 4160 0 [(4227, 1), (4224, 3)] 0, attempt 4161 0 4161 0 [(4228, 1), (4224, 3)] 0, attempt 4162 0 4162 0 [(4229, 1), (4224, 3)] 0, attempt 4163 0 4163 0 [(4230, 1), (4224, 3)] 0, attempt 4164 0 4164 0 [(4231, 1), (4224, 3)] 0, attempt 4165 0 4165 0 [(4232, 1), (4224, 3)] 0, attempt 4166 0 4166 0 [(4233, 1), (4224, 3)] 0, attempt 4167 0 4167 0 [(4234, 1), (4224, 3)] 0, attempt 4168 0 4168 0 [(4235, 1), (4224, 3)] 0, attempt 4169 0 4169 0 [(4236, 1), (4224, 3)] 0, attempt 4170 0 4170 0 [(4237, 1), (4224, 3)] 0, attempt 4171 0 4171 0 [(4238, 1), (4224, 3)] 0, attempt 4172 0 4172 0 [(4239, 1), (4224, 3)] 0, attempt 4173 0 4173 0 [(4240, 1), (4224, 3)] 0, attempt 4174 0 4174 0 [(4241, 1), (4224, 3)] 0, attempt 4175 0 4175 0 [(4242, 1), (4224, 3)] 0, attempt 4176 0 4176 0 [(4243, 1), (4224, 3)] 0, attempt 4177 0 4177 0 [(4244, 1), (4224, 3)] 0, attempt 4178 0 4178 0 [(4245, 1), (4224, 3)] 0, attempt 4179 0 4179 0 [(4246, 1), (4224, 3)] 0, attempt 4180 0 4180 0 [(4247, 1), (4224, 3)] 0, attempt 4181 0 4181 0 [(4248, 1), (4224, 3)] 0, attempt 4182 0 4182 0 [(4249, 1), (4224, 3)] 0, attempt 4183 0 4183 0 [(4250, 1), (4224, 3)] 0, attempt 4184 0 4184 0 [(4251, 1), (4224, 3)] 0, attempt 4185 0 4185 0 [(4252, 1), (4224, 3)] 0, attempt 4186 0 4186 0 [(4253, 1), (4224, 3)] 0, attempt 4187 0 4187 0 [(4254, 1), (4224, 3)] 0, attempt 4188 0 4188 0 [(4255, 1), (4224, 3)] 0, attempt 4189 0 4189 0 [(4256, 1), (4224, 3)] 0, attempt 4190 0 4190 0 [(4257, 1), (4224, 3)] 0, attempt 4191 0 4191 0 [(4258, 1), (4224, 3)] 0]
def counters003 : List Nat := [4192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4160
        counters002 chunk002 = true ∧ chunk002.length = 32 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def chunk003 : List CsrExecutableAttempt :=
  [attempt 4192 0 4192 0 [(4259, 1), (4224, 3)] 0, attempt 4193 0 4193 0 [(4260, 1), (4224, 3)] 0, attempt 4194 0 4194 0 [(4261, 1), (4224, 3)] 0, attempt 4195 0 4195 0 [(4262, 1), (4224, 3)] 0, attempt 4196 0 4196 0 [(4263, 1), (4224, 3)] 0, attempt 4197 0 4197 0 [(4264, 1), (4224, 3)] 0, attempt 4198 0 4198 0 [(4265, 1), (4224, 3)] 0, attempt 4199 0 4199 0 [(4266, 1), (4224, 3)] 0, attempt 4200 0 4200 0 [(4267, 1), (4224, 3)] 0, attempt 4201 0 4201 0 [(4268, 1), (4224, 3)] 0, attempt 4202 0 4202 0 [(4269, 1), (4224, 3)] 0, attempt 4203 0 4203 0 [(4270, 1), (4224, 3)] 0, attempt 4204 0 4204 0 [(4271, 1), (4224, 3)] 0, attempt 4205 0 4205 0 [(4272, 1), (4224, 3)] 0, attempt 4206 0 4206 0 [(4273, 1), (4224, 3)] 0, attempt 4207 0 4207 0 [(4274, 1), (4224, 3)] 0, attempt 4208 0 4208 0 [(4275, 1), (4224, 3)] 0, attempt 4209 0 4209 0 [(4276, 1), (4224, 3)] 0, attempt 4210 0 4210 0 [(4277, 1), (4224, 3)] 0, attempt 4211 0 4211 0 [(4278, 1), (4224, 3)] 0, attempt 4212 0 4212 0 [(4279, 1), (4224, 3)] 0, attempt 4213 0 4213 0 [(4280, 1), (4224, 3)] 0, attempt 4214 0 4214 0 [(4281, 1), (4224, 3)] 0, attempt 4215 0 4215 0 [(4282, 1), (4224, 3)] 0, attempt 4216 0 4216 0 [(4283, 1), (4224, 3)] 0, attempt 4217 0 4217 0 [(4284, 1), (4224, 3)] 0, attempt 4218 0 4218 0 [(4285, 1), (4224, 3)] 0, attempt 4219 0 4219 0 [(4286, 1), (4224, 3)] 0, attempt 4220 0 4220 0 [(4287, 1), (4224, 3)] 0, attempt 4221 0 4221 0 [(4289, 1), (4288, 3)] 0, attempt 4222 0 4222 0 [(4290, 1), (4288, 3)] 0, attempt 4223 0 4223 0 [(4291, 1), (4288, 3)] 0]
def counters004 : List Nat := [4224, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4192
        counters003 chunk003 = true ∧ chunk003.length = 32 ∧
      advanceCsrCounters counters003 chunk003 = counters004 := by decide

def chunk004 : List CsrExecutableAttempt :=
  [attempt 4224 0 4224 0 [(4292, 1), (4288, 3)] 0, attempt 4225 0 4225 0 [(4293, 1), (4288, 3)] 0, attempt 4226 0 4226 0 [(4294, 1), (4288, 3)] 0, attempt 4227 0 4227 0 [(4295, 1), (4288, 3)] 0, attempt 4228 0 4228 0 [(4296, 1), (4288, 3)] 0, attempt 4229 0 4229 0 [(4297, 1), (4288, 3)] 0, attempt 4230 0 4230 0 [(4298, 1), (4288, 3)] 0, attempt 4231 0 4231 0 [(4299, 1), (4288, 3)] 0, attempt 4232 0 4232 0 [(4300, 1), (4288, 3)] 0, attempt 4233 0 4233 0 [(4301, 1), (4288, 3)] 0, attempt 4234 0 4234 0 [(4302, 1), (4288, 3)] 0, attempt 4235 0 4235 0 [(4303, 1), (4288, 3)] 0, attempt 4236 0 4236 0 [(4304, 1), (4288, 3)] 0, attempt 4237 0 4237 0 [(4305, 1), (4288, 3)] 0, attempt 4238 0 4238 0 [(4306, 1), (4288, 3)] 0, attempt 4239 0 4239 0 [(4307, 1), (4288, 3)] 0, attempt 4240 0 4240 0 [(4308, 1), (4288, 3)] 0, attempt 4241 0 4241 0 [(4309, 1), (4288, 3)] 0, attempt 4242 0 4242 0 [(4310, 1), (4288, 3)] 0, attempt 4243 0 4243 0 [(4311, 1), (4288, 3)] 0, attempt 4244 0 4244 0 [(4312, 1), (4288, 3)] 0, attempt 4245 0 4245 0 [(4313, 1), (4288, 3)] 0, attempt 4246 0 4246 0 [(4314, 1), (4288, 3)] 0, attempt 4247 0 4247 0 [(4315, 1), (4288, 3)] 0, attempt 4248 0 4248 0 [(4316, 1), (4288, 3)] 0, attempt 4249 0 4249 0 [(4317, 1), (4288, 3)] 0, attempt 4250 0 4250 0 [(4318, 1), (4288, 3)] 0, attempt 4251 0 4251 0 [(4319, 1), (4288, 3)] 0, attempt 4252 0 4252 0 [(4320, 1), (4288, 3)] 0, attempt 4253 0 4253 0 [(4321, 1), (4288, 3)] 0, attempt 4254 0 4254 0 [(4322, 1), (4288, 3)] 0, attempt 4255 0 4255 0 [(4323, 1), (4288, 3)] 0]
def counters005 : List Nat := [4256, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4224
        counters004 chunk004 = true ∧ chunk004.length = 32 ∧
      advanceCsrCounters counters004 chunk004 = counters005 := by decide

def chunk005 : List CsrExecutableAttempt :=
  [attempt 4256 0 4256 0 [(4324, 1), (4288, 3)] 0, attempt 4257 0 4257 0 [(4325, 1), (4288, 3)] 0, attempt 4258 0 4258 0 [(4326, 1), (4288, 3)] 0, attempt 4259 0 4259 0 [(4327, 1), (4288, 3)] 0, attempt 4260 0 4260 0 [(4328, 1), (4288, 3)] 0, attempt 4261 0 4261 0 [(4329, 1), (4288, 3)] 0, attempt 4262 0 4262 0 [(4330, 1), (4288, 3)] 0, attempt 4263 0 4263 0 [(4331, 1), (4288, 3)] 0, attempt 4264 0 4264 0 [(4332, 1), (4288, 3)] 0, attempt 4265 0 4265 0 [(4333, 1), (4288, 3)] 0, attempt 4266 0 4266 0 [(4334, 1), (4288, 3)] 0, attempt 4267 0 4267 0 [(4335, 1), (4288, 3)] 0, attempt 4268 0 4268 0 [(4336, 1), (4288, 3)] 0, attempt 4269 0 4269 0 [(4337, 1), (4288, 3)] 0, attempt 4270 0 4270 0 [(4338, 1), (4288, 3)] 0, attempt 4271 0 4271 0 [(4339, 1), (4288, 3)] 0, attempt 4272 0 4272 0 [(4340, 1), (4288, 3)] 0, attempt 4273 0 4273 0 [(4341, 1), (4288, 3)] 0, attempt 4274 0 4274 0 [(4342, 1), (4288, 3)] 0, attempt 4275 0 4275 0 [(4343, 1), (4288, 3)] 0, attempt 4276 0 4276 0 [(4344, 1), (4288, 3)] 0, attempt 4277 0 4277 0 [(4345, 1), (4288, 3)] 0, attempt 4278 0 4278 0 [(4346, 1), (4288, 3)] 0, attempt 4279 0 4279 0 [(4347, 1), (4288, 3)] 0, attempt 4280 0 4280 0 [(4348, 1), (4288, 3)] 0, attempt 4281 0 4281 0 [(4349, 1), (4288, 3)] 0, attempt 4282 0 4282 0 [(4350, 1), (4288, 3)] 0, attempt 4283 0 4283 0 [(4351, 1), (4288, 3)] 0, attempt 4284 0 4284 0 [(4353, 1), (4352, 3)] 0, attempt 4285 0 4285 0 [(4354, 1), (4352, 3)] 0, attempt 4286 0 4286 0 [(4355, 1), (4352, 3)] 0, attempt 4287 0 4287 0 [(4356, 1), (4352, 3)] 0]
def counters006 : List Nat := [4288, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4256
        counters005 chunk005 = true ∧ chunk005.length = 32 ∧
      advanceCsrCounters counters005 chunk005 = counters006 := by decide

def chunk006 : List CsrExecutableAttempt :=
  [attempt 4288 0 4288 0 [(4357, 1), (4352, 3)] 0, attempt 4289 0 4289 0 [(4358, 1), (4352, 3)] 0, attempt 4290 0 4290 0 [(4359, 1), (4352, 3)] 0, attempt 4291 0 4291 0 [(4360, 1), (4352, 3)] 0, attempt 4292 0 4292 0 [(4361, 1), (4352, 3)] 0, attempt 4293 0 4293 0 [(4362, 1), (4352, 3)] 0, attempt 4294 0 4294 0 [(4363, 1), (4352, 3)] 0, attempt 4295 0 4295 0 [(4364, 1), (4352, 3)] 0, attempt 4296 0 4296 0 [(4365, 1), (4352, 3)] 0, attempt 4297 0 4297 0 [(4366, 1), (4352, 3)] 0, attempt 4298 0 4298 0 [(4367, 1), (4352, 3)] 0, attempt 4299 0 4299 0 [(4368, 1), (4352, 3)] 0, attempt 4300 0 4300 0 [(4369, 1), (4352, 3)] 0, attempt 4301 0 4301 0 [(4370, 1), (4352, 3)] 0, attempt 4302 0 4302 0 [(4371, 1), (4352, 3)] 0, attempt 4303 0 4303 0 [(4372, 1), (4352, 3)] 0, attempt 4304 0 4304 0 [(4373, 1), (4352, 3)] 0, attempt 4305 0 4305 0 [(4374, 1), (4352, 3)] 0, attempt 4306 0 4306 0 [(4375, 1), (4352, 3)] 0, attempt 4307 0 4307 0 [(4376, 1), (4352, 3)] 0, attempt 4308 0 4308 0 [(4377, 1), (4352, 3)] 0, attempt 4309 0 4309 0 [(4378, 1), (4352, 3)] 0, attempt 4310 0 4310 0 [(4379, 1), (4352, 3)] 0, attempt 4311 0 4311 0 [(4380, 1), (4352, 3)] 0, attempt 4312 0 4312 0 [(4381, 1), (4352, 3)] 0, attempt 4313 0 4313 0 [(4382, 1), (4352, 3)] 0, attempt 4314 0 4314 0 [(4383, 1), (4352, 3)] 0, attempt 4315 0 4315 0 [(4384, 1), (4352, 3)] 0, attempt 4316 0 4316 0 [(4385, 1), (4352, 3)] 0, attempt 4317 0 4317 0 [(4386, 1), (4352, 3)] 0, attempt 4318 0 4318 0 [(4387, 1), (4352, 3)] 0, attempt 4319 0 4319 0 [(4388, 1), (4352, 3)] 0]
def counters007 : List Nat := [4320, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4288
        counters006 chunk006 = true ∧ chunk006.length = 32 ∧
      advanceCsrCounters counters006 chunk006 = counters007 := by decide

def chunk007 : List CsrExecutableAttempt :=
  [attempt 4320 0 4320 0 [(4389, 1), (4352, 3)] 0, attempt 4321 0 4321 0 [(4390, 1), (4352, 3)] 0, attempt 4322 0 4322 0 [(4391, 1), (4352, 3)] 0, attempt 4323 0 4323 0 [(4392, 1), (4352, 3)] 0, attempt 4324 0 4324 0 [(4393, 1), (4352, 3)] 0, attempt 4325 0 4325 0 [(4394, 1), (4352, 3)] 0, attempt 4326 0 4326 0 [(4395, 1), (4352, 3)] 0, attempt 4327 0 4327 0 [(4396, 1), (4352, 3)] 0, attempt 4328 0 4328 0 [(4397, 1), (4352, 3)] 0, attempt 4329 0 4329 0 [(4398, 1), (4352, 3)] 0, attempt 4330 0 4330 0 [(4399, 1), (4352, 3)] 0, attempt 4331 0 4331 0 [(4400, 1), (4352, 3)] 0, attempt 4332 0 4332 0 [(4401, 1), (4352, 3)] 0, attempt 4333 0 4333 0 [(4402, 1), (4352, 3)] 0, attempt 4334 0 4334 0 [(4403, 1), (4352, 3)] 0, attempt 4335 0 4335 0 [(4404, 1), (4352, 3)] 0, attempt 4336 0 4336 0 [(4405, 1), (4352, 3)] 0, attempt 4337 0 4337 0 [(4406, 1), (4352, 3)] 0, attempt 4338 0 4338 0 [(4407, 1), (4352, 3)] 0, attempt 4339 0 4339 0 [(4408, 1), (4352, 3)] 0, attempt 4340 0 4340 0 [(4409, 1), (4352, 3)] 0, attempt 4341 0 4341 0 [(4410, 1), (4352, 3)] 0, attempt 4342 0 4342 0 [(4411, 1), (4352, 3)] 0, attempt 4343 0 4343 0 [(4412, 1), (4352, 3)] 0, attempt 4344 0 4344 0 [(4413, 1), (4352, 3)] 0, attempt 4345 0 4345 0 [(4414, 1), (4352, 3)] 0, attempt 4346 0 4346 0 [(4415, 1), (4352, 3)] 0, attempt 4347 0 4347 0 [(4417, 1), (4416, 3)] 0, attempt 4348 0 4348 0 [(4418, 1), (4416, 3)] 0, attempt 4349 0 4349 0 [(4419, 1), (4416, 3)] 0, attempt 4350 0 4350 0 [(4420, 1), (4416, 3)] 0, attempt 4351 0 4351 0 [(4421, 1), (4416, 3)] 0]
def counters008 : List Nat := [4352, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4320
        counters007 chunk007 = true ∧ chunk007.length = 32 ∧
      advanceCsrCounters counters007 chunk007 = counters008 := by decide

def chunk008 : List CsrExecutableAttempt :=
  [attempt 4352 0 4352 0 [(4422, 1), (4416, 3)] 0, attempt 4353 0 4353 0 [(4423, 1), (4416, 3)] 0, attempt 4354 0 4354 0 [(4424, 1), (4416, 3)] 0, attempt 4355 0 4355 0 [(4425, 1), (4416, 3)] 0, attempt 4356 0 4356 0 [(4426, 1), (4416, 3)] 0, attempt 4357 0 4357 0 [(4427, 1), (4416, 3)] 0, attempt 4358 0 4358 0 [(4428, 1), (4416, 3)] 0, attempt 4359 0 4359 0 [(4429, 1), (4416, 3)] 0, attempt 4360 0 4360 0 [(4430, 1), (4416, 3)] 0, attempt 4361 0 4361 0 [(4431, 1), (4416, 3)] 0, attempt 4362 0 4362 0 [(4432, 1), (4416, 3)] 0, attempt 4363 0 4363 0 [(4433, 1), (4416, 3)] 0, attempt 4364 0 4364 0 [(4434, 1), (4416, 3)] 0, attempt 4365 0 4365 0 [(4435, 1), (4416, 3)] 0, attempt 4366 0 4366 0 [(4436, 1), (4416, 3)] 0, attempt 4367 0 4367 0 [(4437, 1), (4416, 3)] 0, attempt 4368 0 4368 0 [(4438, 1), (4416, 3)] 0, attempt 4369 0 4369 0 [(4439, 1), (4416, 3)] 0, attempt 4370 0 4370 0 [(4440, 1), (4416, 3)] 0, attempt 4371 0 4371 0 [(4441, 1), (4416, 3)] 0, attempt 4372 0 4372 0 [(4442, 1), (4416, 3)] 0, attempt 4373 0 4373 0 [(4443, 1), (4416, 3)] 0, attempt 4374 0 4374 0 [(4444, 1), (4416, 3)] 0, attempt 4375 0 4375 0 [(4445, 1), (4416, 3)] 0, attempt 4376 0 4376 0 [(4446, 1), (4416, 3)] 0, attempt 4377 0 4377 0 [(4447, 1), (4416, 3)] 0, attempt 4378 0 4378 0 [(4448, 1), (4416, 3)] 0, attempt 4379 0 4379 0 [(4449, 1), (4416, 3)] 0, attempt 4380 0 4380 0 [(4450, 1), (4416, 3)] 0, attempt 4381 0 4381 0 [(4451, 1), (4416, 3)] 0, attempt 4382 0 4382 0 [(4452, 1), (4416, 3)] 0, attempt 4383 0 4383 0 [(4453, 1), (4416, 3)] 0]
def counters009 : List Nat := [4384, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4352
        counters008 chunk008 = true ∧ chunk008.length = 32 ∧
      advanceCsrCounters counters008 chunk008 = counters009 := by decide

def chunk009 : List CsrExecutableAttempt :=
  [attempt 4384 0 4384 0 [(4454, 1), (4416, 3)] 0, attempt 4385 0 4385 0 [(4455, 1), (4416, 3)] 0, attempt 4386 0 4386 0 [(4456, 1), (4416, 3)] 0, attempt 4387 0 4387 0 [(4457, 1), (4416, 3)] 0, attempt 4388 0 4388 0 [(4458, 1), (4416, 3)] 0, attempt 4389 0 4389 0 [(4459, 1), (4416, 3)] 0, attempt 4390 0 4390 0 [(4460, 1), (4416, 3)] 0, attempt 4391 0 4391 0 [(4461, 1), (4416, 3)] 0, attempt 4392 0 4392 0 [(4462, 1), (4416, 3)] 0, attempt 4393 0 4393 0 [(4463, 1), (4416, 3)] 0, attempt 4394 0 4394 0 [(4464, 1), (4416, 3)] 0, attempt 4395 0 4395 0 [(4465, 1), (4416, 3)] 0, attempt 4396 0 4396 0 [(4466, 1), (4416, 3)] 0, attempt 4397 0 4397 0 [(4467, 1), (4416, 3)] 0, attempt 4398 0 4398 0 [(4468, 1), (4416, 3)] 0, attempt 4399 0 4399 0 [(4469, 1), (4416, 3)] 0, attempt 4400 0 4400 0 [(4470, 1), (4416, 3)] 0, attempt 4401 0 4401 0 [(4471, 1), (4416, 3)] 0, attempt 4402 0 4402 0 [(4472, 1), (4416, 3)] 0, attempt 4403 0 4403 0 [(4473, 1), (4416, 3)] 0, attempt 4404 0 4404 0 [(4474, 1), (4416, 3)] 0, attempt 4405 0 4405 0 [(4475, 1), (4416, 3)] 0, attempt 4406 0 4406 0 [(4476, 1), (4416, 3)] 0, attempt 4407 0 4407 0 [(4477, 1), (4416, 3)] 0, attempt 4408 0 4408 0 [(4478, 1), (4416, 3)] 0, attempt 4409 0 4409 0 [(4479, 1), (4416, 3)] 0, attempt 4410 0 4410 0 [(4481, 1), (4480, 3)] 0, attempt 4411 0 4411 0 [(4482, 1), (4480, 3)] 0, attempt 4412 0 4412 0 [(4483, 1), (4480, 3)] 0, attempt 4413 0 4413 0 [(4484, 1), (4480, 3)] 0, attempt 4414 0 4414 0 [(4485, 1), (4480, 3)] 0, attempt 4415 0 4415 0 [(4486, 1), (4480, 3)] 0]
def counters010 : List Nat := [4416, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4384
        counters009 chunk009 = true ∧ chunk009.length = 32 ∧
      advanceCsrCounters counters009 chunk009 = counters010 := by decide

def chunk010 : List CsrExecutableAttempt :=
  [attempt 4416 0 4416 0 [(4487, 1), (4480, 3)] 0, attempt 4417 0 4417 0 [(4488, 1), (4480, 3)] 0, attempt 4418 0 4418 0 [(4489, 1), (4480, 3)] 0, attempt 4419 0 4419 0 [(4490, 1), (4480, 3)] 0, attempt 4420 0 4420 0 [(4491, 1), (4480, 3)] 0, attempt 4421 0 4421 0 [(4492, 1), (4480, 3)] 0, attempt 4422 0 4422 0 [(4493, 1), (4480, 3)] 0, attempt 4423 0 4423 0 [(4494, 1), (4480, 3)] 0, attempt 4424 0 4424 0 [(4495, 1), (4480, 3)] 0, attempt 4425 0 4425 0 [(4496, 1), (4480, 3)] 0, attempt 4426 0 4426 0 [(4497, 1), (4480, 3)] 0, attempt 4427 0 4427 0 [(4498, 1), (4480, 3)] 0, attempt 4428 0 4428 0 [(4499, 1), (4480, 3)] 0, attempt 4429 0 4429 0 [(4500, 1), (4480, 3)] 0, attempt 4430 0 4430 0 [(4501, 1), (4480, 3)] 0, attempt 4431 0 4431 0 [(4502, 1), (4480, 3)] 0, attempt 4432 0 4432 0 [(4503, 1), (4480, 3)] 0, attempt 4433 0 4433 0 [(4504, 1), (4480, 3)] 0, attempt 4434 0 4434 0 [(4505, 1), (4480, 3)] 0, attempt 4435 0 4435 0 [(4506, 1), (4480, 3)] 0, attempt 4436 0 4436 0 [(4507, 1), (4480, 3)] 0, attempt 4437 0 4437 0 [(4508, 1), (4480, 3)] 0, attempt 4438 0 4438 0 [(4509, 1), (4480, 3)] 0, attempt 4439 0 4439 0 [(4510, 1), (4480, 3)] 0, attempt 4440 0 4440 0 [(4511, 1), (4480, 3)] 0, attempt 4441 0 4441 0 [(4512, 1), (4480, 3)] 0, attempt 4442 0 4442 0 [(4513, 1), (4480, 3)] 0, attempt 4443 0 4443 0 [(4514, 1), (4480, 3)] 0, attempt 4444 0 4444 0 [(4515, 1), (4480, 3)] 0, attempt 4445 0 4445 0 [(4516, 1), (4480, 3)] 0, attempt 4446 0 4446 0 [(4517, 1), (4480, 3)] 0, attempt 4447 0 4447 0 [(4518, 1), (4480, 3)] 0]
def counters011 : List Nat := [4448, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4416
        counters010 chunk010 = true ∧ chunk010.length = 32 ∧
      advanceCsrCounters counters010 chunk010 = counters011 := by decide

def chunk011 : List CsrExecutableAttempt :=
  [attempt 4448 0 4448 0 [(4519, 1), (4480, 3)] 0, attempt 4449 0 4449 0 [(4520, 1), (4480, 3)] 0, attempt 4450 0 4450 0 [(4521, 1), (4480, 3)] 0, attempt 4451 0 4451 0 [(4522, 1), (4480, 3)] 0, attempt 4452 0 4452 0 [(4523, 1), (4480, 3)] 0, attempt 4453 0 4453 0 [(4524, 1), (4480, 3)] 0, attempt 4454 0 4454 0 [(4525, 1), (4480, 3)] 0, attempt 4455 0 4455 0 [(4526, 1), (4480, 3)] 0, attempt 4456 0 4456 0 [(4527, 1), (4480, 3)] 0, attempt 4457 0 4457 0 [(4528, 1), (4480, 3)] 0, attempt 4458 0 4458 0 [(4529, 1), (4480, 3)] 0, attempt 4459 0 4459 0 [(4530, 1), (4480, 3)] 0, attempt 4460 0 4460 0 [(4531, 1), (4480, 3)] 0, attempt 4461 0 4461 0 [(4532, 1), (4480, 3)] 0, attempt 4462 0 4462 0 [(4533, 1), (4480, 3)] 0, attempt 4463 0 4463 0 [(4534, 1), (4480, 3)] 0, attempt 4464 0 4464 0 [(4535, 1), (4480, 3)] 0, attempt 4465 0 4465 0 [(4536, 1), (4480, 3)] 0, attempt 4466 0 4466 0 [(4537, 1), (4480, 3)] 0, attempt 4467 0 4467 0 [(4538, 1), (4480, 3)] 0, attempt 4468 0 4468 0 [(4539, 1), (4480, 3)] 0, attempt 4469 0 4469 0 [(4540, 1), (4480, 3)] 0, attempt 4470 0 4470 0 [(4541, 1), (4480, 3)] 0, attempt 4471 0 4471 0 [(4542, 1), (4480, 3)] 0, attempt 4472 0 4472 0 [(4543, 1), (4480, 3)] 0, attempt 4473 0 4473 0 [(4545, 1), (4544, 3)] 0, attempt 4474 0 4474 0 [(4546, 1), (4544, 3)] 0, attempt 4475 0 4475 0 [(4547, 1), (4544, 3)] 0, attempt 4476 0 4476 0 [(4548, 1), (4544, 3)] 0, attempt 4477 0 4477 0 [(4549, 1), (4544, 3)] 0, attempt 4478 0 4478 0 [(4550, 1), (4544, 3)] 0, attempt 4479 0 4479 0 [(4551, 1), (4544, 3)] 0]
def counters012 : List Nat := [4480, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4448
        counters011 chunk011 = true ∧ chunk011.length = 32 ∧
      advanceCsrCounters counters011 chunk011 = counters012 := by decide

def chunk012 : List CsrExecutableAttempt :=
  [attempt 4480 0 4480 0 [(4552, 1), (4544, 3)] 0, attempt 4481 0 4481 0 [(4553, 1), (4544, 3)] 0, attempt 4482 0 4482 0 [(4554, 1), (4544, 3)] 0, attempt 4483 0 4483 0 [(4555, 1), (4544, 3)] 0, attempt 4484 0 4484 0 [(4556, 1), (4544, 3)] 0, attempt 4485 0 4485 0 [(4557, 1), (4544, 3)] 0, attempt 4486 0 4486 0 [(4558, 1), (4544, 3)] 0, attempt 4487 0 4487 0 [(4559, 1), (4544, 3)] 0, attempt 4488 0 4488 0 [(4560, 1), (4544, 3)] 0, attempt 4489 0 4489 0 [(4561, 1), (4544, 3)] 0, attempt 4490 0 4490 0 [(4562, 1), (4544, 3)] 0, attempt 4491 0 4491 0 [(4563, 1), (4544, 3)] 0, attempt 4492 0 4492 0 [(4564, 1), (4544, 3)] 0, attempt 4493 0 4493 0 [(4565, 1), (4544, 3)] 0, attempt 4494 0 4494 0 [(4566, 1), (4544, 3)] 0, attempt 4495 0 4495 0 [(4567, 1), (4544, 3)] 0, attempt 4496 0 4496 0 [(4568, 1), (4544, 3)] 0, attempt 4497 0 4497 0 [(4569, 1), (4544, 3)] 0, attempt 4498 0 4498 0 [(4570, 1), (4544, 3)] 0, attempt 4499 0 4499 0 [(4571, 1), (4544, 3)] 0, attempt 4500 0 4500 0 [(4572, 1), (4544, 3)] 0, attempt 4501 0 4501 0 [(4573, 1), (4544, 3)] 0, attempt 4502 0 4502 0 [(4574, 1), (4544, 3)] 0, attempt 4503 0 4503 0 [(4575, 1), (4544, 3)] 0, attempt 4504 0 4504 0 [(4576, 1), (4544, 3)] 0, attempt 4505 0 4505 0 [(4577, 1), (4544, 3)] 0, attempt 4506 0 4506 0 [(4578, 1), (4544, 3)] 0, attempt 4507 0 4507 0 [(4579, 1), (4544, 3)] 0, attempt 4508 0 4508 0 [(4580, 1), (4544, 3)] 0, attempt 4509 0 4509 0 [(4581, 1), (4544, 3)] 0, attempt 4510 0 4510 0 [(4582, 1), (4544, 3)] 0, attempt 4511 0 4511 0 [(4583, 1), (4544, 3)] 0]
def counters013 : List Nat := [4512, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4480
        counters012 chunk012 = true ∧ chunk012.length = 32 ∧
      advanceCsrCounters counters012 chunk012 = counters013 := by decide

def chunk013 : List CsrExecutableAttempt :=
  [attempt 4512 0 4512 0 [(4584, 1), (4544, 3)] 0, attempt 4513 0 4513 0 [(4585, 1), (4544, 3)] 0, attempt 4514 0 4514 0 [(4586, 1), (4544, 3)] 0, attempt 4515 0 4515 0 [(4587, 1), (4544, 3)] 0, attempt 4516 0 4516 0 [(4588, 1), (4544, 3)] 0, attempt 4517 0 4517 0 [(4589, 1), (4544, 3)] 0, attempt 4518 0 4518 0 [(4590, 1), (4544, 3)] 0, attempt 4519 0 4519 0 [(4591, 1), (4544, 3)] 0, attempt 4520 0 4520 0 [(4592, 1), (4544, 3)] 0, attempt 4521 0 4521 0 [(4593, 1), (4544, 3)] 0, attempt 4522 0 4522 0 [(4594, 1), (4544, 3)] 0, attempt 4523 0 4523 0 [(4595, 1), (4544, 3)] 0, attempt 4524 0 4524 0 [(4596, 1), (4544, 3)] 0, attempt 4525 0 4525 0 [(4597, 1), (4544, 3)] 0, attempt 4526 0 4526 0 [(4598, 1), (4544, 3)] 0, attempt 4527 0 4527 0 [(4599, 1), (4544, 3)] 0, attempt 4528 0 4528 0 [(4600, 1), (4544, 3)] 0, attempt 4529 0 4529 0 [(4601, 1), (4544, 3)] 0, attempt 4530 0 4530 0 [(4602, 1), (4544, 3)] 0, attempt 4531 0 4531 0 [(4603, 1), (4544, 3)] 0, attempt 4532 0 4532 0 [(4604, 1), (4544, 3)] 0, attempt 4533 0 4533 0 [(4605, 1), (4544, 3)] 0, attempt 4534 0 4534 0 [(4606, 1), (4544, 3)] 0, attempt 4535 0 4535 0 [(4607, 1), (4544, 3)] 0, attempt 4536 0 4536 0 [(4609, 1), (4608, 3)] 0, attempt 4537 0 4537 0 [(4610, 1), (4608, 3)] 0, attempt 4538 0 4538 0 [(4611, 1), (4608, 3)] 0, attempt 4539 0 4539 0 [(4612, 1), (4608, 3)] 0, attempt 4540 0 4540 0 [(4613, 1), (4608, 3)] 0, attempt 4541 0 4541 0 [(4614, 1), (4608, 3)] 0, attempt 4542 0 4542 0 [(4615, 1), (4608, 3)] 0, attempt 4543 0 4543 0 [(4616, 1), (4608, 3)] 0]
def counters014 : List Nat := [4544, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4512
        counters013 chunk013 = true ∧ chunk013.length = 32 ∧
      advanceCsrCounters counters013 chunk013 = counters014 := by decide

def chunk014 : List CsrExecutableAttempt :=
  [attempt 4544 0 4544 0 [(4617, 1), (4608, 3)] 0, attempt 4545 0 4545 0 [(4618, 1), (4608, 3)] 0, attempt 4546 0 4546 0 [(4619, 1), (4608, 3)] 0, attempt 4547 0 4547 0 [(4620, 1), (4608, 3)] 0, attempt 4548 0 4548 0 [(4621, 1), (4608, 3)] 0, attempt 4549 0 4549 0 [(4622, 1), (4608, 3)] 0, attempt 4550 0 4550 0 [(4623, 1), (4608, 3)] 0, attempt 4551 0 4551 0 [(4624, 1), (4608, 3)] 0, attempt 4552 0 4552 0 [(4625, 1), (4608, 3)] 0, attempt 4553 0 4553 0 [(4626, 1), (4608, 3)] 0, attempt 4554 0 4554 0 [(4627, 1), (4608, 3)] 0, attempt 4555 0 4555 0 [(4628, 1), (4608, 3)] 0, attempt 4556 0 4556 0 [(4629, 1), (4608, 3)] 0, attempt 4557 0 4557 0 [(4630, 1), (4608, 3)] 0, attempt 4558 0 4558 0 [(4631, 1), (4608, 3)] 0, attempt 4559 0 4559 0 [(4632, 1), (4608, 3)] 0, attempt 4560 0 4560 0 [(4633, 1), (4608, 3)] 0, attempt 4561 0 4561 0 [(4634, 1), (4608, 3)] 0, attempt 4562 0 4562 0 [(4635, 1), (4608, 3)] 0, attempt 4563 0 4563 0 [(4636, 1), (4608, 3)] 0, attempt 4564 0 4564 0 [(4637, 1), (4608, 3)] 0, attempt 4565 0 4565 0 [(4638, 1), (4608, 3)] 0, attempt 4566 0 4566 0 [(4639, 1), (4608, 3)] 0, attempt 4567 0 4567 0 [(4640, 1), (4608, 3)] 0, attempt 4568 0 4568 0 [(4641, 1), (4608, 3)] 0, attempt 4569 0 4569 0 [(4642, 1), (4608, 3)] 0, attempt 4570 0 4570 0 [(4643, 1), (4608, 3)] 0, attempt 4571 0 4571 0 [(4644, 1), (4608, 3)] 0, attempt 4572 0 4572 0 [(4645, 1), (4608, 3)] 0, attempt 4573 0 4573 0 [(4646, 1), (4608, 3)] 0, attempt 4574 0 4574 0 [(4647, 1), (4608, 3)] 0, attempt 4575 0 4575 0 [(4648, 1), (4608, 3)] 0]
def counters015 : List Nat := [4576, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4544
        counters014 chunk014 = true ∧ chunk014.length = 32 ∧
      advanceCsrCounters counters014 chunk014 = counters015 := by decide

def chunk015 : List CsrExecutableAttempt :=
  [attempt 4576 0 4576 0 [(4649, 1), (4608, 3)] 0, attempt 4577 0 4577 0 [(4650, 1), (4608, 3)] 0, attempt 4578 0 4578 0 [(4651, 1), (4608, 3)] 0, attempt 4579 0 4579 0 [(4652, 1), (4608, 3)] 0, attempt 4580 0 4580 0 [(4653, 1), (4608, 3)] 0, attempt 4581 0 4581 0 [(4654, 1), (4608, 3)] 0, attempt 4582 0 4582 0 [(4655, 1), (4608, 3)] 0, attempt 4583 0 4583 0 [(4656, 1), (4608, 3)] 0, attempt 4584 0 4584 0 [(4657, 1), (4608, 3)] 0, attempt 4585 0 4585 0 [(4658, 1), (4608, 3)] 0, attempt 4586 0 4586 0 [(4659, 1), (4608, 3)] 0, attempt 4587 0 4587 0 [(4660, 1), (4608, 3)] 0, attempt 4588 0 4588 0 [(4661, 1), (4608, 3)] 0, attempt 4589 0 4589 0 [(4662, 1), (4608, 3)] 0, attempt 4590 0 4590 0 [(4663, 1), (4608, 3)] 0, attempt 4591 0 4591 0 [(4664, 1), (4608, 3)] 0, attempt 4592 0 4592 0 [(4665, 1), (4608, 3)] 0, attempt 4593 0 4593 0 [(4666, 1), (4608, 3)] 0, attempt 4594 0 4594 0 [(4667, 1), (4608, 3)] 0, attempt 4595 0 4595 0 [(4668, 1), (4608, 3)] 0, attempt 4596 0 4596 0 [(4669, 1), (4608, 3)] 0, attempt 4597 0 4597 0 [(4670, 1), (4608, 3)] 0, attempt 4598 0 4598 0 [(4671, 1), (4608, 3)] 0, attempt 4599 0 4599 0 [(4673, 1), (4672, 3)] 0, attempt 4600 0 4600 0 [(4674, 1), (4672, 3)] 0, attempt 4601 0 4601 0 [(4675, 1), (4672, 3)] 0, attempt 4602 0 4602 0 [(4676, 1), (4672, 3)] 0, attempt 4603 0 4603 0 [(4677, 1), (4672, 3)] 0, attempt 4604 0 4604 0 [(4678, 1), (4672, 3)] 0, attempt 4605 0 4605 0 [(4679, 1), (4672, 3)] 0, attempt 4606 0 4606 0 [(4680, 1), (4672, 3)] 0, attempt 4607 0 4607 0 [(4681, 1), (4672, 3)] 0]
def counters016 : List Nat := [4608, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4576
        counters015 chunk015 = true ∧ chunk015.length = 32 ∧
      advanceCsrCounters counters015 chunk015 = counters016 := by decide

def suffix016 : List CsrExecutableAttempt := []
theorem suffix016_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4608
      counters016 suffix016 = true := by rfl
theorem suffix016_length : suffix016.length = 0 := by rfl
theorem suffix016_state : advanceCsrCounters counters016 suffix016 = counters016 := by rfl

def suffix015 : List CsrExecutableAttempt := chunk015 ++ suffix016
theorem suffix015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4576
      counters015 suffix015 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk015 suffix016 4576 4608 counters015 counters016
    chunk015_checked.1 (congrArg (Nat.add 4576) chunk015_checked.2.1)
    chunk015_checked.2.2 suffix016_checked
theorem suffix015_length : suffix015.length = 32 := by
  rw [suffix015, List.length_append, chunk015_checked.2.1, suffix016_length]
theorem suffix015_state : advanceCsrCounters counters015 suffix015 = counters016 := by
  rw [suffix015, advanceCsrCounters_append, chunk015_checked.2.2, suffix016_state]

def suffix014 : List CsrExecutableAttempt := chunk014 ++ suffix015
theorem suffix014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4544
      counters014 suffix014 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk014 suffix015 4544 4576 counters014 counters015
    chunk014_checked.1 (congrArg (Nat.add 4544) chunk014_checked.2.1)
    chunk014_checked.2.2 suffix015_checked
theorem suffix014_length : suffix014.length = 64 := by
  rw [suffix014, List.length_append, chunk014_checked.2.1, suffix015_length]
theorem suffix014_state : advanceCsrCounters counters014 suffix014 = counters016 := by
  rw [suffix014, advanceCsrCounters_append, chunk014_checked.2.2, suffix015_state]

def suffix013 : List CsrExecutableAttempt := chunk013 ++ suffix014
theorem suffix013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4512
      counters013 suffix013 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk013 suffix014 4512 4544 counters013 counters014
    chunk013_checked.1 (congrArg (Nat.add 4512) chunk013_checked.2.1)
    chunk013_checked.2.2 suffix014_checked
theorem suffix013_length : suffix013.length = 96 := by
  rw [suffix013, List.length_append, chunk013_checked.2.1, suffix014_length]
theorem suffix013_state : advanceCsrCounters counters013 suffix013 = counters016 := by
  rw [suffix013, advanceCsrCounters_append, chunk013_checked.2.2, suffix014_state]

def suffix012 : List CsrExecutableAttempt := chunk012 ++ suffix013
theorem suffix012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4480
      counters012 suffix012 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk012 suffix013 4480 4512 counters012 counters013
    chunk012_checked.1 (congrArg (Nat.add 4480) chunk012_checked.2.1)
    chunk012_checked.2.2 suffix013_checked
theorem suffix012_length : suffix012.length = 128 := by
  rw [suffix012, List.length_append, chunk012_checked.2.1, suffix013_length]
theorem suffix012_state : advanceCsrCounters counters012 suffix012 = counters016 := by
  rw [suffix012, advanceCsrCounters_append, chunk012_checked.2.2, suffix013_state]

def suffix011 : List CsrExecutableAttempt := chunk011 ++ suffix012
theorem suffix011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4448
      counters011 suffix011 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk011 suffix012 4448 4480 counters011 counters012
    chunk011_checked.1 (congrArg (Nat.add 4448) chunk011_checked.2.1)
    chunk011_checked.2.2 suffix012_checked
theorem suffix011_length : suffix011.length = 160 := by
  rw [suffix011, List.length_append, chunk011_checked.2.1, suffix012_length]
theorem suffix011_state : advanceCsrCounters counters011 suffix011 = counters016 := by
  rw [suffix011, advanceCsrCounters_append, chunk011_checked.2.2, suffix012_state]

def suffix010 : List CsrExecutableAttempt := chunk010 ++ suffix011
theorem suffix010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4416
      counters010 suffix010 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk010 suffix011 4416 4448 counters010 counters011
    chunk010_checked.1 (congrArg (Nat.add 4416) chunk010_checked.2.1)
    chunk010_checked.2.2 suffix011_checked
theorem suffix010_length : suffix010.length = 192 := by
  rw [suffix010, List.length_append, chunk010_checked.2.1, suffix011_length]
theorem suffix010_state : advanceCsrCounters counters010 suffix010 = counters016 := by
  rw [suffix010, advanceCsrCounters_append, chunk010_checked.2.2, suffix011_state]

def suffix009 : List CsrExecutableAttempt := chunk009 ++ suffix010
theorem suffix009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4384
      counters009 suffix009 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk009 suffix010 4384 4416 counters009 counters010
    chunk009_checked.1 (congrArg (Nat.add 4384) chunk009_checked.2.1)
    chunk009_checked.2.2 suffix010_checked
theorem suffix009_length : suffix009.length = 224 := by
  rw [suffix009, List.length_append, chunk009_checked.2.1, suffix010_length]
theorem suffix009_state : advanceCsrCounters counters009 suffix009 = counters016 := by
  rw [suffix009, advanceCsrCounters_append, chunk009_checked.2.2, suffix010_state]

def suffix008 : List CsrExecutableAttempt := chunk008 ++ suffix009
theorem suffix008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4352
      counters008 suffix008 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk008 suffix009 4352 4384 counters008 counters009
    chunk008_checked.1 (congrArg (Nat.add 4352) chunk008_checked.2.1)
    chunk008_checked.2.2 suffix009_checked
theorem suffix008_length : suffix008.length = 256 := by
  rw [suffix008, List.length_append, chunk008_checked.2.1, suffix009_length]
theorem suffix008_state : advanceCsrCounters counters008 suffix008 = counters016 := by
  rw [suffix008, advanceCsrCounters_append, chunk008_checked.2.2, suffix009_state]

def suffix007 : List CsrExecutableAttempt := chunk007 ++ suffix008
theorem suffix007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4320
      counters007 suffix007 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk007 suffix008 4320 4352 counters007 counters008
    chunk007_checked.1 (congrArg (Nat.add 4320) chunk007_checked.2.1)
    chunk007_checked.2.2 suffix008_checked
theorem suffix007_length : suffix007.length = 288 := by
  rw [suffix007, List.length_append, chunk007_checked.2.1, suffix008_length]
theorem suffix007_state : advanceCsrCounters counters007 suffix007 = counters016 := by
  rw [suffix007, advanceCsrCounters_append, chunk007_checked.2.2, suffix008_state]

def suffix006 : List CsrExecutableAttempt := chunk006 ++ suffix007
theorem suffix006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4288
      counters006 suffix006 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk006 suffix007 4288 4320 counters006 counters007
    chunk006_checked.1 (congrArg (Nat.add 4288) chunk006_checked.2.1)
    chunk006_checked.2.2 suffix007_checked
theorem suffix006_length : suffix006.length = 320 := by
  rw [suffix006, List.length_append, chunk006_checked.2.1, suffix007_length]
theorem suffix006_state : advanceCsrCounters counters006 suffix006 = counters016 := by
  rw [suffix006, advanceCsrCounters_append, chunk006_checked.2.2, suffix007_state]

def suffix005 : List CsrExecutableAttempt := chunk005 ++ suffix006
theorem suffix005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4256
      counters005 suffix005 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk005 suffix006 4256 4288 counters005 counters006
    chunk005_checked.1 (congrArg (Nat.add 4256) chunk005_checked.2.1)
    chunk005_checked.2.2 suffix006_checked
theorem suffix005_length : suffix005.length = 352 := by
  rw [suffix005, List.length_append, chunk005_checked.2.1, suffix006_length]
theorem suffix005_state : advanceCsrCounters counters005 suffix005 = counters016 := by
  rw [suffix005, advanceCsrCounters_append, chunk005_checked.2.2, suffix006_state]

def suffix004 : List CsrExecutableAttempt := chunk004 ++ suffix005
theorem suffix004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4224
      counters004 suffix004 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk004 suffix005 4224 4256 counters004 counters005
    chunk004_checked.1 (congrArg (Nat.add 4224) chunk004_checked.2.1)
    chunk004_checked.2.2 suffix005_checked
theorem suffix004_length : suffix004.length = 384 := by
  rw [suffix004, List.length_append, chunk004_checked.2.1, suffix005_length]
theorem suffix004_state : advanceCsrCounters counters004 suffix004 = counters016 := by
  rw [suffix004, advanceCsrCounters_append, chunk004_checked.2.2, suffix005_state]

def suffix003 : List CsrExecutableAttempt := chunk003 ++ suffix004
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4192
      counters003 suffix003 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk003 suffix004 4192 4224 counters003 counters004
    chunk003_checked.1 (congrArg (Nat.add 4192) chunk003_checked.2.1)
    chunk003_checked.2.2 suffix004_checked
theorem suffix003_length : suffix003.length = 416 := by
  rw [suffix003, List.length_append, chunk003_checked.2.1, suffix004_length]
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters016 := by
  rw [suffix003, advanceCsrCounters_append, chunk003_checked.2.2, suffix004_state]

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4160
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 4160 4192 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 4160) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 448 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters016 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4128
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 4128 4160 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 4128) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 480 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters016 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 4096
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 4096 4128 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 4096) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 512 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters016 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002, chunk003, chunk004, chunk005, chunk006, chunk007, chunk008, chunk009, chunk010, chunk011, chunk012, chunk013, chunk014, chunk015]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, suffix004, suffix005, suffix006, suffix007, suffix008, suffix009, suffix010, suffix011, suffix012, suffix013, suffix014, suffix015, suffix016, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr08
