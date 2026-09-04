import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityCsr05

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr06
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [3072, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 3072 0 3072 0 [(3121, 1), (3072, 3)] 0, attempt 3073 0 3073 0 [(3122, 1), (3072, 3)] 0, attempt 3074 0 3074 0 [(3123, 1), (3072, 3)] 0, attempt 3075 0 3075 0 [(3124, 1), (3072, 3)] 0, attempt 3076 0 3076 0 [(3125, 1), (3072, 3)] 0, attempt 3077 0 3077 0 [(3126, 1), (3072, 3)] 0, attempt 3078 0 3078 0 [(3127, 1), (3072, 3)] 0, attempt 3079 0 3079 0 [(3128, 1), (3072, 3)] 0, attempt 3080 0 3080 0 [(3129, 1), (3072, 3)] 0, attempt 3081 0 3081 0 [(3130, 1), (3072, 3)] 0, attempt 3082 0 3082 0 [(3131, 1), (3072, 3)] 0, attempt 3083 0 3083 0 [(3132, 1), (3072, 3)] 0, attempt 3084 0 3084 0 [(3133, 1), (3072, 3)] 0, attempt 3085 0 3085 0 [(3134, 1), (3072, 3)] 0, attempt 3086 0 3086 0 [(3135, 1), (3072, 3)] 0, attempt 3087 0 3087 0 [(3137, 1), (3136, 3)] 0, attempt 3088 0 3088 0 [(3138, 1), (3136, 3)] 0, attempt 3089 0 3089 0 [(3139, 1), (3136, 3)] 0, attempt 3090 0 3090 0 [(3140, 1), (3136, 3)] 0, attempt 3091 0 3091 0 [(3141, 1), (3136, 3)] 0, attempt 3092 0 3092 0 [(3142, 1), (3136, 3)] 0, attempt 3093 0 3093 0 [(3143, 1), (3136, 3)] 0, attempt 3094 0 3094 0 [(3144, 1), (3136, 3)] 0, attempt 3095 0 3095 0 [(3145, 1), (3136, 3)] 0, attempt 3096 0 3096 0 [(3146, 1), (3136, 3)] 0, attempt 3097 0 3097 0 [(3147, 1), (3136, 3)] 0, attempt 3098 0 3098 0 [(3148, 1), (3136, 3)] 0, attempt 3099 0 3099 0 [(3149, 1), (3136, 3)] 0, attempt 3100 0 3100 0 [(3150, 1), (3136, 3)] 0, attempt 3101 0 3101 0 [(3151, 1), (3136, 3)] 0, attempt 3102 0 3102 0 [(3152, 1), (3136, 3)] 0, attempt 3103 0 3103 0 [(3153, 1), (3136, 3)] 0]
def counters001 : List Nat := [3104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3072
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 3104 0 3104 0 [(3154, 1), (3136, 3)] 0, attempt 3105 0 3105 0 [(3155, 1), (3136, 3)] 0, attempt 3106 0 3106 0 [(3156, 1), (3136, 3)] 0, attempt 3107 0 3107 0 [(3157, 1), (3136, 3)] 0, attempt 3108 0 3108 0 [(3158, 1), (3136, 3)] 0, attempt 3109 0 3109 0 [(3159, 1), (3136, 3)] 0, attempt 3110 0 3110 0 [(3160, 1), (3136, 3)] 0, attempt 3111 0 3111 0 [(3161, 1), (3136, 3)] 0, attempt 3112 0 3112 0 [(3162, 1), (3136, 3)] 0, attempt 3113 0 3113 0 [(3163, 1), (3136, 3)] 0, attempt 3114 0 3114 0 [(3164, 1), (3136, 3)] 0, attempt 3115 0 3115 0 [(3165, 1), (3136, 3)] 0, attempt 3116 0 3116 0 [(3166, 1), (3136, 3)] 0, attempt 3117 0 3117 0 [(3167, 1), (3136, 3)] 0, attempt 3118 0 3118 0 [(3168, 1), (3136, 3)] 0, attempt 3119 0 3119 0 [(3169, 1), (3136, 3)] 0, attempt 3120 0 3120 0 [(3170, 1), (3136, 3)] 0, attempt 3121 0 3121 0 [(3171, 1), (3136, 3)] 0, attempt 3122 0 3122 0 [(3172, 1), (3136, 3)] 0, attempt 3123 0 3123 0 [(3173, 1), (3136, 3)] 0, attempt 3124 0 3124 0 [(3174, 1), (3136, 3)] 0, attempt 3125 0 3125 0 [(3175, 1), (3136, 3)] 0, attempt 3126 0 3126 0 [(3176, 1), (3136, 3)] 0, attempt 3127 0 3127 0 [(3177, 1), (3136, 3)] 0, attempt 3128 0 3128 0 [(3178, 1), (3136, 3)] 0, attempt 3129 0 3129 0 [(3179, 1), (3136, 3)] 0, attempt 3130 0 3130 0 [(3180, 1), (3136, 3)] 0, attempt 3131 0 3131 0 [(3181, 1), (3136, 3)] 0, attempt 3132 0 3132 0 [(3182, 1), (3136, 3)] 0, attempt 3133 0 3133 0 [(3183, 1), (3136, 3)] 0, attempt 3134 0 3134 0 [(3184, 1), (3136, 3)] 0, attempt 3135 0 3135 0 [(3185, 1), (3136, 3)] 0]
def counters002 : List Nat := [3136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3104
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 3136 0 3136 0 [(3186, 1), (3136, 3)] 0, attempt 3137 0 3137 0 [(3187, 1), (3136, 3)] 0, attempt 3138 0 3138 0 [(3188, 1), (3136, 3)] 0, attempt 3139 0 3139 0 [(3189, 1), (3136, 3)] 0, attempt 3140 0 3140 0 [(3190, 1), (3136, 3)] 0, attempt 3141 0 3141 0 [(3191, 1), (3136, 3)] 0, attempt 3142 0 3142 0 [(3192, 1), (3136, 3)] 0, attempt 3143 0 3143 0 [(3193, 1), (3136, 3)] 0, attempt 3144 0 3144 0 [(3194, 1), (3136, 3)] 0, attempt 3145 0 3145 0 [(3195, 1), (3136, 3)] 0, attempt 3146 0 3146 0 [(3196, 1), (3136, 3)] 0, attempt 3147 0 3147 0 [(3197, 1), (3136, 3)] 0, attempt 3148 0 3148 0 [(3198, 1), (3136, 3)] 0, attempt 3149 0 3149 0 [(3199, 1), (3136, 3)] 0, attempt 3150 0 3150 0 [(3201, 1), (3200, 3)] 0, attempt 3151 0 3151 0 [(3202, 1), (3200, 3)] 0, attempt 3152 0 3152 0 [(3203, 1), (3200, 3)] 0, attempt 3153 0 3153 0 [(3204, 1), (3200, 3)] 0, attempt 3154 0 3154 0 [(3205, 1), (3200, 3)] 0, attempt 3155 0 3155 0 [(3206, 1), (3200, 3)] 0, attempt 3156 0 3156 0 [(3207, 1), (3200, 3)] 0, attempt 3157 0 3157 0 [(3208, 1), (3200, 3)] 0, attempt 3158 0 3158 0 [(3209, 1), (3200, 3)] 0, attempt 3159 0 3159 0 [(3210, 1), (3200, 3)] 0, attempt 3160 0 3160 0 [(3211, 1), (3200, 3)] 0, attempt 3161 0 3161 0 [(3212, 1), (3200, 3)] 0, attempt 3162 0 3162 0 [(3213, 1), (3200, 3)] 0, attempt 3163 0 3163 0 [(3214, 1), (3200, 3)] 0, attempt 3164 0 3164 0 [(3215, 1), (3200, 3)] 0, attempt 3165 0 3165 0 [(3216, 1), (3200, 3)] 0, attempt 3166 0 3166 0 [(3217, 1), (3200, 3)] 0, attempt 3167 0 3167 0 [(3218, 1), (3200, 3)] 0]
def counters003 : List Nat := [3168, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3136
        counters002 chunk002 = true ∧ chunk002.length = 32 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def chunk003 : List CsrExecutableAttempt :=
  [attempt 3168 0 3168 0 [(3219, 1), (3200, 3)] 0, attempt 3169 0 3169 0 [(3220, 1), (3200, 3)] 0, attempt 3170 0 3170 0 [(3221, 1), (3200, 3)] 0, attempt 3171 0 3171 0 [(3222, 1), (3200, 3)] 0, attempt 3172 0 3172 0 [(3223, 1), (3200, 3)] 0, attempt 3173 0 3173 0 [(3224, 1), (3200, 3)] 0, attempt 3174 0 3174 0 [(3225, 1), (3200, 3)] 0, attempt 3175 0 3175 0 [(3226, 1), (3200, 3)] 0, attempt 3176 0 3176 0 [(3227, 1), (3200, 3)] 0, attempt 3177 0 3177 0 [(3228, 1), (3200, 3)] 0, attempt 3178 0 3178 0 [(3229, 1), (3200, 3)] 0, attempt 3179 0 3179 0 [(3230, 1), (3200, 3)] 0, attempt 3180 0 3180 0 [(3231, 1), (3200, 3)] 0, attempt 3181 0 3181 0 [(3232, 1), (3200, 3)] 0, attempt 3182 0 3182 0 [(3233, 1), (3200, 3)] 0, attempt 3183 0 3183 0 [(3234, 1), (3200, 3)] 0, attempt 3184 0 3184 0 [(3235, 1), (3200, 3)] 0, attempt 3185 0 3185 0 [(3236, 1), (3200, 3)] 0, attempt 3186 0 3186 0 [(3237, 1), (3200, 3)] 0, attempt 3187 0 3187 0 [(3238, 1), (3200, 3)] 0, attempt 3188 0 3188 0 [(3239, 1), (3200, 3)] 0, attempt 3189 0 3189 0 [(3240, 1), (3200, 3)] 0, attempt 3190 0 3190 0 [(3241, 1), (3200, 3)] 0, attempt 3191 0 3191 0 [(3242, 1), (3200, 3)] 0, attempt 3192 0 3192 0 [(3243, 1), (3200, 3)] 0, attempt 3193 0 3193 0 [(3244, 1), (3200, 3)] 0, attempt 3194 0 3194 0 [(3245, 1), (3200, 3)] 0, attempt 3195 0 3195 0 [(3246, 1), (3200, 3)] 0, attempt 3196 0 3196 0 [(3247, 1), (3200, 3)] 0, attempt 3197 0 3197 0 [(3248, 1), (3200, 3)] 0, attempt 3198 0 3198 0 [(3249, 1), (3200, 3)] 0, attempt 3199 0 3199 0 [(3250, 1), (3200, 3)] 0]
def counters004 : List Nat := [3200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3168
        counters003 chunk003 = true ∧ chunk003.length = 32 ∧
      advanceCsrCounters counters003 chunk003 = counters004 := by decide

def chunk004 : List CsrExecutableAttempt :=
  [attempt 3200 0 3200 0 [(3251, 1), (3200, 3)] 0, attempt 3201 0 3201 0 [(3252, 1), (3200, 3)] 0, attempt 3202 0 3202 0 [(3253, 1), (3200, 3)] 0, attempt 3203 0 3203 0 [(3254, 1), (3200, 3)] 0, attempt 3204 0 3204 0 [(3255, 1), (3200, 3)] 0, attempt 3205 0 3205 0 [(3256, 1), (3200, 3)] 0, attempt 3206 0 3206 0 [(3257, 1), (3200, 3)] 0, attempt 3207 0 3207 0 [(3258, 1), (3200, 3)] 0, attempt 3208 0 3208 0 [(3259, 1), (3200, 3)] 0, attempt 3209 0 3209 0 [(3260, 1), (3200, 3)] 0, attempt 3210 0 3210 0 [(3261, 1), (3200, 3)] 0, attempt 3211 0 3211 0 [(3262, 1), (3200, 3)] 0, attempt 3212 0 3212 0 [(3263, 1), (3200, 3)] 0, attempt 3213 0 3213 0 [(3265, 1), (3264, 3)] 0, attempt 3214 0 3214 0 [(3266, 1), (3264, 3)] 0, attempt 3215 0 3215 0 [(3267, 1), (3264, 3)] 0, attempt 3216 0 3216 0 [(3268, 1), (3264, 3)] 0, attempt 3217 0 3217 0 [(3269, 1), (3264, 3)] 0, attempt 3218 0 3218 0 [(3270, 1), (3264, 3)] 0, attempt 3219 0 3219 0 [(3271, 1), (3264, 3)] 0, attempt 3220 0 3220 0 [(3272, 1), (3264, 3)] 0, attempt 3221 0 3221 0 [(3273, 1), (3264, 3)] 0, attempt 3222 0 3222 0 [(3274, 1), (3264, 3)] 0, attempt 3223 0 3223 0 [(3275, 1), (3264, 3)] 0, attempt 3224 0 3224 0 [(3276, 1), (3264, 3)] 0, attempt 3225 0 3225 0 [(3277, 1), (3264, 3)] 0, attempt 3226 0 3226 0 [(3278, 1), (3264, 3)] 0, attempt 3227 0 3227 0 [(3279, 1), (3264, 3)] 0, attempt 3228 0 3228 0 [(3280, 1), (3264, 3)] 0, attempt 3229 0 3229 0 [(3281, 1), (3264, 3)] 0, attempt 3230 0 3230 0 [(3282, 1), (3264, 3)] 0, attempt 3231 0 3231 0 [(3283, 1), (3264, 3)] 0]
def counters005 : List Nat := [3232, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3200
        counters004 chunk004 = true ∧ chunk004.length = 32 ∧
      advanceCsrCounters counters004 chunk004 = counters005 := by decide

def chunk005 : List CsrExecutableAttempt :=
  [attempt 3232 0 3232 0 [(3284, 1), (3264, 3)] 0, attempt 3233 0 3233 0 [(3285, 1), (3264, 3)] 0, attempt 3234 0 3234 0 [(3286, 1), (3264, 3)] 0, attempt 3235 0 3235 0 [(3287, 1), (3264, 3)] 0, attempt 3236 0 3236 0 [(3288, 1), (3264, 3)] 0, attempt 3237 0 3237 0 [(3289, 1), (3264, 3)] 0, attempt 3238 0 3238 0 [(3290, 1), (3264, 3)] 0, attempt 3239 0 3239 0 [(3291, 1), (3264, 3)] 0, attempt 3240 0 3240 0 [(3292, 1), (3264, 3)] 0, attempt 3241 0 3241 0 [(3293, 1), (3264, 3)] 0, attempt 3242 0 3242 0 [(3294, 1), (3264, 3)] 0, attempt 3243 0 3243 0 [(3295, 1), (3264, 3)] 0, attempt 3244 0 3244 0 [(3296, 1), (3264, 3)] 0, attempt 3245 0 3245 0 [(3297, 1), (3264, 3)] 0, attempt 3246 0 3246 0 [(3298, 1), (3264, 3)] 0, attempt 3247 0 3247 0 [(3299, 1), (3264, 3)] 0, attempt 3248 0 3248 0 [(3300, 1), (3264, 3)] 0, attempt 3249 0 3249 0 [(3301, 1), (3264, 3)] 0, attempt 3250 0 3250 0 [(3302, 1), (3264, 3)] 0, attempt 3251 0 3251 0 [(3303, 1), (3264, 3)] 0, attempt 3252 0 3252 0 [(3304, 1), (3264, 3)] 0, attempt 3253 0 3253 0 [(3305, 1), (3264, 3)] 0, attempt 3254 0 3254 0 [(3306, 1), (3264, 3)] 0, attempt 3255 0 3255 0 [(3307, 1), (3264, 3)] 0, attempt 3256 0 3256 0 [(3308, 1), (3264, 3)] 0, attempt 3257 0 3257 0 [(3309, 1), (3264, 3)] 0, attempt 3258 0 3258 0 [(3310, 1), (3264, 3)] 0, attempt 3259 0 3259 0 [(3311, 1), (3264, 3)] 0, attempt 3260 0 3260 0 [(3312, 1), (3264, 3)] 0, attempt 3261 0 3261 0 [(3313, 1), (3264, 3)] 0, attempt 3262 0 3262 0 [(3314, 1), (3264, 3)] 0, attempt 3263 0 3263 0 [(3315, 1), (3264, 3)] 0]
def counters006 : List Nat := [3264, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3232
        counters005 chunk005 = true ∧ chunk005.length = 32 ∧
      advanceCsrCounters counters005 chunk005 = counters006 := by decide

def chunk006 : List CsrExecutableAttempt :=
  [attempt 3264 0 3264 0 [(3316, 1), (3264, 3)] 0, attempt 3265 0 3265 0 [(3317, 1), (3264, 3)] 0, attempt 3266 0 3266 0 [(3318, 1), (3264, 3)] 0, attempt 3267 0 3267 0 [(3319, 1), (3264, 3)] 0, attempt 3268 0 3268 0 [(3320, 1), (3264, 3)] 0, attempt 3269 0 3269 0 [(3321, 1), (3264, 3)] 0, attempt 3270 0 3270 0 [(3322, 1), (3264, 3)] 0, attempt 3271 0 3271 0 [(3323, 1), (3264, 3)] 0, attempt 3272 0 3272 0 [(3324, 1), (3264, 3)] 0, attempt 3273 0 3273 0 [(3325, 1), (3264, 3)] 0, attempt 3274 0 3274 0 [(3326, 1), (3264, 3)] 0, attempt 3275 0 3275 0 [(3327, 1), (3264, 3)] 0, attempt 3276 0 3276 0 [(3329, 1), (3328, 3)] 0, attempt 3277 0 3277 0 [(3330, 1), (3328, 3)] 0, attempt 3278 0 3278 0 [(3331, 1), (3328, 3)] 0, attempt 3279 0 3279 0 [(3332, 1), (3328, 3)] 0, attempt 3280 0 3280 0 [(3333, 1), (3328, 3)] 0, attempt 3281 0 3281 0 [(3334, 1), (3328, 3)] 0, attempt 3282 0 3282 0 [(3335, 1), (3328, 3)] 0, attempt 3283 0 3283 0 [(3336, 1), (3328, 3)] 0, attempt 3284 0 3284 0 [(3337, 1), (3328, 3)] 0, attempt 3285 0 3285 0 [(3338, 1), (3328, 3)] 0, attempt 3286 0 3286 0 [(3339, 1), (3328, 3)] 0, attempt 3287 0 3287 0 [(3340, 1), (3328, 3)] 0, attempt 3288 0 3288 0 [(3341, 1), (3328, 3)] 0, attempt 3289 0 3289 0 [(3342, 1), (3328, 3)] 0, attempt 3290 0 3290 0 [(3343, 1), (3328, 3)] 0, attempt 3291 0 3291 0 [(3344, 1), (3328, 3)] 0, attempt 3292 0 3292 0 [(3345, 1), (3328, 3)] 0, attempt 3293 0 3293 0 [(3346, 1), (3328, 3)] 0, attempt 3294 0 3294 0 [(3347, 1), (3328, 3)] 0, attempt 3295 0 3295 0 [(3348, 1), (3328, 3)] 0]
def counters007 : List Nat := [3296, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3264
        counters006 chunk006 = true ∧ chunk006.length = 32 ∧
      advanceCsrCounters counters006 chunk006 = counters007 := by decide

def chunk007 : List CsrExecutableAttempt :=
  [attempt 3296 0 3296 0 [(3349, 1), (3328, 3)] 0, attempt 3297 0 3297 0 [(3350, 1), (3328, 3)] 0, attempt 3298 0 3298 0 [(3351, 1), (3328, 3)] 0, attempt 3299 0 3299 0 [(3352, 1), (3328, 3)] 0, attempt 3300 0 3300 0 [(3353, 1), (3328, 3)] 0, attempt 3301 0 3301 0 [(3354, 1), (3328, 3)] 0, attempt 3302 0 3302 0 [(3355, 1), (3328, 3)] 0, attempt 3303 0 3303 0 [(3356, 1), (3328, 3)] 0, attempt 3304 0 3304 0 [(3357, 1), (3328, 3)] 0, attempt 3305 0 3305 0 [(3358, 1), (3328, 3)] 0, attempt 3306 0 3306 0 [(3359, 1), (3328, 3)] 0, attempt 3307 0 3307 0 [(3360, 1), (3328, 3)] 0, attempt 3308 0 3308 0 [(3361, 1), (3328, 3)] 0, attempt 3309 0 3309 0 [(3362, 1), (3328, 3)] 0, attempt 3310 0 3310 0 [(3363, 1), (3328, 3)] 0, attempt 3311 0 3311 0 [(3364, 1), (3328, 3)] 0, attempt 3312 0 3312 0 [(3365, 1), (3328, 3)] 0, attempt 3313 0 3313 0 [(3366, 1), (3328, 3)] 0, attempt 3314 0 3314 0 [(3367, 1), (3328, 3)] 0, attempt 3315 0 3315 0 [(3368, 1), (3328, 3)] 0, attempt 3316 0 3316 0 [(3369, 1), (3328, 3)] 0, attempt 3317 0 3317 0 [(3370, 1), (3328, 3)] 0, attempt 3318 0 3318 0 [(3371, 1), (3328, 3)] 0, attempt 3319 0 3319 0 [(3372, 1), (3328, 3)] 0, attempt 3320 0 3320 0 [(3373, 1), (3328, 3)] 0, attempt 3321 0 3321 0 [(3374, 1), (3328, 3)] 0, attempt 3322 0 3322 0 [(3375, 1), (3328, 3)] 0, attempt 3323 0 3323 0 [(3376, 1), (3328, 3)] 0, attempt 3324 0 3324 0 [(3377, 1), (3328, 3)] 0, attempt 3325 0 3325 0 [(3378, 1), (3328, 3)] 0, attempt 3326 0 3326 0 [(3379, 1), (3328, 3)] 0, attempt 3327 0 3327 0 [(3380, 1), (3328, 3)] 0]
def counters008 : List Nat := [3328, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3296
        counters007 chunk007 = true ∧ chunk007.length = 32 ∧
      advanceCsrCounters counters007 chunk007 = counters008 := by decide

def chunk008 : List CsrExecutableAttempt :=
  [attempt 3328 0 3328 0 [(3381, 1), (3328, 3)] 0, attempt 3329 0 3329 0 [(3382, 1), (3328, 3)] 0, attempt 3330 0 3330 0 [(3383, 1), (3328, 3)] 0, attempt 3331 0 3331 0 [(3384, 1), (3328, 3)] 0, attempt 3332 0 3332 0 [(3385, 1), (3328, 3)] 0, attempt 3333 0 3333 0 [(3386, 1), (3328, 3)] 0, attempt 3334 0 3334 0 [(3387, 1), (3328, 3)] 0, attempt 3335 0 3335 0 [(3388, 1), (3328, 3)] 0, attempt 3336 0 3336 0 [(3389, 1), (3328, 3)] 0, attempt 3337 0 3337 0 [(3390, 1), (3328, 3)] 0, attempt 3338 0 3338 0 [(3391, 1), (3328, 3)] 0, attempt 3339 0 3339 0 [(3393, 1), (3392, 3)] 0, attempt 3340 0 3340 0 [(3394, 1), (3392, 3)] 0, attempt 3341 0 3341 0 [(3395, 1), (3392, 3)] 0, attempt 3342 0 3342 0 [(3396, 1), (3392, 3)] 0, attempt 3343 0 3343 0 [(3397, 1), (3392, 3)] 0, attempt 3344 0 3344 0 [(3398, 1), (3392, 3)] 0, attempt 3345 0 3345 0 [(3399, 1), (3392, 3)] 0, attempt 3346 0 3346 0 [(3400, 1), (3392, 3)] 0, attempt 3347 0 3347 0 [(3401, 1), (3392, 3)] 0, attempt 3348 0 3348 0 [(3402, 1), (3392, 3)] 0, attempt 3349 0 3349 0 [(3403, 1), (3392, 3)] 0, attempt 3350 0 3350 0 [(3404, 1), (3392, 3)] 0, attempt 3351 0 3351 0 [(3405, 1), (3392, 3)] 0, attempt 3352 0 3352 0 [(3406, 1), (3392, 3)] 0, attempt 3353 0 3353 0 [(3407, 1), (3392, 3)] 0, attempt 3354 0 3354 0 [(3408, 1), (3392, 3)] 0, attempt 3355 0 3355 0 [(3409, 1), (3392, 3)] 0, attempt 3356 0 3356 0 [(3410, 1), (3392, 3)] 0, attempt 3357 0 3357 0 [(3411, 1), (3392, 3)] 0, attempt 3358 0 3358 0 [(3412, 1), (3392, 3)] 0, attempt 3359 0 3359 0 [(3413, 1), (3392, 3)] 0]
def counters009 : List Nat := [3360, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3328
        counters008 chunk008 = true ∧ chunk008.length = 32 ∧
      advanceCsrCounters counters008 chunk008 = counters009 := by decide

def chunk009 : List CsrExecutableAttempt :=
  [attempt 3360 0 3360 0 [(3414, 1), (3392, 3)] 0, attempt 3361 0 3361 0 [(3415, 1), (3392, 3)] 0, attempt 3362 0 3362 0 [(3416, 1), (3392, 3)] 0, attempt 3363 0 3363 0 [(3417, 1), (3392, 3)] 0, attempt 3364 0 3364 0 [(3418, 1), (3392, 3)] 0, attempt 3365 0 3365 0 [(3419, 1), (3392, 3)] 0, attempt 3366 0 3366 0 [(3420, 1), (3392, 3)] 0, attempt 3367 0 3367 0 [(3421, 1), (3392, 3)] 0, attempt 3368 0 3368 0 [(3422, 1), (3392, 3)] 0, attempt 3369 0 3369 0 [(3423, 1), (3392, 3)] 0, attempt 3370 0 3370 0 [(3424, 1), (3392, 3)] 0, attempt 3371 0 3371 0 [(3425, 1), (3392, 3)] 0, attempt 3372 0 3372 0 [(3426, 1), (3392, 3)] 0, attempt 3373 0 3373 0 [(3427, 1), (3392, 3)] 0, attempt 3374 0 3374 0 [(3428, 1), (3392, 3)] 0, attempt 3375 0 3375 0 [(3429, 1), (3392, 3)] 0, attempt 3376 0 3376 0 [(3430, 1), (3392, 3)] 0, attempt 3377 0 3377 0 [(3431, 1), (3392, 3)] 0, attempt 3378 0 3378 0 [(3432, 1), (3392, 3)] 0, attempt 3379 0 3379 0 [(3433, 1), (3392, 3)] 0, attempt 3380 0 3380 0 [(3434, 1), (3392, 3)] 0, attempt 3381 0 3381 0 [(3435, 1), (3392, 3)] 0, attempt 3382 0 3382 0 [(3436, 1), (3392, 3)] 0, attempt 3383 0 3383 0 [(3437, 1), (3392, 3)] 0, attempt 3384 0 3384 0 [(3438, 1), (3392, 3)] 0, attempt 3385 0 3385 0 [(3439, 1), (3392, 3)] 0, attempt 3386 0 3386 0 [(3440, 1), (3392, 3)] 0, attempt 3387 0 3387 0 [(3441, 1), (3392, 3)] 0, attempt 3388 0 3388 0 [(3442, 1), (3392, 3)] 0, attempt 3389 0 3389 0 [(3443, 1), (3392, 3)] 0, attempt 3390 0 3390 0 [(3444, 1), (3392, 3)] 0, attempt 3391 0 3391 0 [(3445, 1), (3392, 3)] 0]
def counters010 : List Nat := [3392, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3360
        counters009 chunk009 = true ∧ chunk009.length = 32 ∧
      advanceCsrCounters counters009 chunk009 = counters010 := by decide

def chunk010 : List CsrExecutableAttempt :=
  [attempt 3392 0 3392 0 [(3446, 1), (3392, 3)] 0, attempt 3393 0 3393 0 [(3447, 1), (3392, 3)] 0, attempt 3394 0 3394 0 [(3448, 1), (3392, 3)] 0, attempt 3395 0 3395 0 [(3449, 1), (3392, 3)] 0, attempt 3396 0 3396 0 [(3450, 1), (3392, 3)] 0, attempt 3397 0 3397 0 [(3451, 1), (3392, 3)] 0, attempt 3398 0 3398 0 [(3452, 1), (3392, 3)] 0, attempt 3399 0 3399 0 [(3453, 1), (3392, 3)] 0, attempt 3400 0 3400 0 [(3454, 1), (3392, 3)] 0, attempt 3401 0 3401 0 [(3455, 1), (3392, 3)] 0, attempt 3402 0 3402 0 [(3457, 1), (3456, 3)] 0, attempt 3403 0 3403 0 [(3458, 1), (3456, 3)] 0, attempt 3404 0 3404 0 [(3459, 1), (3456, 3)] 0, attempt 3405 0 3405 0 [(3460, 1), (3456, 3)] 0, attempt 3406 0 3406 0 [(3461, 1), (3456, 3)] 0, attempt 3407 0 3407 0 [(3462, 1), (3456, 3)] 0, attempt 3408 0 3408 0 [(3463, 1), (3456, 3)] 0, attempt 3409 0 3409 0 [(3464, 1), (3456, 3)] 0, attempt 3410 0 3410 0 [(3465, 1), (3456, 3)] 0, attempt 3411 0 3411 0 [(3466, 1), (3456, 3)] 0, attempt 3412 0 3412 0 [(3467, 1), (3456, 3)] 0, attempt 3413 0 3413 0 [(3468, 1), (3456, 3)] 0, attempt 3414 0 3414 0 [(3469, 1), (3456, 3)] 0, attempt 3415 0 3415 0 [(3470, 1), (3456, 3)] 0, attempt 3416 0 3416 0 [(3471, 1), (3456, 3)] 0, attempt 3417 0 3417 0 [(3472, 1), (3456, 3)] 0, attempt 3418 0 3418 0 [(3473, 1), (3456, 3)] 0, attempt 3419 0 3419 0 [(3474, 1), (3456, 3)] 0, attempt 3420 0 3420 0 [(3475, 1), (3456, 3)] 0, attempt 3421 0 3421 0 [(3476, 1), (3456, 3)] 0, attempt 3422 0 3422 0 [(3477, 1), (3456, 3)] 0, attempt 3423 0 3423 0 [(3478, 1), (3456, 3)] 0]
def counters011 : List Nat := [3424, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3392
        counters010 chunk010 = true ∧ chunk010.length = 32 ∧
      advanceCsrCounters counters010 chunk010 = counters011 := by decide

def chunk011 : List CsrExecutableAttempt :=
  [attempt 3424 0 3424 0 [(3479, 1), (3456, 3)] 0, attempt 3425 0 3425 0 [(3480, 1), (3456, 3)] 0, attempt 3426 0 3426 0 [(3481, 1), (3456, 3)] 0, attempt 3427 0 3427 0 [(3482, 1), (3456, 3)] 0, attempt 3428 0 3428 0 [(3483, 1), (3456, 3)] 0, attempt 3429 0 3429 0 [(3484, 1), (3456, 3)] 0, attempt 3430 0 3430 0 [(3485, 1), (3456, 3)] 0, attempt 3431 0 3431 0 [(3486, 1), (3456, 3)] 0, attempt 3432 0 3432 0 [(3487, 1), (3456, 3)] 0, attempt 3433 0 3433 0 [(3488, 1), (3456, 3)] 0, attempt 3434 0 3434 0 [(3489, 1), (3456, 3)] 0, attempt 3435 0 3435 0 [(3490, 1), (3456, 3)] 0, attempt 3436 0 3436 0 [(3491, 1), (3456, 3)] 0, attempt 3437 0 3437 0 [(3492, 1), (3456, 3)] 0, attempt 3438 0 3438 0 [(3493, 1), (3456, 3)] 0, attempt 3439 0 3439 0 [(3494, 1), (3456, 3)] 0, attempt 3440 0 3440 0 [(3495, 1), (3456, 3)] 0, attempt 3441 0 3441 0 [(3496, 1), (3456, 3)] 0, attempt 3442 0 3442 0 [(3497, 1), (3456, 3)] 0, attempt 3443 0 3443 0 [(3498, 1), (3456, 3)] 0, attempt 3444 0 3444 0 [(3499, 1), (3456, 3)] 0, attempt 3445 0 3445 0 [(3500, 1), (3456, 3)] 0, attempt 3446 0 3446 0 [(3501, 1), (3456, 3)] 0, attempt 3447 0 3447 0 [(3502, 1), (3456, 3)] 0, attempt 3448 0 3448 0 [(3503, 1), (3456, 3)] 0, attempt 3449 0 3449 0 [(3504, 1), (3456, 3)] 0, attempt 3450 0 3450 0 [(3505, 1), (3456, 3)] 0, attempt 3451 0 3451 0 [(3506, 1), (3456, 3)] 0, attempt 3452 0 3452 0 [(3507, 1), (3456, 3)] 0, attempt 3453 0 3453 0 [(3508, 1), (3456, 3)] 0, attempt 3454 0 3454 0 [(3509, 1), (3456, 3)] 0, attempt 3455 0 3455 0 [(3510, 1), (3456, 3)] 0]
def counters012 : List Nat := [3456, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3424
        counters011 chunk011 = true ∧ chunk011.length = 32 ∧
      advanceCsrCounters counters011 chunk011 = counters012 := by decide

def chunk012 : List CsrExecutableAttempt :=
  [attempt 3456 0 3456 0 [(3511, 1), (3456, 3)] 0, attempt 3457 0 3457 0 [(3512, 1), (3456, 3)] 0, attempt 3458 0 3458 0 [(3513, 1), (3456, 3)] 0, attempt 3459 0 3459 0 [(3514, 1), (3456, 3)] 0, attempt 3460 0 3460 0 [(3515, 1), (3456, 3)] 0, attempt 3461 0 3461 0 [(3516, 1), (3456, 3)] 0, attempt 3462 0 3462 0 [(3517, 1), (3456, 3)] 0, attempt 3463 0 3463 0 [(3518, 1), (3456, 3)] 0, attempt 3464 0 3464 0 [(3519, 1), (3456, 3)] 0, attempt 3465 0 3465 0 [(3521, 1), (3520, 3)] 0, attempt 3466 0 3466 0 [(3522, 1), (3520, 3)] 0, attempt 3467 0 3467 0 [(3523, 1), (3520, 3)] 0, attempt 3468 0 3468 0 [(3524, 1), (3520, 3)] 0, attempt 3469 0 3469 0 [(3525, 1), (3520, 3)] 0, attempt 3470 0 3470 0 [(3526, 1), (3520, 3)] 0, attempt 3471 0 3471 0 [(3527, 1), (3520, 3)] 0, attempt 3472 0 3472 0 [(3528, 1), (3520, 3)] 0, attempt 3473 0 3473 0 [(3529, 1), (3520, 3)] 0, attempt 3474 0 3474 0 [(3530, 1), (3520, 3)] 0, attempt 3475 0 3475 0 [(3531, 1), (3520, 3)] 0, attempt 3476 0 3476 0 [(3532, 1), (3520, 3)] 0, attempt 3477 0 3477 0 [(3533, 1), (3520, 3)] 0, attempt 3478 0 3478 0 [(3534, 1), (3520, 3)] 0, attempt 3479 0 3479 0 [(3535, 1), (3520, 3)] 0, attempt 3480 0 3480 0 [(3536, 1), (3520, 3)] 0, attempt 3481 0 3481 0 [(3537, 1), (3520, 3)] 0, attempt 3482 0 3482 0 [(3538, 1), (3520, 3)] 0, attempt 3483 0 3483 0 [(3539, 1), (3520, 3)] 0, attempt 3484 0 3484 0 [(3540, 1), (3520, 3)] 0, attempt 3485 0 3485 0 [(3541, 1), (3520, 3)] 0, attempt 3486 0 3486 0 [(3542, 1), (3520, 3)] 0, attempt 3487 0 3487 0 [(3543, 1), (3520, 3)] 0]
def counters013 : List Nat := [3488, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3456
        counters012 chunk012 = true ∧ chunk012.length = 32 ∧
      advanceCsrCounters counters012 chunk012 = counters013 := by decide

def chunk013 : List CsrExecutableAttempt :=
  [attempt 3488 0 3488 0 [(3544, 1), (3520, 3)] 0, attempt 3489 0 3489 0 [(3545, 1), (3520, 3)] 0, attempt 3490 0 3490 0 [(3546, 1), (3520, 3)] 0, attempt 3491 0 3491 0 [(3547, 1), (3520, 3)] 0, attempt 3492 0 3492 0 [(3548, 1), (3520, 3)] 0, attempt 3493 0 3493 0 [(3549, 1), (3520, 3)] 0, attempt 3494 0 3494 0 [(3550, 1), (3520, 3)] 0, attempt 3495 0 3495 0 [(3551, 1), (3520, 3)] 0, attempt 3496 0 3496 0 [(3552, 1), (3520, 3)] 0, attempt 3497 0 3497 0 [(3553, 1), (3520, 3)] 0, attempt 3498 0 3498 0 [(3554, 1), (3520, 3)] 0, attempt 3499 0 3499 0 [(3555, 1), (3520, 3)] 0, attempt 3500 0 3500 0 [(3556, 1), (3520, 3)] 0, attempt 3501 0 3501 0 [(3557, 1), (3520, 3)] 0, attempt 3502 0 3502 0 [(3558, 1), (3520, 3)] 0, attempt 3503 0 3503 0 [(3559, 1), (3520, 3)] 0, attempt 3504 0 3504 0 [(3560, 1), (3520, 3)] 0, attempt 3505 0 3505 0 [(3561, 1), (3520, 3)] 0, attempt 3506 0 3506 0 [(3562, 1), (3520, 3)] 0, attempt 3507 0 3507 0 [(3563, 1), (3520, 3)] 0, attempt 3508 0 3508 0 [(3564, 1), (3520, 3)] 0, attempt 3509 0 3509 0 [(3565, 1), (3520, 3)] 0, attempt 3510 0 3510 0 [(3566, 1), (3520, 3)] 0, attempt 3511 0 3511 0 [(3567, 1), (3520, 3)] 0, attempt 3512 0 3512 0 [(3568, 1), (3520, 3)] 0, attempt 3513 0 3513 0 [(3569, 1), (3520, 3)] 0, attempt 3514 0 3514 0 [(3570, 1), (3520, 3)] 0, attempt 3515 0 3515 0 [(3571, 1), (3520, 3)] 0, attempt 3516 0 3516 0 [(3572, 1), (3520, 3)] 0, attempt 3517 0 3517 0 [(3573, 1), (3520, 3)] 0, attempt 3518 0 3518 0 [(3574, 1), (3520, 3)] 0, attempt 3519 0 3519 0 [(3575, 1), (3520, 3)] 0]
def counters014 : List Nat := [3520, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3488
        counters013 chunk013 = true ∧ chunk013.length = 32 ∧
      advanceCsrCounters counters013 chunk013 = counters014 := by decide

def chunk014 : List CsrExecutableAttempt :=
  [attempt 3520 0 3520 0 [(3576, 1), (3520, 3)] 0, attempt 3521 0 3521 0 [(3577, 1), (3520, 3)] 0, attempt 3522 0 3522 0 [(3578, 1), (3520, 3)] 0, attempt 3523 0 3523 0 [(3579, 1), (3520, 3)] 0, attempt 3524 0 3524 0 [(3580, 1), (3520, 3)] 0, attempt 3525 0 3525 0 [(3581, 1), (3520, 3)] 0, attempt 3526 0 3526 0 [(3582, 1), (3520, 3)] 0, attempt 3527 0 3527 0 [(3583, 1), (3520, 3)] 0, attempt 3528 0 3528 0 [(3585, 1), (3584, 3)] 0, attempt 3529 0 3529 0 [(3586, 1), (3584, 3)] 0, attempt 3530 0 3530 0 [(3587, 1), (3584, 3)] 0, attempt 3531 0 3531 0 [(3588, 1), (3584, 3)] 0, attempt 3532 0 3532 0 [(3589, 1), (3584, 3)] 0, attempt 3533 0 3533 0 [(3590, 1), (3584, 3)] 0, attempt 3534 0 3534 0 [(3591, 1), (3584, 3)] 0, attempt 3535 0 3535 0 [(3592, 1), (3584, 3)] 0, attempt 3536 0 3536 0 [(3593, 1), (3584, 3)] 0, attempt 3537 0 3537 0 [(3594, 1), (3584, 3)] 0, attempt 3538 0 3538 0 [(3595, 1), (3584, 3)] 0, attempt 3539 0 3539 0 [(3596, 1), (3584, 3)] 0, attempt 3540 0 3540 0 [(3597, 1), (3584, 3)] 0, attempt 3541 0 3541 0 [(3598, 1), (3584, 3)] 0, attempt 3542 0 3542 0 [(3599, 1), (3584, 3)] 0, attempt 3543 0 3543 0 [(3600, 1), (3584, 3)] 0, attempt 3544 0 3544 0 [(3601, 1), (3584, 3)] 0, attempt 3545 0 3545 0 [(3602, 1), (3584, 3)] 0, attempt 3546 0 3546 0 [(3603, 1), (3584, 3)] 0, attempt 3547 0 3547 0 [(3604, 1), (3584, 3)] 0, attempt 3548 0 3548 0 [(3605, 1), (3584, 3)] 0, attempt 3549 0 3549 0 [(3606, 1), (3584, 3)] 0, attempt 3550 0 3550 0 [(3607, 1), (3584, 3)] 0, attempt 3551 0 3551 0 [(3608, 1), (3584, 3)] 0]
def counters015 : List Nat := [3552, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3520
        counters014 chunk014 = true ∧ chunk014.length = 32 ∧
      advanceCsrCounters counters014 chunk014 = counters015 := by decide

def chunk015 : List CsrExecutableAttempt :=
  [attempt 3552 0 3552 0 [(3609, 1), (3584, 3)] 0, attempt 3553 0 3553 0 [(3610, 1), (3584, 3)] 0, attempt 3554 0 3554 0 [(3611, 1), (3584, 3)] 0, attempt 3555 0 3555 0 [(3612, 1), (3584, 3)] 0, attempt 3556 0 3556 0 [(3613, 1), (3584, 3)] 0, attempt 3557 0 3557 0 [(3614, 1), (3584, 3)] 0, attempt 3558 0 3558 0 [(3615, 1), (3584, 3)] 0, attempt 3559 0 3559 0 [(3616, 1), (3584, 3)] 0, attempt 3560 0 3560 0 [(3617, 1), (3584, 3)] 0, attempt 3561 0 3561 0 [(3618, 1), (3584, 3)] 0, attempt 3562 0 3562 0 [(3619, 1), (3584, 3)] 0, attempt 3563 0 3563 0 [(3620, 1), (3584, 3)] 0, attempt 3564 0 3564 0 [(3621, 1), (3584, 3)] 0, attempt 3565 0 3565 0 [(3622, 1), (3584, 3)] 0, attempt 3566 0 3566 0 [(3623, 1), (3584, 3)] 0, attempt 3567 0 3567 0 [(3624, 1), (3584, 3)] 0, attempt 3568 0 3568 0 [(3625, 1), (3584, 3)] 0, attempt 3569 0 3569 0 [(3626, 1), (3584, 3)] 0, attempt 3570 0 3570 0 [(3627, 1), (3584, 3)] 0, attempt 3571 0 3571 0 [(3628, 1), (3584, 3)] 0, attempt 3572 0 3572 0 [(3629, 1), (3584, 3)] 0, attempt 3573 0 3573 0 [(3630, 1), (3584, 3)] 0, attempt 3574 0 3574 0 [(3631, 1), (3584, 3)] 0, attempt 3575 0 3575 0 [(3632, 1), (3584, 3)] 0, attempt 3576 0 3576 0 [(3633, 1), (3584, 3)] 0, attempt 3577 0 3577 0 [(3634, 1), (3584, 3)] 0, attempt 3578 0 3578 0 [(3635, 1), (3584, 3)] 0, attempt 3579 0 3579 0 [(3636, 1), (3584, 3)] 0, attempt 3580 0 3580 0 [(3637, 1), (3584, 3)] 0, attempt 3581 0 3581 0 [(3638, 1), (3584, 3)] 0, attempt 3582 0 3582 0 [(3639, 1), (3584, 3)] 0, attempt 3583 0 3583 0 [(3640, 1), (3584, 3)] 0]
def counters016 : List Nat := [3584, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3552
        counters015 chunk015 = true ∧ chunk015.length = 32 ∧
      advanceCsrCounters counters015 chunk015 = counters016 := by decide

def suffix016 : List CsrExecutableAttempt := []
theorem suffix016_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3584
      counters016 suffix016 = true := by rfl
theorem suffix016_length : suffix016.length = 0 := by rfl
theorem suffix016_state : advanceCsrCounters counters016 suffix016 = counters016 := by rfl

def suffix015 : List CsrExecutableAttempt := chunk015 ++ suffix016
theorem suffix015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3552
      counters015 suffix015 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk015 suffix016 3552 3584 counters015 counters016
    chunk015_checked.1 (congrArg (Nat.add 3552) chunk015_checked.2.1)
    chunk015_checked.2.2 suffix016_checked
theorem suffix015_length : suffix015.length = 32 := by
  rw [suffix015, List.length_append, chunk015_checked.2.1, suffix016_length]
theorem suffix015_state : advanceCsrCounters counters015 suffix015 = counters016 := by
  rw [suffix015, advanceCsrCounters_append, chunk015_checked.2.2, suffix016_state]

def suffix014 : List CsrExecutableAttempt := chunk014 ++ suffix015
theorem suffix014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3520
      counters014 suffix014 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk014 suffix015 3520 3552 counters014 counters015
    chunk014_checked.1 (congrArg (Nat.add 3520) chunk014_checked.2.1)
    chunk014_checked.2.2 suffix015_checked
theorem suffix014_length : suffix014.length = 64 := by
  rw [suffix014, List.length_append, chunk014_checked.2.1, suffix015_length]
theorem suffix014_state : advanceCsrCounters counters014 suffix014 = counters016 := by
  rw [suffix014, advanceCsrCounters_append, chunk014_checked.2.2, suffix015_state]

def suffix013 : List CsrExecutableAttempt := chunk013 ++ suffix014
theorem suffix013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3488
      counters013 suffix013 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk013 suffix014 3488 3520 counters013 counters014
    chunk013_checked.1 (congrArg (Nat.add 3488) chunk013_checked.2.1)
    chunk013_checked.2.2 suffix014_checked
theorem suffix013_length : suffix013.length = 96 := by
  rw [suffix013, List.length_append, chunk013_checked.2.1, suffix014_length]
theorem suffix013_state : advanceCsrCounters counters013 suffix013 = counters016 := by
  rw [suffix013, advanceCsrCounters_append, chunk013_checked.2.2, suffix014_state]

def suffix012 : List CsrExecutableAttempt := chunk012 ++ suffix013
theorem suffix012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3456
      counters012 suffix012 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk012 suffix013 3456 3488 counters012 counters013
    chunk012_checked.1 (congrArg (Nat.add 3456) chunk012_checked.2.1)
    chunk012_checked.2.2 suffix013_checked
theorem suffix012_length : suffix012.length = 128 := by
  rw [suffix012, List.length_append, chunk012_checked.2.1, suffix013_length]
theorem suffix012_state : advanceCsrCounters counters012 suffix012 = counters016 := by
  rw [suffix012, advanceCsrCounters_append, chunk012_checked.2.2, suffix013_state]

def suffix011 : List CsrExecutableAttempt := chunk011 ++ suffix012
theorem suffix011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3424
      counters011 suffix011 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk011 suffix012 3424 3456 counters011 counters012
    chunk011_checked.1 (congrArg (Nat.add 3424) chunk011_checked.2.1)
    chunk011_checked.2.2 suffix012_checked
theorem suffix011_length : suffix011.length = 160 := by
  rw [suffix011, List.length_append, chunk011_checked.2.1, suffix012_length]
theorem suffix011_state : advanceCsrCounters counters011 suffix011 = counters016 := by
  rw [suffix011, advanceCsrCounters_append, chunk011_checked.2.2, suffix012_state]

def suffix010 : List CsrExecutableAttempt := chunk010 ++ suffix011
theorem suffix010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3392
      counters010 suffix010 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk010 suffix011 3392 3424 counters010 counters011
    chunk010_checked.1 (congrArg (Nat.add 3392) chunk010_checked.2.1)
    chunk010_checked.2.2 suffix011_checked
theorem suffix010_length : suffix010.length = 192 := by
  rw [suffix010, List.length_append, chunk010_checked.2.1, suffix011_length]
theorem suffix010_state : advanceCsrCounters counters010 suffix010 = counters016 := by
  rw [suffix010, advanceCsrCounters_append, chunk010_checked.2.2, suffix011_state]

def suffix009 : List CsrExecutableAttempt := chunk009 ++ suffix010
theorem suffix009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3360
      counters009 suffix009 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk009 suffix010 3360 3392 counters009 counters010
    chunk009_checked.1 (congrArg (Nat.add 3360) chunk009_checked.2.1)
    chunk009_checked.2.2 suffix010_checked
theorem suffix009_length : suffix009.length = 224 := by
  rw [suffix009, List.length_append, chunk009_checked.2.1, suffix010_length]
theorem suffix009_state : advanceCsrCounters counters009 suffix009 = counters016 := by
  rw [suffix009, advanceCsrCounters_append, chunk009_checked.2.2, suffix010_state]

def suffix008 : List CsrExecutableAttempt := chunk008 ++ suffix009
theorem suffix008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3328
      counters008 suffix008 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk008 suffix009 3328 3360 counters008 counters009
    chunk008_checked.1 (congrArg (Nat.add 3328) chunk008_checked.2.1)
    chunk008_checked.2.2 suffix009_checked
theorem suffix008_length : suffix008.length = 256 := by
  rw [suffix008, List.length_append, chunk008_checked.2.1, suffix009_length]
theorem suffix008_state : advanceCsrCounters counters008 suffix008 = counters016 := by
  rw [suffix008, advanceCsrCounters_append, chunk008_checked.2.2, suffix009_state]

def suffix007 : List CsrExecutableAttempt := chunk007 ++ suffix008
theorem suffix007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3296
      counters007 suffix007 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk007 suffix008 3296 3328 counters007 counters008
    chunk007_checked.1 (congrArg (Nat.add 3296) chunk007_checked.2.1)
    chunk007_checked.2.2 suffix008_checked
theorem suffix007_length : suffix007.length = 288 := by
  rw [suffix007, List.length_append, chunk007_checked.2.1, suffix008_length]
theorem suffix007_state : advanceCsrCounters counters007 suffix007 = counters016 := by
  rw [suffix007, advanceCsrCounters_append, chunk007_checked.2.2, suffix008_state]

def suffix006 : List CsrExecutableAttempt := chunk006 ++ suffix007
theorem suffix006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3264
      counters006 suffix006 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk006 suffix007 3264 3296 counters006 counters007
    chunk006_checked.1 (congrArg (Nat.add 3264) chunk006_checked.2.1)
    chunk006_checked.2.2 suffix007_checked
theorem suffix006_length : suffix006.length = 320 := by
  rw [suffix006, List.length_append, chunk006_checked.2.1, suffix007_length]
theorem suffix006_state : advanceCsrCounters counters006 suffix006 = counters016 := by
  rw [suffix006, advanceCsrCounters_append, chunk006_checked.2.2, suffix007_state]

def suffix005 : List CsrExecutableAttempt := chunk005 ++ suffix006
theorem suffix005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3232
      counters005 suffix005 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk005 suffix006 3232 3264 counters005 counters006
    chunk005_checked.1 (congrArg (Nat.add 3232) chunk005_checked.2.1)
    chunk005_checked.2.2 suffix006_checked
theorem suffix005_length : suffix005.length = 352 := by
  rw [suffix005, List.length_append, chunk005_checked.2.1, suffix006_length]
theorem suffix005_state : advanceCsrCounters counters005 suffix005 = counters016 := by
  rw [suffix005, advanceCsrCounters_append, chunk005_checked.2.2, suffix006_state]

def suffix004 : List CsrExecutableAttempt := chunk004 ++ suffix005
theorem suffix004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3200
      counters004 suffix004 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk004 suffix005 3200 3232 counters004 counters005
    chunk004_checked.1 (congrArg (Nat.add 3200) chunk004_checked.2.1)
    chunk004_checked.2.2 suffix005_checked
theorem suffix004_length : suffix004.length = 384 := by
  rw [suffix004, List.length_append, chunk004_checked.2.1, suffix005_length]
theorem suffix004_state : advanceCsrCounters counters004 suffix004 = counters016 := by
  rw [suffix004, advanceCsrCounters_append, chunk004_checked.2.2, suffix005_state]

def suffix003 : List CsrExecutableAttempt := chunk003 ++ suffix004
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3168
      counters003 suffix003 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk003 suffix004 3168 3200 counters003 counters004
    chunk003_checked.1 (congrArg (Nat.add 3168) chunk003_checked.2.1)
    chunk003_checked.2.2 suffix004_checked
theorem suffix003_length : suffix003.length = 416 := by
  rw [suffix003, List.length_append, chunk003_checked.2.1, suffix004_length]
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters016 := by
  rw [suffix003, advanceCsrCounters_append, chunk003_checked.2.2, suffix004_state]

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3136
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 3136 3168 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 3136) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 448 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters016 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3104
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 3104 3136 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 3104) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 480 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters016 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 3072
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 3072 3104 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 3072) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 512 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters016 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002, chunk003, chunk004, chunk005, chunk006, chunk007, chunk008, chunk009, chunk010, chunk011, chunk012, chunk013, chunk014, chunk015]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, suffix004, suffix005, suffix006, suffix007, suffix008, suffix009, suffix010, suffix011, suffix012, suffix013, suffix014, suffix015, suffix016, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr06
