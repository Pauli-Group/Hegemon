import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityCsr03

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr04
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [2048, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 2048 0 2048 0 [(2081, 1), (2048, 3)] 0, attempt 2049 0 2049 0 [(2082, 1), (2048, 3)] 0, attempt 2050 0 2050 0 [(2083, 1), (2048, 3)] 0, attempt 2051 0 2051 0 [(2084, 1), (2048, 3)] 0, attempt 2052 0 2052 0 [(2085, 1), (2048, 3)] 0, attempt 2053 0 2053 0 [(2086, 1), (2048, 3)] 0, attempt 2054 0 2054 0 [(2087, 1), (2048, 3)] 0, attempt 2055 0 2055 0 [(2088, 1), (2048, 3)] 0, attempt 2056 0 2056 0 [(2089, 1), (2048, 3)] 0, attempt 2057 0 2057 0 [(2090, 1), (2048, 3)] 0, attempt 2058 0 2058 0 [(2091, 1), (2048, 3)] 0, attempt 2059 0 2059 0 [(2092, 1), (2048, 3)] 0, attempt 2060 0 2060 0 [(2093, 1), (2048, 3)] 0, attempt 2061 0 2061 0 [(2094, 1), (2048, 3)] 0, attempt 2062 0 2062 0 [(2095, 1), (2048, 3)] 0, attempt 2063 0 2063 0 [(2096, 1), (2048, 3)] 0, attempt 2064 0 2064 0 [(2097, 1), (2048, 3)] 0, attempt 2065 0 2065 0 [(2098, 1), (2048, 3)] 0, attempt 2066 0 2066 0 [(2099, 1), (2048, 3)] 0, attempt 2067 0 2067 0 [(2100, 1), (2048, 3)] 0, attempt 2068 0 2068 0 [(2101, 1), (2048, 3)] 0, attempt 2069 0 2069 0 [(2102, 1), (2048, 3)] 0, attempt 2070 0 2070 0 [(2103, 1), (2048, 3)] 0, attempt 2071 0 2071 0 [(2104, 1), (2048, 3)] 0, attempt 2072 0 2072 0 [(2105, 1), (2048, 3)] 0, attempt 2073 0 2073 0 [(2106, 1), (2048, 3)] 0, attempt 2074 0 2074 0 [(2107, 1), (2048, 3)] 0, attempt 2075 0 2075 0 [(2108, 1), (2048, 3)] 0, attempt 2076 0 2076 0 [(2109, 1), (2048, 3)] 0, attempt 2077 0 2077 0 [(2110, 1), (2048, 3)] 0, attempt 2078 0 2078 0 [(2111, 1), (2048, 3)] 0, attempt 2079 0 2079 0 [(2113, 1), (2112, 3)] 0]
def counters001 : List Nat := [2080, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2048
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 2080 0 2080 0 [(2114, 1), (2112, 3)] 0, attempt 2081 0 2081 0 [(2115, 1), (2112, 3)] 0, attempt 2082 0 2082 0 [(2116, 1), (2112, 3)] 0, attempt 2083 0 2083 0 [(2117, 1), (2112, 3)] 0, attempt 2084 0 2084 0 [(2118, 1), (2112, 3)] 0, attempt 2085 0 2085 0 [(2119, 1), (2112, 3)] 0, attempt 2086 0 2086 0 [(2120, 1), (2112, 3)] 0, attempt 2087 0 2087 0 [(2121, 1), (2112, 3)] 0, attempt 2088 0 2088 0 [(2122, 1), (2112, 3)] 0, attempt 2089 0 2089 0 [(2123, 1), (2112, 3)] 0, attempt 2090 0 2090 0 [(2124, 1), (2112, 3)] 0, attempt 2091 0 2091 0 [(2125, 1), (2112, 3)] 0, attempt 2092 0 2092 0 [(2126, 1), (2112, 3)] 0, attempt 2093 0 2093 0 [(2127, 1), (2112, 3)] 0, attempt 2094 0 2094 0 [(2128, 1), (2112, 3)] 0, attempt 2095 0 2095 0 [(2129, 1), (2112, 3)] 0, attempt 2096 0 2096 0 [(2130, 1), (2112, 3)] 0, attempt 2097 0 2097 0 [(2131, 1), (2112, 3)] 0, attempt 2098 0 2098 0 [(2132, 1), (2112, 3)] 0, attempt 2099 0 2099 0 [(2133, 1), (2112, 3)] 0, attempt 2100 0 2100 0 [(2134, 1), (2112, 3)] 0, attempt 2101 0 2101 0 [(2135, 1), (2112, 3)] 0, attempt 2102 0 2102 0 [(2136, 1), (2112, 3)] 0, attempt 2103 0 2103 0 [(2137, 1), (2112, 3)] 0, attempt 2104 0 2104 0 [(2138, 1), (2112, 3)] 0, attempt 2105 0 2105 0 [(2139, 1), (2112, 3)] 0, attempt 2106 0 2106 0 [(2140, 1), (2112, 3)] 0, attempt 2107 0 2107 0 [(2141, 1), (2112, 3)] 0, attempt 2108 0 2108 0 [(2142, 1), (2112, 3)] 0, attempt 2109 0 2109 0 [(2143, 1), (2112, 3)] 0, attempt 2110 0 2110 0 [(2144, 1), (2112, 3)] 0, attempt 2111 0 2111 0 [(2145, 1), (2112, 3)] 0]
def counters002 : List Nat := [2112, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2080
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 2112 0 2112 0 [(2146, 1), (2112, 3)] 0, attempt 2113 0 2113 0 [(2147, 1), (2112, 3)] 0, attempt 2114 0 2114 0 [(2148, 1), (2112, 3)] 0, attempt 2115 0 2115 0 [(2149, 1), (2112, 3)] 0, attempt 2116 0 2116 0 [(2150, 1), (2112, 3)] 0, attempt 2117 0 2117 0 [(2151, 1), (2112, 3)] 0, attempt 2118 0 2118 0 [(2152, 1), (2112, 3)] 0, attempt 2119 0 2119 0 [(2153, 1), (2112, 3)] 0, attempt 2120 0 2120 0 [(2154, 1), (2112, 3)] 0, attempt 2121 0 2121 0 [(2155, 1), (2112, 3)] 0, attempt 2122 0 2122 0 [(2156, 1), (2112, 3)] 0, attempt 2123 0 2123 0 [(2157, 1), (2112, 3)] 0, attempt 2124 0 2124 0 [(2158, 1), (2112, 3)] 0, attempt 2125 0 2125 0 [(2159, 1), (2112, 3)] 0, attempt 2126 0 2126 0 [(2160, 1), (2112, 3)] 0, attempt 2127 0 2127 0 [(2161, 1), (2112, 3)] 0, attempt 2128 0 2128 0 [(2162, 1), (2112, 3)] 0, attempt 2129 0 2129 0 [(2163, 1), (2112, 3)] 0, attempt 2130 0 2130 0 [(2164, 1), (2112, 3)] 0, attempt 2131 0 2131 0 [(2165, 1), (2112, 3)] 0, attempt 2132 0 2132 0 [(2166, 1), (2112, 3)] 0, attempt 2133 0 2133 0 [(2167, 1), (2112, 3)] 0, attempt 2134 0 2134 0 [(2168, 1), (2112, 3)] 0, attempt 2135 0 2135 0 [(2169, 1), (2112, 3)] 0, attempt 2136 0 2136 0 [(2170, 1), (2112, 3)] 0, attempt 2137 0 2137 0 [(2171, 1), (2112, 3)] 0, attempt 2138 0 2138 0 [(2172, 1), (2112, 3)] 0, attempt 2139 0 2139 0 [(2173, 1), (2112, 3)] 0, attempt 2140 0 2140 0 [(2174, 1), (2112, 3)] 0, attempt 2141 0 2141 0 [(2175, 1), (2112, 3)] 0, attempt 2142 0 2142 0 [(2177, 1), (2176, 3)] 0, attempt 2143 0 2143 0 [(2178, 1), (2176, 3)] 0]
def counters003 : List Nat := [2144, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2112
        counters002 chunk002 = true ∧ chunk002.length = 32 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def chunk003 : List CsrExecutableAttempt :=
  [attempt 2144 0 2144 0 [(2179, 1), (2176, 3)] 0, attempt 2145 0 2145 0 [(2180, 1), (2176, 3)] 0, attempt 2146 0 2146 0 [(2181, 1), (2176, 3)] 0, attempt 2147 0 2147 0 [(2182, 1), (2176, 3)] 0, attempt 2148 0 2148 0 [(2183, 1), (2176, 3)] 0, attempt 2149 0 2149 0 [(2184, 1), (2176, 3)] 0, attempt 2150 0 2150 0 [(2185, 1), (2176, 3)] 0, attempt 2151 0 2151 0 [(2186, 1), (2176, 3)] 0, attempt 2152 0 2152 0 [(2187, 1), (2176, 3)] 0, attempt 2153 0 2153 0 [(2188, 1), (2176, 3)] 0, attempt 2154 0 2154 0 [(2189, 1), (2176, 3)] 0, attempt 2155 0 2155 0 [(2190, 1), (2176, 3)] 0, attempt 2156 0 2156 0 [(2191, 1), (2176, 3)] 0, attempt 2157 0 2157 0 [(2192, 1), (2176, 3)] 0, attempt 2158 0 2158 0 [(2193, 1), (2176, 3)] 0, attempt 2159 0 2159 0 [(2194, 1), (2176, 3)] 0, attempt 2160 0 2160 0 [(2195, 1), (2176, 3)] 0, attempt 2161 0 2161 0 [(2196, 1), (2176, 3)] 0, attempt 2162 0 2162 0 [(2197, 1), (2176, 3)] 0, attempt 2163 0 2163 0 [(2198, 1), (2176, 3)] 0, attempt 2164 0 2164 0 [(2199, 1), (2176, 3)] 0, attempt 2165 0 2165 0 [(2200, 1), (2176, 3)] 0, attempt 2166 0 2166 0 [(2201, 1), (2176, 3)] 0, attempt 2167 0 2167 0 [(2202, 1), (2176, 3)] 0, attempt 2168 0 2168 0 [(2203, 1), (2176, 3)] 0, attempt 2169 0 2169 0 [(2204, 1), (2176, 3)] 0, attempt 2170 0 2170 0 [(2205, 1), (2176, 3)] 0, attempt 2171 0 2171 0 [(2206, 1), (2176, 3)] 0, attempt 2172 0 2172 0 [(2207, 1), (2176, 3)] 0, attempt 2173 0 2173 0 [(2208, 1), (2176, 3)] 0, attempt 2174 0 2174 0 [(2209, 1), (2176, 3)] 0, attempt 2175 0 2175 0 [(2210, 1), (2176, 3)] 0]
def counters004 : List Nat := [2176, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2144
        counters003 chunk003 = true ∧ chunk003.length = 32 ∧
      advanceCsrCounters counters003 chunk003 = counters004 := by decide

def chunk004 : List CsrExecutableAttempt :=
  [attempt 2176 0 2176 0 [(2211, 1), (2176, 3)] 0, attempt 2177 0 2177 0 [(2212, 1), (2176, 3)] 0, attempt 2178 0 2178 0 [(2213, 1), (2176, 3)] 0, attempt 2179 0 2179 0 [(2214, 1), (2176, 3)] 0, attempt 2180 0 2180 0 [(2215, 1), (2176, 3)] 0, attempt 2181 0 2181 0 [(2216, 1), (2176, 3)] 0, attempt 2182 0 2182 0 [(2217, 1), (2176, 3)] 0, attempt 2183 0 2183 0 [(2218, 1), (2176, 3)] 0, attempt 2184 0 2184 0 [(2219, 1), (2176, 3)] 0, attempt 2185 0 2185 0 [(2220, 1), (2176, 3)] 0, attempt 2186 0 2186 0 [(2221, 1), (2176, 3)] 0, attempt 2187 0 2187 0 [(2222, 1), (2176, 3)] 0, attempt 2188 0 2188 0 [(2223, 1), (2176, 3)] 0, attempt 2189 0 2189 0 [(2224, 1), (2176, 3)] 0, attempt 2190 0 2190 0 [(2225, 1), (2176, 3)] 0, attempt 2191 0 2191 0 [(2226, 1), (2176, 3)] 0, attempt 2192 0 2192 0 [(2227, 1), (2176, 3)] 0, attempt 2193 0 2193 0 [(2228, 1), (2176, 3)] 0, attempt 2194 0 2194 0 [(2229, 1), (2176, 3)] 0, attempt 2195 0 2195 0 [(2230, 1), (2176, 3)] 0, attempt 2196 0 2196 0 [(2231, 1), (2176, 3)] 0, attempt 2197 0 2197 0 [(2232, 1), (2176, 3)] 0, attempt 2198 0 2198 0 [(2233, 1), (2176, 3)] 0, attempt 2199 0 2199 0 [(2234, 1), (2176, 3)] 0, attempt 2200 0 2200 0 [(2235, 1), (2176, 3)] 0, attempt 2201 0 2201 0 [(2236, 1), (2176, 3)] 0, attempt 2202 0 2202 0 [(2237, 1), (2176, 3)] 0, attempt 2203 0 2203 0 [(2238, 1), (2176, 3)] 0, attempt 2204 0 2204 0 [(2239, 1), (2176, 3)] 0, attempt 2205 0 2205 0 [(2241, 1), (2240, 3)] 0, attempt 2206 0 2206 0 [(2242, 1), (2240, 3)] 0, attempt 2207 0 2207 0 [(2243, 1), (2240, 3)] 0]
def counters005 : List Nat := [2208, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2176
        counters004 chunk004 = true ∧ chunk004.length = 32 ∧
      advanceCsrCounters counters004 chunk004 = counters005 := by decide

def chunk005 : List CsrExecutableAttempt :=
  [attempt 2208 0 2208 0 [(2244, 1), (2240, 3)] 0, attempt 2209 0 2209 0 [(2245, 1), (2240, 3)] 0, attempt 2210 0 2210 0 [(2246, 1), (2240, 3)] 0, attempt 2211 0 2211 0 [(2247, 1), (2240, 3)] 0, attempt 2212 0 2212 0 [(2248, 1), (2240, 3)] 0, attempt 2213 0 2213 0 [(2249, 1), (2240, 3)] 0, attempt 2214 0 2214 0 [(2250, 1), (2240, 3)] 0, attempt 2215 0 2215 0 [(2251, 1), (2240, 3)] 0, attempt 2216 0 2216 0 [(2252, 1), (2240, 3)] 0, attempt 2217 0 2217 0 [(2253, 1), (2240, 3)] 0, attempt 2218 0 2218 0 [(2254, 1), (2240, 3)] 0, attempt 2219 0 2219 0 [(2255, 1), (2240, 3)] 0, attempt 2220 0 2220 0 [(2256, 1), (2240, 3)] 0, attempt 2221 0 2221 0 [(2257, 1), (2240, 3)] 0, attempt 2222 0 2222 0 [(2258, 1), (2240, 3)] 0, attempt 2223 0 2223 0 [(2259, 1), (2240, 3)] 0, attempt 2224 0 2224 0 [(2260, 1), (2240, 3)] 0, attempt 2225 0 2225 0 [(2261, 1), (2240, 3)] 0, attempt 2226 0 2226 0 [(2262, 1), (2240, 3)] 0, attempt 2227 0 2227 0 [(2263, 1), (2240, 3)] 0, attempt 2228 0 2228 0 [(2264, 1), (2240, 3)] 0, attempt 2229 0 2229 0 [(2265, 1), (2240, 3)] 0, attempt 2230 0 2230 0 [(2266, 1), (2240, 3)] 0, attempt 2231 0 2231 0 [(2267, 1), (2240, 3)] 0, attempt 2232 0 2232 0 [(2268, 1), (2240, 3)] 0, attempt 2233 0 2233 0 [(2269, 1), (2240, 3)] 0, attempt 2234 0 2234 0 [(2270, 1), (2240, 3)] 0, attempt 2235 0 2235 0 [(2271, 1), (2240, 3)] 0, attempt 2236 0 2236 0 [(2272, 1), (2240, 3)] 0, attempt 2237 0 2237 0 [(2273, 1), (2240, 3)] 0, attempt 2238 0 2238 0 [(2274, 1), (2240, 3)] 0, attempt 2239 0 2239 0 [(2275, 1), (2240, 3)] 0]
def counters006 : List Nat := [2240, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2208
        counters005 chunk005 = true ∧ chunk005.length = 32 ∧
      advanceCsrCounters counters005 chunk005 = counters006 := by decide

def chunk006 : List CsrExecutableAttempt :=
  [attempt 2240 0 2240 0 [(2276, 1), (2240, 3)] 0, attempt 2241 0 2241 0 [(2277, 1), (2240, 3)] 0, attempt 2242 0 2242 0 [(2278, 1), (2240, 3)] 0, attempt 2243 0 2243 0 [(2279, 1), (2240, 3)] 0, attempt 2244 0 2244 0 [(2280, 1), (2240, 3)] 0, attempt 2245 0 2245 0 [(2281, 1), (2240, 3)] 0, attempt 2246 0 2246 0 [(2282, 1), (2240, 3)] 0, attempt 2247 0 2247 0 [(2283, 1), (2240, 3)] 0, attempt 2248 0 2248 0 [(2284, 1), (2240, 3)] 0, attempt 2249 0 2249 0 [(2285, 1), (2240, 3)] 0, attempt 2250 0 2250 0 [(2286, 1), (2240, 3)] 0, attempt 2251 0 2251 0 [(2287, 1), (2240, 3)] 0, attempt 2252 0 2252 0 [(2288, 1), (2240, 3)] 0, attempt 2253 0 2253 0 [(2289, 1), (2240, 3)] 0, attempt 2254 0 2254 0 [(2290, 1), (2240, 3)] 0, attempt 2255 0 2255 0 [(2291, 1), (2240, 3)] 0, attempt 2256 0 2256 0 [(2292, 1), (2240, 3)] 0, attempt 2257 0 2257 0 [(2293, 1), (2240, 3)] 0, attempt 2258 0 2258 0 [(2294, 1), (2240, 3)] 0, attempt 2259 0 2259 0 [(2295, 1), (2240, 3)] 0, attempt 2260 0 2260 0 [(2296, 1), (2240, 3)] 0, attempt 2261 0 2261 0 [(2297, 1), (2240, 3)] 0, attempt 2262 0 2262 0 [(2298, 1), (2240, 3)] 0, attempt 2263 0 2263 0 [(2299, 1), (2240, 3)] 0, attempt 2264 0 2264 0 [(2300, 1), (2240, 3)] 0, attempt 2265 0 2265 0 [(2301, 1), (2240, 3)] 0, attempt 2266 0 2266 0 [(2302, 1), (2240, 3)] 0, attempt 2267 0 2267 0 [(2303, 1), (2240, 3)] 0, attempt 2268 0 2268 0 [(2305, 1), (2304, 3)] 0, attempt 2269 0 2269 0 [(2306, 1), (2304, 3)] 0, attempt 2270 0 2270 0 [(2307, 1), (2304, 3)] 0, attempt 2271 0 2271 0 [(2308, 1), (2304, 3)] 0]
def counters007 : List Nat := [2272, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2240
        counters006 chunk006 = true ∧ chunk006.length = 32 ∧
      advanceCsrCounters counters006 chunk006 = counters007 := by decide

def chunk007 : List CsrExecutableAttempt :=
  [attempt 2272 0 2272 0 [(2309, 1), (2304, 3)] 0, attempt 2273 0 2273 0 [(2310, 1), (2304, 3)] 0, attempt 2274 0 2274 0 [(2311, 1), (2304, 3)] 0, attempt 2275 0 2275 0 [(2312, 1), (2304, 3)] 0, attempt 2276 0 2276 0 [(2313, 1), (2304, 3)] 0, attempt 2277 0 2277 0 [(2314, 1), (2304, 3)] 0, attempt 2278 0 2278 0 [(2315, 1), (2304, 3)] 0, attempt 2279 0 2279 0 [(2316, 1), (2304, 3)] 0, attempt 2280 0 2280 0 [(2317, 1), (2304, 3)] 0, attempt 2281 0 2281 0 [(2318, 1), (2304, 3)] 0, attempt 2282 0 2282 0 [(2319, 1), (2304, 3)] 0, attempt 2283 0 2283 0 [(2320, 1), (2304, 3)] 0, attempt 2284 0 2284 0 [(2321, 1), (2304, 3)] 0, attempt 2285 0 2285 0 [(2322, 1), (2304, 3)] 0, attempt 2286 0 2286 0 [(2323, 1), (2304, 3)] 0, attempt 2287 0 2287 0 [(2324, 1), (2304, 3)] 0, attempt 2288 0 2288 0 [(2325, 1), (2304, 3)] 0, attempt 2289 0 2289 0 [(2326, 1), (2304, 3)] 0, attempt 2290 0 2290 0 [(2327, 1), (2304, 3)] 0, attempt 2291 0 2291 0 [(2328, 1), (2304, 3)] 0, attempt 2292 0 2292 0 [(2329, 1), (2304, 3)] 0, attempt 2293 0 2293 0 [(2330, 1), (2304, 3)] 0, attempt 2294 0 2294 0 [(2331, 1), (2304, 3)] 0, attempt 2295 0 2295 0 [(2332, 1), (2304, 3)] 0, attempt 2296 0 2296 0 [(2333, 1), (2304, 3)] 0, attempt 2297 0 2297 0 [(2334, 1), (2304, 3)] 0, attempt 2298 0 2298 0 [(2335, 1), (2304, 3)] 0, attempt 2299 0 2299 0 [(2336, 1), (2304, 3)] 0, attempt 2300 0 2300 0 [(2337, 1), (2304, 3)] 0, attempt 2301 0 2301 0 [(2338, 1), (2304, 3)] 0, attempt 2302 0 2302 0 [(2339, 1), (2304, 3)] 0, attempt 2303 0 2303 0 [(2340, 1), (2304, 3)] 0]
def counters008 : List Nat := [2304, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2272
        counters007 chunk007 = true ∧ chunk007.length = 32 ∧
      advanceCsrCounters counters007 chunk007 = counters008 := by decide

def chunk008 : List CsrExecutableAttempt :=
  [attempt 2304 0 2304 0 [(2341, 1), (2304, 3)] 0, attempt 2305 0 2305 0 [(2342, 1), (2304, 3)] 0, attempt 2306 0 2306 0 [(2343, 1), (2304, 3)] 0, attempt 2307 0 2307 0 [(2344, 1), (2304, 3)] 0, attempt 2308 0 2308 0 [(2345, 1), (2304, 3)] 0, attempt 2309 0 2309 0 [(2346, 1), (2304, 3)] 0, attempt 2310 0 2310 0 [(2347, 1), (2304, 3)] 0, attempt 2311 0 2311 0 [(2348, 1), (2304, 3)] 0, attempt 2312 0 2312 0 [(2349, 1), (2304, 3)] 0, attempt 2313 0 2313 0 [(2350, 1), (2304, 3)] 0, attempt 2314 0 2314 0 [(2351, 1), (2304, 3)] 0, attempt 2315 0 2315 0 [(2352, 1), (2304, 3)] 0, attempt 2316 0 2316 0 [(2353, 1), (2304, 3)] 0, attempt 2317 0 2317 0 [(2354, 1), (2304, 3)] 0, attempt 2318 0 2318 0 [(2355, 1), (2304, 3)] 0, attempt 2319 0 2319 0 [(2356, 1), (2304, 3)] 0, attempt 2320 0 2320 0 [(2357, 1), (2304, 3)] 0, attempt 2321 0 2321 0 [(2358, 1), (2304, 3)] 0, attempt 2322 0 2322 0 [(2359, 1), (2304, 3)] 0, attempt 2323 0 2323 0 [(2360, 1), (2304, 3)] 0, attempt 2324 0 2324 0 [(2361, 1), (2304, 3)] 0, attempt 2325 0 2325 0 [(2362, 1), (2304, 3)] 0, attempt 2326 0 2326 0 [(2363, 1), (2304, 3)] 0, attempt 2327 0 2327 0 [(2364, 1), (2304, 3)] 0, attempt 2328 0 2328 0 [(2365, 1), (2304, 3)] 0, attempt 2329 0 2329 0 [(2366, 1), (2304, 3)] 0, attempt 2330 0 2330 0 [(2367, 1), (2304, 3)] 0, attempt 2331 0 2331 0 [(2369, 1), (2368, 3)] 0, attempt 2332 0 2332 0 [(2370, 1), (2368, 3)] 0, attempt 2333 0 2333 0 [(2371, 1), (2368, 3)] 0, attempt 2334 0 2334 0 [(2372, 1), (2368, 3)] 0, attempt 2335 0 2335 0 [(2373, 1), (2368, 3)] 0]
def counters009 : List Nat := [2336, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2304
        counters008 chunk008 = true ∧ chunk008.length = 32 ∧
      advanceCsrCounters counters008 chunk008 = counters009 := by decide

def chunk009 : List CsrExecutableAttempt :=
  [attempt 2336 0 2336 0 [(2374, 1), (2368, 3)] 0, attempt 2337 0 2337 0 [(2375, 1), (2368, 3)] 0, attempt 2338 0 2338 0 [(2376, 1), (2368, 3)] 0, attempt 2339 0 2339 0 [(2377, 1), (2368, 3)] 0, attempt 2340 0 2340 0 [(2378, 1), (2368, 3)] 0, attempt 2341 0 2341 0 [(2379, 1), (2368, 3)] 0, attempt 2342 0 2342 0 [(2380, 1), (2368, 3)] 0, attempt 2343 0 2343 0 [(2381, 1), (2368, 3)] 0, attempt 2344 0 2344 0 [(2382, 1), (2368, 3)] 0, attempt 2345 0 2345 0 [(2383, 1), (2368, 3)] 0, attempt 2346 0 2346 0 [(2384, 1), (2368, 3)] 0, attempt 2347 0 2347 0 [(2385, 1), (2368, 3)] 0, attempt 2348 0 2348 0 [(2386, 1), (2368, 3)] 0, attempt 2349 0 2349 0 [(2387, 1), (2368, 3)] 0, attempt 2350 0 2350 0 [(2388, 1), (2368, 3)] 0, attempt 2351 0 2351 0 [(2389, 1), (2368, 3)] 0, attempt 2352 0 2352 0 [(2390, 1), (2368, 3)] 0, attempt 2353 0 2353 0 [(2391, 1), (2368, 3)] 0, attempt 2354 0 2354 0 [(2392, 1), (2368, 3)] 0, attempt 2355 0 2355 0 [(2393, 1), (2368, 3)] 0, attempt 2356 0 2356 0 [(2394, 1), (2368, 3)] 0, attempt 2357 0 2357 0 [(2395, 1), (2368, 3)] 0, attempt 2358 0 2358 0 [(2396, 1), (2368, 3)] 0, attempt 2359 0 2359 0 [(2397, 1), (2368, 3)] 0, attempt 2360 0 2360 0 [(2398, 1), (2368, 3)] 0, attempt 2361 0 2361 0 [(2399, 1), (2368, 3)] 0, attempt 2362 0 2362 0 [(2400, 1), (2368, 3)] 0, attempt 2363 0 2363 0 [(2401, 1), (2368, 3)] 0, attempt 2364 0 2364 0 [(2402, 1), (2368, 3)] 0, attempt 2365 0 2365 0 [(2403, 1), (2368, 3)] 0, attempt 2366 0 2366 0 [(2404, 1), (2368, 3)] 0, attempt 2367 0 2367 0 [(2405, 1), (2368, 3)] 0]
def counters010 : List Nat := [2368, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2336
        counters009 chunk009 = true ∧ chunk009.length = 32 ∧
      advanceCsrCounters counters009 chunk009 = counters010 := by decide

def chunk010 : List CsrExecutableAttempt :=
  [attempt 2368 0 2368 0 [(2406, 1), (2368, 3)] 0, attempt 2369 0 2369 0 [(2407, 1), (2368, 3)] 0, attempt 2370 0 2370 0 [(2408, 1), (2368, 3)] 0, attempt 2371 0 2371 0 [(2409, 1), (2368, 3)] 0, attempt 2372 0 2372 0 [(2410, 1), (2368, 3)] 0, attempt 2373 0 2373 0 [(2411, 1), (2368, 3)] 0, attempt 2374 0 2374 0 [(2412, 1), (2368, 3)] 0, attempt 2375 0 2375 0 [(2413, 1), (2368, 3)] 0, attempt 2376 0 2376 0 [(2414, 1), (2368, 3)] 0, attempt 2377 0 2377 0 [(2415, 1), (2368, 3)] 0, attempt 2378 0 2378 0 [(2416, 1), (2368, 3)] 0, attempt 2379 0 2379 0 [(2417, 1), (2368, 3)] 0, attempt 2380 0 2380 0 [(2418, 1), (2368, 3)] 0, attempt 2381 0 2381 0 [(2419, 1), (2368, 3)] 0, attempt 2382 0 2382 0 [(2420, 1), (2368, 3)] 0, attempt 2383 0 2383 0 [(2421, 1), (2368, 3)] 0, attempt 2384 0 2384 0 [(2422, 1), (2368, 3)] 0, attempt 2385 0 2385 0 [(2423, 1), (2368, 3)] 0, attempt 2386 0 2386 0 [(2424, 1), (2368, 3)] 0, attempt 2387 0 2387 0 [(2425, 1), (2368, 3)] 0, attempt 2388 0 2388 0 [(2426, 1), (2368, 3)] 0, attempt 2389 0 2389 0 [(2427, 1), (2368, 3)] 0, attempt 2390 0 2390 0 [(2428, 1), (2368, 3)] 0, attempt 2391 0 2391 0 [(2429, 1), (2368, 3)] 0, attempt 2392 0 2392 0 [(2430, 1), (2368, 3)] 0, attempt 2393 0 2393 0 [(2431, 1), (2368, 3)] 0, attempt 2394 0 2394 0 [(2433, 1), (2432, 3)] 0, attempt 2395 0 2395 0 [(2434, 1), (2432, 3)] 0, attempt 2396 0 2396 0 [(2435, 1), (2432, 3)] 0, attempt 2397 0 2397 0 [(2436, 1), (2432, 3)] 0, attempt 2398 0 2398 0 [(2437, 1), (2432, 3)] 0, attempt 2399 0 2399 0 [(2438, 1), (2432, 3)] 0]
def counters011 : List Nat := [2400, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2368
        counters010 chunk010 = true ∧ chunk010.length = 32 ∧
      advanceCsrCounters counters010 chunk010 = counters011 := by decide

def chunk011 : List CsrExecutableAttempt :=
  [attempt 2400 0 2400 0 [(2439, 1), (2432, 3)] 0, attempt 2401 0 2401 0 [(2440, 1), (2432, 3)] 0, attempt 2402 0 2402 0 [(2441, 1), (2432, 3)] 0, attempt 2403 0 2403 0 [(2442, 1), (2432, 3)] 0, attempt 2404 0 2404 0 [(2443, 1), (2432, 3)] 0, attempt 2405 0 2405 0 [(2444, 1), (2432, 3)] 0, attempt 2406 0 2406 0 [(2445, 1), (2432, 3)] 0, attempt 2407 0 2407 0 [(2446, 1), (2432, 3)] 0, attempt 2408 0 2408 0 [(2447, 1), (2432, 3)] 0, attempt 2409 0 2409 0 [(2448, 1), (2432, 3)] 0, attempt 2410 0 2410 0 [(2449, 1), (2432, 3)] 0, attempt 2411 0 2411 0 [(2450, 1), (2432, 3)] 0, attempt 2412 0 2412 0 [(2451, 1), (2432, 3)] 0, attempt 2413 0 2413 0 [(2452, 1), (2432, 3)] 0, attempt 2414 0 2414 0 [(2453, 1), (2432, 3)] 0, attempt 2415 0 2415 0 [(2454, 1), (2432, 3)] 0, attempt 2416 0 2416 0 [(2455, 1), (2432, 3)] 0, attempt 2417 0 2417 0 [(2456, 1), (2432, 3)] 0, attempt 2418 0 2418 0 [(2457, 1), (2432, 3)] 0, attempt 2419 0 2419 0 [(2458, 1), (2432, 3)] 0, attempt 2420 0 2420 0 [(2459, 1), (2432, 3)] 0, attempt 2421 0 2421 0 [(2460, 1), (2432, 3)] 0, attempt 2422 0 2422 0 [(2461, 1), (2432, 3)] 0, attempt 2423 0 2423 0 [(2462, 1), (2432, 3)] 0, attempt 2424 0 2424 0 [(2463, 1), (2432, 3)] 0, attempt 2425 0 2425 0 [(2464, 1), (2432, 3)] 0, attempt 2426 0 2426 0 [(2465, 1), (2432, 3)] 0, attempt 2427 0 2427 0 [(2466, 1), (2432, 3)] 0, attempt 2428 0 2428 0 [(2467, 1), (2432, 3)] 0, attempt 2429 0 2429 0 [(2468, 1), (2432, 3)] 0, attempt 2430 0 2430 0 [(2469, 1), (2432, 3)] 0, attempt 2431 0 2431 0 [(2470, 1), (2432, 3)] 0]
def counters012 : List Nat := [2432, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2400
        counters011 chunk011 = true ∧ chunk011.length = 32 ∧
      advanceCsrCounters counters011 chunk011 = counters012 := by decide

def chunk012 : List CsrExecutableAttempt :=
  [attempt 2432 0 2432 0 [(2471, 1), (2432, 3)] 0, attempt 2433 0 2433 0 [(2472, 1), (2432, 3)] 0, attempt 2434 0 2434 0 [(2473, 1), (2432, 3)] 0, attempt 2435 0 2435 0 [(2474, 1), (2432, 3)] 0, attempt 2436 0 2436 0 [(2475, 1), (2432, 3)] 0, attempt 2437 0 2437 0 [(2476, 1), (2432, 3)] 0, attempt 2438 0 2438 0 [(2477, 1), (2432, 3)] 0, attempt 2439 0 2439 0 [(2478, 1), (2432, 3)] 0, attempt 2440 0 2440 0 [(2479, 1), (2432, 3)] 0, attempt 2441 0 2441 0 [(2480, 1), (2432, 3)] 0, attempt 2442 0 2442 0 [(2481, 1), (2432, 3)] 0, attempt 2443 0 2443 0 [(2482, 1), (2432, 3)] 0, attempt 2444 0 2444 0 [(2483, 1), (2432, 3)] 0, attempt 2445 0 2445 0 [(2484, 1), (2432, 3)] 0, attempt 2446 0 2446 0 [(2485, 1), (2432, 3)] 0, attempt 2447 0 2447 0 [(2486, 1), (2432, 3)] 0, attempt 2448 0 2448 0 [(2487, 1), (2432, 3)] 0, attempt 2449 0 2449 0 [(2488, 1), (2432, 3)] 0, attempt 2450 0 2450 0 [(2489, 1), (2432, 3)] 0, attempt 2451 0 2451 0 [(2490, 1), (2432, 3)] 0, attempt 2452 0 2452 0 [(2491, 1), (2432, 3)] 0, attempt 2453 0 2453 0 [(2492, 1), (2432, 3)] 0, attempt 2454 0 2454 0 [(2493, 1), (2432, 3)] 0, attempt 2455 0 2455 0 [(2494, 1), (2432, 3)] 0, attempt 2456 0 2456 0 [(2495, 1), (2432, 3)] 0, attempt 2457 0 2457 0 [(2497, 1), (2496, 3)] 0, attempt 2458 0 2458 0 [(2498, 1), (2496, 3)] 0, attempt 2459 0 2459 0 [(2499, 1), (2496, 3)] 0, attempt 2460 0 2460 0 [(2500, 1), (2496, 3)] 0, attempt 2461 0 2461 0 [(2501, 1), (2496, 3)] 0, attempt 2462 0 2462 0 [(2502, 1), (2496, 3)] 0, attempt 2463 0 2463 0 [(2503, 1), (2496, 3)] 0]
def counters013 : List Nat := [2464, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2432
        counters012 chunk012 = true ∧ chunk012.length = 32 ∧
      advanceCsrCounters counters012 chunk012 = counters013 := by decide

def chunk013 : List CsrExecutableAttempt :=
  [attempt 2464 0 2464 0 [(2504, 1), (2496, 3)] 0, attempt 2465 0 2465 0 [(2505, 1), (2496, 3)] 0, attempt 2466 0 2466 0 [(2506, 1), (2496, 3)] 0, attempt 2467 0 2467 0 [(2507, 1), (2496, 3)] 0, attempt 2468 0 2468 0 [(2508, 1), (2496, 3)] 0, attempt 2469 0 2469 0 [(2509, 1), (2496, 3)] 0, attempt 2470 0 2470 0 [(2510, 1), (2496, 3)] 0, attempt 2471 0 2471 0 [(2511, 1), (2496, 3)] 0, attempt 2472 0 2472 0 [(2512, 1), (2496, 3)] 0, attempt 2473 0 2473 0 [(2513, 1), (2496, 3)] 0, attempt 2474 0 2474 0 [(2514, 1), (2496, 3)] 0, attempt 2475 0 2475 0 [(2515, 1), (2496, 3)] 0, attempt 2476 0 2476 0 [(2516, 1), (2496, 3)] 0, attempt 2477 0 2477 0 [(2517, 1), (2496, 3)] 0, attempt 2478 0 2478 0 [(2518, 1), (2496, 3)] 0, attempt 2479 0 2479 0 [(2519, 1), (2496, 3)] 0, attempt 2480 0 2480 0 [(2520, 1), (2496, 3)] 0, attempt 2481 0 2481 0 [(2521, 1), (2496, 3)] 0, attempt 2482 0 2482 0 [(2522, 1), (2496, 3)] 0, attempt 2483 0 2483 0 [(2523, 1), (2496, 3)] 0, attempt 2484 0 2484 0 [(2524, 1), (2496, 3)] 0, attempt 2485 0 2485 0 [(2525, 1), (2496, 3)] 0, attempt 2486 0 2486 0 [(2526, 1), (2496, 3)] 0, attempt 2487 0 2487 0 [(2527, 1), (2496, 3)] 0, attempt 2488 0 2488 0 [(2528, 1), (2496, 3)] 0, attempt 2489 0 2489 0 [(2529, 1), (2496, 3)] 0, attempt 2490 0 2490 0 [(2530, 1), (2496, 3)] 0, attempt 2491 0 2491 0 [(2531, 1), (2496, 3)] 0, attempt 2492 0 2492 0 [(2532, 1), (2496, 3)] 0, attempt 2493 0 2493 0 [(2533, 1), (2496, 3)] 0, attempt 2494 0 2494 0 [(2534, 1), (2496, 3)] 0, attempt 2495 0 2495 0 [(2535, 1), (2496, 3)] 0]
def counters014 : List Nat := [2496, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2464
        counters013 chunk013 = true ∧ chunk013.length = 32 ∧
      advanceCsrCounters counters013 chunk013 = counters014 := by decide

def chunk014 : List CsrExecutableAttempt :=
  [attempt 2496 0 2496 0 [(2536, 1), (2496, 3)] 0, attempt 2497 0 2497 0 [(2537, 1), (2496, 3)] 0, attempt 2498 0 2498 0 [(2538, 1), (2496, 3)] 0, attempt 2499 0 2499 0 [(2539, 1), (2496, 3)] 0, attempt 2500 0 2500 0 [(2540, 1), (2496, 3)] 0, attempt 2501 0 2501 0 [(2541, 1), (2496, 3)] 0, attempt 2502 0 2502 0 [(2542, 1), (2496, 3)] 0, attempt 2503 0 2503 0 [(2543, 1), (2496, 3)] 0, attempt 2504 0 2504 0 [(2544, 1), (2496, 3)] 0, attempt 2505 0 2505 0 [(2545, 1), (2496, 3)] 0, attempt 2506 0 2506 0 [(2546, 1), (2496, 3)] 0, attempt 2507 0 2507 0 [(2547, 1), (2496, 3)] 0, attempt 2508 0 2508 0 [(2548, 1), (2496, 3)] 0, attempt 2509 0 2509 0 [(2549, 1), (2496, 3)] 0, attempt 2510 0 2510 0 [(2550, 1), (2496, 3)] 0, attempt 2511 0 2511 0 [(2551, 1), (2496, 3)] 0, attempt 2512 0 2512 0 [(2552, 1), (2496, 3)] 0, attempt 2513 0 2513 0 [(2553, 1), (2496, 3)] 0, attempt 2514 0 2514 0 [(2554, 1), (2496, 3)] 0, attempt 2515 0 2515 0 [(2555, 1), (2496, 3)] 0, attempt 2516 0 2516 0 [(2556, 1), (2496, 3)] 0, attempt 2517 0 2517 0 [(2557, 1), (2496, 3)] 0, attempt 2518 0 2518 0 [(2558, 1), (2496, 3)] 0, attempt 2519 0 2519 0 [(2559, 1), (2496, 3)] 0, attempt 2520 0 2520 0 [(2561, 1), (2560, 3)] 0, attempt 2521 0 2521 0 [(2562, 1), (2560, 3)] 0, attempt 2522 0 2522 0 [(2563, 1), (2560, 3)] 0, attempt 2523 0 2523 0 [(2564, 1), (2560, 3)] 0, attempt 2524 0 2524 0 [(2565, 1), (2560, 3)] 0, attempt 2525 0 2525 0 [(2566, 1), (2560, 3)] 0, attempt 2526 0 2526 0 [(2567, 1), (2560, 3)] 0, attempt 2527 0 2527 0 [(2568, 1), (2560, 3)] 0]
def counters015 : List Nat := [2528, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2496
        counters014 chunk014 = true ∧ chunk014.length = 32 ∧
      advanceCsrCounters counters014 chunk014 = counters015 := by decide

def chunk015 : List CsrExecutableAttempt :=
  [attempt 2528 0 2528 0 [(2569, 1), (2560, 3)] 0, attempt 2529 0 2529 0 [(2570, 1), (2560, 3)] 0, attempt 2530 0 2530 0 [(2571, 1), (2560, 3)] 0, attempt 2531 0 2531 0 [(2572, 1), (2560, 3)] 0, attempt 2532 0 2532 0 [(2573, 1), (2560, 3)] 0, attempt 2533 0 2533 0 [(2574, 1), (2560, 3)] 0, attempt 2534 0 2534 0 [(2575, 1), (2560, 3)] 0, attempt 2535 0 2535 0 [(2576, 1), (2560, 3)] 0, attempt 2536 0 2536 0 [(2577, 1), (2560, 3)] 0, attempt 2537 0 2537 0 [(2578, 1), (2560, 3)] 0, attempt 2538 0 2538 0 [(2579, 1), (2560, 3)] 0, attempt 2539 0 2539 0 [(2580, 1), (2560, 3)] 0, attempt 2540 0 2540 0 [(2581, 1), (2560, 3)] 0, attempt 2541 0 2541 0 [(2582, 1), (2560, 3)] 0, attempt 2542 0 2542 0 [(2583, 1), (2560, 3)] 0, attempt 2543 0 2543 0 [(2584, 1), (2560, 3)] 0, attempt 2544 0 2544 0 [(2585, 1), (2560, 3)] 0, attempt 2545 0 2545 0 [(2586, 1), (2560, 3)] 0, attempt 2546 0 2546 0 [(2587, 1), (2560, 3)] 0, attempt 2547 0 2547 0 [(2588, 1), (2560, 3)] 0, attempt 2548 0 2548 0 [(2589, 1), (2560, 3)] 0, attempt 2549 0 2549 0 [(2590, 1), (2560, 3)] 0, attempt 2550 0 2550 0 [(2591, 1), (2560, 3)] 0, attempt 2551 0 2551 0 [(2592, 1), (2560, 3)] 0, attempt 2552 0 2552 0 [(2593, 1), (2560, 3)] 0, attempt 2553 0 2553 0 [(2594, 1), (2560, 3)] 0, attempt 2554 0 2554 0 [(2595, 1), (2560, 3)] 0, attempt 2555 0 2555 0 [(2596, 1), (2560, 3)] 0, attempt 2556 0 2556 0 [(2597, 1), (2560, 3)] 0, attempt 2557 0 2557 0 [(2598, 1), (2560, 3)] 0, attempt 2558 0 2558 0 [(2599, 1), (2560, 3)] 0, attempt 2559 0 2559 0 [(2600, 1), (2560, 3)] 0]
def counters016 : List Nat := [2560, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2528
        counters015 chunk015 = true ∧ chunk015.length = 32 ∧
      advanceCsrCounters counters015 chunk015 = counters016 := by decide

def suffix016 : List CsrExecutableAttempt := []
theorem suffix016_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2560
      counters016 suffix016 = true := by rfl
theorem suffix016_length : suffix016.length = 0 := by rfl
theorem suffix016_state : advanceCsrCounters counters016 suffix016 = counters016 := by rfl

def suffix015 : List CsrExecutableAttempt := chunk015 ++ suffix016
theorem suffix015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2528
      counters015 suffix015 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk015 suffix016 2528 2560 counters015 counters016
    chunk015_checked.1 (congrArg (Nat.add 2528) chunk015_checked.2.1)
    chunk015_checked.2.2 suffix016_checked
theorem suffix015_length : suffix015.length = 32 := by
  rw [suffix015, List.length_append, chunk015_checked.2.1, suffix016_length]
theorem suffix015_state : advanceCsrCounters counters015 suffix015 = counters016 := by
  rw [suffix015, advanceCsrCounters_append, chunk015_checked.2.2, suffix016_state]

def suffix014 : List CsrExecutableAttempt := chunk014 ++ suffix015
theorem suffix014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2496
      counters014 suffix014 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk014 suffix015 2496 2528 counters014 counters015
    chunk014_checked.1 (congrArg (Nat.add 2496) chunk014_checked.2.1)
    chunk014_checked.2.2 suffix015_checked
theorem suffix014_length : suffix014.length = 64 := by
  rw [suffix014, List.length_append, chunk014_checked.2.1, suffix015_length]
theorem suffix014_state : advanceCsrCounters counters014 suffix014 = counters016 := by
  rw [suffix014, advanceCsrCounters_append, chunk014_checked.2.2, suffix015_state]

def suffix013 : List CsrExecutableAttempt := chunk013 ++ suffix014
theorem suffix013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2464
      counters013 suffix013 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk013 suffix014 2464 2496 counters013 counters014
    chunk013_checked.1 (congrArg (Nat.add 2464) chunk013_checked.2.1)
    chunk013_checked.2.2 suffix014_checked
theorem suffix013_length : suffix013.length = 96 := by
  rw [suffix013, List.length_append, chunk013_checked.2.1, suffix014_length]
theorem suffix013_state : advanceCsrCounters counters013 suffix013 = counters016 := by
  rw [suffix013, advanceCsrCounters_append, chunk013_checked.2.2, suffix014_state]

def suffix012 : List CsrExecutableAttempt := chunk012 ++ suffix013
theorem suffix012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2432
      counters012 suffix012 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk012 suffix013 2432 2464 counters012 counters013
    chunk012_checked.1 (congrArg (Nat.add 2432) chunk012_checked.2.1)
    chunk012_checked.2.2 suffix013_checked
theorem suffix012_length : suffix012.length = 128 := by
  rw [suffix012, List.length_append, chunk012_checked.2.1, suffix013_length]
theorem suffix012_state : advanceCsrCounters counters012 suffix012 = counters016 := by
  rw [suffix012, advanceCsrCounters_append, chunk012_checked.2.2, suffix013_state]

def suffix011 : List CsrExecutableAttempt := chunk011 ++ suffix012
theorem suffix011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2400
      counters011 suffix011 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk011 suffix012 2400 2432 counters011 counters012
    chunk011_checked.1 (congrArg (Nat.add 2400) chunk011_checked.2.1)
    chunk011_checked.2.2 suffix012_checked
theorem suffix011_length : suffix011.length = 160 := by
  rw [suffix011, List.length_append, chunk011_checked.2.1, suffix012_length]
theorem suffix011_state : advanceCsrCounters counters011 suffix011 = counters016 := by
  rw [suffix011, advanceCsrCounters_append, chunk011_checked.2.2, suffix012_state]

def suffix010 : List CsrExecutableAttempt := chunk010 ++ suffix011
theorem suffix010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2368
      counters010 suffix010 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk010 suffix011 2368 2400 counters010 counters011
    chunk010_checked.1 (congrArg (Nat.add 2368) chunk010_checked.2.1)
    chunk010_checked.2.2 suffix011_checked
theorem suffix010_length : suffix010.length = 192 := by
  rw [suffix010, List.length_append, chunk010_checked.2.1, suffix011_length]
theorem suffix010_state : advanceCsrCounters counters010 suffix010 = counters016 := by
  rw [suffix010, advanceCsrCounters_append, chunk010_checked.2.2, suffix011_state]

def suffix009 : List CsrExecutableAttempt := chunk009 ++ suffix010
theorem suffix009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2336
      counters009 suffix009 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk009 suffix010 2336 2368 counters009 counters010
    chunk009_checked.1 (congrArg (Nat.add 2336) chunk009_checked.2.1)
    chunk009_checked.2.2 suffix010_checked
theorem suffix009_length : suffix009.length = 224 := by
  rw [suffix009, List.length_append, chunk009_checked.2.1, suffix010_length]
theorem suffix009_state : advanceCsrCounters counters009 suffix009 = counters016 := by
  rw [suffix009, advanceCsrCounters_append, chunk009_checked.2.2, suffix010_state]

def suffix008 : List CsrExecutableAttempt := chunk008 ++ suffix009
theorem suffix008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2304
      counters008 suffix008 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk008 suffix009 2304 2336 counters008 counters009
    chunk008_checked.1 (congrArg (Nat.add 2304) chunk008_checked.2.1)
    chunk008_checked.2.2 suffix009_checked
theorem suffix008_length : suffix008.length = 256 := by
  rw [suffix008, List.length_append, chunk008_checked.2.1, suffix009_length]
theorem suffix008_state : advanceCsrCounters counters008 suffix008 = counters016 := by
  rw [suffix008, advanceCsrCounters_append, chunk008_checked.2.2, suffix009_state]

def suffix007 : List CsrExecutableAttempt := chunk007 ++ suffix008
theorem suffix007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2272
      counters007 suffix007 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk007 suffix008 2272 2304 counters007 counters008
    chunk007_checked.1 (congrArg (Nat.add 2272) chunk007_checked.2.1)
    chunk007_checked.2.2 suffix008_checked
theorem suffix007_length : suffix007.length = 288 := by
  rw [suffix007, List.length_append, chunk007_checked.2.1, suffix008_length]
theorem suffix007_state : advanceCsrCounters counters007 suffix007 = counters016 := by
  rw [suffix007, advanceCsrCounters_append, chunk007_checked.2.2, suffix008_state]

def suffix006 : List CsrExecutableAttempt := chunk006 ++ suffix007
theorem suffix006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2240
      counters006 suffix006 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk006 suffix007 2240 2272 counters006 counters007
    chunk006_checked.1 (congrArg (Nat.add 2240) chunk006_checked.2.1)
    chunk006_checked.2.2 suffix007_checked
theorem suffix006_length : suffix006.length = 320 := by
  rw [suffix006, List.length_append, chunk006_checked.2.1, suffix007_length]
theorem suffix006_state : advanceCsrCounters counters006 suffix006 = counters016 := by
  rw [suffix006, advanceCsrCounters_append, chunk006_checked.2.2, suffix007_state]

def suffix005 : List CsrExecutableAttempt := chunk005 ++ suffix006
theorem suffix005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2208
      counters005 suffix005 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk005 suffix006 2208 2240 counters005 counters006
    chunk005_checked.1 (congrArg (Nat.add 2208) chunk005_checked.2.1)
    chunk005_checked.2.2 suffix006_checked
theorem suffix005_length : suffix005.length = 352 := by
  rw [suffix005, List.length_append, chunk005_checked.2.1, suffix006_length]
theorem suffix005_state : advanceCsrCounters counters005 suffix005 = counters016 := by
  rw [suffix005, advanceCsrCounters_append, chunk005_checked.2.2, suffix006_state]

def suffix004 : List CsrExecutableAttempt := chunk004 ++ suffix005
theorem suffix004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2176
      counters004 suffix004 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk004 suffix005 2176 2208 counters004 counters005
    chunk004_checked.1 (congrArg (Nat.add 2176) chunk004_checked.2.1)
    chunk004_checked.2.2 suffix005_checked
theorem suffix004_length : suffix004.length = 384 := by
  rw [suffix004, List.length_append, chunk004_checked.2.1, suffix005_length]
theorem suffix004_state : advanceCsrCounters counters004 suffix004 = counters016 := by
  rw [suffix004, advanceCsrCounters_append, chunk004_checked.2.2, suffix005_state]

def suffix003 : List CsrExecutableAttempt := chunk003 ++ suffix004
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2144
      counters003 suffix003 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk003 suffix004 2144 2176 counters003 counters004
    chunk003_checked.1 (congrArg (Nat.add 2144) chunk003_checked.2.1)
    chunk003_checked.2.2 suffix004_checked
theorem suffix003_length : suffix003.length = 416 := by
  rw [suffix003, List.length_append, chunk003_checked.2.1, suffix004_length]
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters016 := by
  rw [suffix003, advanceCsrCounters_append, chunk003_checked.2.2, suffix004_state]

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2112
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 2112 2144 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 2112) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 448 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters016 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2080
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 2080 2112 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 2080) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 480 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters016 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2048
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 2048 2080 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 2048) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 512 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters016 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002, chunk003, chunk004, chunk005, chunk006, chunk007, chunk008, chunk009, chunk010, chunk011, chunk012, chunk013, chunk014, chunk015]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, suffix004, suffix005, suffix006, suffix007, suffix008, suffix009, suffix010, suffix011, suffix012, suffix013, suffix014, suffix015, suffix016, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr04
