#!/usr/bin/env python3
"""Executable source reference for CFW26 Construction 11.4.

The implementation makes the paper's internal mask-coefficient ambiguity
executable instead of silently repairing it.  It supports both source branches:

* ``construction_literal_coefficient_1`` follows Step 3 and Step 8's first
  equality; and
* ``proof_sketch_coefficient_2`` follows Step 8's second equality and the
  HVZK proof.

Both branches provide deterministic honest transcripts and a public-view
simulator.  Neither is production authority because the paper does not select
one branch, Step 9's identity-form state is ill-typed as written, and the live
Plonky3 PCS has no Section 11 output-relation API.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


GOLDILOCKS_MODULUS = 0xFFFFFFFF00000001
FIELD_BYTES = 8
FIELD_NAMES = ("A", "B", "C")
SCHEMA = "hegemon.cfw26-section11-r1cs-ior.v1"
TRANSCRIPT_VERSION = 1
CONSTRUCTION_LITERAL = "construction_literal_coefficient_1"
PROOF_SKETCH = "proof_sketch_coefficient_2"
MASK_FACTORS = {CONSTRUCTION_LITERAL: 1, PROOF_SKETCH: 2}
REFERENCE_DOMAIN = b"HEGEMON-CFW26-SECTION11-REFERENCE-v1"


class ReferenceError(ValueError):
    pass


class PaperAmbiguityError(ReferenceError):
    pass


class SuccinctLinearFormTypeError(ReferenceError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha512_frame(domain: bytes, *parts: bytes) -> bytes:
    if not isinstance(domain, bytes) or len(domain) > 0xFFFF:
        raise ReferenceError("invalid hash domain")
    digest = hashlib.sha512()
    digest.update(REFERENCE_DOMAIN)
    digest.update(len(domain).to_bytes(2, "big"))
    digest.update(domain)
    digest.update(len(parts).to_bytes(2, "big"))
    for part in parts:
        if not isinstance(part, bytes):
            raise TypeError("hash frame parts must be bytes")
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.digest()


def field(value: int) -> int:
    # ``bool`` is an ``int`` subclass in Python.  Accepting it would create a
    # second in-memory representation of 0/1 even though the wire codec has a
    # unique field-element representation.
    if type(value) is not int or not 0 <= value < GOLDILOCKS_MODULUS:
        raise ReferenceError("non-canonical Goldilocks field element")
    return value


def fadd(left: int, right: int) -> int:
    return (field(left) + field(right)) % GOLDILOCKS_MODULUS


def fsub(left: int, right: int) -> int:
    return (field(left) - field(right)) % GOLDILOCKS_MODULUS


def fmul(left: int, right: int) -> int:
    return (field(left) * field(right)) % GOLDILOCKS_MODULUS


def fneg(value: int) -> int:
    return (-field(value)) % GOLDILOCKS_MODULUS


def finv(value: int) -> int:
    value = field(value)
    if value == 0:
        raise ReferenceError("zero has no field inverse")
    return pow(value, GOLDILOCKS_MODULUS - 2, GOLDILOCKS_MODULUS)


def fsum(values: Iterable[int]) -> int:
    total = 0
    for value in values:
        total = fadd(total, value)
    return total


def fe_hex(value: int) -> str:
    return field(value).to_bytes(FIELD_BYTES, "little").hex()


def parse_fe_hex(encoded: str) -> int:
    if not isinstance(encoded, str) or len(encoded) != 2 * FIELD_BYTES:
        raise ReferenceError("field element must be 8-byte lowercase hex")
    try:
        raw = bytes.fromhex(encoded)
    except ValueError as exc:
        raise ReferenceError("invalid field hex") from exc
    if raw.hex() != encoded:
        raise ReferenceError("field hex is not canonical lowercase")
    return field(int.from_bytes(raw, "little"))


def is_power_of_two(value: int) -> bool:
    return type(value) is int and value > 0 and value & (value - 1) == 0


def bit_vectors(width: int) -> tuple[tuple[int, ...], ...]:
    if type(width) is not int or width < 0:
        raise ReferenceError("negative Boolean width")
    return tuple(tuple((index >> bit) & 1 for bit in range(width)) for index in range(1 << width))


def eq_polynomial(left: Sequence[int], right: Sequence[int]) -> int:
    """Multilinear equality polynomial on two field vectors."""

    if len(left) != len(right):
        raise ReferenceError("eq arity mismatch")
    result = 1
    for left_coordinate, right_coordinate in zip(left, right):
        left_coordinate = field(left_coordinate)
        right_coordinate = field(right_coordinate)
        factor = fadd(
            fmul(left_coordinate, right_coordinate),
            fmul(fsub(1, left_coordinate), fsub(1, right_coordinate)),
        )
        result = fmul(result, factor)
    return result


def multilinear_eval(values: Sequence[int], point: Sequence[int]) -> int:
    if len(values) != 1 << len(point):
        raise ReferenceError("multilinear table dimension mismatch")
    return fsum(
        fmul(field(value), eq_polynomial(point, bits))
        for value, bits in zip(values, bit_vectors(len(point)))
    )


def poly_eval(coefficients: Sequence[int], value: int) -> int:
    value = field(value)
    result = 0
    for coefficient in reversed(coefficients):
        result = fadd(fmul(result, value), field(coefficient))
    return result


def poly_add(left: Sequence[int], right: Sequence[int]) -> list[int]:
    length = max(len(left), len(right))
    result = [0] * length
    for index in range(length):
        result[index] = fadd(left[index] if index < len(left) else 0, right[index] if index < len(right) else 0)
    return result


def poly_mul(left: Sequence[int], right: Sequence[int]) -> list[int]:
    if not left or not right:
        return []
    result = [0] * (len(left) + len(right) - 1)
    for left_index, left_value in enumerate(left):
        for right_index, right_value in enumerate(right):
            result[left_index + right_index] = fadd(
                result[left_index + right_index], fmul(left_value, right_value)
            )
    return result


def interpolate(points: Sequence[int], values: Sequence[int]) -> tuple[int, ...]:
    if len(points) != len(values) or len(set(points)) != len(points):
        raise ReferenceError("invalid interpolation input")
    result: list[int] = [0]
    for index, (x_i, y_i) in enumerate(zip(points, values)):
        basis = [1]
        denominator = 1
        for other_index, x_j in enumerate(points):
            if other_index == index:
                continue
            basis = poly_mul(basis, [fneg(x_j), 1])
            denominator = fmul(denominator, fsub(x_i, x_j))
        scale = fmul(y_i, finv(denominator))
        result = poly_add(result, [fmul(scale, coefficient) for coefficient in basis])
    result += [0] * (len(points) - len(result))
    return tuple(result[: len(points)])


def powers(value: int, length: int) -> tuple[int, ...]:
    value = field(value)
    result = [1]
    for _ in range(1, length):
        result.append(fmul(result[-1], value))
    return tuple(result)


def dot(left: Sequence[int], right: Sequence[int]) -> int:
    if len(left) != len(right):
        raise ReferenceError("dot-product dimension mismatch")
    return fsum(fmul(a, b) for a, b in zip(left, right))


@dataclass(frozen=True)
class LinearFormMatrix:
    """A fully evaluated succinct linear form with an explicit matrix type.

    Definition 5.1 says a succinct linear form evaluates its state to a
    ``t x n`` matrix.  Retaining that matrix shape here is important: the
    printed Construction 11.4 Step 9 state is a pair ``(pow(alpha_i), z_M)``,
    not a matrix accepted by the identity form in Definition 5.2.
    """

    values: tuple[tuple[int, ...], ...]

    def __post_init__(self) -> None:
        if not self.values or not self.values[0]:
            raise SuccinctLinearFormTypeError("linear-form matrix must be nonempty")
        columns = len(self.values[0])
        if any(len(row) != columns for row in self.values):
            raise SuccinctLinearFormTypeError("ragged linear-form matrix")
        for row in self.values:
            for value in row:
                field(value)

    @property
    def rows(self) -> int:
        return len(self.values)

    @property
    def columns(self) -> int:
        return len(self.values[0])

    def apply(self, message: Sequence[int]) -> tuple[int, ...]:
        if len(message) != self.columns:
            raise SuccinctLinearFormTypeError("linear-form/message dimension mismatch")
        return tuple(dot(row, message) for row in self.values)


@dataclass(frozen=True)
class IdentityLinearForm:
    """Typed executable model of CFW26 Definition 5.2."""

    rows: int
    columns: int

    def __post_init__(self) -> None:
        if type(self.rows) is not int or type(self.columns) is not int:
            raise SuccinctLinearFormTypeError("linear-form dimensions must be integers")
        if self.rows < 1 or self.columns < 1:
            raise SuccinctLinearFormTypeError("linear-form dimensions must be positive")

    def evaluate(self, state: object) -> LinearFormMatrix:
        if not isinstance(state, LinearFormMatrix):
            raise SuccinctLinearFormTypeError(
                "Definition 5.2 identity state must already be a t-by-n matrix"
            )
        if (state.rows, state.columns) != (self.rows, self.columns):
            raise SuccinctLinearFormTypeError("identity linear-form state shape mismatch")
        return state


@dataclass(frozen=True)
class ScaledIdentityState:
    base_state: LinearFormMatrix
    scalar: int

    def __post_init__(self) -> None:
        field(self.scalar)


@dataclass(frozen=True)
class ScaledIdentityLinearForm:
    """Typed executable model of Definition 5.4 applied to ``sl_id``."""

    rows: int
    columns: int

    def evaluate(self, state: object) -> LinearFormMatrix:
        if not isinstance(state, ScaledIdentityState):
            raise SuccinctLinearFormTypeError(
                "scaled identity state must be ScaledIdentityState(base_state, scalar)"
            )
        base = IdentityLinearForm(self.rows, self.columns).evaluate(state.base_state)
        return LinearFormMatrix(
            tuple(
                tuple(fmul(state.scalar, value) for value in row)
                for row in base.values
            )
        )


IDENTITY_PREMULTIPLIED_REPAIR = "identity_premultiplied_state"
SCALED_IDENTITY_REPAIR = "scaled_identity_form"
TYPED_OUTPUT_REPAIRS = (IDENTITY_PREMULTIPLIED_REPAIR, SCALED_IDENTITY_REPAIR)


class DeterministicFieldRng:
    """SHA-512 counter sampler used only for reproducible source tests."""

    def __init__(self, seed: bytes, domain: bytes) -> None:
        if not isinstance(seed, bytes) or not seed:
            raise ReferenceError("deterministic source RNG requires a nonempty seed")
        self.seed = seed
        self.domain = domain
        self.counter = 0

    def draw(self) -> int:
        while True:
            block = sha512_frame(
                b"source-rng",
                self.domain,
                self.seed,
                self.counter.to_bytes(8, "big"),
            )
            self.counter += 1
            candidate = int.from_bytes(block[:8], "little")
            if candidate < GOLDILOCKS_MODULUS:
                return candidate

    def draw_non_boolean(self) -> int:
        while True:
            value = self.draw()
            if value not in (0, 1):
                return value

    def vector(self, length: int) -> tuple[int, ...]:
        if length < 0:
            raise ReferenceError("negative random-vector length")
        return tuple(self.draw() for _ in range(length))


@dataclass(frozen=True)
class RSZKEncodingSpec:
    name: str
    message_length: int
    t_queries: int
    block_length: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.name, str)
            or not self.name
            or type(self.message_length) is not int
            or type(self.t_queries) is not int
            or type(self.block_length) is not int
            or self.message_length < 1
            or self.t_queries < 1
        ):
            raise ReferenceError("invalid RS ZK encoding dimensions")
        if self.block_length < self.message_length + self.t_queries:
            raise ReferenceError("RS block is shorter than polynomial dimension")
        if self.block_length >= GOLDILOCKS_MODULUS:
            raise ReferenceError("RS evaluation domain exceeds the field")

    @property
    def randomness_length(self) -> int:
        return self.t_queries

    @property
    def evaluation_points(self) -> tuple[int, ...]:
        return tuple(range(1, self.block_length + 1))

    @property
    def digest(self) -> str:
        return sha512_frame(b"rs-zk-spec", canonical_json(self.to_dict())).hex()

    def to_dict(self) -> dict[str, Any]:
        return {
            "alphabet_width": 1,
            "block_length": self.block_length,
            "message_length": self.message_length,
            "name": self.name,
            "randomness_length": self.randomness_length,
            "t_queries": self.t_queries,
        }

    def encode(self, message: Sequence[int], randomness: Sequence[int]) -> tuple[int, ...]:
        if len(message) != self.message_length or len(randomness) != self.randomness_length:
            raise ReferenceError("RS ZK encoding input dimension mismatch")
        # Proposition 3.19 instantiation: t random low coefficients followed
        # by the message coefficients.  Any t distinct evaluations are uniform.
        coefficients = tuple(field(value) for value in randomness) + tuple(field(value) for value in message)
        return tuple(poly_eval(coefficients, point) for point in self.evaluation_points)

    def simulate_queries(
        self, query_indexes: Sequence[int], rng: DeterministicFieldRng
    ) -> tuple[int, ...]:
        if len(query_indexes) > self.t_queries or len(set(query_indexes)) != len(query_indexes):
            raise ReferenceError("query plan exceeds the RS perfect-ZK bound")
        if any(index < 0 or index >= self.block_length for index in query_indexes):
            raise ReferenceError("RS query index out of range")
        return rng.vector(len(query_indexes))


@dataclass(frozen=True)
class ReferenceProfile:
    inner_message_length: int = 4
    outer_message_length: int = 8
    t_queries: int = 1

    def __post_init__(self) -> None:
        if any(
            type(value) is not int
            for value in (
                self.inner_message_length,
                self.outer_message_length,
                self.t_queries,
            )
        ):
            raise ReferenceError("reference profile dimensions must be integers")
        if self.inner_message_length < 4:
            raise ReferenceError("CFW26 Theorem 11.3 requires inner length at least four")
        if self.outer_message_length < 2 * self.inner_message_length:
            raise ReferenceError("CFW26 Theorem 11.3 requires outer length >= 2*inner length")
        if self.t_queries < 1:
            raise ReferenceError("reference requires a positive query bound")

    @property
    def digest(self) -> str:
        return sha512_frame(b"reference-profile", canonical_json(self.to_dict())).hex()

    def to_dict(self) -> dict[str, Any]:
        return {
            "field_modulus": GOLDILOCKS_MODULUS,
            "inner_message_length": self.inner_message_length,
            "outer_message_length": self.outer_message_length,
            "t_queries": self.t_queries,
        }

    def specs(self, ell: int) -> dict[str, RSZKEncodingSpec]:
        if not is_power_of_two(ell):
            raise ReferenceError("R1CS witness length must be a power of two")
        return {
            "main": RSZKEncodingSpec("main", ell, self.t_queries, 2 * (ell + self.t_queries)),
            "inner": RSZKEncodingSpec(
                "inner",
                self.inner_message_length,
                self.t_queries,
                2 * (self.inner_message_length + self.t_queries),
            ),
            "outer": RSZKEncodingSpec(
                "outer",
                self.outer_message_length,
                self.t_queries,
                2 * (self.outer_message_length + self.t_queries),
            ),
        }


@dataclass(frozen=True)
class GeneralR1CSGeometry:
    """Source-R1CS counts before the restrictive Section 11 carrier shape."""

    constraints: int
    nonconstant_variables: int
    public_variables: int
    matrix_nonzeros: int

    def __post_init__(self) -> None:
        if any(
            type(value) is not int
            for value in (
                self.constraints,
                self.nonconstant_variables,
                self.public_variables,
                self.matrix_nonzeros,
            )
        ):
            raise ReferenceError("general R1CS geometry must use exact integers")
        if self.constraints < 1 or self.nonconstant_variables < 1 or self.matrix_nonzeros < 1:
            raise ReferenceError("general R1CS geometry must be positive")
        if not 0 <= self.public_variables <= self.nonconstant_variables:
            raise ReferenceError("public-variable geometry is inconsistent")

    @property
    def witness_variables(self) -> int:
        return self.nonconstant_variables - self.public_variables


def section11_padding_projection(geometry: GeneralR1CSGeometry) -> dict[str, int | bool]:
    """Compute a candidate square/power-of-two padding ledger only.

    Definition 11.2 fixes both the matrix side and constraint count to
    ``ell+n0``. Theorem 11.3 additionally assumes ``ell=n0`` and ``ell`` a
    power of two. A general compiler output with unequal constraint, public,
    and witness counts therefore is not a theorem input. This function only
    projects the minimum arithmetic shape for a possible embedding:

    * the public half contains the standard R1CS constant, public values, and
      parser-fixed zero padding;
    * the witness half contains private/auxiliary values and existential zero
      padding; and
    * zero constraints for witness padding are followed by zero rows.

    It does not construct matrices or prove parser/refinement equivalence.
    """

    if not isinstance(geometry, GeneralR1CSGeometry):
        raise ReferenceError("Section 11 projection requires typed source geometry")
    public_used = geometry.public_variables + 1
    witness_used = geometry.witness_variables
    half_floor = max(public_used, witness_used, (geometry.constraints + 1) // 2)
    ell = 1 << (half_floor - 1).bit_length()
    log_ell = ell.bit_length() - 1
    carrier_rows = 2 * ell
    public_padding = ell - public_used
    witness_padding = ell - witness_used
    remaining_zero_rows = carrier_rows - geometry.constraints - witness_padding
    if remaining_zero_rows < 0:
        raise AssertionError("Section 11 projection row capacity failed")
    return {
        "authoritative_carrier": False,
        "ell": ell,
        "n0": ell,
        "carrier_matrix_side": carrier_rows,
        "carrier_nonconstant_variables": carrier_rows - 1,
        "source_constraints": geometry.constraints,
        "source_nonconstant_variables": geometry.nonconstant_variables,
        "source_public_variables": geometry.public_variables,
        "source_witness_variables": witness_used,
        "source_matrix_nonzeros": geometry.matrix_nonzeros,
        "candidate_embedded_matrix_nonzeros": geometry.matrix_nonzeros + 2 * witness_padding,
        "public_zero_padding_elements": public_padding,
        "witness_zero_padding_elements_and_rows": witness_padding,
        "remaining_zero_rows": remaining_zero_rows,
        "section11_hvzk_oracle_hybrid_count": 4 * log_ell + 5,
        "section11_main_message_elements": ell,
        "section11_sumcheck_variables": log_ell + 1,
        "whir_codeword_elements_defined": False,
        "matrix_embedding_constructed": False,
        "parser_padding_binding_proved": False,
        "semantic_refinement_proved": False,
    }


REPORTED_HEGEMON_MIXED_SOURCE_GEOMETRY = GeneralR1CSGeometry(
    constraints=20_457_227,
    nonconstant_variables=19_311_555,
    public_variables=10_152,
    matrix_nonzeros=94_551_238,
)


@dataclass(frozen=True)
class R1CSInstance:
    n0: int
    ell: int
    A: tuple[tuple[int, ...], ...]
    B: tuple[tuple[int, ...], ...]
    C: tuple[tuple[int, ...], ...]
    public_input: tuple[int, ...]
    compiler_binding_digest: str

    def __post_init__(self) -> None:
        if type(self.n0) is not int or type(self.ell) is not int:
            raise ReferenceError("R1CS dimensions must be integers")
        if self.n0 != self.ell or not is_power_of_two(self.ell):
            raise ReferenceError("Section 11 requires n0=ell and ell a power of two")
        size = self.n0 + self.ell
        if len(self.public_input) != self.n0:
            raise ReferenceError("public input dimension mismatch")
        for value in self.public_input:
            field(value)
        for name, matrix in (("A", self.A), ("B", self.B), ("C", self.C)):
            if len(matrix) != size or any(len(row) != size for row in matrix):
                raise ReferenceError(f"{name} matrix dimension mismatch")
            for row in matrix:
                for value in row:
                    field(value)
        try:
            _require_digest(self.compiler_binding_digest)
        except ReferenceError as exc:
            raise ReferenceError(
                "compiler binding must be canonical full SHA-512/SHAKE256-512 hex"
            ) from exc

    @property
    def size(self) -> int:
        return self.n0 + self.ell

    @property
    def log_ell(self) -> int:
        return self.ell.bit_length() - 1

    @property
    def sumcheck_variables(self) -> int:
        return self.log_ell + 1

    def to_dict(self) -> dict[str, Any]:
        encode_matrix = lambda matrix: [[fe_hex(value) for value in row] for row in matrix]
        return {
            "A": encode_matrix(self.A),
            "B": encode_matrix(self.B),
            "C": encode_matrix(self.C),
            "compiler_binding_digest": self.compiler_binding_digest,
            "ell": self.ell,
            "field_modulus": GOLDILOCKS_MODULUS,
            "index_bijection": "little_endian_bits_last_partition_bit_high",
            "n0": self.n0,
            "public_input": [fe_hex(value) for value in self.public_input],
        }

    @property
    def digest(self) -> str:
        return sha512_frame(b"r1cs-instance", canonical_json(self.to_dict())).hex()

    def matrix_vector(self, matrix: Sequence[Sequence[int]], vector: Sequence[int]) -> tuple[int, ...]:
        if len(vector) != self.size:
            raise ReferenceError("R1CS vector dimension mismatch")
        return tuple(dot(row, vector) for row in matrix)

    def is_satisfied(self, witness: Sequence[int]) -> bool:
        if len(witness) != self.ell:
            return False
        try:
            z = self.public_input + tuple(field(value) for value in witness)
        except ReferenceError:
            return False
        az = self.matrix_vector(self.A, z)
        bz = self.matrix_vector(self.B, z)
        cz = self.matrix_vector(self.C, z)
        return all(fmul(a, b) == c for a, b, c in zip(az, bz, cz))


def toy_instance(binding_digest: str) -> tuple[R1CSInstance, tuple[int, ...]]:
    ell = 4
    size = 8
    public = (1, 2, 3, 4)
    witness = (5, 6, 30, 11)
    matrices = {name: [[0 for _ in range(size)] for _ in range(size)] for name in FIELD_NAMES}
    # Four identity constraints on public inputs.
    for row in range(4):
        matrices["A"][row][row] = 1
        matrices["B"][row][0] = 1
        matrices["C"][row][row] = 1
    # w0*w1=w2; w2*1=w2; w3*1=w3; (w0+w1)*1=w3.
    matrices["A"][4][4] = 1
    matrices["B"][4][5] = 1
    matrices["C"][4][6] = 1
    matrices["A"][5][6] = 1
    matrices["B"][5][0] = 1
    matrices["C"][5][6] = 1
    matrices["A"][6][7] = 1
    matrices["B"][6][0] = 1
    matrices["C"][6][7] = 1
    matrices["A"][7][4] = 1
    matrices["A"][7][5] = 1
    matrices["B"][7][0] = 1
    matrices["C"][7][7] = 1
    instance = R1CSInstance(
        n0=ell,
        ell=ell,
        A=tuple(tuple(row) for row in matrices["A"]),
        B=tuple(tuple(row) for row in matrices["B"]),
        C=tuple(tuple(row) for row in matrices["C"]),
        public_input=public,
        compiler_binding_digest=binding_digest,
    )
    if not instance.is_satisfied(witness):
        raise AssertionError("toy R1CS fixture is not satisfied")
    return instance, witness


@dataclass(frozen=True)
class EncodedOracle:
    name: str
    spec_digest: str
    values: tuple[int, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "spec_digest": self.spec_digest,
            "values": [fe_hex(value) for value in self.values],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EncodedOracle":
        value = _require_mapping(value)
        _expect_keys(value, {"name", "spec_digest", "values"})
        return cls(
            name=_require_string(value["name"]),
            spec_digest=_require_digest(value["spec_digest"]),
            values=tuple(parse_fe_hex(item) for item in _require_list(value["values"])),
        )


@dataclass(frozen=True)
class SumcheckRound:
    coefficients: tuple[int, ...]
    alpha: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "alpha": fe_hex(self.alpha),
            "coefficients": [fe_hex(value) for value in self.coefficients],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SumcheckRound":
        value = _require_mapping(value)
        _expect_keys(value, {"alpha", "coefficients"})
        return cls(
            coefficients=tuple(parse_fe_hex(item) for item in _require_list(value["coefficients"])),
            alpha=parse_fe_hex(value["alpha"]),
        )


@dataclass(frozen=True)
class Transcript:
    convention: str
    instance_digest: str
    compiler_binding_digest: str
    profile_digest: str
    inner_oracles: tuple[EncodedOracle, ...]
    witness_oracle: EncodedOracle
    outer_oracles: tuple[EncodedOracle, ...]
    mu_tilde: int
    epsilon: int
    r: tuple[int, ...]
    rounds: tuple[SumcheckRound, ...]
    outer_evaluations: tuple[int, ...]
    v_values: tuple[int, int, int]
    u_values: tuple[int, int, int]
    rho: int
    joint_mu: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "compiler_binding_digest": self.compiler_binding_digest,
            "convention": self.convention,
            "epsilon": fe_hex(self.epsilon),
            "inner_oracles": [oracle.to_dict() for oracle in self.inner_oracles],
            "instance_digest": self.instance_digest,
            "joint_mu": fe_hex(self.joint_mu),
            "mu_tilde": fe_hex(self.mu_tilde),
            "outer_evaluations": [fe_hex(value) for value in self.outer_evaluations],
            "outer_oracles": [oracle.to_dict() for oracle in self.outer_oracles],
            "profile_digest": self.profile_digest,
            "r": [fe_hex(value) for value in self.r],
            "rho": fe_hex(self.rho),
            "rounds": [round_message.to_dict() for round_message in self.rounds],
            "schema": SCHEMA,
            "u_values": [fe_hex(value) for value in self.u_values],
            "v_values": [fe_hex(value) for value in self.v_values],
            "version": TRANSCRIPT_VERSION,
            "witness_oracle": self.witness_oracle.to_dict(),
        }

    def to_bytes(self) -> bytes:
        return canonical_json(self.to_dict())

    @classmethod
    def from_bytes(cls, encoded: bytes) -> "Transcript":
        if type(encoded) is not bytes:
            raise ReferenceError("transcript input must be immutable bytes")
        try:
            value = json.loads(encoded)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ReferenceError("invalid transcript JSON") from exc
        if not isinstance(value, dict) or canonical_json(value) != encoded:
            raise ReferenceError("transcript is not canonical JSON")
        _expect_keys(
            value,
            {
                "compiler_binding_digest",
                "convention",
                "epsilon",
                "inner_oracles",
                "instance_digest",
                "joint_mu",
                "mu_tilde",
                "outer_evaluations",
                "outer_oracles",
                "profile_digest",
                "r",
                "rho",
                "rounds",
                "schema",
                "u_values",
                "v_values",
                "version",
                "witness_oracle",
            },
        )
        if (
            type(value["schema"]) is not str
            or value["schema"] != SCHEMA
            or type(value["version"]) is not int
            or value["version"] != TRANSCRIPT_VERSION
        ):
            raise ReferenceError("transcript schema/version mismatch")
        convention = _require_string(value["convention"])
        if convention not in MASK_FACTORS:
            raise ReferenceError("unknown paper convention")
        v_values = tuple(parse_fe_hex(item) for item in _require_list(value["v_values"]))
        u_values = tuple(parse_fe_hex(item) for item in _require_list(value["u_values"]))
        if len(v_values) != 3 or len(u_values) != 3:
            raise ReferenceError("A/B/C value dimension mismatch")
        return cls(
            convention=convention,
            instance_digest=_require_digest(value["instance_digest"]),
            compiler_binding_digest=_require_digest(value["compiler_binding_digest"]),
            profile_digest=_require_digest(value["profile_digest"]),
            inner_oracles=tuple(EncodedOracle.from_dict(item) for item in _require_list(value["inner_oracles"])),
            witness_oracle=EncodedOracle.from_dict(_require_mapping(value["witness_oracle"])),
            outer_oracles=tuple(EncodedOracle.from_dict(item) for item in _require_list(value["outer_oracles"])),
            mu_tilde=parse_fe_hex(value["mu_tilde"]),
            epsilon=parse_fe_hex(value["epsilon"]),
            r=tuple(parse_fe_hex(item) for item in _require_list(value["r"])),
            rounds=tuple(SumcheckRound.from_dict(item) for item in _require_list(value["rounds"])),
            outer_evaluations=tuple(parse_fe_hex(item) for item in _require_list(value["outer_evaluations"])),
            v_values=v_values,  # type: ignore[arg-type]
            u_values=u_values,  # type: ignore[arg-type]
            rho=parse_fe_hex(value["rho"]),
            joint_mu=parse_fe_hex(value["joint_mu"]),
        )


@dataclass(frozen=True)
class OutputWitness:
    witness_message: tuple[int, ...]
    witness_randomness: tuple[int, ...]
    inner_messages: tuple[tuple[int, ...], ...]
    inner_randomness: tuple[tuple[int, ...], ...]
    outer_messages: tuple[tuple[int, ...], ...]
    outer_randomness: tuple[tuple[int, ...], ...]


@dataclass(frozen=True)
class HonestRun:
    transcript: Transcript
    output_witness: OutputWitness


@dataclass(frozen=True)
class HonestProver:
    instance: R1CSInstance
    profile: ReferenceProfile
    seed: bytes
    convention: str

    def prove(self, witness: Sequence[int]) -> HonestRun:
        return honest_prove(
            self.instance,
            witness,
            self.profile,
            seed=self.seed,
            convention=self.convention,
        )


@dataclass(frozen=True)
class HonestVerifier:
    instance: R1CSInstance
    profile: ReferenceProfile

    def reduce(self, transcript: Transcript) -> None:
        verify_direct(self.instance, self.profile, transcript)

    def verify_derived_output(self, transcript: Transcript, witness: OutputWitness) -> None:
        verify_derived_output_relation(self.instance, self.profile, transcript, witness)

    def verify_paper_output(self, transcript: Transcript, witness: OutputWitness) -> None:
        verify_paper_literal_output_relation(self.instance, self.profile, transcript, witness)


def _require_string(value: Any) -> str:
    if not isinstance(value, str):
        raise ReferenceError("expected string")
    return value


def _require_digest(value: Any) -> str:
    value = _require_string(value)
    if len(value) != 128:
        raise ReferenceError("expected full 64-byte digest hex")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ReferenceError("digest is not hex") from exc
    if raw.hex() != value:
        raise ReferenceError("digest hex is not canonical lowercase")
    return value


def _require_list(value: Any) -> list[Any]:
    if not isinstance(value, list):
        raise ReferenceError("expected list")
    return value


def _require_mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ReferenceError("expected object")
    return value


def _expect_keys(value: Mapping[str, Any], expected: set[str]) -> None:
    if set(value) != expected:
        raise ReferenceError("object key set mismatch")


def matrix_vectors(instance: R1CSInstance, witness: Sequence[int]) -> dict[str, tuple[int, ...]]:
    z = instance.public_input + tuple(field(value) for value in witness)
    return {
        "A": instance.matrix_vector(instance.A, z),
        "B": instance.matrix_vector(instance.B, z),
        "C": instance.matrix_vector(instance.C, z),
    }


def public_matrix_vectors(instance: R1CSInstance) -> dict[str, tuple[int, ...]]:
    z = instance.public_input + (0,) * instance.ell
    return {
        "A": instance.matrix_vector(instance.A, z),
        "B": instance.matrix_vector(instance.B, z),
        "C": instance.matrix_vector(instance.C, z),
    }


def zero_evader(rho: int) -> tuple[int, int, int]:
    rho = field(rho)
    return (1, rho, fmul(rho, rho))


def sample_inner_mask(length: int, rng: DeterministicFieldRng) -> tuple[int, ...]:
    if length < 4:
        raise ReferenceError("inner mask dimension must be at least four")
    middle = list(rng.vector(length - 2))
    coefficients = [0] + middle + [fneg(fsum(middle))]
    if poly_eval(coefficients, 0) != 0 or poly_eval(coefficients, 1) != 0:
        raise AssertionError("inner mask conditioning failed")
    return tuple(coefficients)


def constraint_factor(
    row_values: Sequence[int], point: Sequence[int], masks: Sequence[Sequence[int]], factor: int
) -> int:
    if len(point) != len(masks):
        raise ReferenceError("constraint mask arity mismatch")
    mask_value = fsum(poly_eval(mask, coordinate) for mask, coordinate in zip(masks, point))
    return fadd(multilinear_eval(row_values, point), fmul(factor, mask_value))


def constraint_polynomial(
    rows: Mapping[str, Sequence[int]],
    point: Sequence[int],
    inner_masks: Mapping[str, Sequence[Sequence[int]]],
    factor: int,
) -> int:
    values = {
        name: constraint_factor(rows[name], point, inner_masks[name], factor)
        for name in FIELD_NAMES
    }
    return fsub(fmul(values["A"], values["B"]), values["C"])


def honest_prove(
    instance: R1CSInstance,
    witness: Sequence[int],
    profile: ReferenceProfile,
    *,
    seed: bytes,
    convention: str,
) -> HonestRun:
    if convention not in MASK_FACTORS:
        raise ReferenceError("unknown mask convention")
    if not instance.is_satisfied(witness):
        raise ReferenceError("honest prover requires a satisfying R1CS witness")
    factor = MASK_FACTORS[convention]
    d = instance.sumcheck_variables
    specs = profile.specs(instance.ell)
    prover_rng = DeterministicFieldRng(seed, b"honest-prover")
    verifier_rng = DeterministicFieldRng(seed, b"honest-verifier")

    inner_messages: dict[str, list[tuple[int, ...]]] = {name: [] for name in FIELD_NAMES}
    inner_randomness: list[tuple[int, ...]] = []
    inner_oracles: list[EncodedOracle] = []
    for name in FIELD_NAMES:
        for round_index in range(d):
            message = sample_inner_mask(profile.inner_message_length, prover_rng)
            randomness = prover_rng.vector(specs["inner"].randomness_length)
            inner_messages[name].append(message)
            inner_randomness.append(randomness)
            inner_oracles.append(
                EncodedOracle(
                    name=f"inner/{name}/{round_index}",
                    spec_digest=specs["inner"].digest,
                    values=specs["inner"].encode(message, randomness),
                )
            )

    witness_message = tuple(field(value) for value in witness)
    witness_randomness = prover_rng.vector(specs["main"].randomness_length)
    witness_oracle = EncodedOracle(
        name="witness",
        spec_digest=specs["main"].digest,
        values=specs["main"].encode(witness_message, witness_randomness),
    )

    outer_messages = tuple(prover_rng.vector(profile.outer_message_length) for _ in range(d))
    outer_randomness = tuple(
        prover_rng.vector(specs["outer"].randomness_length) for _ in range(d)
    )
    outer_oracles = tuple(
        EncodedOracle(
            name=f"outer/{index}",
            spec_digest=specs["outer"].digest,
            values=specs["outer"].encode(message, randomness),
        )
        for index, (message, randomness) in enumerate(zip(outer_messages, outer_randomness))
    )
    mu_tilde = fsum(
        fsum(poly_eval(mask, bits[index]) for index, mask in enumerate(outer_messages))
        for bits in bit_vectors(d)
    )

    epsilon = verifier_rng.draw()
    r = verifier_rng.vector(d)
    rows = matrix_vectors(instance, witness)
    immutable_inner = {name: tuple(inner_messages[name]) for name in FIELD_NAMES}

    def integrand(point: Sequence[int]) -> int:
        g_value = constraint_polynomial(rows, point, immutable_inner, factor)
        outer_value = fsum(poly_eval(mask, coordinate) for mask, coordinate in zip(outer_messages, point))
        return fadd(fmul(fmul(epsilon, g_value), eq_polynomial(r, point)), outer_value)

    rounds: list[SumcheckRound] = []
    prefix: list[int] = []
    previous_claim = mu_tilde
    interpolation_points = tuple(range(profile.outer_message_length))
    for round_index in range(d):
        tail_width = d - round_index - 1

        def round_eval(value: int) -> int:
            return fsum(
                integrand(tuple(prefix) + (value,) + tail)
                for tail in bit_vectors(tail_width)
            )

        samples = tuple(round_eval(point) for point in interpolation_points)
        coefficients = interpolate(interpolation_points, samples)
        # The theorem's degree condition must hold, rather than being assumed
        # from interpolation at exactly l_out points.
        extra_point = profile.outer_message_length
        if poly_eval(coefficients, extra_point) != round_eval(extra_point):
            raise ReferenceError("sumcheck degree exceeds outer mask dimension")
        if fadd(poly_eval(coefficients, 0), poly_eval(coefficients, 1)) != previous_claim:
            raise AssertionError("honest sumcheck recurrence failed")
        alpha = verifier_rng.draw_non_boolean() if round_index == d - 1 else verifier_rng.draw()
        rounds.append(SumcheckRound(coefficients, alpha))
        prefix.append(alpha)
        previous_claim = poly_eval(coefficients, alpha)

    alpha = tuple(prefix)
    outer_evaluations = tuple(
        poly_eval(mask, coordinate) for mask, coordinate in zip(outer_messages, alpha)
    )
    v_values = tuple(
        constraint_factor(rows[name], alpha, immutable_inner[name], factor)
        for name in FIELD_NAMES
    )
    final_left = fadd(
        fmul(fmul(epsilon, fsub(fmul(v_values[0], v_values[1]), v_values[2])), eq_polynomial(r, alpha)),
        fsum(outer_evaluations),
    )
    if final_left != previous_claim:
        raise AssertionError("honest final sumcheck check failed")

    public_rows = public_matrix_vectors(instance)
    u_values = tuple(multilinear_eval(public_rows[name], alpha) for name in FIELD_NAMES)
    rho = verifier_rng.draw()
    ze = zero_evader(rho)
    joint_mu = fsum(
        fmul(coefficient, fsub(v_value, u_value))
        for coefficient, v_value, u_value in zip(ze, v_values, u_values)
    )
    transcript = Transcript(
        convention=convention,
        instance_digest=instance.digest,
        compiler_binding_digest=instance.compiler_binding_digest,
        profile_digest=profile.digest,
        inner_oracles=tuple(inner_oracles),
        witness_oracle=witness_oracle,
        outer_oracles=outer_oracles,
        mu_tilde=mu_tilde,
        epsilon=epsilon,
        r=r,
        rounds=tuple(rounds),
        outer_evaluations=outer_evaluations,
        v_values=v_values,  # type: ignore[arg-type]
        u_values=u_values,  # type: ignore[arg-type]
        rho=rho,
        joint_mu=joint_mu,
    )
    output_witness = OutputWitness(
        witness_message=witness_message,
        witness_randomness=witness_randomness,
        inner_messages=tuple(
            message for name in FIELD_NAMES for message in immutable_inner[name]
        ),
        inner_randomness=tuple(inner_randomness),
        outer_messages=outer_messages,
        outer_randomness=outer_randomness,
    )
    verify_direct(instance, profile, transcript)
    verify_derived_output_relation(instance, profile, transcript, output_witness)
    return HonestRun(transcript, output_witness)


def _check_oracle(oracle: EncodedOracle, expected_name: str, spec: RSZKEncodingSpec) -> None:
    if oracle.name != expected_name or oracle.spec_digest != spec.digest:
        raise ReferenceError("oracle name/spec binding mismatch")
    if len(oracle.values) != spec.block_length:
        raise ReferenceError("oracle block length mismatch")
    for value in oracle.values:
        field(value)


def verify_direct(instance: R1CSInstance, profile: ReferenceProfile, transcript: Transcript) -> None:
    if transcript.convention not in MASK_FACTORS:
        raise ReferenceError("unknown transcript convention")
    if transcript.instance_digest != instance.digest:
        raise ReferenceError("R1CS statement digest mismatch")
    if transcript.compiler_binding_digest != instance.compiler_binding_digest:
        raise ReferenceError("compiler artifact binding mismatch")
    if transcript.profile_digest != profile.digest:
        raise ReferenceError("reference profile mismatch")
    d = instance.sumcheck_variables
    specs = profile.specs(instance.ell)
    if len(transcript.inner_oracles) != 3 * d or len(transcript.outer_oracles) != d:
        raise ReferenceError("oracle count mismatch")
    for index, oracle in enumerate(transcript.inner_oracles):
        name = FIELD_NAMES[index // d]
        round_index = index % d
        _check_oracle(oracle, f"inner/{name}/{round_index}", specs["inner"])
    _check_oracle(transcript.witness_oracle, "witness", specs["main"])
    for index, oracle in enumerate(transcript.outer_oracles):
        _check_oracle(oracle, f"outer/{index}", specs["outer"])
    if len(transcript.r) != d or len(transcript.rounds) != d:
        raise ReferenceError("sumcheck dimension mismatch")
    if len(transcript.outer_evaluations) != d:
        raise ReferenceError("outer evaluation count mismatch")
    previous_claim = field(transcript.mu_tilde)
    alpha: list[int] = []
    for index, round_message in enumerate(transcript.rounds):
        if len(round_message.coefficients) != profile.outer_message_length:
            raise ReferenceError("sumcheck polynomial width mismatch")
        if fadd(poly_eval(round_message.coefficients, 0), poly_eval(round_message.coefficients, 1)) != previous_claim:
            raise ReferenceError("sumcheck recurrence rejected")
        if index == d - 1 and round_message.alpha in (0, 1):
            raise ReferenceError("last sumcheck challenge must exclude 0 and 1")
        previous_claim = poly_eval(round_message.coefficients, round_message.alpha)
        alpha.append(round_message.alpha)
    final_left = fadd(
        fmul(
            fmul(
                transcript.epsilon,
                fsub(fmul(transcript.v_values[0], transcript.v_values[1]), transcript.v_values[2]),
            ),
            eq_polynomial(transcript.r, alpha),
        ),
        fsum(transcript.outer_evaluations),
    )
    if final_left != previous_claim:
        raise ReferenceError("sumcheck final check rejected")
    public_rows = public_matrix_vectors(instance)
    expected_u = tuple(multilinear_eval(public_rows[name], alpha) for name in FIELD_NAMES)
    if transcript.u_values != expected_u:
        raise ReferenceError("public matrix/input contribution mismatch")
    ze = zero_evader(transcript.rho)
    expected_mu = fsum(
        fmul(coefficient, fsub(v_value, u_value))
        for coefficient, v_value, u_value in zip(ze, transcript.v_values, transcript.u_values)
    )
    if transcript.joint_mu != expected_mu:
        raise ReferenceError("joint target mismatch")


def paper_printed_inner_state(
    alpha_coordinate: int, ze_coordinate: int, message_length: int
) -> tuple[tuple[int, ...], int]:
    """Return the Step 9 state exactly as printed, without repairing its type."""

    if type(message_length) is not int or message_length < 1:
        raise ReferenceError("invalid printed-state message length")
    return (powers(alpha_coordinate, message_length), field(ze_coordinate))


def evaluate_paper_printed_inner_state(
    message: Sequence[int], alpha_coordinate: int, ze_coordinate: int
) -> int:
    """Demonstrate the printed ``sl_id``/state type failure.

    Construction 11.4 Step 9 declares ``sl_in = sl_id`` but supplies the
    pair ``(pow(alpha_i), ze(rho)_M)`` as its state.  Definition 5.2 requires
    the identity state itself to be the complete ``t x n`` matrix.  This
    function intentionally rejects the printed pair rather than implicitly
    interpreting it as Definition 5.4's scalar-multiplied identity form.
    """

    form = IdentityLinearForm(1, len(message))
    printed_state = paper_printed_inner_state(
        alpha_coordinate, ze_coordinate, len(message)
    )
    matrix = form.evaluate(printed_state)
    return matrix.apply(message)[0]


def evaluate_paper_printed_main_state(
    instance: R1CSInstance, witness_message: Sequence[int], matrix_name: str = "A"
) -> int:
    """Demonstrate the second Step 9 succinct-form shape failure.

    Step 9 declares the three main forms to be identity forms and supplies an
    entire matrix description as each state (with a footnote calling this an
    abuse of notation).  The target relation instead needs a 1-by-ell row
    obtained by fixing the row variables at ``alpha`` and restricting to the
    witness columns.  The printed state lacks that typed evaluator and even
    omits ``alpha`` from ``st_M``.  Feeding the matrix literally to ``sl_id``
    therefore fails its exact shape.
    """

    matrices = {"A": instance.A, "B": instance.B, "C": instance.C}
    if matrix_name not in matrices:
        raise SuccinctLinearFormTypeError("unknown printed main matrix state")
    printed_state = LinearFormMatrix(matrices[matrix_name])
    matrix = IdentityLinearForm(1, instance.ell).evaluate(printed_state)
    return matrix.apply(witness_message)[0]


def _witness_linear_form_state(
    instance: R1CSInstance, alpha: Sequence[int], ze: Sequence[int]
) -> LinearFormMatrix:
    """Evaluate the joint A/B/C witness-column form to a typed 1-by-ell row."""

    if len(alpha) != instance.sumcheck_variables or len(ze) != 3:
        raise SuccinctLinearFormTypeError("main joint-form state dimension mismatch")
    matrices = (instance.A, instance.B, instance.C)
    row: list[int] = []
    for witness_index in range(instance.ell):
        column = instance.n0 + witness_index
        value = fsum(
            fmul(
                ze[matrix_index],
                multilinear_eval(
                    tuple(matrix[row_index][column] for row_index in range(instance.size)),
                    alpha,
                ),
            )
            for matrix_index, matrix in enumerate(matrices)
        )
        row.append(value)
    return LinearFormMatrix((tuple(row),))


def _inner_linear_form_target(
    message: Sequence[int],
    *,
    alpha_coordinate: int,
    ze_coordinate: int,
    mask_factor: int,
    repair: str,
) -> int:
    """Evaluate one typed repair of Step 9's inner-mask form.

    The two repairs are algebraically identical but type the paper's intended
    scalar in different places:

    * keep ``sl_id`` and pre-multiply the matrix state; or
    * use Definition 5.4's ``times(sl_id)`` with a structured scaled state.

    The branch's mask factor is one for the literal Steps 3/8-first branch and
    two for the Step 8-second/HVZK-proof branch.
    """

    base = LinearFormMatrix((powers(alpha_coordinate, len(message)),))
    scalar = fmul(mask_factor, ze_coordinate)
    if repair == IDENTITY_PREMULTIPLIED_REPAIR:
        state = LinearFormMatrix(
            (tuple(fmul(scalar, value) for value in base.values[0]),)
        )
        matrix = IdentityLinearForm(1, len(message)).evaluate(state)
    elif repair == SCALED_IDENTITY_REPAIR:
        matrix = ScaledIdentityLinearForm(1, len(message)).evaluate(
            ScaledIdentityState(base, scalar)
        )
    else:
        raise SuccinctLinearFormTypeError("unknown typed Step 9 repair")
    return matrix.apply(message)[0]


def typed_joint_output_claim(
    instance: R1CSInstance,
    profile: ReferenceProfile,
    transcript: Transcript,
    witness: OutputWitness,
    *,
    repair: str,
) -> int:
    """Evaluate the branch-relative joint claim through typed linear forms.

    This is an executable diagnostic completion, not an interpretation with
    theorem authority.  The paper does not select either mask coefficient and
    its printed Step 9 state does not type-check.
    """

    if transcript.convention not in MASK_FACTORS:
        raise ReferenceError("unknown transcript convention")
    d = instance.sumcheck_variables
    if len(transcript.rounds) != d or len(witness.witness_message) != instance.ell:
        raise SuccinctLinearFormTypeError("typed output main dimension mismatch")
    if len(witness.inner_messages) != 3 * d:
        raise SuccinctLinearFormTypeError("typed output inner dimension mismatch")
    if profile.inner_message_length < 1 or any(
        len(message) != profile.inner_message_length for message in witness.inner_messages
    ):
        raise SuccinctLinearFormTypeError("typed output inner message width mismatch")
    alpha = tuple(round_message.alpha for round_message in transcript.rounds)
    ze = zero_evader(transcript.rho)
    main_matrix = IdentityLinearForm(1, instance.ell).evaluate(
        _witness_linear_form_state(instance, alpha, ze)
    )
    claim = main_matrix.apply(witness.witness_message)[0]
    factor = MASK_FACTORS[transcript.convention]
    for matrix_index in range(3):
        for round_index in range(d):
            message = witness.inner_messages[matrix_index * d + round_index]
            claim = fadd(
                claim,
                _inner_linear_form_target(
                    message,
                    alpha_coordinate=alpha[round_index],
                    ze_coordinate=ze[matrix_index],
                    mask_factor=factor,
                    repair=repair,
                ),
            )
    return claim


def verify_derived_output_relation(
    instance: R1CSInstance,
    profile: ReferenceProfile,
    transcript: Transcript,
    witness: OutputWitness,
) -> None:
    """Verify two explicit algebraically consistent completions of each branch.

    This is a diagnostic relation verifier.  It is not the paper-literal
    relation because Step 9 does not provide a typed identity-form vector and
    does not resolve the coefficient-one/coefficient-two split.
    """

    verify_direct(instance, profile, transcript)
    d = instance.sumcheck_variables
    specs = profile.specs(instance.ell)
    if len(witness.witness_message) != instance.ell:
        raise ReferenceError("output witness message length mismatch")
    if tuple(transcript.witness_oracle.values) != specs["main"].encode(
        witness.witness_message, witness.witness_randomness
    ):
        raise ReferenceError("witness oracle is not the claimed encoding")
    if len(witness.inner_messages) != 3 * d or len(witness.inner_randomness) != 3 * d:
        raise ReferenceError("inner output-witness count mismatch")
    for index, (message, randomness, oracle) in enumerate(
        zip(witness.inner_messages, witness.inner_randomness, transcript.inner_oracles)
    ):
        if poly_eval(message, 0) != 0 or poly_eval(message, 1) != 0:
            raise ReferenceError("inner mask endpoint target rejected")
        if tuple(oracle.values) != specs["inner"].encode(message, randomness):
            raise ReferenceError("inner oracle encoding rejected")
    if len(witness.outer_messages) != d or len(witness.outer_randomness) != d:
        raise ReferenceError("outer output-witness count mismatch")
    alpha = tuple(round_message.alpha for round_message in transcript.rounds)
    for index, (message, randomness, oracle, target) in enumerate(
        zip(
            witness.outer_messages,
            witness.outer_randomness,
            transcript.outer_oracles,
            transcript.outer_evaluations,
        )
    ):
        if tuple(oracle.values) != specs["outer"].encode(message, randomness):
            raise ReferenceError("outer oracle encoding rejected")
        if poly_eval(message, alpha[index]) != target:
            raise ReferenceError("outer succinct evaluation rejected")

    # Both explicitly typed repairs must agree.  Agreement only establishes
    # the algebra of the selected diagnostic branch; it does not repair the
    # paper or instantiate its target IOR theorem.
    typed_claims = tuple(
        typed_joint_output_claim(
            instance,
            profile,
            transcript,
            witness,
            repair=repair,
        )
        for repair in TYPED_OUTPUT_REPAIRS
    )
    if len(set(typed_claims)) != 1:
        raise AssertionError("typed Step 9 repairs disagree")
    if typed_claims[0] != transcript.joint_mu:
        raise ReferenceError("derived joint output relation rejected")


def verify_paper_literal_output_relation(*_args: Any, **_kwargs: Any) -> None:
    raise PaperAmbiguityError(
        "CFW26 Construction 11.4 is internally inconsistent: Steps 3/8-first use mask coefficient 1; "
        "Step 8-second/HVZK proof use coefficient 2; Step 9 supplies ill-typed main and inner "
        "identity-form states"
    )


@dataclass(frozen=True)
class PublicView:
    convention: str
    instance_digest: str
    compiler_binding_digest: str
    profile_digest: str
    mu_tilde: int
    epsilon: int
    r: tuple[int, ...]
    rounds: tuple[SumcheckRound, ...]
    outer_evaluations: tuple[int, ...]
    v_values: tuple[int, int, int]
    u_values: tuple[int, int, int]
    rho: int
    joint_mu: int
    oracle_queries: tuple[tuple[str, tuple[int, ...], tuple[int, ...]], ...]


def all_oracle_specs(instance: R1CSInstance, profile: ReferenceProfile) -> dict[str, RSZKEncodingSpec]:
    d = instance.sumcheck_variables
    specs = profile.specs(instance.ell)
    result = {"witness": specs["main"]}
    result.update(
        {f"inner/{name}/{index}": specs["inner"] for name in FIELD_NAMES for index in range(d)}
    )
    result.update({f"outer/{index}": specs["outer"] for index in range(d)})
    return result


def _sample_public_direct(
    instance: R1CSInstance,
    profile: ReferenceProfile,
    *,
    seed: bytes,
    convention: str,
) -> tuple[
    int,
    tuple[int, ...],
    tuple[SumcheckRound, ...],
    int,
    tuple[int, ...],
    tuple[int, int, int],
    tuple[int, int, int],
    int,
    int,
]:
    if convention not in MASK_FACTORS:
        raise ReferenceError("unknown simulator convention")
    d = instance.sumcheck_variables
    rng = DeterministicFieldRng(seed, b"public-view-simulator")
    epsilon = rng.draw()
    r = rng.vector(d)
    alphas = tuple(rng.draw_non_boolean() if index == d - 1 else rng.draw() for index in range(d))
    rho = rng.draw()
    v_values = rng.vector(3)
    rounds: list[SumcheckRound] = []
    # Uniform affine parameterization of T(vA,vB,vC): h1 is free; for
    # subsequent h_j, coefficients 1.. are free and coefficient 0 is solved.
    first_coefficients = rng.vector(profile.outer_message_length)
    rounds.append(SumcheckRound(first_coefficients, alphas[0]))
    mu_tilde = fadd(poly_eval(first_coefficients, 0), poly_eval(first_coefficients, 1))
    for index in range(1, d):
        tail_coefficients = rng.vector(profile.outer_message_length - 1)
        target = poly_eval(rounds[-1].coefficients, alphas[index - 1])
        # h(0)+h(1)=2*c0+sum_{k>=1} c_k.
        c0 = fmul(fsub(target, fsum(tail_coefficients)), finv(2))
        rounds.append(SumcheckRound((c0,) + tail_coefficients, alphas[index]))
    outer_evaluations = list(rng.vector(d - 1))
    final_polynomial_value = poly_eval(rounds[-1].coefficients, alphas[-1])
    g_at_alpha = fsub(fmul(v_values[0], v_values[1]), v_values[2])
    final_mask = fsub(
        fsub(final_polynomial_value, fmul(fmul(epsilon, g_at_alpha), eq_polynomial(r, alphas))),
        fsum(outer_evaluations),
    )
    outer_evaluations.append(final_mask)
    public_rows = public_matrix_vectors(instance)
    u_values = tuple(multilinear_eval(public_rows[name], alphas) for name in FIELD_NAMES)
    ze = zero_evader(rho)
    joint_mu = fsum(
        fmul(coefficient, fsub(v_value, u_value))
        for coefficient, v_value, u_value in zip(ze, v_values, u_values)
    )
    return (
        epsilon,
        r,
        tuple(rounds),
        mu_tilde,
        tuple(outer_evaluations),
        v_values,  # type: ignore[return-value]
        u_values,  # type: ignore[return-value]
        rho,
        joint_mu,
    )


def simulate_public_view(
    instance: R1CSInstance,
    profile: ReferenceProfile,
    query_plan: Mapping[str, Sequence[int]],
    *,
    seed: bytes,
    convention: str,
) -> PublicView:
    """CFW26 public-only simulator for direct messages and bounded queries.

    The signature intentionally has no witness argument.  This executable
    sampler demonstrates the paper's affine-space construction and the exact
    RS query simulators; it is not a distributional proof or a PCS simulator.
    """

    (
        epsilon,
        r,
        rounds,
        mu_tilde,
        outer_evaluations,
        v_values,
        u_values,
        rho,
        joint_mu,
    ) = _sample_public_direct(instance, profile, seed=seed, convention=convention)
    specs = all_oracle_specs(instance, profile)
    if set(query_plan) - set(specs):
        raise ReferenceError("query plan names an unknown oracle")
    rng = DeterministicFieldRng(seed, b"public-oracle-query-simulator")
    answers = []
    for name in sorted(query_plan):
        indexes = tuple(query_plan[name])
        values = specs[name].simulate_queries(indexes, rng)
        answers.append((name, indexes, values))
    view = PublicView(
        convention=convention,
        instance_digest=instance.digest,
        compiler_binding_digest=instance.compiler_binding_digest,
        profile_digest=profile.digest,
        mu_tilde=mu_tilde,
        epsilon=epsilon,
        r=r,
        rounds=rounds,
        outer_evaluations=outer_evaluations,
        v_values=v_values,
        u_values=u_values,
        rho=rho,
        joint_mu=joint_mu,
        oracle_queries=tuple(answers),
    )
    verify_public_view(instance, profile, view)
    return view


def extract_public_view(
    instance: R1CSInstance,
    profile: ReferenceProfile,
    transcript: Transcript,
    query_plan: Mapping[str, Sequence[int]],
) -> PublicView:
    verify_direct(instance, profile, transcript)
    oracles = {oracle.name: oracle for oracle in transcript.inner_oracles + transcript.outer_oracles}
    oracles[transcript.witness_oracle.name] = transcript.witness_oracle
    if set(query_plan) - set(oracles):
        raise ReferenceError("query plan names an unknown oracle")
    specs = all_oracle_specs(instance, profile)
    answers = []
    for name in sorted(query_plan):
        indexes = tuple(query_plan[name])
        if len(indexes) > specs[name].t_queries or len(set(indexes)) != len(indexes):
            raise ReferenceError("query plan exceeds honest-view ZK bound")
        if any(index < 0 or index >= len(oracles[name].values) for index in indexes):
            raise ReferenceError("honest-view query index out of range")
        answers.append((name, indexes, tuple(oracles[name].values[index] for index in indexes)))
    return PublicView(
        convention=transcript.convention,
        instance_digest=transcript.instance_digest,
        compiler_binding_digest=transcript.compiler_binding_digest,
        profile_digest=transcript.profile_digest,
        mu_tilde=transcript.mu_tilde,
        epsilon=transcript.epsilon,
        r=transcript.r,
        rounds=transcript.rounds,
        outer_evaluations=transcript.outer_evaluations,
        v_values=transcript.v_values,
        u_values=transcript.u_values,
        rho=transcript.rho,
        joint_mu=transcript.joint_mu,
        oracle_queries=tuple(answers),
    )


def verify_public_view(instance: R1CSInstance, profile: ReferenceProfile, view: PublicView) -> None:
    if view.convention not in MASK_FACTORS:
        raise ReferenceError("public view convention mismatch")
    if view.instance_digest != instance.digest or view.compiler_binding_digest != instance.compiler_binding_digest:
        raise ReferenceError("public view statement/compiler binding mismatch")
    if view.profile_digest != profile.digest:
        raise ReferenceError("public view profile mismatch")
    d = instance.sumcheck_variables
    if len(view.r) != d or len(view.rounds) != d or len(view.outer_evaluations) != d:
        raise ReferenceError("public view sumcheck dimension mismatch")
    previous = view.mu_tilde
    alpha = []
    for index, round_message in enumerate(view.rounds):
        if len(round_message.coefficients) != profile.outer_message_length:
            raise ReferenceError("public view polynomial width mismatch")
        if fadd(poly_eval(round_message.coefficients, 0), poly_eval(round_message.coefficients, 1)) != previous:
            raise ReferenceError("public view recurrence rejected")
        if index == d - 1 and round_message.alpha in (0, 1):
            raise ReferenceError("public view last alpha is Boolean")
        previous = poly_eval(round_message.coefficients, round_message.alpha)
        alpha.append(round_message.alpha)
    expected_final = fadd(
        fmul(
            fmul(view.epsilon, fsub(fmul(view.v_values[0], view.v_values[1]), view.v_values[2])),
            eq_polynomial(view.r, alpha),
        ),
        fsum(view.outer_evaluations),
    )
    if expected_final != previous:
        raise ReferenceError("public view final equation rejected")
    public_rows = public_matrix_vectors(instance)
    expected_u = tuple(multilinear_eval(public_rows[name], alpha) for name in FIELD_NAMES)
    if expected_u != view.u_values:
        raise ReferenceError("public view public contribution rejected")
    ze = zero_evader(view.rho)
    expected_mu = fsum(
        fmul(coefficient, fsub(v_value, u_value))
        for coefficient, v_value, u_value in zip(ze, view.v_values, view.u_values)
    )
    if expected_mu != view.joint_mu:
        raise ReferenceError("public view joint target rejected")
    specs = all_oracle_specs(instance, profile)
    seen = set()
    for name, indexes, values in view.oracle_queries:
        if name in seen or name not in specs:
            raise ReferenceError("public view oracle query name rejected")
        seen.add(name)
        if len(indexes) != len(values) or len(indexes) > specs[name].t_queries:
            raise ReferenceError("public view oracle query width rejected")
        if len(set(indexes)) != len(indexes):
            raise ReferenceError("public view duplicate query rejected")
        if any(index < 0 or index >= specs[name].block_length for index in indexes):
            raise ReferenceError("public view query index rejected")
        for value in values:
            field(value)


def exact_dimensions(instance: R1CSInstance, profile: ReferenceProfile) -> dict[str, int]:
    d = instance.sumcheck_variables
    specs = profile.specs(instance.ell)
    main_oracle_elements = specs["main"].block_length
    inner_oracle_elements = 3 * d * specs["inner"].block_length
    outer_oracle_elements = d * specs["outer"].block_length
    oracle_elements = main_oracle_elements + inner_oracle_elements + outer_oracle_elements
    sumcheck_polynomial_elements = d * profile.outer_message_length
    outer_evaluation_elements = d
    other_direct_elements = 4  # mu_tilde and v_A,v_B,v_C
    direct_elements = (
        sumcheck_polynomial_elements
        + outer_evaluation_elements
        + other_direct_elements
    )
    return {
        "ell": instance.ell,
        "n0": instance.n0,
        "r1cs_matrix_side": instance.size,
        "r1cs_constraint_count": instance.size,
        "r1cs_variable_count": instance.size,
        "boolean_index_width": d,
        "sumcheck_variables": d,
        "main_message_length": instance.ell,
        "main_randomness_length": specs["main"].randomness_length,
        "main_block_length": specs["main"].block_length,
        "inner_message_length": profile.inner_message_length,
        "inner_randomness_length": specs["inner"].randomness_length,
        "inner_block_length": specs["inner"].block_length,
        "inner_oracle_count": 3 * d,
        "outer_message_length": profile.outer_message_length,
        "outer_randomness_length": specs["outer"].randomness_length,
        "outer_block_length": specs["outer"].block_length,
        "outer_oracle_count": d,
        "main_oracle_field_elements": main_oracle_elements,
        "inner_oracle_field_elements": inner_oracle_elements,
        "outer_oracle_field_elements": outer_oracle_elements,
        "oracle_prover_field_elements": oracle_elements,
        "sumcheck_polynomial_field_elements": sumcheck_polynomial_elements,
        "outer_evaluation_field_elements": outer_evaluation_elements,
        "other_direct_field_elements": other_direct_elements,
        "direct_prover_field_elements": direct_elements,
        "total_prover_field_elements": oracle_elements + direct_elements,
        "verifier_field_elements": 2 * d + 2,
        "query_bound_per_oracle": profile.t_queries,
        "hvzk_encoding_hybrid_count": 4 * instance.log_ell + 5,
    }


def source_capabilities() -> dict[str, bool]:
    return {
        "deterministic_honest_transcript": True,
        "direct_sumcheck_verifier": True,
        "both_mask_coefficient_branches_executable": True,
        "section11_padding_arithmetic_diagnostic": True,
        "derived_branch_output_relation_diagnostic": True,
        "typed_succinct_linear_form_diagnostic": True,
        "canonical_json_transcript_parser": True,
        "public_only_affine_view_simulator": True,
        "public_sampler_distributional_proof": False,
        "adaptive_query_simulator": False,
        "pcs_commitment_opening_simulator": False,
        "whole_fiat_shamir_view_simulator": False,
        "bounded_consensus_parser": False,
        "unequal_geometry_native_paper_carrier": False,
        "full_hegemon_section11_carrier": False,
        "exact_padding_parser_refinement": False,
        "paper_output_relation_unambiguous": False,
        "paper_hvzk_reduction_instantiated": False,
        "plonky3_section11_carrier": False,
        "rbr_bound_instantiated": False,
        "complete_zk": False,
        "strict_pq128": False,
        "production_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("self-check", "summary"))
    args = parser.parse_args()
    binding = sha512_frame(b"test-only-unbound-compiler", b"fixture").hex()
    instance, witness = toy_instance(binding)
    profile = ReferenceProfile()
    if args.command == "self-check":
        for convention in MASK_FACTORS:
            run = honest_prove(instance, witness, profile, seed=b"cfw26-reference-fixture", convention=convention)
            parsed = Transcript.from_bytes(run.transcript.to_bytes())
            verify_direct(instance, profile, parsed)
            verify_derived_output_relation(instance, profile, parsed, run.output_witness)
            query_plan = {name: (0,) for name in all_oracle_specs(instance, profile)}
            verify_public_view(
                instance,
                profile,
                simulate_public_view(
                    instance,
                    profile,
                    query_plan,
                    seed=b"cfw26-public-simulator",
                    convention=convention,
                ),
            )
        print("CFW26_R1CS_IOR_SOURCE_REFERENCE_SELF_CHECK_PASS")
        print("paper_output_relation_unambiguous=false")
        print("production_authorized=false")
    else:
        print(json.dumps({
            "capabilities": source_capabilities(),
            "dimensions": exact_dimensions(instance, profile),
            "field_modulus": GOLDILOCKS_MODULUS,
            "mask_conventions": MASK_FACTORS,
            "reported_hegemon_mixed_section11_projection": section11_padding_projection(
                REPORTED_HEGEMON_MIXED_SOURCE_GEOMETRY
            ),
        }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
