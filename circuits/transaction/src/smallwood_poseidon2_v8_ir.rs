//! Canonical executable expression IR for the SmallWood/Poseidon2 V8 relation.
//!
//! The relation program and the verifier share this representation.  It is deliberately a
//! tiny field-expression machine rather than a source-code digest: every operand, constant,
//! public input, witness row, inverse and public specialization is serialized explicitly.

#![forbid(unsafe_code)]

use std::{
    cell::RefCell,
    collections::HashMap,
    fmt,
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use hegemon_field::{PrimeCharacteristicRing, GOLDILOCKS_MODULUS};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SmallwoodPoseidon2V8Expr {
    Constant(u64),
    Public(u16),
    WitnessRow(u16),
    Add {
        left: u32,
        right: u32,
    },
    Sub {
        left: u32,
        right: u32,
    },
    Mul {
        left: u32,
        right: u32,
    },
    Neg {
        value: u32,
    },
    /// Goldilocks inverse with the total convention `inv(0) = 0`.
    Inverse {
        value: u32,
    },
    /// Public specialization used by the fixed relation compiler.  Both compared expressions
    /// and both result arms are committed; equality is canonical field equality.
    SelectEqual {
        left: u32,
        right: u32,
        equal: u32,
        not_equal: u32,
    },
    /// Exact canonical-u64 bit extraction used only for parser-bounded public scalars.
    Bit {
        value: u32,
        bit: u8,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8ExpressionProgram {
    pub expressions: Vec<SmallwoodPoseidon2V8Expr>,
    pub roots: Vec<u32>,
}

#[derive(Default)]
struct Arena {
    expressions: Vec<SmallwoodPoseidon2V8Expr>,
    interned: HashMap<SmallwoodPoseidon2V8Expr, u32>,
}

impl Arena {
    fn new() -> Self {
        let mut arena = Self::default();
        for value in [0, 1, 2, GOLDILOCKS_MODULUS - 1] {
            arena.intern(SmallwoodPoseidon2V8Expr::Constant(value));
        }
        arena
    }

    fn intern(&mut self, expression: SmallwoodPoseidon2V8Expr) -> u32 {
        if let Some(index) = self.interned.get(&expression) {
            return *index;
        }
        let index =
            u32::try_from(self.expressions.len()).expect("V8 executable expression table fits u32");
        self.expressions.push(expression);
        self.interned.insert(expression, index);
        index
    }
}

thread_local! {
    static ACTIVE_ARENA: RefCell<Option<Arena>> = const { RefCell::new(None) };
}

// Internal-only handles let the existing u64 nonlinear formula constructor run in symbolic
// mode without keeping a second copy of its 471 base/auth and 27 stable identities.  Relation
// constants in those constructors are all below this reserved range; the guard is asserted when
// a handle is created.  Handles never enter a transcript or a proof.
const SYMBOLIC_HANDLE_BASE: u64 = u64::MAX;
const SYMBOLIC_HANDLE_CAPACITY: u32 = 1 << 24;

fn encode_handle(node: u32) -> u64 {
    assert!(
        node < SYMBOLIC_HANDLE_CAPACITY,
        "V8 symbolic handle capacity exceeded"
    );
    SYMBOLIC_HANDLE_BASE - u64::from(node)
}

fn decode_handle(value: u64) -> Option<u32> {
    let distance = SYMBOLIC_HANDLE_BASE.wrapping_sub(value);
    (distance < u64::from(SYMBOLIC_HANDLE_CAPACITY)).then_some(distance as u32)
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct SmallwoodPoseidon2V8SymbolicValue {
    node: u32,
}

impl fmt::Debug for SmallwoodPoseidon2V8SymbolicValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "v8e{}", self.node)
    }
}

impl SmallwoodPoseidon2V8SymbolicValue {
    pub const ZERO: Self = Self { node: 0 };
    pub const ONE: Self = Self { node: 1 };
    pub const TWO: Self = Self { node: 2 };
    pub const NEG_ONE: Self = Self { node: 3 };

    fn intern(expression: SmallwoodPoseidon2V8Expr) -> Self {
        let node = ACTIVE_ARENA.with(|slot| {
            slot.borrow_mut()
                .as_mut()
                .expect("V8 executable expression arena is active")
                .intern(expression)
        });
        Self { node }
    }

    pub fn public(index: usize) -> Self {
        Self::intern(SmallwoodPoseidon2V8Expr::Public(
            u16::try_from(index).expect("120 V8 public words fit u16"),
        ))
    }

    pub fn witness_row(index: usize) -> Self {
        Self::intern(SmallwoodPoseidon2V8Expr::WitnessRow(
            u16::try_from(index).expect("686 V8 witness rows fit u16"),
        ))
    }

    pub fn inverse(self) -> Self {
        Self::intern(SmallwoodPoseidon2V8Expr::Inverse { value: self.node })
    }

    pub fn select_equal(self, other: Self, equal: Self, not_equal: Self) -> Self {
        Self::intern(SmallwoodPoseidon2V8Expr::SelectEqual {
            left: self.node,
            right: other.node,
            equal: equal.node,
            not_equal: not_equal.node,
        })
    }

    pub fn bit(self, bit: usize) -> Self {
        Self::intern(SmallwoodPoseidon2V8Expr::Bit {
            value: self.node,
            bit: u8::try_from(bit).expect("V8 public bit index fits u8"),
        })
    }

    pub const fn root(self) -> u32 {
        self.node
    }

    pub fn from_internal_handle(value: u64) -> Self {
        if let Some(node) = decode_handle(value) {
            Self { node }
        } else {
            Self::from_u64(value)
        }
    }

    pub fn into_internal_handle(self) -> u64 {
        encode_handle(self.node)
    }
}

impl Add for SmallwoodPoseidon2V8SymbolicValue {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        if self == Self::ZERO {
            return rhs;
        }
        if rhs == Self::ZERO {
            return self;
        }
        let (left, right) = if self.node <= rhs.node {
            (self.node, rhs.node)
        } else {
            (rhs.node, self.node)
        };
        Self::intern(SmallwoodPoseidon2V8Expr::Add { left, right })
    }
}

impl AddAssign for SmallwoodPoseidon2V8SymbolicValue {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for SmallwoodPoseidon2V8SymbolicValue {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        if rhs == Self::ZERO {
            return self;
        }
        if self == rhs {
            return Self::ZERO;
        }
        Self::intern(SmallwoodPoseidon2V8Expr::Sub {
            left: self.node,
            right: rhs.node,
        })
    }
}

impl SubAssign for SmallwoodPoseidon2V8SymbolicValue {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for SmallwoodPoseidon2V8SymbolicValue {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        if self == Self::ZERO || rhs == Self::ZERO {
            return Self::ZERO;
        }
        if self == Self::ONE {
            return rhs;
        }
        if rhs == Self::ONE {
            return self;
        }
        let (left, right) = if self.node <= rhs.node {
            (self.node, rhs.node)
        } else {
            (rhs.node, self.node)
        };
        Self::intern(SmallwoodPoseidon2V8Expr::Mul { left, right })
    }
}

impl MulAssign for SmallwoodPoseidon2V8SymbolicValue {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Neg for SmallwoodPoseidon2V8SymbolicValue {
    type Output = Self;

    fn neg(self) -> Self::Output {
        if self == Self::ZERO {
            self
        } else {
            Self::intern(SmallwoodPoseidon2V8Expr::Neg { value: self.node })
        }
    }
}

impl Sum for SmallwoodPoseidon2V8SymbolicValue {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, Add::add)
    }
}

impl<'a> Sum<&'a SmallwoodPoseidon2V8SymbolicValue> for SmallwoodPoseidon2V8SymbolicValue {
    fn sum<I: Iterator<Item = &'a SmallwoodPoseidon2V8SymbolicValue>>(iter: I) -> Self {
        iter.copied().sum()
    }
}

impl Product for SmallwoodPoseidon2V8SymbolicValue {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ONE, Mul::mul)
    }
}

impl<'a> Product<&'a SmallwoodPoseidon2V8SymbolicValue> for SmallwoodPoseidon2V8SymbolicValue {
    fn product<I: Iterator<Item = &'a SmallwoodPoseidon2V8SymbolicValue>>(iter: I) -> Self {
        iter.copied().product()
    }
}

impl PrimeCharacteristicRing for SmallwoodPoseidon2V8SymbolicValue {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;
    const TWO: Self = Self::TWO;
    const NEG_ONE: Self = Self::NEG_ONE;

    fn from_bool(value: bool) -> Self {
        if value {
            Self::ONE
        } else {
            Self::ZERO
        }
    }

    fn from_u64(value: u64) -> Self {
        Self::intern(SmallwoodPoseidon2V8Expr::Constant(
            value % GOLDILOCKS_MODULUS,
        ))
    }
}

pub fn begin_smallwood_poseidon2_v8_expression_program() {
    ACTIVE_ARENA.with(|slot| {
        let mut slot = slot.borrow_mut();
        assert!(
            slot.is_none(),
            "V8 executable expression arena is not reentrant"
        );
        *slot = Some(Arena::new());
    });
}

pub fn finish_smallwood_poseidon2_v8_expression_program(
    roots: impl IntoIterator<Item = u64>,
) -> SmallwoodPoseidon2V8ExpressionProgram {
    let roots = roots
        .into_iter()
        .map(SmallwoodPoseidon2V8SymbolicValue::from_internal_handle)
        .map(SmallwoodPoseidon2V8SymbolicValue::root)
        .collect();
    let arena = ACTIVE_ARENA.with(|slot| {
        slot.borrow_mut()
            .take()
            .expect("V8 executable expression arena remains active")
    });
    SmallwoodPoseidon2V8ExpressionProgram {
        expressions: arena.expressions,
        roots,
    }
}

pub fn smallwood_poseidon2_v8_symbolic_public_handle(index: usize) -> u64 {
    SmallwoodPoseidon2V8SymbolicValue::public(index).into_internal_handle()
}

pub fn smallwood_poseidon2_v8_symbolic_witness_row_handle(index: usize) -> u64 {
    SmallwoodPoseidon2V8SymbolicValue::witness_row(index).into_internal_handle()
}

pub fn smallwood_poseidon2_v8_symbolic_add(left: u64, right: u64) -> Option<u64> {
    ACTIVE_ARENA.with(|slot| slot.borrow().as_ref().map(|_| ()))?;
    Some(
        (SmallwoodPoseidon2V8SymbolicValue::from_internal_handle(left)
            + SmallwoodPoseidon2V8SymbolicValue::from_internal_handle(right))
        .into_internal_handle(),
    )
}

pub fn smallwood_poseidon2_v8_symbolic_sub(left: u64, right: u64) -> Option<u64> {
    ACTIVE_ARENA.with(|slot| slot.borrow().as_ref().map(|_| ()))?;
    Some(
        (SmallwoodPoseidon2V8SymbolicValue::from_internal_handle(left)
            - SmallwoodPoseidon2V8SymbolicValue::from_internal_handle(right))
        .into_internal_handle(),
    )
}

pub fn smallwood_poseidon2_v8_symbolic_mul(left: u64, right: u64) -> Option<u64> {
    ACTIVE_ARENA.with(|slot| slot.borrow().as_ref().map(|_| ()))?;
    Some(
        (SmallwoodPoseidon2V8SymbolicValue::from_internal_handle(left)
            * SmallwoodPoseidon2V8SymbolicValue::from_internal_handle(right))
        .into_internal_handle(),
    )
}

pub fn smallwood_poseidon2_v8_symbolic_inverse(value: u64) -> Option<u64> {
    ACTIVE_ARENA.with(|slot| slot.borrow().as_ref().map(|_| ()))?;
    Some(
        SmallwoodPoseidon2V8SymbolicValue::from_internal_handle(value)
            .inverse()
            .into_internal_handle(),
    )
}

pub fn smallwood_poseidon2_v8_symbolic_select_equal(
    left: u64,
    right: u64,
    equal: u64,
    not_equal: u64,
) -> Option<u64> {
    ACTIVE_ARENA.with(|slot| slot.borrow().as_ref().map(|_| ()))?;
    Some(
        SmallwoodPoseidon2V8SymbolicValue::from_internal_handle(left)
            .select_equal(
                SmallwoodPoseidon2V8SymbolicValue::from_internal_handle(right),
                SmallwoodPoseidon2V8SymbolicValue::from_internal_handle(equal),
                SmallwoodPoseidon2V8SymbolicValue::from_internal_handle(not_equal),
            )
            .into_internal_handle(),
    )
}

pub fn smallwood_poseidon2_v8_symbolic_bit(value: u64, bit: usize) -> Option<u64> {
    ACTIVE_ARENA.with(|slot| slot.borrow().as_ref().map(|_| ()))?;
    Some(
        SmallwoodPoseidon2V8SymbolicValue::from_internal_handle(value)
            .bit(bit)
            .into_internal_handle(),
    )
}

pub fn smallwood_poseidon2_v8_expression_program_is_active() -> bool {
    ACTIVE_ARENA.with(|slot| slot.borrow().is_some())
}

#[inline]
fn add(left: u64, right: u64) -> u64 {
    ((u128::from(left) + u128::from(right)) % u128::from(GOLDILOCKS_MODULUS)) as u64
}

#[inline]
fn sub(left: u64, right: u64) -> u64 {
    if left >= right {
        left - right
    } else {
        GOLDILOCKS_MODULUS - (right - left)
    }
}

#[inline]
fn mul(left: u64, right: u64) -> u64 {
    ((u128::from(left) * u128::from(right)) % u128::from(GOLDILOCKS_MODULUS)) as u64
}

fn inverse(value: u64) -> u64 {
    if value == 0 {
        return 0;
    }
    let mut exponent = GOLDILOCKS_MODULUS - 2;
    let mut base = value;
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = mul(result, base);
        }
        base = mul(base, base);
        exponent >>= 1;
    }
    result
}

pub fn evaluate_smallwood_poseidon2_v8_expression_nodes(
    expressions: &[SmallwoodPoseidon2V8Expr],
    public: &[u64],
    rows: &[u64],
) -> Result<Vec<u64>, &'static str> {
    let mut values = Vec::with_capacity(expressions.len());
    for expression in expressions {
        let value = match *expression {
            SmallwoodPoseidon2V8Expr::Constant(value) => value,
            SmallwoodPoseidon2V8Expr::Public(index) => *public
                .get(usize::from(index))
                .ok_or("V8 executable program public index is out of range")?,
            SmallwoodPoseidon2V8Expr::WitnessRow(index) => *rows
                .get(usize::from(index))
                .ok_or("V8 executable program witness row is out of range")?,
            SmallwoodPoseidon2V8Expr::Add { left, right } => {
                add(values[left as usize], values[right as usize])
            }
            SmallwoodPoseidon2V8Expr::Sub { left, right } => {
                sub(values[left as usize], values[right as usize])
            }
            SmallwoodPoseidon2V8Expr::Mul { left, right } => {
                mul(values[left as usize], values[right as usize])
            }
            SmallwoodPoseidon2V8Expr::Neg { value } => sub(0, values[value as usize]),
            SmallwoodPoseidon2V8Expr::Inverse { value } => inverse(values[value as usize]),
            SmallwoodPoseidon2V8Expr::SelectEqual {
                left,
                right,
                equal,
                not_equal,
            } => {
                if values[left as usize] == values[right as usize] {
                    values[equal as usize]
                } else {
                    values[not_equal as usize]
                }
            }
            SmallwoodPoseidon2V8Expr::Bit { value, bit } => (values[value as usize] >> bit) & 1,
        };
        values.push(value);
    }
    Ok(values)
}

pub fn evaluate_smallwood_poseidon2_v8_expression_program(
    program: &SmallwoodPoseidon2V8ExpressionProgram,
    public: &[u64],
    rows: &[u64],
) -> Result<Vec<u64>, &'static str> {
    let values =
        evaluate_smallwood_poseidon2_v8_expression_nodes(&program.expressions, public, rows)?;
    program
        .roots
        .iter()
        .map(|root| {
            values
                .get(*root as usize)
                .copied()
                .ok_or("V8 executable program root is out of range")
        })
        .collect()
}
