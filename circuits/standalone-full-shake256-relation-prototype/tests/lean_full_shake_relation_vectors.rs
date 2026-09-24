use std::collections::{BTreeMap, BTreeSet};

use hegemon_standalone_full_shake256_relation_prototype as relation;
use relation::{
    AccumulatorOpening, Digest, FullStatement, FullWitness, MAX_NOTE_VALUE, MAX_SIGNERS, NoteKind,
    PrivateAuthMode, PrivateAuthWitness, SignedAmount, StablecoinBinding, accumulator_digest,
    intent_digest, mask_fixture, policy_root, refresh_derived_statement, value_lock_digest,
    verify_relation_with_expected_activation,
};

const VECTORS: &str =
    include_str!("../../../testdata/formal_core_vectors/full_shake_relation.json");

#[derive(Clone, Debug, PartialEq, Eq)]
enum Json {
    Bool(bool),
    Number(u64),
    String(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

impl Json {
    fn object(&self) -> &BTreeMap<String, Json> {
        match self {
            Self::Object(value) => value,
            _ => panic!("expected JSON object, got {self:?}"),
        }
    }

    fn field(&self, name: &str) -> &Json {
        self.object()
            .get(name)
            .unwrap_or_else(|| panic!("missing JSON field {name}"))
    }

    fn array(&self) -> &[Json] {
        match self {
            Self::Array(value) => value,
            _ => panic!("expected JSON array, got {self:?}"),
        }
    }

    fn boolean(&self) -> bool {
        match self {
            Self::Bool(value) => *value,
            _ => panic!("expected JSON boolean, got {self:?}"),
        }
    }

    fn number(&self) -> u64 {
        match self {
            Self::Number(value) => *value,
            _ => panic!("expected JSON number, got {self:?}"),
        }
    }

    fn string(&self) -> &str {
        match self {
            Self::String(value) => value,
            _ => panic!("expected JSON string, got {self:?}"),
        }
    }
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> JsonParser<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            bytes: source.as_bytes(),
            offset: 0,
        }
    }

    fn finish(mut self) -> Json {
        let value = self.value();
        self.whitespace();
        assert_eq!(self.offset, self.bytes.len(), "trailing JSON input");
        value
    }

    fn value(&mut self) -> Json {
        self.whitespace();
        match self.peek() {
            b'{' => self.object_value(),
            b'[' => self.array_value(),
            b'"' => Json::String(self.string_value()),
            b't' => {
                self.literal(b"true");
                Json::Bool(true)
            }
            b'f' => {
                self.literal(b"false");
                Json::Bool(false)
            }
            b'0'..=b'9' => Json::Number(self.number_value()),
            byte => panic!("unsupported JSON byte {byte:?} at {}", self.offset),
        }
    }

    fn object_value(&mut self) -> Json {
        self.expect(b'{');
        let mut fields = BTreeMap::new();
        self.whitespace();
        if self.take_if(b'}') {
            return Json::Object(fields);
        }
        loop {
            self.whitespace();
            let name = self.string_value();
            self.whitespace();
            self.expect(b':');
            assert!(
                fields.insert(name, self.value()).is_none(),
                "duplicate field"
            );
            self.whitespace();
            if self.take_if(b'}') {
                break;
            }
            self.expect(b',');
        }
        Json::Object(fields)
    }

    fn array_value(&mut self) -> Json {
        self.expect(b'[');
        let mut values = Vec::new();
        self.whitespace();
        if self.take_if(b']') {
            return Json::Array(values);
        }
        loop {
            values.push(self.value());
            self.whitespace();
            if self.take_if(b']') {
                break;
            }
            self.expect(b',');
        }
        Json::Array(values)
    }

    fn string_value(&mut self) -> String {
        self.expect(b'"');
        let mut output = Vec::new();
        loop {
            let byte = self.next();
            match byte {
                b'"' => break,
                b'\\' => {
                    let escaped = match self.next() {
                        b'"' => b'"',
                        b'\\' => b'\\',
                        b'/' => b'/',
                        b'b' => 8,
                        b'f' => 12,
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        other => panic!("unsupported JSON escape {other:?}"),
                    };
                    output.push(escaped);
                }
                0..=31 => panic!("control byte in JSON string"),
                other => output.push(other),
            }
        }
        String::from_utf8(output).expect("vector strings are UTF-8")
    }

    fn number_value(&mut self) -> u64 {
        let start = self.offset;
        while matches!(self.peek_optional(), Some(b'0'..=b'9')) {
            self.offset += 1;
        }
        std::str::from_utf8(&self.bytes[start..self.offset])
            .unwrap()
            .parse()
            .unwrap()
    }

    fn literal(&mut self, expected: &[u8]) {
        let end = self.offset + expected.len();
        assert_eq!(self.bytes.get(self.offset..end), Some(expected));
        self.offset = end;
    }

    fn whitespace(&mut self) {
        while matches!(self.peek_optional(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.offset += 1;
        }
    }

    fn take_if(&mut self, expected: u8) -> bool {
        if self.peek_optional() == Some(expected) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: u8) {
        assert_eq!(self.next(), expected, "unexpected JSON byte");
    }

    fn peek(&self) -> u8 {
        self.peek_optional().expect("unexpected end of JSON")
    }

    fn peek_optional(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }

    fn next(&mut self) -> u8 {
        let value = self.peek();
        self.offset += 1;
        value
    }
}

fn vectors() -> Json {
    JsonParser::new(VECTORS).finish()
}

fn bools(value: &Json) -> Vec<bool> {
    value.array().iter().map(Json::boolean).collect()
}

fn numbers(value: &Json) -> Vec<u64> {
    value.array().iter().map(Json::number).collect()
}

fn signed(value: &Json) -> (bool, u64) {
    (
        value.field("negative").boolean(),
        value.field("magnitude").number(),
    )
}

fn signed_canonical(value: (bool, u64)) -> bool {
    value.1 <= MAX_NOTE_VALUE && !(value.0 && value.1 == 0)
}

fn balance_row_accepts(row: &Json) -> bool {
    let input0 = row.field("input0").number();
    let input1 = row.field("input1").number();
    let output0 = row.field("output0").number();
    let output1 = row.field("output1").number();
    let delta = signed(row.field("expected_delta"));
    [input0, input1, output0, output1]
        .into_iter()
        .all(|value| value <= MAX_NOTE_VALUE)
        && signed_canonical(delta)
        && if delta.0 {
            input0 + input1 + delta.1 == output0 + output1
        } else {
            input0 + input1 == output0 + output1 + delta.1
        }
}

fn stable_surface_accepts(surface: &Json) -> bool {
    let value_balance = signed(surface.field("value_balance"));
    let issuance = signed(surface.field("stable_issuance"));
    let enabled = surface.field("stable_enabled").boolean();
    value_balance == (false, 0)
        && !signed(surface.field("native_row").field("expected_delta")).0
        && balance_row_accepts(surface.field("native_row"))
        && signed_canonical(issuance)
        && ((!enabled && issuance == (false, 0)) || (enabled && issuance.1 != 0))
}

fn note_active(note: &Json) -> bool {
    note.field("active").boolean()
}

fn note_kind(note: &Json) -> &str {
    note.field("kind").string()
}

fn active_kind(note: &Json, kind: &str) -> bool {
    !note_active(note) || note_kind(note) == kind
}

fn zero_native_accumulator(note: &Json) -> bool {
    note_active(note)
        && note_kind(note) == "accumulator"
        && note.field("value").number() == 0
        && note.field("asset_id").number() == 0
}

fn state_is_zero(state: &Json) -> bool {
    state.field("policy_root").number() == 0
        && state.field("intent_digest").number() == 0
        && state.field("threshold").number() == 0
        && state.field("signer_count").number() == 0
        && state.field("approval_count").number() == 0
        && bools(state.field("approved_slots")) == [false; MAX_SIGNERS]
}

fn state_well_formed(state: &Json) -> bool {
    let slots = bools(state.field("approved_slots"));
    let signer_count = state.field("signer_count").number();
    let threshold = state.field("threshold").number();
    let approval_count = state.field("approval_count").number();
    slots.len() == MAX_SIGNERS
        && state.field("policy_root").number() != 0
        && state.field("intent_digest").number() != 0
        && (1..=MAX_SIGNERS as u64).contains(&signer_count)
        && (1..=signer_count).contains(&threshold)
        && approval_count <= signer_count
        && approval_count == slots.iter().filter(|&&value| value).count() as u64
}

fn same_lineage(current: &Json, next: &Json) -> bool {
    ["policy_root", "intent_digest", "threshold", "signer_count"]
        .into_iter()
        .all(|field| current.field(field).number() == next.field(field).number())
}

fn zero_approvals(state: &Json) -> bool {
    state.field("approval_count").number() == 0
        && bools(state.field("approved_slots"))
            .into_iter()
            .all(|value| !value)
}

fn ordered_policy(surface: &Json, state: &Json) -> bool {
    let tags = numbers(surface.field("signer_tags"));
    let signer_count = state.field("signer_count").number() as usize;
    let active: BTreeSet<_> = tags.iter().take(signer_count).copied().collect();
    tags.len() == MAX_SIGNERS
        && tags.iter().take(signer_count).all(|&tag| tag != 0)
        && active.len() == signer_count
        && tags.iter().skip(signer_count).all(|&tag| tag == 0)
        && surface.field("policy_root_hash_matches").boolean()
}

fn approval_transition(surface: &Json) -> bool {
    let current = surface.field("current");
    let next = surface.field("next");
    let chosen = surface.field("chosen_signer_slot").number() as usize;
    let signer_count = current.field("signer_count").number() as usize;
    let tags = numbers(surface.field("signer_tags"));
    let current_slots = bools(current.field("approved_slots"));
    let mut expected_next = current_slots.clone();
    if chosen >= signer_count || chosen >= tags.len() || chosen >= current_slots.len() {
        return false;
    }
    expected_next[chosen] = true;
    tags[chosen] == surface.field("derived_signer_tag").number()
        && !current_slots[chosen]
        && bools(next.field("approved_slots")) == expected_next
}

fn auth_surface_accepts(surface: &Json) -> bool {
    let inputs = surface.field("inputs").array();
    let outputs = surface.field("outputs").array();
    assert_eq!(inputs.len(), 2);
    assert_eq!(outputs.len(), 2);
    let activity = inputs.iter().any(note_active) && outputs.iter().any(note_active);
    let current = surface.field("current");
    let next = surface.field("next");
    let tags = numbers(surface.field("signer_tags"));
    activity
        && match surface.field("mode").string() {
            "single_key" => {
                state_is_zero(current)
                    && state_is_zero(next)
                    && tags.len() == MAX_SIGNERS
                    && tags.iter().all(|&tag| tag == 0)
                    && inputs.iter().all(|note| active_kind(note, "ordinary"))
                    && outputs.iter().all(|note| active_kind(note, "ordinary"))
            }
            "accumulator_init" => {
                inputs.iter().any(note_active)
                    && note_active(&outputs[0])
                    && inputs.iter().all(|note| active_kind(note, "ordinary"))
                    && zero_native_accumulator(&outputs[0])
                    && active_kind(&outputs[1], "ordinary")
                    && state_is_zero(current)
                    && state_well_formed(next)
                    && zero_approvals(next)
                    && ordered_policy(surface, next)
            }
            "approval_step" => {
                note_active(&inputs[0])
                    && note_active(&inputs[1])
                    && zero_native_accumulator(&inputs[0])
                    && note_kind(&inputs[1]) == "ordinary"
                    && zero_native_accumulator(&outputs[0])
                    && active_kind(&outputs[1], "ordinary")
                    && state_well_formed(current)
                    && state_well_formed(next)
                    && same_lineage(current, next)
                    && next.field("approval_count").number()
                        == current.field("approval_count").number() + 1
                    && approval_transition(surface)
                    && ordered_policy(surface, current)
            }
            "value_lock_creation" => {
                inputs.iter().any(note_active)
                    && note_active(&outputs[0])
                    && inputs.iter().all(|note| active_kind(note, "ordinary"))
                    && note_kind(&outputs[0]) == "value_lock"
                    && active_kind(&outputs[1], "ordinary")
                    && state_is_zero(next)
                    && state_well_formed(current)
                    && zero_approvals(current)
                    && ordered_policy(surface, current)
            }
            "final_threshold_spend" => {
                note_active(&inputs[0])
                    && note_active(&inputs[1])
                    && note_kind(&inputs[0]) == "value_lock"
                    && zero_native_accumulator(&inputs[1])
                    && outputs.iter().all(|note| active_kind(note, "ordinary"))
                    && state_is_zero(next)
                    && state_well_formed(current)
                    && current.field("intent_digest").number()
                        == surface.field("statement_intent").number()
                    && current.field("threshold").number()
                        <= current.field("approval_count").number()
                    && ordered_policy(surface, current)
            }
            mode => panic!("unknown authorization mode {mode}"),
        }
}

fn verify(statement: &FullStatement, witness: &FullWitness) -> bool {
    verify_relation_with_expected_activation(statement, witness, &statement.activation).is_ok()
}

fn signer_tags(member: Digest) -> [Digest; MAX_SIGNERS] {
    [
        [0x91; relation::DIGEST_BYTES],
        member,
        [0x93; relation::DIGEST_BYTES],
        [0; relation::DIGEST_BYTES],
        [0; relation::DIGEST_BYTES],
        [0; relation::DIGEST_BYTES],
    ]
}

fn accumulator_init_fixture() -> (FullStatement, FullWitness) {
    let (mut statement, mut witness) = mask_fixture(0b1111);
    witness.outputs[0].note.kind = NoteKind::Accumulator;
    witness.outputs[0].note.value = 0;
    witness.outputs[1].note.value = 199;
    let tags = signer_tags(witness.inputs[0].note.pk_auth);
    let next = AccumulatorOpening {
        policy_root: policy_root(2, 3, &tags),
        intent_digest: [0xd1; relation::DIGEST_BYTES],
        threshold: 2,
        signer_count: 3,
        approval_count: 0,
        approved_slots: [false; MAX_SIGNERS],
    };
    witness.auth = PrivateAuthWitness {
        mode: PrivateAuthMode::AccumulatorInit,
        current: AccumulatorOpening::zero(),
        next,
        signer_tags: tags,
    };
    witness.outputs[0].note.pk_auth = accumulator_digest(&witness.auth.next);
    refresh_derived_statement(&mut statement, &mut witness);
    (statement, witness)
}

fn approval_fixture() -> (FullStatement, FullWitness) {
    let (mut statement, mut witness) = mask_fixture(0b1111);
    witness.inputs[0].note.kind = NoteKind::Accumulator;
    witness.outputs[0].note.kind = NoteKind::Accumulator;
    witness.inputs[0].note.value = 0;
    witness.outputs[0].note.value = 0;
    witness.outputs[1].note.value = 99;
    let member = witness.inputs[1].note.pk_auth;
    let tags = signer_tags(member);
    let root = policy_root(2, 3, &tags);
    let current = AccumulatorOpening {
        policy_root: root,
        intent_digest: [0xc1; relation::DIGEST_BYTES],
        threshold: 2,
        signer_count: 3,
        approval_count: 1,
        approved_slots: [true, false, false, false, false, false],
    };
    let next = AccumulatorOpening {
        approval_count: 2,
        approved_slots: [true, true, false, false, false, false],
        ..current.clone()
    };
    witness.auth = PrivateAuthWitness {
        mode: PrivateAuthMode::ApprovalStep,
        current,
        next,
        signer_tags: tags,
    };
    witness.inputs[0].spend_key = [0; 48];
    witness.inputs[0].note.pk_auth = accumulator_digest(&witness.auth.current);
    witness.outputs[0].note.pk_auth = accumulator_digest(&witness.auth.next);
    refresh_derived_statement(&mut statement, &mut witness);
    (statement, witness)
}

fn value_lock_creation_fixture() -> (FullStatement, FullWitness) {
    let (mut statement, mut witness) = mask_fixture(0b1111);
    witness.outputs[0].note.kind = NoteKind::ValueLock;
    witness.outputs[0].note.value = 100;
    witness.outputs[1].note.value = 99;
    let tags = signer_tags(witness.inputs[0].note.pk_auth);
    let current = AccumulatorOpening {
        policy_root: policy_root(2, 3, &tags),
        intent_digest: [0xd2; relation::DIGEST_BYTES],
        threshold: 2,
        signer_count: 3,
        approval_count: 0,
        approved_slots: [false; MAX_SIGNERS],
    };
    witness.auth = PrivateAuthWitness {
        mode: PrivateAuthMode::ValueLockCreation,
        current,
        next: AccumulatorOpening::zero(),
        signer_tags: tags,
    };
    witness.outputs[0].note.pk_auth = value_lock_digest(
        witness.auth.current.policy_root,
        witness.auth.current.intent_digest,
    );
    refresh_derived_statement(&mut statement, &mut witness);
    (statement, witness)
}

fn final_fixture() -> (FullStatement, FullWitness) {
    let (mut statement, mut witness) = mask_fixture(0b1111);
    witness.inputs[0].note.kind = NoteKind::ValueLock;
    witness.inputs[1].note.kind = NoteKind::Accumulator;
    witness.inputs[1].note.value = 0;
    witness.outputs[0].note.value = 49;
    witness.outputs[1].note.value = 50;
    refresh_derived_statement(&mut statement, &mut witness);
    let tags = signer_tags([0x92; relation::DIGEST_BYTES]);
    let root = policy_root(2, 3, &tags);
    let intent = intent_digest(&statement);
    witness.auth = PrivateAuthWitness {
        mode: PrivateAuthMode::FinalThresholdSpend,
        current: AccumulatorOpening {
            policy_root: root,
            intent_digest: intent,
            threshold: 2,
            signer_count: 3,
            approval_count: 2,
            approved_slots: [true, true, false, false, false, false],
        },
        next: AccumulatorOpening::zero(),
        signer_tags: tags,
    };
    witness.inputs[0].spend_key = [0; 48];
    witness.inputs[1].spend_key = [0; 48];
    witness.inputs[0].note.pk_auth = value_lock_digest(root, intent);
    witness.inputs[1].note.pk_auth = accumulator_digest(&witness.auth.current);
    refresh_derived_statement(&mut statement, &mut witness);
    assert_eq!(intent_digest(&statement), intent);
    (statement, witness)
}

fn actual_auth_case(name: &str) -> bool {
    let (mut statement, mut witness) = match name {
        "single_key_valid" | "single_key_typed_state_forgery" => mask_fixture(0b1111),
        "accumulator_init_valid" | "accumulator_init_preapproved" => accumulator_init_fixture(),
        "approval_step_valid" | "duplicate_approval" | "approval_intent_lineage_change" => {
            approval_fixture()
        }
        "value_lock_creation_valid" => value_lock_creation_fixture(),
        "final_threshold_spend_valid"
        | "final_without_accumulator_input"
        | "final_below_threshold"
        | "final_wrong_intent" => final_fixture(),
        unknown => panic!("unmapped authorization vector {unknown}"),
    };
    match name {
        "single_key_valid"
        | "accumulator_init_valid"
        | "approval_step_valid"
        | "value_lock_creation_valid"
        | "final_threshold_spend_valid" => {}
        "single_key_typed_state_forgery" => {
            witness.outputs[0].note.kind = NoteKind::Accumulator;
            refresh_derived_statement(&mut statement, &mut witness);
        }
        "accumulator_init_preapproved" => {
            witness.auth.next.approval_count = 1;
            witness.auth.next.approved_slots[0] = true;
            witness.outputs[0].note.pk_auth = accumulator_digest(&witness.auth.next);
            refresh_derived_statement(&mut statement, &mut witness);
        }
        "duplicate_approval" => {
            witness.auth.current.approval_count = 2;
            witness.auth.current.approved_slots[1] = true;
            witness.auth.next.approval_count = 3;
            witness.auth.next.approved_slots[2] = true;
            witness.inputs[0].note.pk_auth = accumulator_digest(&witness.auth.current);
            witness.outputs[0].note.pk_auth = accumulator_digest(&witness.auth.next);
            refresh_derived_statement(&mut statement, &mut witness);
        }
        "approval_intent_lineage_change" => {
            witness.auth.next.intent_digest[0] ^= 1;
            witness.outputs[0].note.pk_auth = accumulator_digest(&witness.auth.next);
            refresh_derived_statement(&mut statement, &mut witness);
        }
        "final_without_accumulator_input" => {
            witness.inputs[1].note.kind = NoteKind::Ordinary;
            refresh_derived_statement(&mut statement, &mut witness);
        }
        "final_below_threshold" => {
            witness.auth.current.threshold = 3;
            witness.auth.current.policy_root = policy_root(3, 3, &witness.auth.signer_tags);
            witness.inputs[0].note.pk_auth = value_lock_digest(
                witness.auth.current.policy_root,
                witness.auth.current.intent_digest,
            );
            witness.inputs[1].note.pk_auth = accumulator_digest(&witness.auth.current);
            refresh_derived_statement(&mut statement, &mut witness);
        }
        "final_wrong_intent" => {
            witness.auth.current.intent_digest[0] ^= 1;
            witness.inputs[0].note.pk_auth = value_lock_digest(
                witness.auth.current.policy_root,
                witness.auth.current.intent_digest,
            );
            witness.inputs[1].note.pk_auth = accumulator_digest(&witness.auth.current);
            refresh_derived_statement(&mut statement, &mut witness);
        }
        unknown => panic!("unmapped authorization mutation {unknown}"),
    }
    verify(&statement, &witness)
}

fn stablecoin_fixture(mint: bool) -> (FullStatement, FullWitness) {
    let (mut statement, mut witness) = mask_fixture(0b1111);
    statement.balance_slot_asset_ids = [0, 7, u64::MAX, u64::MAX];
    witness.inputs[0].note.value = 100;
    witness.inputs[0].balance_slot_selectors = [true, false, false, false];
    witness.outputs[0].note.value = 99;
    witness.outputs[0].balance_slot_selectors = [true, false, false, false];
    witness.inputs[1].note.asset_id = 7;
    witness.inputs[1].note.value = if mint { 60 } else { 50 };
    witness.inputs[1].balance_slot_selectors = [false, true, false, false];
    witness.outputs[1].note.asset_id = 7;
    witness.outputs[1].note.value = if mint { 50 } else { 60 };
    witness.outputs[1].balance_slot_selectors = [false, true, false, false];
    statement.fee = 1;
    statement.stablecoin = StablecoinBinding {
        enabled: true,
        asset_id: 7,
        policy_version: 1,
        issuance_delta: SignedAmount {
            negative: !mint,
            magnitude: 10,
        },
        policy_hash: [0xb1; relation::DIGEST_BYTES],
        oracle_commitment: [0xb2; relation::DIGEST_BYTES],
        attestation_commitment: [0xb3; relation::DIGEST_BYTES],
    };
    refresh_derived_statement(&mut statement, &mut witness);
    (statement, witness)
}

fn actual_balance_case(name: &str) -> bool {
    let (mut statement, mut witness) = mask_fixture(0b1111);
    match name {
        "zero_delta_balanced" => {
            statement.fee = 0;
            witness.outputs[1].note.value += 1;
        }
        "zero_delta_hidden_mint" => {
            statement.fee = 0;
            witness.outputs[1].note.value += 2;
        }
        "positive_delta_fee" => {}
        // The generic negative row is realized by the stable-asset lane. The
        // production native row separately rejects a negative expected delta.
        "negative_delta_burn" => {
            let (stable_statement, stable_witness) = stablecoin_fixture(false);
            return verify(&stable_statement, &stable_witness);
        }
        "negative_zero" => {
            statement.value_balance = SignedAmount {
                negative: true,
                magnitude: 0,
            };
        }
        "input_out_of_range" => witness.inputs[0].note.value = MAX_NOTE_VALUE + 1,
        unknown => panic!("unmapped balance vector {unknown}"),
    }
    refresh_derived_statement(&mut statement, &mut witness);
    verify(&statement, &witness)
}

fn actual_stable_case(name: &str) -> bool {
    let (mut statement, mut witness) = match name {
        "enabled_mint_nonzero" => stablecoin_fixture(true),
        "enabled_burn_nonzero" | "enabled_zero" => stablecoin_fixture(false),
        _ => mask_fixture(0b1111),
    };
    match name {
        "disabled_zero" | "enabled_mint_nonzero" | "enabled_burn_nonzero" => {}
        "disabled_nonzero_issuance" => {
            statement.stablecoin.issuance_delta.magnitude = 1;
        }
        "enabled_zero" => statement.stablecoin.issuance_delta = SignedAmount::default(),
        "value_balance_nonzero" => statement.value_balance.magnitude = 1,
        "native_negative_delta" => {
            statement.fee = 0;
            witness.outputs[1].note.value += 2;
        }
        unknown => panic!("unmapped stable vector {unknown}"),
    }
    refresh_derived_statement(&mut statement, &mut witness);
    verify(&statement, &witness)
}

#[test]
fn lean_widths_and_all_activity_masks_match_the_scalar_oracle() {
    let root = vectors();
    assert_eq!(root.field("schema_version").number(), 1);
    assert_eq!(
        root.field("authority").string(),
        "finite Lean executable semantics; not a release certificate"
    );
    let widths = root.field("statement_widths");
    let component_names = [
        "magic",
        "grammar_version",
        "activity_flags",
        "anchor",
        "nullifiers",
        "commitments",
        "ciphertext_hashes",
        "balance_asset_slots",
        "fee",
        "value_balance",
        "stablecoin_binding",
        "balance_tag",
        "activation_binding",
    ];
    let digest = relation::DIGEST_BYTES as u64;
    let expected_component_widths = [
        8,
        2,
        4,
        digest,
        2 * digest,
        2 * digest,
        2 * digest,
        4 * 8,
        8,
        1 + 8,
        1 + 8 + 4 + (1 + 8) + 3 * digest,
        digest,
        4 * 2 + 8 + 8 + 32 + 48 + 48,
    ];
    for (name, expected) in component_names.into_iter().zip(expected_component_widths) {
        assert_eq!(widths.field(name).number(), expected, "width {name}");
    }
    let width_sum: u64 = component_names
        .into_iter()
        .map(|name| widths.field(name).number())
        .sum();
    assert_eq!(width_sum, widths.field("total").number());
    assert_eq!(width_sum as usize, relation::CANONICAL_STATEMENT_BYTES);
    assert_eq!(
        widths.field("digest").number() as usize,
        relation::DIGEST_BYTES
    );

    let (statement, _) = mask_fixture(0b1111);
    let encoded = relation::encode_canonical_statement(&statement).unwrap();
    assert_eq!(encoded.len(), width_sum as usize);
    assert_eq!(
        relation::decode_canonical_statement(&encoded).unwrap(),
        statement
    );

    let cases = root.field("activity_cases").array();
    assert_eq!(cases.len(), 16);
    for (expected_mask, case) in cases.iter().enumerate() {
        let mask = case.field("mask").number() as u8;
        assert_eq!(usize::from(mask), expected_mask);
        let input_flags = bools(case.field("input_flags"));
        let output_flags = bools(case.field("output_flags"));
        assert_eq!(input_flags, vec![mask & 1 != 0, mask & 2 != 0]);
        assert_eq!(output_flags, vec![mask & 4 != 0, mask & 8 != 0]);
        let independently_expected =
            input_flags.iter().any(|&flag| flag) && output_flags.iter().any(|&flag| flag);
        assert_eq!(
            case.field("expected_valid").boolean(),
            independently_expected
        );
        let (statement, witness) = mask_fixture(mask);
        assert_eq!(
            verify(&statement, &witness),
            independently_expected,
            "mask {mask}"
        );
    }
}

#[test]
fn lean_typed_authorization_vectors_match_model_and_real_scalar_cases() {
    let root = vectors();
    let cases = root.field("auth_cases").array();
    assert_eq!(cases.len(), 12);
    for case in cases {
        let name = case.field("name").string();
        let expected = case.field("expected_valid").boolean();
        assert_eq!(
            auth_surface_accepts(case),
            expected,
            "Lean model case {name}"
        );
        assert_eq!(actual_auth_case(name), expected, "Rust scalar case {name}");
    }
}

#[test]
fn lean_balance_and_stable_vectors_match_independent_rust_decisions() {
    let root = vectors();
    let balance_cases = root.field("balance_cases").array();
    assert_eq!(balance_cases.len(), 6);
    for case in balance_cases {
        let name = case.field("name").string();
        let expected = case.field("expected_valid").boolean();
        assert_eq!(balance_row_accepts(case.field("row")), expected, "{name}");
        assert_eq!(
            actual_balance_case(name),
            expected,
            "Rust scalar balance case {name}"
        );
    }

    let stable_cases = root.field("stable_cases").array();
    assert_eq!(stable_cases.len(), 7);
    for case in stable_cases {
        let name = case.field("name").string();
        let expected = case.field("expected_valid").boolean();
        assert_eq!(
            stable_surface_accepts(case),
            expected,
            "Lean stable case {name}"
        );
        assert_eq!(
            actual_stable_case(name),
            expected,
            "Rust scalar stable case {name}"
        );
    }
}

#[test]
fn vector_file_keeps_refinement_limits_explicit() {
    let root = vectors();
    let limits: BTreeSet<_> = root
        .field("refinement_limits")
        .array()
        .iter()
        .map(Json::string)
        .collect();
    assert_eq!(
        limits,
        BTreeSet::from([
            "finite_cases_only",
            "opaque_digest_values_not_shake256",
            "no_arbitrary_byte_parser_equivalence",
            "no_rust_or_m4_acceptance_iff_proof",
            "no_zero_knowledge_or_pq128_qrom_certificate",
        ])
    );
}
