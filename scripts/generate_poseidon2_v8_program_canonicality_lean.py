#!/usr/bin/env python3
"""Emit bounded kernel certificates for the frozen HGV8RP03 CSR program.

The generator supplies data and ordinary Lean proofs.  It cannot assert that its
output passes: Lean checks each 32-record transition and the exact equality of
the complete attempt list with the independently materialized program.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from generate_poseidon2_v8_relation_program_components_lean import (
    DEFAULT_INPUT,
    ROOT,
    chunks,
    lean_nat_list,
    parse_components,
    render_attempt,
    render_descriptor,
)


DEFAULT_OUTPUT = (
    ROOT / "formal/crypto/HegemonCrypto/SmallWoodV8Smz9ProgramCanonicalityGenerated.lean"
)


def emit_csr_shard(program, shard_index: int) -> str:
    all_groups = list(chunks(program.csr_attempts, 32))
    first_group = shard_index * 16
    groups = all_groups[first_group : first_group + 16]
    if not groups:
        raise ValueError("CSR shard index is out of range")
    prefix = f"V8Smz9ProgramCanonicalityCsr{shard_index:02d}"
    lines = [
        "import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicality"
        + (f"Csr{shard_index - 1:02d}" if shard_index else ""),
        "",
        "/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/",
        f"namespace HegemonCrypto.SmallWood.{prefix}",
        "open Hegemon.Transaction.Poseidon2V8RelationProgram",
        "open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated",
        "open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality",
        "set_option Elab.async false",
        "set_option maxRecDepth 1000000",
        "set_option maxHeartbeats 0",
        "",
    ]
    counters = [0] * 86
    for item in program.csr_attempts[: first_group * 32]:
        counters[item.family] = item.local_index + 1
    lines.append(f"def counters000 : List Nat := {lean_nat_list(counters)}")
    for index, group in enumerate(groups):
        tag, next_tag = f"{index:03d}", f"{index + 1:03d}"
        start = (first_group + index) * 32
        for item in group:
            counters[item.family] = item.local_index + 1
        lines.extend(
            [
                f"def chunk{tag} : List CsrExecutableAttempt :=",
                "  [" + ", ".join(render_attempt(item) for item in group) + "]",
                f"def counters{next_tag} : List Nat := {lean_nat_list(counters)}",
                f"theorem chunk{tag}_checked :",
                f"    checkCsrFrom 565 exactLinearCsrCompilerFamilies {start}",
                f"        counters{tag} chunk{tag} = true ∧ chunk{tag}.length = {len(group)} ∧",
                f"      advanceCsrCounters counters{tag} chunk{tag} = counters{next_tag} := by decide",
                "",
            ]
        )
    last = f"{len(groups):03d}"
    end = min((first_group + len(groups)) * 32, len(program.csr_attempts))
    lines.extend(
        [
            f"def suffix{last} : List CsrExecutableAttempt := []",
            f"theorem suffix{last}_checked :",
            f"    checkCsrFrom 565 exactLinearCsrCompilerFamilies {end}",
            f"      counters{last} suffix{last} = true := by rfl",
            f"theorem suffix{last}_length : suffix{last}.length = 0 := by rfl",
            f"theorem suffix{last}_state : advanceCsrCounters counters{last} suffix{last} = counters{last} := by rfl",
            "",
        ]
    )
    for index in reversed(range(len(groups))):
        tag, next_tag = f"{index:03d}", f"{index + 1:03d}"
        start = (first_group + index) * 32
        next_start = min(start + 32, end)
        lines.extend(
            [
                f"def suffix{tag} : List CsrExecutableAttempt := chunk{tag} ++ suffix{next_tag}",
                f"theorem suffix{tag}_checked :",
                f"    checkCsrFrom 565 exactLinearCsrCompilerFamilies {start}",
                f"      counters{tag} suffix{tag} = true := by",
                f"  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies",
                f"    chunk{tag} suffix{next_tag} {start} {next_start} counters{tag} counters{next_tag}",
                f"    chunk{tag}_checked.1 (congrArg (Nat.add {start}) chunk{tag}_checked.2.1)",
                f"    chunk{tag}_checked.2.2 suffix{next_tag}_checked",
                f"theorem suffix{tag}_length : suffix{tag}.length = {end - start} := by",
                f"  rw [suffix{tag}, List.length_append, chunk{tag}_checked.2.1, suffix{next_tag}_length]",
                f"theorem suffix{tag}_state : advanceCsrCounters counters{tag} suffix{tag} = counters{last} := by",
                f"  rw [suffix{tag}, advanceCsrCounters_append, chunk{tag}_checked.2.2, suffix{next_tag}_state]",
                "",
            ]
        )
    names = [f"chunk{index:03d}" for index in range(len(groups))]
    suffixes = [f"suffix{index:03d}" for index in range(len(groups) + 1)]
    lines.extend(
        [
            f"def chunkList : List (List CsrExecutableAttempt) := [{', '.join(names)}]",
            "theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by",
            "  simp only [chunkList, " + ", ".join(suffixes)
            + ", List.flatten_cons, List.flatten_nil, List.append_nil]",
            "",
            f"end HegemonCrypto.SmallWood.{prefix}",
            "",
        ]
    )
    return "\n".join(lines)




def descriptor_groups(program):
    return [group for values in (program.public_descriptors, program.nonlinear_descriptors,
        program.csr_family_descriptors, program.hash_descriptors, program.binding_descriptors)
        for group in chunks(values, 32)]


def emit_descriptor_shard(program, index: int, csr_count: int) -> str:
    groups = descriptor_groups(program)[index * 6 : index * 6 + 6]
    previous = f"Csr{csr_count - 1:02d}" if index == 0 else f"Descriptors{index - 1:02d}"
    ns = f"V8Smz9ProgramCanonicalityDescriptors{index:02d}"
    lines = [f"import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicality{previous}", "",
        f"namespace HegemonCrypto.SmallWood.{ns}",
        "open Hegemon.Transaction.Poseidon2V8RelationProgram",
        "open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated",
        "open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality",
        "set_option Elab.async false", "set_option maxRecDepth 1000000",
        "set_option maxHeartbeats 0", ""]
    for i, group in enumerate(groups):
        lines.extend([f"def chunk{i:03d} : List ProgramDescriptor :=",
            "  [" + ", ".join(render_descriptor(d) for d in group) + "]",
            f"theorem chunk{i:03d}_checked : chunk{i:03d}.all checkDescriptor = true := by",
            f"  simp only [chunk{i:03d}, List.all_cons, List.all_nil, checkDescriptor,",
            "    descriptor, asciiBytes, asciiLabel, String.toList_ofList]",
            "  decide", ""])
    last = len(groups)
    lines.extend([f"def suffix{last:03d} : List ProgramDescriptor := []",
        f"theorem suffix{last:03d}_checked : suffix{last:03d}.all checkDescriptor = true := by rfl"])
    for i in reversed(range(last)):
        lines.extend([f"def suffix{i:03d} : List ProgramDescriptor := chunk{i:03d} ++ suffix{i+1:03d}",
            f"theorem suffix{i:03d}_checked : suffix{i:03d}.all checkDescriptor = true := by",
            f"  change (chunk{i:03d} ++ suffix{i+1:03d}).all checkDescriptor = true",
            f"  rw [List.all_append, chunk{i:03d}_checked, suffix{i+1:03d}_checked]", "  rfl"])
    lines.extend(["def chunkList : List (List ProgramDescriptor) := [" +
        ", ".join(f"chunk{i:03d}" for i in range(last)) + "]",
        "theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by",
        "  simp only [chunkList, " + ", ".join(f"suffix{i:03d}" for i in range(last + 1)) +
        ", List.flatten_cons, List.flatten_nil, List.append_nil]",
        f"end HegemonCrypto.SmallWood.{ns}", ""])
    return "\n".join(lines)


def emit_final(program, csr_count: int, descriptor_count: int) -> str:
    lines = [f"import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityDescriptors{descriptor_count-1:02d}", "",
        "/-! Generated composition of independently kernel-checked bounded certificates. -/",
        "namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityGenerated",
        "open Hegemon.Transaction.Poseidon2V8RelationProgram",
        "open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated",
        "open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality",
        "set_option Elab.async false", "set_option maxRecDepth 1000000",
        "set_option maxHeartbeats 0", ""]
    last_csr_ns = f"V8Smz9ProgramCanonicalityCsr{csr_count-1:02d}"
    last_chunks = (len(program.csr_attempts) + 31) // 32 - (csr_count - 1) * 16
    lines.extend([f"def csrTail{csr_count:03d} : List CsrExecutableAttempt := []",
        f"def csrChunks{csr_count:03d} : List (List CsrExecutableAttempt) := []",
        f"theorem csrTail{csr_count:03d}_checked :",
        f"    checkCsrFrom 565 exactLinearCsrCompilerFamilies {len(program.csr_attempts)}",
        f"      {last_csr_ns}.counters{last_chunks:03d} csrTail{csr_count:03d} = true := by rfl",
        f"theorem csrTail{csr_count:03d}_eq_chunks : csrTail{csr_count:03d} = csrChunks{csr_count:03d}.flatten := by rfl"])
    for i in reversed(range(csr_count)):
        ns = f"V8Smz9ProgramCanonicalityCsr{i:02d}"
        start = i * 512
        end = min(start + 512, len(program.csr_attempts))
        count = (end - start + 31) // 32
        lines.extend([f"def csrTail{i:03d} : List CsrExecutableAttempt := {ns}.suffix000 ++ csrTail{i+1:03d}",
            f"def csrChunks{i:03d} : List (List CsrExecutableAttempt) := {ns}.chunkList ++ csrChunks{i+1:03d}",
            f"theorem csrTail{i:03d}_checked :",
            f"    checkCsrFrom 565 exactLinearCsrCompilerFamilies {start}",
            f"      {ns}.counters000 csrTail{i:03d} = true := by",
            f"  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies",
            f"    {ns}.suffix000 csrTail{i+1:03d} {start} {end}",
            f"    {ns}.counters000 {ns}.counters{count:03d}",
            f"    {ns}.suffix000_checked (congrArg (Nat.add {start}) {ns}.suffix000_length)",
            f"    {ns}.suffix000_state csrTail{i+1:03d}_checked",
            f"theorem csrTail{i:03d}_eq_chunks : csrTail{i:03d} = csrChunks{i:03d}.flatten := by",
            f"  simp only [csrTail{i:03d}, csrChunks{i:03d}, List.flatten_append,",
            f"    {ns}.suffix_eq_flatten_chunks, csrTail{i+1:03d}_eq_chunks]", ""])
    lines.extend(["theorem csr_chunks_equal_materialized_attempts :",
        "    csrChunks000.flatten = exactCsrAttempts := by",
        "  unfold exactCsrAttempts", "  apply congrArg List.flatten", "  rfl",
        "theorem hgv8rp03_csr_check_passes :",
        "    checkCsr hgv8rp03ProgramComponents.csrExpressions.length",
        "      hgv8rp03ProgramComponents.linearCsrCompilerFamilies hgv8rp03ProgramComponents.csrAttempts = true := by",
        "  change checkCsrFrom 565 exactLinearCsrCompilerFamilies 0",
        "    V8Smz9ProgramCanonicalityCsr00.counters000 exactCsrAttempts = true",
        "  rw [← csr_chunks_equal_materialized_attempts, ← csrTail000_eq_chunks]",
        "  exact csrTail000_checked", ""])
    last = descriptor_count
    lines.extend([f"def descriptorTail{last:03d} : List ProgramDescriptor := []",
        f"def descriptorChunks{last:03d} : List (List ProgramDescriptor) := []",
        f"theorem descriptorTail{last:03d}_checked : descriptorTail{last:03d}.all checkDescriptor = true := by rfl",
        f"theorem descriptorTail{last:03d}_eq_chunks : descriptorTail{last:03d} = descriptorChunks{last:03d}.flatten := by rfl"])
    for i in reversed(range(last)):
        ns = f"V8Smz9ProgramCanonicalityDescriptors{i:02d}"
        lines.extend([f"def descriptorTail{i:03d} : List ProgramDescriptor := {ns}.suffix000 ++ descriptorTail{i+1:03d}",
            f"def descriptorChunks{i:03d} : List (List ProgramDescriptor) := {ns}.chunkList ++ descriptorChunks{i+1:03d}",
            f"theorem descriptorTail{i:03d}_checked : descriptorTail{i:03d}.all checkDescriptor = true := by",
            f"  change ({ns}.suffix000 ++ descriptorTail{i+1:03d}).all checkDescriptor = true",
            f"  rw [List.all_append, {ns}.suffix000_checked, descriptorTail{i+1:03d}_checked]", "  rfl",
            f"theorem descriptorTail{i:03d}_eq_chunks : descriptorTail{i:03d} = descriptorChunks{i:03d}.flatten := by",
            f"  simp only [descriptorTail{i:03d}, descriptorChunks{i:03d}, List.flatten_append,",
            f"    {ns}.suffix_eq_flatten_chunks, descriptorTail{i+1:03d}_eq_chunks]"])
    lines.extend(["theorem descriptor_chunks_equal_materialized_descriptors :",
        "    descriptorChunks000.flatten = hgv8rp03ProgramComponents.publicMapVersionDomain ++",
        "      hgv8rp03ProgramComponents.nonlinearIdentities ++ hgv8rp03ProgramComponents.linearCsrCompilerFamilies ++",
        "      hgv8rp03ProgramComponents.hashScheduleAndCallRoles ++ hgv8rp03ProgramComponents.bindingDescriptors := by",
        "  change descriptorChunks000.flatten = exactPublicMapVersionDomain ++ exactNonlinearIdentities ++",
        "    exactLinearCsrCompilerFamilies ++ exactHashScheduleAndCallRoles ++",
        "    V8Smz9RelationProgramComponentsGenerated.exactBindingDescriptors",
        "  unfold exactPublicMapVersionDomain exactNonlinearIdentities exactLinearCsrCompilerFamilies",
        "    exactHashScheduleAndCallRoles V8Smz9RelationProgramComponentsGenerated.exactBindingDescriptors",
        "  rw [← List.flatten_append, ← List.flatten_append, ← List.flatten_append, ← List.flatten_append]",
        "  apply congrArg List.flatten", "  rfl",
        "theorem hgv8rp03_descriptor_check_passes :",
        "    (hgv8rp03ProgramComponents.publicMapVersionDomain ++ hgv8rp03ProgramComponents.nonlinearIdentities ++",
        "      hgv8rp03ProgramComponents.linearCsrCompilerFamilies ++ hgv8rp03ProgramComponents.hashScheduleAndCallRoles ++",
        "      hgv8rp03ProgramComponents.bindingDescriptors).all checkDescriptor = true := by",
        "  rw [← descriptor_chunks_equal_materialized_descriptors, ← descriptorTail000_eq_chunks]",
        "  exact descriptorTail000_checked",
        "/-- Complete original canonicality predicate for the exact materialized program, without premises. -/",
        "theorem hgv8rp03_program_is_canonical : hgv8rp03ProgramComponents.Canonical :=",
        "  hgv8rp03_program_is_canonical_of_checked_csr hgv8rp03_csr_check_passes hgv8rp03_descriptor_check_passes",
        "",
        "end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityGenerated", ""])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--csr-shard", type=int)
    args = parser.parse_args()
    program = parse_components(args.input.read_bytes())
    if args.csr_shard is not None:
        outputs = {args.output: emit_csr_shard(program, args.csr_shard)}
    else:
        csr_count = (len(program.csr_attempts) + 511) // 512
        desc_count = (len(descriptor_groups(program)) + 5) // 6
        outputs = {args.output.parent / f"SmallWoodV8Smz9ProgramCanonicalityCsr{i:02d}.lean":
            emit_csr_shard(program, i) for i in range(csr_count)}
        outputs.update({args.output.parent / f"SmallWoodV8Smz9ProgramCanonicalityDescriptors{i:02d}.lean":
            emit_descriptor_shard(program, i, csr_count) for i in range(desc_count)})
        outputs[args.output] = emit_final(program, csr_count, desc_count)
    for path, source in outputs.items():
        if args.check:
            if path.read_text() != source:
                raise SystemExit(f"generated HGV8RP03 canonicality certificate is stale: {path}")
        else:
            path.write_text(source)
    print(f"{'Checked' if args.check else 'Generated'} {len(outputs)} certificate modules, "
        f"{sum(len(source.encode()) for source in outputs.values())} source bytes")


if __name__ == "__main__":
    main()
