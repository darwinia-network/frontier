// SPDX-License-Identifier: Apache-2.0
// This file is part of Frontier.
//
// Copyright (c) 2020-2022 Parity Technologies (UK) Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::*;
use pallet_evm_test_vector_support::test_precompile_test_vectors;

#[test]
fn process_consensus_tests_for_add_g1() -> Result<(), String> {
	test_precompile_test_vectors::<Bls12377G1Add>("../testdata/bls12377G1Add_matter.json")?;
	test_precompile_test_vectors::<Bls12377G1Add>("../testdata/bls12377G1Add_zexe.json")?;
	Ok(())
}

#[test]
fn process_consensus_tests_for_mul_g1() -> Result<(), String> {
	test_precompile_test_vectors::<Bls12377G1Mul>("../testdata/bls12377G1Mul_matter.json")?;
	test_precompile_test_vectors::<Bls12377G1Mul>("../testdata/bls12377G1Mul_zexe.json")?;
	Ok(())
}

#[test]
fn process_consensus_tests_for_multiexp_g1() -> Result<(), String> {
	// TODO:: matter tests
	// test_precompile_test_vectors::<Bls12377G1MultiExp>(
	// 	"../testdata/bls12377G1MultiExp_matter.json",
	// )?;
	test_precompile_test_vectors::<Bls12377G1MultiExp>("../testdata/bls12377G1MultiExp_zexe.json")?;
	Ok(())
}

#[test]
fn process_consensus_tests_for_add_g2() -> Result<(), String> {
	test_precompile_test_vectors::<Bls12377G2Add>("../testdata/bls12377G2Add_matter.json")?;
	test_precompile_test_vectors::<Bls12377G2Add>("../testdata/bls12377G2Add_zexe.json")?;
	Ok(())
}

#[test]
fn process_consensus_tests_for_mul_g2() -> Result<(), String> {
	test_precompile_test_vectors::<Bls12377G2Mul>("../testdata/bls12377G2Mul_matter.json")?;
	test_precompile_test_vectors::<Bls12377G2Mul>("../testdata/bls12377G2Mul_zexe.json")?;
	Ok(())
}

#[test]
fn process_consensus_tests_for_multiexp_g2() -> Result<(), String> {
	// TODO:: matter tests
	// test_precompile_test_vectors::<Bls12377G2MultiExp>(
	// 	"../testdata/bls12377G2MultiExp_matter.json",
	// )?;
	test_precompile_test_vectors::<Bls12377G2MultiExp>("../testdata/bls12377G2MultiExp_zexe.json")?;
	Ok(())
}

#[test]
fn process_consensus_tests_for_pairing() -> Result<(), String> {
	test_precompile_test_vectors::<Bls12377Pairing>("../testdata/bls12377Pairing_matter.json")?;
	test_precompile_test_vectors::<Bls12377Pairing>("../testdata/bls12377Pairing_zexe.json")?;
	Ok(())
}
