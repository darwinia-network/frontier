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

#![cfg_attr(not(feature = "std"), no_std)]

// Arkworks
use ark_bls12_377::{Bls12_377, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger384, PrimeField, Zero};
use ark_std::ops::Mul;

// Frontier
use fp_evm::{
	ExitError, ExitSucceed, Precompile, PrecompileFailure, PrecompileOutput, PrecompileResult,
};

/// Gas discount table for BLS12-377 G1 and G2 multi exponentiation operations.
const BLS12377_MULTIEXP_DISCOUNT_TABLE: [u16; 128] = [
	1200, 888, 764, 641, 594, 547, 500, 453, 438, 423, 408, 394, 379, 364, 349, 334, 330, 326, 322,
	318, 314, 310, 306, 302, 298, 294, 289, 285, 281, 277, 273, 269, 268, 266, 265, 263, 262, 260,
	259, 257, 256, 254, 253, 251, 250, 248, 247, 245, 244, 242, 241, 239, 238, 236, 235, 233, 232,
	231, 229, 228, 226, 225, 223, 222, 221, 220, 219, 219, 218, 217, 216, 216, 215, 214, 213, 213,
	212, 211, 211, 210, 209, 208, 208, 207, 206, 205, 205, 204, 203, 202, 202, 201, 200, 199, 199,
	198, 197, 196, 196, 195, 194, 193, 193, 192, 191, 191, 190, 189, 188, 188, 187, 186, 185, 185,
	184, 183, 182, 182, 181, 180, 179, 179, 178, 177, 176, 176, 175, 174,
];

/// Encode Fq as `64` bytes by performing Big-Endian encoding of the corresponding (unsigned) integer (top 16 bytes are always zeroes).
fn encode_fq(field: Fq) -> [u8; 64] {
	let mut result = [0u8; 64];

	let rep = field.into_bigint();

	result[16..24].copy_from_slice(&rep.0[5].to_be_bytes());
	result[24..32].copy_from_slice(&rep.0[4].to_be_bytes());
	result[32..40].copy_from_slice(&rep.0[3].to_be_bytes());
	result[40..48].copy_from_slice(&rep.0[2].to_be_bytes());
	result[48..56].copy_from_slice(&rep.0[1].to_be_bytes());
	result[56..64].copy_from_slice(&rep.0[0].to_be_bytes());

	result
}

// Encode point G1 as byte concatenation of encodings of the `x` and `y` affine coordinates.
fn encode_g1(g1: G1Affine) -> [u8; 128] {
	let mut result = [0u8; 128];
	if !g1.is_zero() {
		let x_bytes = encode_fq(g1.x);
		result[0..64].copy_from_slice(&x_bytes[..]);
		let y_bytes = encode_fq(g1.y);
		result[64..128].copy_from_slice(&y_bytes[..]);
	}
	result
}

// Encode point G2 as byte concatenation of encodings of the `x` and `y` affine coordinates.
fn encode_g2(g2: G2Affine) -> [u8; 256] {
	let mut result = [0u8; 256];
	if !g2.is_zero() {
		let x0_bytes = encode_fq(g2.x.c0);
		result[0..64].copy_from_slice(&x0_bytes[..]);
		let x1_bytes = encode_fq(g2.x.c1);
		result[64..128].copy_from_slice(&x1_bytes[..]);
		let y0_bytes = encode_fq(g2.y.c0);
		result[128..192].copy_from_slice(&y0_bytes[..]);
		let y1_bytes = encode_fq(g2.y.c1);
		result[192..256].copy_from_slice(&y1_bytes[..]);
	}
	result
}

/// Copy bytes from source.offset to target.
fn read_input(source: &[u8], target: &mut [u8], offset: usize) {
	let len = target.len();
	target[..len].copy_from_slice(&source[offset..][..len]);
}

/// Decode Fr expects 32 byte input, returns fr in scalar field.
fn decode_fr(input: &[u8], offset: usize) -> Fr {
	let mut bytes = [0u8; 32];
	read_input(input, &mut bytes, offset);
	Fr::from_be_bytes_mod_order(&bytes)
}

/// Decode Fq expects 64 byte input with zero top 16 bytes,
/// returns Fq in base field.
fn decode_fq(bytes: [u8; 64]) -> Option<Fq> {
	// check top bytes
	for i in 0..16 {
		if bytes[i] != 0 {
			return None;
		}
	}

	let mut tmp = BigInteger384::new([0, 0, 0, 0, 0, 0]);
	// Note: The following unwraps are if the compiler cannot convert
	// the byte slice into [u8;8], we know this is infallible since we
	// are providing the indices at compile time and bytes has a fixed size
	tmp.0[5] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap());
	tmp.0[4] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap());
	tmp.0[3] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[32..40]).unwrap());
	tmp.0[2] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[40..48]).unwrap());
	tmp.0[1] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[48..56]).unwrap());
	tmp.0[0] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[56..64]).unwrap());

	Fq::from_bigint(tmp)
}

/// Decode G1 given encoded (x, y) coordinates in 128 bytes returns a valid G1 Point.
fn decode_g1(input: &[u8], offset: usize) -> Result<G1Projective, PrecompileFailure> {
	let mut px_buf = [0u8; 64];
	let mut py_buf = [0u8; 64];
	read_input(input, &mut px_buf, offset);
	read_input(input, &mut py_buf, offset + 64);

	let px = match decode_fq(px_buf) {
		None => {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("invliad x coordinate".into()),
			})
		}
		Some(x) => x,
	};
	let py = match decode_fq(py_buf) {
		None => {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("invliad y coordinate".into()),
			})
		}
		Some(y) => y,
	};

	if px.is_zero() && py.is_zero() {
		Ok(G1Projective::zero())
	} else {
		let g1 = G1Affine::new_unchecked(px, py);
		if !g1.is_on_curve() || !g1.is_in_correct_subgroup_assuming_on_curve() {
			Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("Point is not on curve".into()),
			})
		} else {
			Ok(g1.into())
		}
	}
}

// Decode G2 given encoded (x, y) coordinates in 256 bytes returns a valid G2 Point.
fn decode_g2(input: &[u8], start_inx: usize) -> Result<G2Projective, PrecompileFailure> {
	let mut px0_buf = [0u8; 64];
	let mut px1_buf = [0u8; 64];
	let mut py0_buf = [0u8; 64];
	let mut py1_buf = [0u8; 64];
	read_input(input, &mut px0_buf, start_inx);
	read_input(input, &mut px1_buf, start_inx + 64);
	read_input(input, &mut py0_buf, start_inx + 128);
	read_input(input, &mut py1_buf, start_inx + 192);

	let px0 = match decode_fq(px0_buf) {
		None => {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("Point x0 coordinate is great than MODULUS".into()),
			})
		}
		Some(x0) => x0,
	};
	let px1 = match decode_fq(px1_buf) {
		None => {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("Point x0 coordinate is great than MODULUS".into()),
			})
		}
		Some(x1) => x1,
	};
	let py0 = match decode_fq(py0_buf) {
		None => {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("Point y0 coordinate is great than MODULUS".into()),
			})
		}
		Some(y0) => y0,
	};
	let py1 = match decode_fq(py1_buf) {
		None => {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("Point y1 coordinate is great than MODULUS".into()),
			})
		}
		Some(y1) => y1,
	};
	let px = Fq2::new(px0, px1);
	let py = Fq2::new(py0, py1);

	if px.is_zero() && py.is_zero() {
		Ok(G2Projective::zero())
	} else {
		let g2 = G2Affine::new_unchecked(px, py);
		if !g2.is_on_curve() || !g2.is_in_correct_subgroup_assuming_on_curve() {
			Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("Point is not on curve".into()),
			})
		} else {
			Ok(g2.into())
		}
	}
}

/// bls12377G1Add implements EIP-2539 G1Add precompile.
pub struct BLS12377G1Add;

impl BLS12377G1Add {
	/// https://eips.ethereum.org/EIPS/eip-2539#g1-addition
	const GAS_COST: u64 = 600;
}

impl Precompile for BLS12377G1Add {
	/// Implements EIP-2539 G1Add precompile.
	/// > G1 addition call expects `256` bytes as an input that is interpreted as byte concatenation of two G1 points (`128` bytes each).
	/// > Output is an encoding of addition operation result - single G1 point (`128` bytes).
	fn execute(handle: &mut impl fp_evm::PrecompileHandle) -> PrecompileResult {
		handle.record_cost(BLS12377G1Add::GAS_COST)?;

		let input = handle.input();
		if input.len() != 256 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("Input must contain 256 bytes".into()),
			});
		}

		// Decode G1 point p_0
		let p0 = decode_g1(input, 0)?;
		// Decode G1 point p_1
		let p1 = decode_g1(input, 128)?;
		// Compute r = p_0 + p_1
		let r = p0 + p1;
		// Encode the G1 point into 128 bytes output
		let output = encode_g1(r.into_affine());

		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output: output.to_vec(),
		})
	}
}

/// BLS12377G1Mul implements EIP-2539 G1Mul precompile.
pub struct BLS12377G1Mul;

impl BLS12377G1Mul {
	/// https://eips.ethereum.org/EIPS/eip-2539#g1-multiplication
	const GAS_COST: u64 = 12_000;
}

impl Precompile for BLS12377G1Mul {
	/// Implements EIP-2539 G1Mul precompile.
	/// > G1 multiplication call expects `160` bytes as an input that is interpreted as byte concatenation of encoding of G1 point (`128` bytes) and encoding of a scalar value (`32` bytes).
	/// > Output is an encoding of multiplication operation result - single G1 point (`128` bytes).
	fn execute(handle: &mut impl fp_evm::PrecompileHandle) -> PrecompileResult {
		handle.record_cost(BLS12377G1Mul::GAS_COST)?;

		let input = handle.input();
		if input.len() != 160 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("Input must contain 160 bytes".into()),
			});
		}

		// Decode G1 point
		let p = decode_g1(input, 0)?;
		// Decode scalar value
		let e = decode_fr(input, 128);
		// Compute r =  = e * p
		let r = p.mul(e);
		// Encode the G1 point into 128 bytes output
		let output = encode_g1(r.into_affine());

		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output: output.to_vec(),
		})
	}
}

/// BLS12377G1MultiExp implements EIP-2539 G1MultiExp precompile.
pub struct BLS12377G1MultiExp;

impl BLS12377G1MultiExp {
	const MULTIPLIER: u64 = 1_000;

	/// Returns the gas required to execute the pre-compiled contract.
	fn calculate_gas_cost(input_len: usize) -> u64 {
		// Calculate G1 point, scalar value pair length
		let k = input_len / 160;
		if k == 0 {
			return 0;
		}
		// Lookup discount value for G1 point, scalar value pair length
		let d_len = BLS12377_MULTIEXP_DISCOUNT_TABLE.len();
		let discount = if k < d_len {
			BLS12377_MULTIEXP_DISCOUNT_TABLE[k - 1]
		} else {
			BLS12377_MULTIEXP_DISCOUNT_TABLE[d_len - 1]
		};
		// Calculate gas and return the result
		k as u64 * BLS12377G1Mul::GAS_COST * discount as u64 / BLS12377G1MultiExp::MULTIPLIER
	}
}

impl Precompile for BLS12377G1MultiExp {
	/// Implements EIP-2539 G1MultiExp precompile.
	/// G1 multiplication call expects `160*k` bytes as an input that is interpreted as byte concatenation of `k` slices each of them being a byte concatenation of encoding of G1 point (`128` bytes) and encoding of a scalar value (`32` bytes).
	/// Output is an encoding of multiexponentiation operation result - single G1 point (`128` bytes).
	fn execute(handle: &mut impl fp_evm::PrecompileHandle) -> PrecompileResult {
		let gas_cost = BLS12377G1MultiExp::calculate_gas_cost(handle.input().len());
		handle.record_cost(gas_cost)?;

		let k = handle.input().len() / 160;
		if handle.input().is_empty() || handle.input().len() % 160 != 0 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("Input input length".into()),
			});
		}

		let input = handle.input();

		let mut points = Vec::new();
		let mut scalars = Vec::new();
		// Decode point scalar pairs
		for idx in 0..k {
			let offset = idx * 160;
			// Decode G1 point
			let p = decode_g1(input, offset)?;
			// Decode scalar value
			let scalar = decode_fr(input, offset + 128);
			points.push(p.into_affine());
			scalars.push(scalar);
		}

		// Compute r = e_0 * p_0 + e_1 * p_1 + ... + e_(k-1) * p_(k-1)
		let r = G1Projective::msm(&points.to_vec(), &scalars.to_vec()).map_err(|_| {
			PrecompileFailure::Error {
				exit_status: ExitError::Other("MSM failed".into()),
			}
		})?;

		// Encode the G1 point into 128 bytes output
		let output = encode_g1(r.into_affine());
		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output: output.to_vec(),
		})
	}
}

/// bls12377G2Add implements EIP-2539 G2Add precompile.
pub struct BLS12377G2Add;

impl BLS12377G2Add {
	/// https://eips.ethereum.org/EIPS/eip-2539#g2-addition
	const GAS_COST: u64 = 4_500;
}

impl Precompile for BLS12377G2Add {
	/// Implements EIP-2539 G2Add precompile.
	/// > G2 addition call expects `512` bytes as an input that is interpreted as byte concatenation of two G2 points (`256` bytes each).
	/// > Output is an encoding of addition operation result - single G2 point (`256` bytes).
	fn execute(handle: &mut impl fp_evm::PrecompileHandle) -> PrecompileResult {
		handle.record_cost(BLS12377G2Add::GAS_COST)?;

		let input = handle.input();
		if input.len() != 512 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("Input must contain 512 bytes".into()),
			});
		}

		// Decode G2 point p_0
		let p0 = decode_g2(input, 0)?;
		// Decode G2 point p_1
		let p1 = decode_g2(input, 256)?;
		// Compute r = p_0 + p_1
		let r = p0 + p1;
		// Encode the G2 point into 256 bytes output
		let output = encode_g2(r.into_affine());

		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output: output.to_vec(),
		})
	}
}

/// BLS12377G2Mul implements EIP-2539 G2Mul precompile.
pub struct BLS12377G2Mul;

impl BLS12377G2Mul {
	// https://eips.ethereum.org/EIPS/eip-2539#g2-multiplication
	const GAS_COST: u64 = 55_000;
}

impl Precompile for BLS12377G2Mul {
	/// Implements EIP-2539 G2MUL precompile logic.
	/// > G2 multiplication call expects `288` bytes as an input that is interpreted as byte concatenation of encoding of G2 point (`256` bytes) and encoding of a scalar value (`32` bytes).
	/// > Output is an encoding of multiplication operation result - single G2 point (`256` bytes).
	fn execute(handle: &mut impl fp_evm::PrecompileHandle) -> PrecompileResult {
		handle.record_cost(BLS12377G2Mul::GAS_COST)?;

		let input = handle.input();
		if input.len() != 288 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("Input must contain 288 bytes".into()),
			});
		}

		// Decode G2 point
		let p = decode_g2(input, 0)?;
		// Decode scalar value
		let e = decode_fr(input, 256);
		// Compute r = e * p
		let r = p.mul(e);
		// Encode the G2 point into 256 bytes output
		let output = encode_g2(r.into_affine());

		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output: output.to_vec(),
		})
	}
}

// BLS12377G2MultiExp implements EIP-2539 G2MultiExp precompile.
pub struct BLS12377G2MultiExp;

impl BLS12377G2MultiExp {
	const MULTIPLIER: u64 = 1_000;

	/// Returns the gas required to execute the pre-compiled contract.
	fn calculate_gas_cost(input_len: usize) -> u64 {
		// Calculate G2 point, scalar value pair length
		let k = input_len / 288;
		if k == 0 {
			return 0;
		}
		// Lookup discount value for G2 point, scalar value pair length
		let d_len = BLS12377_MULTIEXP_DISCOUNT_TABLE.len();
		let discount = if k < d_len {
			BLS12377_MULTIEXP_DISCOUNT_TABLE[k - 1]
		} else {
			BLS12377_MULTIEXP_DISCOUNT_TABLE[d_len - 1]
		};
		// Calculate gas and return the result
		k as u64 * BLS12377G2Mul::GAS_COST * discount as u64 / BLS12377G2MultiExp::MULTIPLIER
	}
}

impl Precompile for BLS12377G2MultiExp {
	/// Implements EIP-2539 G2MultiExp precompile logic
	/// > G2 multiplication call expects `288*k` bytes as an input that is interpreted as byte concatenation of `k` slices each of them being a byte concatenation of encoding of G2 point (`256` bytes) and encoding of a scalar value (`32` bytes).
	/// > Output is an encoding of multiexponentiation operation result - single G2 point (`256` bytes).
	fn execute(handle: &mut impl fp_evm::PrecompileHandle) -> PrecompileResult {
		let gas_cost = BLS12377G2MultiExp::calculate_gas_cost(handle.input().len());
		handle.record_cost(gas_cost)?;

		let k = handle.input().len() / 288;
		if handle.input().is_empty() || handle.input().len() % 288 != 0 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("Input input length".into()),
			});
		}

		let input = handle.input();

		let mut points = Vec::new();
		let mut scalars = Vec::new();
		// Decode point scalar pairs
		for idx in 0..k {
			let offset = idx * 288;
			// Decode G2 point
			let p = decode_g2(input, offset)?;
			// Decode scalar value
			let scalar = decode_fr(input, offset + 256);
			points.push(p.into_affine());
			scalars.push(scalar);
		}

		// Compute r = e_0 * p_0 + e_1 * p_1 + ... + e_(k-1) * p_(k-1)
		let r = G2Projective::msm(&points.to_vec(), &scalars.to_vec()).map_err(|_| {
			PrecompileFailure::Error {
				exit_status: ExitError::Other("MSM failed".into()),
			}
		})?;

		// Encode the G2 point to 256 bytes output
		let output = encode_g2(r.into_affine());
		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output: output.to_vec(),
		})
	}
}

/// BLS12377Pairing implements EIP-2539 Pairing precompile.
pub struct BLS12377Pairing;

impl BLS12377Pairing {
	/// https://eips.ethereum.org/EIPS/eip-2539#pairing-operation
	const BASE_GAS: u64 = 65000;
	const PER_PAIR_GAS: u64 = 55000;
}

impl Precompile for BLS12377Pairing {
	/// Implements EIP-2539 Pairing precompile logic.
	/// > Pairing call expects `384*k` bytes as an inputs that is interpreted as byte concatenation of `k` slices. Each slice has the following structure:
	/// > - `128` bytes of G1 point encoding
	/// > - `256` bytes of G2 point encoding
	/// > Output is a `32` bytes where last single byte is `0x01` if pairing result is equal to multiplicative identity in a pairing target field and `0x00` otherwise
	/// > (which is equivalent of Big Endian encoding of Solidity values `uint256(1)` and `uin256(0)` respectively).
	fn execute(handle: &mut impl fp_evm::PrecompileHandle) -> PrecompileResult {
		if handle.input().is_empty() || handle.input().len() % 384 != 0 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("Input input length".into()),
			});
		}

		let k = handle.input().len() / 384;
		let gas_cost: u64 = BLS12377Pairing::BASE_GAS + (k as u64 * BLS12377Pairing::PER_PAIR_GAS);

		handle.record_cost(gas_cost)?;

		let input = handle.input();

		let mut a = Vec::new();
		let mut b = Vec::new();
		// Decode G1 G2 pairs
		for idx in 0..k {
			let offset = idx * 384;
			// Decode G1 point
			let g1 = decode_g1(input, offset)?;
			// Decode G2 point
			let g2 = decode_g2(input, offset + 128)?;
			a.push(g1);
			b.push(g2);
		}

		let mut output = [0u8; 32];
		// Compute pairing and set the output
		if Bls12_377::multi_pairing(a, b).is_zero() {
			output[31] = 1;
		}

		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output: output.to_vec(),
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use pallet_evm_test_vector_support::test_precompile_test_vectors;

	#[test]
	fn process_consensus_tests_for_add_g1() -> Result<(), String> {
		test_precompile_test_vectors::<BLS12377G1Add>("../testdata/bls12377G1Add_matter.json")?;
		test_precompile_test_vectors::<BLS12377G1Add>("../testdata/bls12377G1Add_zexe.json")?;
		Ok(())
	}

	#[test]
	fn process_consensus_tests_for_mul_g1() -> Result<(), String> {
		test_precompile_test_vectors::<BLS12377G1Mul>("../testdata/bls12377G1Mul_matter.json")?;
		test_precompile_test_vectors::<BLS12377G1Mul>("../testdata/bls12377G1Mul_zexe.json")?;
		Ok(())
	}

	#[test]
	fn process_consensus_tests_for_multiexp_g1() -> Result<(), String> {
		// TODO:: matter tests
		// test_precompile_test_vectors::<BLS12377G1MultiExp>(
		// 	"../testdata/bls12377G1MultiExp_matter.json",
		// )?;
		test_precompile_test_vectors::<BLS12377G1MultiExp>(
			"../testdata/bls12377G1MultiExp_zexe.json",
		)?;
		Ok(())
	}

	#[test]
	fn process_consensus_tests_for_add_g2() -> Result<(), String> {
		test_precompile_test_vectors::<BLS12377G2Add>("../testdata/bls12377G2Add_matter.json")?;
		test_precompile_test_vectors::<BLS12377G2Add>("../testdata/bls12377G2Add_zexe.json")?;
		Ok(())
	}

	#[test]
	fn process_consensus_tests_for_mul_g2() -> Result<(), String> {
		test_precompile_test_vectors::<BLS12377G2Mul>("../testdata/bls12377G2Mul_matter.json")?;
		test_precompile_test_vectors::<BLS12377G2Mul>("../testdata/bls12377G2Mul_zexe.json")?;
		Ok(())
	}

	#[test]
	fn process_consensus_tests_for_multiexp_g2() -> Result<(), String> {
		// TODO:: matter tests
		// test_precompile_test_vectors::<BLS12377G2MultiExp>(
		// 	"../testdata/bls12377G2MultiExp_matter.json",
		// )?;
		test_precompile_test_vectors::<BLS12377G2MultiExp>(
			"../testdata/bls12377G2MultiExp_zexe.json",
		)?;
		Ok(())
	}

	#[test]
	fn process_consensus_tests_for_pairing() -> Result<(), String> {
		test_precompile_test_vectors::<BLS12377Pairing>("../testdata/bls12377Pairing_matter.json")?;
		test_precompile_test_vectors::<BLS12377Pairing>("../testdata/bls12377Pairing_zexe.json")?;
		Ok(())
	}
}
