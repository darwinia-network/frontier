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

use ark_bls12_377::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInt, PrimeField, Zero};
use ark_std::ops::Mul;
use fp_evm::{
	ExitError, ExitSucceed, Precompile, PrecompileFailure, PrecompileOutput, PrecompileResult,
};
use num_bigint::BigUint;

/// Gas discount table for BLS12-377 G1 and G2 multi exponentiation operations
const BLS12377_MULTIEXP_DISCOUNT_TABLE: [u16; 128] = [
	1200, 888, 764, 641, 594, 547, 500, 453, 438, 423, 408, 394, 379, 364, 349, 334, 330, 326, 322,
	318, 314, 310, 306, 302, 298, 294, 289, 285, 281, 277, 273, 269, 268, 266, 265, 263, 262, 260,
	259, 257, 256, 254, 253, 251, 250, 248, 247, 245, 244, 242, 241, 239, 238, 236, 235, 233, 232,
	231, 229, 228, 226, 225, 223, 222, 221, 220, 219, 219, 218, 217, 216, 216, 215, 214, 213, 213,
	212, 211, 211, 210, 209, 208, 208, 207, 206, 205, 205, 204, 203, 202, 202, 201, 200, 199, 199,
	198, 197, 196, 196, 195, 194, 193, 193, 192, 191, 191, 190, 189, 188, 188, 187, 186, 185, 185,
	184, 183, 182, 182, 181, 180, 179, 179, 178, 177, 176, 176, 175, 174,
];

fn serialize_fq(field: Fq) -> [u8; 48] {
	let mut result = [0u8; 48];

	let rep = field.into_bigint();

	result[0..8].copy_from_slice(&rep.0[5].to_be_bytes());
	result[8..16].copy_from_slice(&rep.0[4].to_be_bytes());
	result[16..24].copy_from_slice(&rep.0[3].to_be_bytes());
	result[24..32].copy_from_slice(&rep.0[2].to_be_bytes());
	result[32..40].copy_from_slice(&rep.0[1].to_be_bytes());
	result[40..48].copy_from_slice(&rep.0[0].to_be_bytes());

	result
}

fn serialize_g1(g1: G1Affine) -> [u8; 128] {
	let mut result = [0u8; 128];
	if !g1.is_zero() {
		let x_bytes = serialize_fq(g1.x);
		result[16..64].copy_from_slice(&x_bytes[..]);
		let y_bytes = serialize_fq(g1.y);
		result[80..128].copy_from_slice(&y_bytes[..]);
	}
	result
}

fn serialize_g2(g2: G2Affine) -> [u8; 256] {
	let mut result = [0u8; 256];
	if !g2.is_zero() {
		let x0_bytes = serialize_fq(g2.x.c0);
		result[16..64].copy_from_slice(&x0_bytes[..]);
		let x1_bytes = serialize_fq(g2.x.c1);
		result[80..128].copy_from_slice(&x1_bytes[..]);
		let y0_bytes = serialize_fq(g2.y.c0);
		result[144..192].copy_from_slice(&y0_bytes[..]);
		let y1_bytes = serialize_fq(g2.y.c1);
		result[208..256].copy_from_slice(&y1_bytes[..]);
	}
	result
}

/// Copy bytes from input to target.
fn read_input(source: &[u8], target: &mut [u8], offset: usize) {
	let len = target.len();
	target[..len].copy_from_slice(&source[offset..][..len]);
}

fn read_fr(input: &[u8], start_inx: usize) -> Result<Fr, PrecompileFailure> {
	let mut result = [0u8; 32];
	read_input(input, &mut result, start_inx);
	let fr_bn = BigInt::try_from(BigUint::from_bytes_be(&result)).map_err(|_| {
		PrecompileFailure::Error {
			exit_status: ExitError::Other("Invalid scalar".into()),
		}
	})?;
	match Fr::from_bigint(fr_bn) {
		None => Err(PrecompileFailure::Error {
			exit_status: ExitError::Other("Scalar is great than MODULUS".into()),
		}),
		Some(fr) => Ok(fr),
	}
}

fn read_g1(input: &[u8], start_inx: usize) -> Result<G1Projective, PrecompileFailure> {
	let mut px_buf = [0u8; 64];
	let mut py_buf = [0u8; 64];
	read_input(input, &mut px_buf, start_inx);
	read_input(input, &mut py_buf, start_inx + 64);

	let px_bn = BigInt::try_from(BigUint::from_bytes_be(&px_buf)).map_err(|_| {
		PrecompileFailure::Error {
			exit_status: ExitError::Other("Invalid point x coordinate".into()),
		}
	})?;
	let py_bn = BigInt::try_from(BigUint::from_bytes_be(&py_buf)).map_err(|_| {
		PrecompileFailure::Error {
			exit_status: ExitError::Other("Invalid point y coordinate".into()),
		}
	})?;

	let px = match Fq::from_bigint(px_bn) {
		None => {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("Point x coordinate is great than MODULUS".into()),
			})
		}
		Some(x) => x,
	};
	let py = match Fq::from_bigint(py_bn) {
		None => {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("Point y coordinate is great than MODULUS".into()),
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

fn read_g2(input: &[u8], start_inx: usize) -> Result<G2Projective, PrecompileFailure> {
	// TODO: check
	let mut px0_buf = [0u8; 64];
	let mut px1_buf = [0u8; 64];
	let mut py0_buf = [0u8; 64];
	let mut py1_buf = [0u8; 64];
	read_input(input, &mut px0_buf, start_inx);
	read_input(input, &mut px1_buf, start_inx + 64);
	read_input(input, &mut py0_buf, start_inx + 128);
	read_input(input, &mut py1_buf, start_inx + 192);

	let px0_bn = BigInt::try_from(BigUint::from_bytes_be(&px0_buf)).map_err(|_| {
		PrecompileFailure::Error {
			exit_status: ExitError::Other("Invalid point x0 coordinate".into()),
		}
	})?;
	let px1_bn = BigInt::try_from(BigUint::from_bytes_be(&px1_buf)).map_err(|_| {
		PrecompileFailure::Error {
			exit_status: ExitError::Other("Invalid point x1 coordinate".into()),
		}
	})?;
	let py0_bn = BigInt::try_from(BigUint::from_bytes_be(&py0_buf)).map_err(|_| {
		PrecompileFailure::Error {
			exit_status: ExitError::Other("Invalid point y1 coordinate".into()),
		}
	})?;
	let py1_bn = BigInt::try_from(BigUint::from_bytes_be(&py1_buf)).map_err(|_| {
		PrecompileFailure::Error {
			exit_status: ExitError::Other("Invalid point y1 coordinate".into()),
		}
	})?;

	let px0 = match Fq::from_bigint(px0_bn) {
		None => {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("Point x0 coordinate is great than MODULUS".into()),
			})
		}
		Some(x0) => x0,
	};
	let px1 = match Fq::from_bigint(px1_bn) {
		None => {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("Point x0 coordinate is great than MODULUS".into()),
			})
		}
		Some(x1) => x1,
	};
	let py0 = match Fq::from_bigint(py0_bn) {
		None => {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("Point y0 coordinate is great than MODULUS".into()),
			})
		}
		Some(y0) => y0,
	};
	let py1 = match Fq::from_bigint(py1_bn) {
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

		let p0 = read_g1(input, 0)?;
		let p1 = read_g1(input, 128)?;

		let sum = p0 + p1;

		let output = serialize_g1(sum.into_affine());

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

		let p = read_g1(input, 0)?;
		let scalar = read_fr(input, 128)?;
		let q = p.mul(scalar);

		let output = serialize_g1(q.into_affine());

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
		let k = input_len / 160;
		if k == 0 {
			return 0;
		}
		let d_len = BLS12377_MULTIEXP_DISCOUNT_TABLE.len();
		let discount = if k < d_len {
			BLS12377_MULTIEXP_DISCOUNT_TABLE[k - 1]
		} else {
			BLS12377_MULTIEXP_DISCOUNT_TABLE[d_len - 1]
		};
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
				exit_status: ExitError::Other("Input must contain 160 bytes".into()),
			});
		}

		let input = handle.input();

		let mut points = Vec::new();
		let mut scalars = Vec::new();
		for idx in 0..k {
			let offset = idx * 160;
			let p = read_g1(input, offset)?;
			let scalar = read_fr(input, offset + 128)?;
			points.push(p.into_affine());
			scalars.push(scalar);
		}

		let r = G1Projective::msm(&points.to_vec(), &scalars.to_vec()).map_err(|_| {
			PrecompileFailure::Error {
				exit_status: ExitError::Other("MSM failed".into()),
			}
		})?;

		let output = serialize_g1(r.into_affine());
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

		let p0 = read_g2(input, 0)?;
		let p1 = read_g2(input, 256)?;

		let sum = p0 + p1;

		let output = serialize_g2(sum.into_affine());

		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output: output.to_vec(),
		})
	}
}

/// bls12377G2Mul implements EIP-2539 G2Mul precompile.
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

		let p = read_g2(input, 0)?;
		let scalar = read_fr(input, 256)?;
		let q = p.mul(scalar);

		let output = serialize_g2(q.into_affine());

		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output: output.to_vec(),
		})
	}
}
