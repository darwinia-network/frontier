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

use ark_bls12_377::{Fq, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInt, PrimeField, Zero};
use fp_evm::{
	ExitError, ExitSucceed, Precompile, PrecompileFailure, PrecompileOutput, PrecompileResult,
};
use num_bigint::BigUint;

pub(crate) fn serialize_fq(field: Fq) -> [u8; 48] {
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

/// Copy bytes from input to target.
fn read_input(source: &[u8], target: &mut [u8], offset: usize) {
	let len = target.len();
	target[..len].copy_from_slice(&source[offset..][..len]);
}

fn read_point(input: &[u8], start_inx: usize) -> Result<G1Projective, PrecompileFailure> {
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

		let p0 = read_point(input, 0)?;
		let p1 = read_point(input, 128)?;

		let mut output = [0u8; 128];
		let sum = (p0 + p1).into_affine();

		if !sum.is_zero() {
			let x_bytes = serialize_fq(sum.x);
			output[16..64].copy_from_slice(&x_bytes[..]);
			let y_bytes = serialize_fq(sum.y);
			output[80..128].copy_from_slice(&y_bytes[..]);
		}

		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output: output.to_vec(),
		})
	}
}
