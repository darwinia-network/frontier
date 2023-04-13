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

use ark_bw6_761::{Fq, Fr, G1Affine, G1Projective, G2Affine, G2Projective, BW6_761};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger768, PrimeField, Zero};
use ark_std::ops::Mul;

use fp_evm::{
	ExitError, ExitSucceed, Precompile, PrecompileFailure, PrecompileOutput, PrecompileResult,
};

/// Encode Fq as `96` bytes by performing Big-Endian encoding of the corresponding (unsigned) integer (top 16 bytes are always zeroes).
fn encode_fq(field: Fq) -> [u8; 96] {
	let mut result = [0u8; 96];
	let rep = field.into_bigint();

	result[0..8].copy_from_slice(&rep.0[11].to_be_bytes());
	result[8..16].copy_from_slice(&rep.0[10].to_be_bytes());
	result[16..24].copy_from_slice(&rep.0[9].to_be_bytes());
	result[24..32].copy_from_slice(&rep.0[8].to_be_bytes());
	result[32..40].copy_from_slice(&rep.0[7].to_be_bytes());
	result[40..48].copy_from_slice(&rep.0[6].to_be_bytes());
	result[48..56].copy_from_slice(&rep.0[5].to_be_bytes());
	result[56..64].copy_from_slice(&rep.0[4].to_be_bytes());
	result[64..72].copy_from_slice(&rep.0[3].to_be_bytes());
	result[72..80].copy_from_slice(&rep.0[2].to_be_bytes());
	result[80..88].copy_from_slice(&rep.0[1].to_be_bytes());
	result[88..96].copy_from_slice(&rep.0[0].to_be_bytes());

	result
}

/// Encode point G1 as byte concatenation of encodings of the `x` and `y` affine coordinates.
fn encode_g1(g1: G1Affine) -> [u8; 192] {
	let mut result = [0u8; 192];
	if !g1.is_zero() {
		let x_bytes = encode_fq(g1.x);
		result[0..96].copy_from_slice(&x_bytes[..]);
		let y_bytes = encode_fq(g1.y);
		result[96..192].copy_from_slice(&y_bytes[..]);
	}
	result
}

/// Copy bytes from source.offset to target.
fn read_input(source: &[u8], target: &mut [u8], offset: usize) {
	let len = target.len();
	target[..len].copy_from_slice(&source[offset..][..len]);
}

/// Decode Fr expects 64 byte input, returns fr in scalar field.
fn decode_fr(input: &[u8], offset: usize) -> Fr {
	let mut bytes = [0u8; 64];
	read_input(input, &mut bytes, offset);
	Fr::from_be_bytes_mod_order(&bytes)
}

/// Decode Fq expects 96 byte input,
/// returns Fq in base field.
fn decode_fq(bytes: [u8; 96]) -> Option<Fq> {
	let mut tmp = BigInteger768::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
	// Note: The following unwraps are if the compiler cannot convert
	// the byte slice into [u8;8], we know this is infallible since we
	// are providing the indices at compile time and bytes has a fixed size
	tmp.0[11] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[88..96]).unwrap());
	tmp.0[10] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[80..88]).unwrap());
	tmp.0[9] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[72..80]).unwrap());
	tmp.0[8] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[64..72]).unwrap());
	tmp.0[7] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[56..64]).unwrap());
	tmp.0[6] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[48..56]).unwrap());
	tmp.0[5] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[40..48]).unwrap());
	tmp.0[4] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[32..40]).unwrap());
	tmp.0[3] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap());
	tmp.0[2] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap());
	tmp.0[1] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap());
	tmp.0[0] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[0..8]).unwrap());

	Fq::from_bigint(tmp)
}

fn extract_fq(bytes: [u8; 96]) -> Result<Fq, PrecompileFailure> {
	let fq = decode_fq(bytes);
	match fq {
		None => Err(PrecompileFailure::Error {
			exit_status: ExitError::Other("invliad Fq".into()),
		}),
		Some(c) => Ok(c),
	}
}

/// Decode G1 given encoded (x, y) coordinates in 128 bytes returns a valid G1 Point.
fn decode_g1(input: &[u8], offset: usize) -> Result<G1Projective, PrecompileFailure> {
	let mut px_buf = [0u8; 96];
	let mut py_buf = [0u8; 96];
	read_input(input, &mut px_buf, offset);
	read_input(input, &mut py_buf, offset + 96);

	// Decode x
	let px = extract_fq(px_buf)?;
	// Decode y
	let py = extract_fq(py_buf)?;

	// Check if given input points to infinity
	if px.is_zero() && py.is_zero() {
		Ok(G1Projective::zero())
	} else {
		let g1 = G1Affine::new_unchecked(px, py);
		if !g1.is_on_curve() {
			Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("point is not on curve".into()),
			})
		} else {
			Ok(g1.into())
		}
	}
}

/// Bw6761G1Add implements EIP-3026 G1Add precompile.
pub struct Bw6761G1Add;

impl Bw6761G1Add {
	// TODO::to be estimated
	const GAS_COST: u64 = 0;
}

impl Precompile for Bw6761G1Add {
	/// Implements EIP-3026 G1Add precompile.
	/// > G1 addition call expects `384` bytes as an input that is interpreted as byte concatenation of two G1 points (`192` bytes each).
	/// > Output is an encoding of addition operation result - single G1 point (`192` bytes).
	fn execute(handle: &mut impl fp_evm::PrecompileHandle) -> PrecompileResult {
		handle.record_cost(Bw6761G1Add::GAS_COST)?;

		let input = handle.input();
		if input.len() != 384 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("invalid input length".into()),
			});
		}

		// Decode G1 point p_0
		let p0 = decode_g1(input, 0)?;
		// Decode G1 point p_1
		let p1 = decode_g1(input, 192)?;
		// Compute r = p_0 + p_1
		let r = p0 + p1;
		// Encode the G1 point into 192 bytes output
		let output = encode_g1(r.into_affine());

		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output: output.to_vec(),
		})
	}
}

/// Bw6761G1Mul implements EIP-3026 G1Mul precompile.
pub struct Bw6761G1Mul;

impl Bw6761G1Mul {
	// TODO::to be estimated
	const GAS_COST: u64 = 0;
}

impl Precompile for Bw6761G1Mul {
	/// Implements EIP-3026 G1Mul precompile.
	/// > G1 multiplication call expects `256` bytes as an input that is interpreted as byte concatenation of encoding of G1 point (`192` bytes) and encoding of a scalar value (`64` bytes).
	/// > Output is an encoding of multiplication operation result - single G1 point (`192` bytes).
	fn execute(handle: &mut impl fp_evm::PrecompileHandle) -> PrecompileResult {
		handle.record_cost(Bw6761G1Mul::GAS_COST)?;

		let input = handle.input();
		if input.len() != 256 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("invalid input length".into()),
			});
		}

		// Decode G1 point
		let p = decode_g1(input, 0)?;
		// Decode scalar value
		let e = decode_fr(input, 192);
		// Compute r = e * p
		let r = p.mul(e);
		// Encode the G1 point into 192 bytes output
		let output = encode_g1(r.into_affine());

		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output: output.to_vec(),
		})
	}
}
