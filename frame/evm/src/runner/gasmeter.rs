// This file is part of Frontier.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

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

use evm::interpreter::{
	error::{ExitError, ExitException},
	etable::Control,
	machine::{Machine, Stack},
	opcode::Opcode,
	runtime::{RuntimeBackend, RuntimeState},
};
use evm::standard::eval_gasometer;
use evm::standard::{
	dynamic_opcode_cost, Config as EVMConfig, GasCost, GasometerState, MemoryCost,
};
use sp_core::{H160, H256, U256};

// pub fn eval<'config, S, H, Tr>(
// 	machine: &mut Machine<S>,
// 	handler: &mut H,
// 	opcode: Opcode,
// 	position: usize,
// ) -> Control<Tr>
// where
// 	S: AsRef<GasometerState<'config>> + AsMut<GasometerState<'config>> + AsRef<RuntimeState>,
// 	H: RuntimeBackend,
// {
// 	let mut ret = eval_gasometer(machine, handler, opcode, position);

// 	if matches!(ret, Control::Continue) {

// 	}

// 	match  {
// 		Ok(()) => Control::Continue,
// 		Err(err) => Control::Exit(Err(err)),
// 	}
// }
