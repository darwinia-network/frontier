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

//! EVM stack-based runner.

use crate::{
	runner::backend::FrontierBackend, runner::Runner as RunnerT, AddressMapping, BalanceOf, Config,
	Error, Event, FeeCalculator, OnChargeEVMTransaction, Pallet, RunnerError,
};
use alloc::vec::Vec;
use core::marker::PhantomData;
use evm::{
	interpreter::runtime::RuntimeBaseBackend,
	standard::{Config as EVMConfig, Etable, EtableResolver, Invoker, TransactArgs, TransactValue},
};
use evm_precompile::StandardPrecompileSet;
use fp_evm::{ExecutionInfo, TransactPov, WeightInfo};
use frame_support::traits::fungible::Balanced;
use frame_support::traits::fungible::Inspect;
use sp_core::Get;
use sp_core::{H160, H256, U256};
use sp_runtime::traits::UniqueSaturatedInto;

#[derive(Default)]
pub struct Runner<T: Config> {
	_marker: PhantomData<T>,
}

impl<T: Config> Runner<T>
where
	BalanceOf<T>: TryFrom<U256> + Into<U256>,
	T::Currency: Balanced<T::AccountId>,
	U256: UniqueSaturatedInto<
		<T::Currency as Inspect<<T as frame_system::Config>::AccountId>>::Balance,
	>,
{
	pub fn effective_gas_price(
		is_transactional: bool,
		max_fee_per_gas: Option<U256>,
		max_priority_fee_per_gas: Option<U256>,
	) -> Result<U256, RunnerError<Error<T>>> {
		let (base_fee, weight) = T::FeeCalculator::min_gas_price();
		let gas_price = if is_transactional {
			match (max_fee_per_gas, max_priority_fee_per_gas) {
				// Zero max_fee_per_gas for validated transactional calls exist in XCM -> EVM
				// because fees are already withdrawn in the xcm-executor.
				(Some(max_fee), _) if max_fee.is_zero() => U256::zero(),
				// With no tip, we pay exactly the base_fee
				(Some(_), None) => base_fee,
				// With tip, we include as much of the tip on top of base_fee that we can, never
				// exceeding max_fee_per_gas
				(Some(max_fee_per_gas), Some(max_priority_fee_per_gas)) => {
					let actual_priority_fee_per_gas = max_fee_per_gas
						.saturating_sub(base_fee)
						.min(max_priority_fee_per_gas);

					base_fee.saturating_add(actual_priority_fee_per_gas)
				}
				_ => {
					return Err(RunnerError {
						error: Error::<T>::GasPriceTooLow,
						weight,
					})
				}
			}
		} else {
			// Gas price check is skipped for non-transactional calls or creates
			Default::default()
		};

		Ok(gas_price)
	}

	#[allow(clippy::let_and_return)]
	/// Execute an already validated EVM operation.
	fn execute<'config>(
		config: &'config EVMConfig,
		transaction_args: TransactArgs,
		transact_pov: Option<TransactPov>,
	) -> Result<ExecutionInfo, RunnerError<Error<T>>> {
		let gas_etable = Etable::single(evm::standard::eval_gasometer);
		let exec_etable = Etable::runtime();
		let etable = (gas_etable, exec_etable);

		let precompiles = StandardPrecompileSet::new(&config);
		let resolver = EtableResolver::new(&config, &precompiles, &etable);
		let invoker = Invoker::new(&config, &resolver);
		let mut backend =
			FrontierBackend::<T>::new(transact_pov, transaction_args.access_list().clone());
		let (value, exit_result) =
			match evm::transact(transaction_args.clone(), None, &mut backend, &invoker) {
				Ok(transact_value) => match transact_value {
					TransactValue::Call { succeed, retval } => (retval, succeed.into()),
					TransactValue::Create { succeed, address } => {
						(address.as_bytes().to_vec(), succeed.into())
					}
				},
				Err(e) => (Vec::new(), e.into()),
			};

		// let changeset = frontier_backend.deconstruct().1;
		// frontier_backend.apply_changeset(&changeset);

		Ok(ExecutionInfo {
			value,
			exit_result,
			used_gas: fp_evm::UsedGas {
				standard: 100.into(),
				effective: 100.into(),
			},
			weight_info: transact_pov.map(WeightInfo::from_transaction_pov),
			// logs: state.substate.logs,
		})
	}
}

impl<T: Config> RunnerT<T> for Runner<T>
where
	BalanceOf<T>: TryFrom<U256> + Into<U256>,
	T::Currency: Balanced<T::AccountId>,
	U256: UniqueSaturatedInto<
		<T::Currency as Inspect<<T as frame_system::Config>::AccountId>>::Balance,
	>,
{
	type Error = Error<T>;

	fn validate(
		source: H160,
		target: Option<H160>,
		input: Vec<u8>,
		value: U256,
		gas_limit: u64,
		max_fee_per_gas: Option<U256>,
		max_priority_fee_per_gas: Option<U256>,
		nonce: Option<U256>,
		access_list: Vec<(H160, Vec<H256>)>,
		is_transactional: bool,
		transact_pov: Option<TransactPov>,
		evm_config: &EVMConfig,
	) -> Result<(), RunnerError<Self::Error>> {
		let (base_fee, mut weight) = T::FeeCalculator::min_gas_price();
		let (source_account, inner_weight) = Pallet::<T>::account_basic(&source);
		weight = weight.saturating_add(inner_weight);

		let _ = fp_evm::CheckEvmTransaction::<Self::Error>::new(
			fp_evm::CheckEvmTransactionConfig {
				evm_config,
				block_gas_limit: T::BlockGasLimit::get(),
				base_fee,
				chain_id: T::ChainId::get(),
				is_transactional,
			},
			fp_evm::CheckEvmTransactionInput {
				chain_id: Some(T::ChainId::get()),
				to: target,
				input,
				nonce: nonce.unwrap_or(source_account.nonce),
				gas_limit: gas_limit.into(),
				gas_price: None,
				max_fee_per_gas,
				max_priority_fee_per_gas,
				value,
				access_list,
			},
			transact_pov,
		)
		.validate_in_block_for(&source_account)
		.and_then(|v| v.with_base_fee())
		.and_then(|v| v.with_balance_for(&source_account))
		.map_err(|error| RunnerError { error, weight })?;
		Ok(())
	}

	fn call(
		source: H160,
		target: H160,
		input: Vec<u8>,
		value: U256,
		gas_limit: u64,
		max_fee_per_gas: Option<U256>,
		max_priority_fee_per_gas: Option<U256>,
		nonce: Option<U256>,
		access_list: Vec<(H160, Vec<H256>)>,
		is_transactional: bool,
		validate: bool,
		transact_pov: Option<TransactPov>,
		config: &EVMConfig,
	) -> Result<ExecutionInfo, RunnerError<Self::Error>> {
		if validate {
			Self::validate(
				source,
				Some(target),
				input.clone(),
				value,
				gas_limit,
				max_fee_per_gas,
				max_priority_fee_per_gas,
				nonce,
				access_list.clone(),
				is_transactional,
				transact_pov,
				config,
			)?;
		}

		let transact_args = TransactArgs::Call {
			caller: source,
			address: target,
			value,
			data: input,
			gas_limit: gas_limit.into(),
			gas_price: Self::effective_gas_price(
				is_transactional,
				max_fee_per_gas,
				max_priority_fee_per_gas,
			)?,
			access_list,
		};
		Self::execute(config, transact_args, transact_pov)
	}

	fn create(
		source: H160,
		init: Vec<u8>,
		value: U256,
		gas_limit: u64,
		max_fee_per_gas: Option<U256>,
		max_priority_fee_per_gas: Option<U256>,
		nonce: Option<U256>,
		access_list: Vec<(H160, Vec<H256>)>,
		is_transactional: bool,
		validate: bool,
		transact_pov: Option<TransactPov>,
		config: &EVMConfig,
	) -> Result<ExecutionInfo, RunnerError<Self::Error>> {
		if validate {
			Self::validate(
				source,
				None,
				init.clone(),
				value,
				gas_limit,
				max_fee_per_gas,
				max_priority_fee_per_gas,
				nonce,
				access_list.clone(),
				is_transactional,
				transact_pov,
				config,
			)?;
		}

		let transact_args = TransactArgs::Create {
			caller: source,
			value,
			init_code: init,
			salt: None,
			gas_limit: gas_limit.into(),
			gas_price: Self::effective_gas_price(
				is_transactional,
				max_fee_per_gas,
				max_priority_fee_per_gas,
			)?,
			access_list,
		};
		Self::execute(config, transact_args, transact_pov)
	}

	fn create2(
		source: H160,
		init: Vec<u8>,
		salt: H256,
		value: U256,
		gas_limit: u64,
		max_fee_per_gas: Option<U256>,
		max_priority_fee_per_gas: Option<U256>,
		nonce: Option<U256>,
		access_list: Vec<(H160, Vec<H256>)>,
		is_transactional: bool,
		validate: bool,
		transact_pov: Option<TransactPov>,
		config: &EVMConfig,
	) -> Result<ExecutionInfo, RunnerError<Self::Error>> {
		if validate {
			Self::validate(
				source,
				None,
				init.clone(),
				value,
				gas_limit,
				max_fee_per_gas,
				max_priority_fee_per_gas,
				nonce,
				access_list.clone(),
				is_transactional,
				transact_pov,
				config,
			)?;
		}

		let transact_args = TransactArgs::Create {
			caller: source,
			value,
			init_code: init,
			salt: Some(salt),
			gas_limit: gas_limit.into(),
			gas_price: Self::effective_gas_price(
				is_transactional,
				max_fee_per_gas,
				max_priority_fee_per_gas,
			)?,
			access_list,
		};

		Self::execute(config, transact_args, transact_pov)
	}
}
