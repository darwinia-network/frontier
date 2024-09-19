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

use alloc::{
	boxed::Box,
	collections::{btree_map::BTreeMap, btree_set::BTreeSet},
	vec::Vec,
};
use core::{marker::PhantomData, mem};
use evm::{
	backend::{OverlayedBackend, RuntimeBackend},
	MergeStrategy,
	interpreter::{
		error::{Capture, ExitError, ExitResult},
		runtime::{GasState, Log, RuntimeBaseBackend, RuntimeEnvironment, SetCodeOrigin, Transfer},
		utils::u256_to_h256,
		Interpreter,
	},
	standard::{Config as EVMConfig, Etable, EtableResolver, Invoker, TransactArgs},
	TransactionalBackend,
};
use fp_evm::TransactionPov;
use sp_core::{H160, H256, U256};


use crate::{Config, Pallet, AccountCodes, AccountStorages, AddressMapping, FeeCalculator, BlockHashMapping, Event};

pub struct FrontierBackend<T> {
	substate: Box<SubState>,
	transaction_pov: Option<TransactionPov>,
	original_storage: BTreeMap<(H160, H256), H256>,
	// TODO: how to access list works
	access_list: Vec<(H160, Vec<H256>)>,
	_marker: PhantomData<T>,
}

impl<T: Config> FrontierBackend<T> {
	pub fn new(
		transaction_pov: Option<TransactionPov>,
		access_list: Vec<(H160, Vec<H256>)>,
	) -> Self {
		Self {
			substate: Box::new(SubState::new()),
			original_storage: BTreeMap::new(),
			access_list,
			transaction_pov,
			_marker: PhantomData,
		}
	}
}

impl<T: Config> TransactionalBackend for FrontierBackend<T> {
	fn push_substate(&mut self) {
		let mut parent = Box::new(SubState::new());
		mem::swap(&mut parent, &mut self.substate);
		self.substate.parent = Some(parent);

		sp_io::storage::start_transaction();
	}

	fn pop_substate(&mut self, strategy: MergeStrategy) {
		let mut child = self.substate.parent.take().expect("uneven substate pop");
		mem::swap(&mut child, &mut self.substate);
		let child = child;

		match strategy {
			MergeStrategy::Commit => {
				for log in child.logs {
					self.substate.logs.push(log);
				}
				for address in child.deletes {
					self.substate.deletes.insert(address);
				}
				sp_io::storage::commit_transaction();
			}
			MergeStrategy::Revert | MergeStrategy::Discard => {
				sp_io::storage::rollback_transaction();
			}
		}
	}
}

impl<T: Config> RuntimeEnvironment for FrontierBackend<T> {
	fn block_hash(&self, number: U256) -> H256 {
		if number > U256::from(u32::MAX) {
			H256::default()
		} else {
			T::BlockHashMapping::block_hash(number.as_u32())
		}
	}

	fn block_number(&self) -> U256 {
		let number: u128 = frame_system::Pallet::<T>::block_number().unique_saturated_into();
		U256::from(number)
	}

	fn block_coinbase(&self) -> H160 {
		Pallet::<T>::find_author()
	}

	fn block_timestamp(&self) -> U256 {
		let now: u128 = T::Timestamp::now().unique_saturated_into();
		U256::from(now / 1000)
	}

	fn block_difficulty(&self) -> U256 {
		U256::zero()
	}

	fn block_randomness(&self) -> Option<H256> {
		None
	}

	fn block_gas_limit(&self) -> U256 {
		T::BlockGasLimit::get()
	}

	fn block_base_fee_per_gas(&self) -> U256 {
		let (base_fee, _) = T::FeeCalculator::min_gas_price();
		base_fee
	}

	fn chain_id(&self) -> U256 {
		U256::from(T::ChainId::get())
	}
}

impl<T: Config> RuntimeBaseBackend for FrontierBackend<T> {
	fn balance(&self, address: H160) -> U256 {
		let (account, _) = Pallet::<T>::account_basic(&address);
		account.balance
	}

	fn code_size(&self, address: H160) -> U256 {
		U256::from(<Pallet<T>>::account_code_metadata(address).size)
	}

	fn code_hash(&self, address: H160) -> H256 {
		<Pallet<T>>::account_code_metadata(address).hash
	}

	fn code(&self, address: H160) -> Vec<u8> {
		<AccountCodes<T>>::get(address)
	}

	fn storage(&self, address: H160, index: H256) -> H256 {
		<AccountStorages<T>>::get(address, index)
	}

	fn transient_storage(&self, address: H160, index: H256) -> H256 {
		<AccountStorages<T>>::get(address, index)
	}

	fn exists(&self, address: H160) -> bool {
		true
	}

	fn nonce(&self, address: H160) -> U256 {
		let (account, _) = Pallet::<T>::account_basic(&address);
		account.nonce
	}
}

impl<T: Config> RuntimeBackend for FrontierBackend<T> {
	fn original_storage(&self, address: H160, index: H256) -> H256 {
		self.original_storage
			.get(&(address, index))
			.cloned()
			.unwrap_or_else(|| self.storage(address, index))
	}

	fn deleted(&self, address: H160) -> bool {
		self.substate.deletes.contains(&address)
	}

	fn is_cold(&self, address: H160, index: Option<H256>) -> bool {}
	fn is_hot(&self, address: H160, index: Option<H256>) -> bool {
		!self.is_cold(address, index)
	}

	fn mark_hot(&mut self, address: H160, index: Option<H256>) {}

	fn set_storage(&mut self, address: H160, index: H256, value: H256) -> Result<(), ExitError> {
		if value == H256::default() {
			<AccountStorages<T>>::remove(address, index);
		} else {
			<AccountStorages<T>>::insert(address, index, value);
		}
		Ok(())
	}
	fn set_transient_storage(
		&mut self,
		address: H160,
		index: H256,
		value: H256,
	) -> Result<(), ExitError> {
		Ok(())
	}
	fn log(&mut self, log: Log) -> Result<(), ExitError> {
		self.substate.logs.push(log);
		Ok(())
	}
	fn mark_delete(&mut self, address: H160) {
		self.substate.deletes.insert(address)
	}
	fn reset_storage(&mut self, address: H160) {
		let _ = <AccountStorages<T>>::remove_prefix(address, None);
	}
	fn set_code(
		&mut self,
		address: H160,
		code: Vec<u8>,
		origin: SetCodeOrigin,
	) -> Result<(), ExitError> {
		Pallet::<T>::create_account(address, code);
		Ok(())
	}
	fn reset_balance(&mut self, address: H160) {}

	fn deposit(&mut self, target: H160, value: U256) {
		// FIX ME
		// let account_id = T::AddressMapping::into_account_id(target);
		// let _ = F::deposit(&account_id, value.peek(), Precision::BestEffort);
		Ok(())
	}

	fn withdrawal(&mut self, source: H160, value: U256) -> Result<(), ExitError> {
		T::OnChargeTransaction::withdraw_fee(&source, value);
		Ok(())
	}
	fn transfer(&mut self, transfer: Transfer) -> Result<(), ExitError> {
		self.withdrawal(transfer.source, transfer.value)?;
		self.deposit(transfer.target, transfer.value);
		Ok(())
	}
	fn inc_nonce(&mut self, address: H160) -> Result<(), ExitError> {
		let account_id = T::AddressMapping::into_account_id(address);
		frame_system::Pallet::<T>::inc_account_nonce(&account_id);
		Ok(())
	}
}

struct SubState {
	parent: Option<Box<SubState>>,
	logs: Vec<Log>,
	deletes: BTreeSet<H160>,
}

impl SubState {
	pub fn new() -> Self {
		Self {
			parent: None,
			logs: Vec::new(),
			deletes: Default::default(),
		}
	}
}
