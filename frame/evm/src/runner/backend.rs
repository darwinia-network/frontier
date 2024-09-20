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

use crate::EVMFungibleAdapter;
use crate::OnChargeEVMTransaction;
use crate::{
	AccountCodes, AccountStorages, AddressMapping, BalanceOf, BlockHashMapping, Config, Event,
	FeeCalculator, Pallet,
};
use alloc::{
	boxed::Box,
	collections::{btree_map::BTreeMap, btree_set::BTreeSet},
	vec::Vec,
};
use core::{marker::PhantomData, mem};
use evm::{
	backend::RuntimeBackend,
	interpreter::{
		error::{ExitError, ExitException},
		runtime::{Log as EVMLog, RuntimeBaseBackend, RuntimeEnvironment, SetCodeOrigin, Transfer},
	},
	MergeStrategy, TransactionalBackend,
};
use fp_evm::{Log, TransactPov};
use frame_support::traits::fungible::Balanced;
use frame_support::traits::tokens::{
	fungible::Inspect, ExistenceRequirement, Fortitude, Precision, Preservation,
};
use frame_support::traits::Currency;
use frame_support::traits::Time;
use sp_core::Get;
use sp_core::{H160, H256, U256};
use sp_runtime::traits::UniqueSaturatedInto;

pub struct FrontierBackend<T> {
	substate: Box<SubState>,
	original_storage: BTreeMap<(H160, H256), H256>,
	transact_pov: Option<TransactPov>,
	// TODO: how to access list works
	access_list: Vec<(H160, Vec<H256>)>,
	_marker: PhantomData<T>,
}

impl<T: Config> FrontierBackend<T> {
	pub fn new(transact_pov: Option<TransactPov>, access_list: Vec<(H160, Vec<H256>)>) -> Self {
		Self {
			substate: Box::new(SubState::new()),
			original_storage: BTreeMap::new(),
			access_list,
			transact_pov,
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
				for address in child.deleted {
					self.substate.deleted.insert(address);
				}

				for ((address, key), value) in child.transient_storage {
					self.substate
						.transient_storage
						.insert((address, key), value);
				}

				for (address, index) in child.accessed {
					self.substate.accessed.insert((address, index));
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

	fn nonce(&self, address: H160) -> U256 {
		let (account, _) = Pallet::<T>::account_basic(&address);
		account.nonce
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
		if let Some(value) = self.substate.recursive_transient_storage(address, index) {
			value
		} else {
			// Return the original storage if the value is not in the transient storage.
			self.storage(address, index)
		}
	}

	fn exists(&self, _address: H160) -> bool {
		true
	}
}

impl<T: Config> RuntimeBackend for FrontierBackend<T>
where
	BalanceOf<T>: TryFrom<U256> + Into<U256>,
	T::Currency: Balanced<T::AccountId>,
	U256: UniqueSaturatedInto<
		<T::Currency as Inspect<<T as frame_system::Config>::AccountId>>::Balance,
	>,
{
	fn mark_delete(&mut self, address: H160) {
		self.substate.deleted.insert(address);
	}

	fn deleted(&self, address: H160) -> bool {
		self.substate.recursive_deleted(address)
	}

	fn set_transient_storage(
		&mut self,
		address: H160,
		index: H256,
		value: H256,
	) -> Result<(), ExitError> {
		self.substate
			.transient_storage
			.insert((address, index), value);

		Ok(())
	}

	fn original_storage(&self, address: H160, index: H256) -> H256 {
		self.original_storage
			.get(&(address, index))
			.cloned()
			.unwrap_or_else(|| self.storage(address, index))
	}

	fn set_storage(&mut self, address: H160, index: H256, value: H256) -> Result<(), ExitError> {
		// Update the original storage before setting the new value.
		self.original_storage
			.entry((address, index))
			.or_insert_with(|| <AccountStorages<T>>::get(address, index));

		if value == H256::default() {
			<AccountStorages<T>>::remove(address, index);
		} else {
			<AccountStorages<T>>::insert(address, index, value);
		}

		Ok(())
	}

	fn reset_storage(&mut self, address: H160) {
		#[allow(deprecated)]
		let _ = <AccountStorages<T>>::remove_prefix(address, None);
	}

	fn set_code(
		&mut self,
		address: H160,
		code: Vec<u8>,
		_origin: SetCodeOrigin,
	) -> Result<(), ExitError> {
		Pallet::<T>::create_account(address, code);

		Ok(())
	}

	fn inc_nonce(&mut self, address: H160) -> Result<(), ExitError> {
		let account_id = T::AddressMapping::into_account_id(address);
		frame_system::Pallet::<T>::inc_account_nonce(&account_id);

		Ok(())
	}

	fn log(&mut self, log: EVMLog) -> Result<(), ExitError> {
		Pallet::<T>::deposit_event(Event::<T>::Log {
			log: Log {
				address: log.address,
				topics: log.topics.clone(),
				data: log.data.clone(),
			},
		});
		Ok(())
	}

	fn mark_hot(&mut self, address: H160, index: Option<H256>) {
		self.substate.accessed.insert((address, index));
	}

	fn is_cold(&self, address: H160, index: Option<H256>) -> bool {
		self.substate.recursive_is_cold(address, index)
	}

	fn is_hot(&self, address: H160, index: Option<H256>) -> bool {
		!self.is_cold(address, index)
	}

	fn deposit(&mut self, target: H160, value: U256) {
		// todo: audit this
		let account_id = T::AddressMapping::into_account_id(target);
		if let Err(e) = T::Currency::deposit(
			&account_id,
			value.unique_saturated_into(),
			Precision::BestEffort,
		) {
			log::error!(target: "evm", "backend deposit failed, err: {e:?}")
		}
	}

	fn withdrawal(&mut self, source: H160, value: U256) -> Result<(), ExitError> {
		// todo: audit this
		let account_id = T::AddressMapping::into_account_id(source);
		let _ = <T::Currency as Balanced<T::AccountId>>::withdraw(
			&account_id,
			value.unique_saturated_into(),
			Precision::Exact,
			Preservation::Preserve,
			Fortitude::Polite,
		)
		.map_err(|_| ExitException::OutOfFund)?;

		Ok(())
	}

	fn transfer(&mut self, transfer: Transfer) -> Result<(), ExitError> {
		// todo: audit this
		let source = T::AddressMapping::into_account_id(transfer.source);
		let target = T::AddressMapping::into_account_id(transfer.target);
		T::Currency::transfer(
			&source,
			&target,
			transfer
				.value
				.try_into()
				.map_err(|_| ExitException::OutOfFund)?,
			ExistenceRequirement::AllowDeath,
		)
		.map_err(|_| ExitException::OutOfFund)?;

		Ok(())
	}

	fn reset_balance(&mut self, _address: H160) {}
}

struct SubState {
	parent: Option<Box<SubState>>,
	transient_storage: BTreeMap<(H160, H256), H256>,
	accessed: BTreeSet<(H160, Option<H256>)>,
	deleted: BTreeSet<H160>,
}

impl SubState {
	pub fn new() -> Self {
		Self {
			parent: None,
			transient_storage: Default::default(),
			accessed: Default::default(),
			deleted: Default::default(),
		}
	}

	pub fn recursive_is_cold(&self, address: H160, index: Option<H256>) -> bool {
		let current = self.accessed.contains(&(address, index));
		if current {
			return false;
		} else {
			self.parent
				.as_ref()
				.map_or(true, |parent| parent.recursive_is_cold(address, index))
		}
	}

	pub fn recursive_deleted(&self, address: H160) -> bool {
		let current = self.deleted.contains(&address);
		if current {
			return true;
		} else if let Some(parent) = self.parent.as_ref() {
			parent.deleted.contains(&address)
		} else {
			false
		}
	}

	pub fn recursive_transient_storage(&self, address: H160, index: H256) -> Option<H256> {
		if let Some(value) = self.transient_storage.get(&(address, index)) {
			Some(*value)
		} else if let Some(parent) = self.parent.as_ref() {
			parent.recursive_transient_storage(address, index)
		} else {
			None
		}
	}
}
