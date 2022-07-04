set -e

echo ">>> Start compile process"

crates=(
   fp-consensus
   fp-evm
   fp-rpc
   fp-self-contained
   fp-storage
   pallet-evm
   fc-db
   fc-rpc
   fc-rpc-core
   pallet-base-fee
   pallet-evm-precompile-modexp
   pallet-evm-precompile-sha3fips
   pallet-evm-precompile-simple
   pallet-evm-precompile-blake2
   fc-mapping-sync
)

for c in ${crates[@]}
do
    echo ">>>>>>>> Start $c"
    cargo check -p $c
    echo ">>>>>>>> End $c"

done