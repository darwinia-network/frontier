set -e

echo ">>> Start compile process"

crates=(
   fp-consensus
   fp-evm
   fp-rpc
   fp-self-contained
   fp-storage
   pallet-evm
   pallet-evm-precompile-simple
   fc-db
   fc-rpc
   fc-rpc-core
   pallet-base-fee
   pallet-evm-precompile-modexp
   pallet-evm-precompile-sha3fips
   pallet-evm-precompile-simple
   fc-mapping-sync
)

for c in ${crates[@]}
do
    echo ">>>>>>>> Start $c"
    cargo check -p $c
    echo ">>>>>>>> End $c"

done