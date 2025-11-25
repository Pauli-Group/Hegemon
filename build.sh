echo "build dashboard"
./scripts/build_dashboard.sh

echo "build node"
cargo build -p node --release
cp target/release/hegemon .

# ./hegemon setup
# ./hegemon --seeds 75.155.93.185:9000 --miner-seed 046c8e2c0d6002b7a9e3dec482915ef62c9d628fafa43fe0b5cd1ad820652981 start

##./hegemon --api-token devnet-token --seeds 75.155.93.185:9000 --miner-seed 046c8e2c0d6002b7a9e3dec482915ef62c9d628fafa43fe0b5cd1ad820652981 --db-path ./node.db --wallet-store ./wallet.store start