
HEGEMON_MINE=1 
HEGEMON_MINE_THREADS=4 
# cargo run --bin hegemon-node --features substrate -- --dev --name NodeB --base-path /tmp/hegemon-node-b --bootnodes "/ip4/75.155.93.185/tcp/30333/p2p/fdb0bc2ae7342e599c699d04b62baa5815a279f4b920fdb3ce9ba958fb752e7c"

./target/release/hegemon-node --dev --base-path /tmp/node2 --port 30334 --rpc-port 9945 --bootnodes "/ip4/75.155.93.185/tcp/30333/p2p/fdb0bc2ae7342e599c699d04b62baa5815a279f4b920fdb3ce9ba958fb752e7c"