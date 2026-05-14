### Prooving things with SP1

```bash
cd program/
cargo prove build

cd ../script
cargo build


## Run only (no proof)
cargo run --release --bin sp1-https-json-script -- \
  --url "https://blockchain.info/ticker" \
  --field "/USD/last" \
  --threshold 1000
<snip>
Response body: ae3
{"snip":{},"USD":{"15m":79349.99,"last":79349.99,"buy":79349.99,"sell":79349.99,"symbol":"USD"}}
0
debug: inbound=10837 bytes, outbound=480 bytes, hs_secret=32 bytes
TLS witness assembled: 3 certs, 7 app records, cv_msg 260 bytes
Execution succeeded (no proof generated).
   host:      blockchain.info
   field:     /USD/last
   threshold: 1000
   value:     79349.99
   cycles:    21202056


## Run using mock prover (note: SP1_PROVER=mock)
SP1_PROVER=mock cargo run --release --bin sp1-https-json-script -- \
  --url "https://blockchain.info/ticker" \
  --field "/USD/last" \
  --threshold 1000 \
  --prove
<snip>
Response body: ad7
{"snip":{},"USD":{"15m":79269.52,"last":79269.52,"buy":79269.52,"sell":79269.52,"symbol":"USD"}}
0
debug: inbound=10825 bytes, outbound=480 bytes, hs_secret=32 bytes
TLS witness assembled: 3 certs, 7 app records, cv_msg 260 bytes
Proof saved to proof.bin
Proof verified.
   host:      blockchain.info
   field:     /USD/last
   threshold: 1000
   value:     79269.52
```
