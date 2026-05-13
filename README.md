### Prooving things with SP1

```bash
cd program/
cargo prove build

cd ../script
cargo build

## Execute only
cargo run --release -- \
  --url https://api.coinbase.com/v2/prices/BTC-USD/spot \
  --field /data/amount \
  --threshold 50000

## Output:
Response body: {"data":{"amount":"79652.885","base":"BTC","currency":"USD"}}
Execution succeeded (no proof generated).
   field:     /data/amount
   threshold: 50000
   value:     79652.885
   cycles:    20002

## Prove and validate
cargo run --release -- \
  --url https://api.coinbase.com/v2/prices/BTC-USD/spot \
  --field /data/amount \
  --threshold 50000 \
  --prove

## Output:
## proof.bin: 1272605 bytes
Response body: {"data":{"amount":"79659.535","base":"BTC","currency":"USD"}}
Proof saved to proof.bin
Proof verified.
   field:     /data/amount
   threshold: 50000
   value:     79659.535
```
