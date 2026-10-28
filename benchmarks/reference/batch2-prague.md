# BLS batch comparison

Fixed batch: two entries, 25-byte payloads, 119-byte signed frames. Fork: prague.

| State before transaction | Verification path | Gas (mean) | Min–max | Calldata bytes | Samples |
| --- | --- | ---: | ---: | ---: | ---: |
| first batch (counter 0) | individual | 552570 | 552570–552570 | 1348–1348 | 5 |
| first batch (counter 0) | aggregate | 476959 | 476959–476959 | 996–996 | 5 |
| first batch (counter 0) | zk | 446691 | 446691–446691 | 1124–1124 | 5 |
| subsequent batch (counter 1) | individual | 535470 | 535470–535470 | 1348–1348 | 5 |
| subsequent batch (counter 1) | aggregate | 459895 | 459895–459895 | 996–996 | 5 |
| subsequent batch (counter 1) | zk | 429579 | 429579–429579 | 1124–1124 | 5 |

Gas samples repeat identical transactions from restored state snapshots; they are not independent proving samples.

| State | Independent proof commands | Prove time, mean (s) | Full command, mean (s) | Peak child RSS, max (GiB) |
| --- | ---: | ---: | ---: | ---: |
| first batch (counter 0) | 1 | 31.07 | 142.44 | 1.39 |
| subsequent batch (counter 1) | 1 | 32.56 | 144.08 | 1.92 |

Setup for this run: **reused**. Cached setup is not a measurement of fresh setup cost.

Complete transaction gas includes calldata, commitment reconstruction, authorization, verification, counter/commitment writes, and the event. Deployment and signer-registration receipts are separate in the JSON.

These results cover one fixed two-entry circuit. They establish no crossover size, general gas-savings claim, throughput, or consensus-finality estimate.
