# WINEX Consensus Protocol Specification

## 1. Monetary Policy & Scarcity Parameters

| Parameter | Value | Description |
| :--- | :--- | :--- |
| **Max Cap** | **12,100,000 WNX** | Total lifetime supply ceiling |
| **Target Block Interval** | **15.0 Minutes** (900s) | Calibrated for network propagation and low uncle rate |
| **Initial Block Subsidy** | **40.0 WNX** | Distributed exclusively to valid PoW miners |
| **Halving Schedule** | **125,000 Blocks** | Block subsidy halves every ~3.56 years |
| **Minimum Unit** | **0.00000001 WNX** | Fractional divisibility (8 decimal precision, Satoshi equivalent) |
| **Difficulty Retargeting** | **Window: 20 Blocks** | Dynamic retargeting with Emergency Difficulty Adjustment (EDA) |

## 2. Subsidy Halving Schedule

The block reward function is deterministic based on block height $H$:

$$\text{Epoch} = \left\lfloor \frac{H}{125000} \right\rfloor$$
$$\text{Reward}(H) = \frac{40.0}{2^{\text{Epoch}}}$$

When the lifetime supply reaches the 12,100,000 WNX limit, block subsidies cease, and validator incentives transition entirely to transaction priority fees.

## 3. Proof-of-Work Consensus Verification

For a block candidate to be accepted by consensus nodes, all of the following rules must pass:

1. **Height Consistency:** Block index must equal previous tip index $+ 1$.
2. **Previous Hash Linkage:** `prev_hash` must match the SHA-256 hash of the parent block header.
3. **Deterministic Merkle Root:** Header Merkle root must match the root calculated from pending mempool transactions:
   $$\text{Merkle Root} = \text{SHA256}(\text{Tx}_1 + \text{Tx}_2 + \dots + \text{Tx}_n)$$
4. **Timestamp Verification:**
   - $\text{Timestamp}_{\text{current}} \ge \text{Timestamp}_{\text{parent}} - 60.0$ seconds (monotonically progressive).
   - $\text{Timestamp}_{\text{current}} \le \text{NetworkTime} + 7200.0$ seconds (max future drift bounded to 2 hours).
5. **Target Difficulty Satisfaction:**
   $$\text{PowHash} < \text{TargetDifficulty}$$
6. **Reorganization Depth Guard:** Reorganizations deeper than `MAX_REORG_DEPTH = 10` are rejected unconditionally to prevent long-range 51% reorganization attacks.
