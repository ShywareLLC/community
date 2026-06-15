**[Shyware LLC](https://shyware.fyi)** — shyware deployment

# shyware — Anonymous Transfer Protocol

A privacy layer for asset transfers. Not a coin — a layer.

**shyware** sits on top of any asset (stablecoin, sovereign currency, DAO treasury token)
and enforces the two-list structural invariant for transfers:

```
List 1 (transferRecords): transfer_id → { amount, asset_id }   — no identity
List 2 (participants):    nullifier   → { account_commitment }  — no amount

Invariant: |L1| == |L2|, never joined on-chain
Value conservation: sender.Balance -= Amount, recipient.Balance += Amount
Supply invariant: TotalSupply = TotalMinted - TotalBurned
```

Financing products can now anchor contract servicing on the same state machine:

```
financingContracts:   contract_id → { contract_hash, interest_bps, return_basis,
                                      goal_target_amount, remittance_source_mode,
                                      funding_mode, tranche_classes[] }
financingRemittances: transfer_id → { contract_id, income_category, source_ref, amount }

Remittance execution:
  - activates only after goal achievement if the contract is goal-gated
  - writes List 1 transfer record (amount + asset, no identity)
  - writes List 2 participant nullifier (identity only, no amount)
  - updates contract.TotalRemitted and enforces cap/category/source-match rules
```

Counterparties cannot see your balance or transfer direction. Authorities access
off-chain records under legal process. This is how cash works.

The transfer branch does not solve regulated misuse by deleting settled
history. Instead it preserves the main utilities by:

- rejecting fake account materialization through wallet proof and, where configured,
  single-use enrollment authorization
- preserving user-auditable transfer history once committed
- preserving value conservation and supply auditability
- keeping reconcile and lawful attribution off the canonical write path

That is the transfer-side analogue to voting's eligibility discipline without
giving up the user-history and conservation utilities that make `shywire`
useful.

---

## Module structure

```
shyware/
  types/      AssetRecord, TransferRecord (List 1), ParticipantRecord (List 2),
              AccountRecord, SupplyRecord
  tx/         TxTypeTransfer, TxTypeMint, TxTypeBurn, TxTypeRegisterAsset,
              TxTypeRegisterAccount, TxTypeRegisterValidator
  state/      Two-list transfer state machine; value conservation enforcement
  app/        CometBFT ABCI 2.0 wrapper
```

Imports `github.com/populist/protocol` for `signer`, `kms`, and `api/rpc`.

---

## What's different from protocol/

| | protocol/ (voting) | shyware/ (transfers) |
|-|--------------------|----------------------|
| List 1 key | `ballot_id = H(nonce)` | `transfer_id = H(TransferNonce)` |
| List 1 value | `vote_direction` | `amount + asset_id` |
| List 2 key | ZK nullifier | `H(wallet, transfer_id)` |
| List 2 value | `identity_hash` | `account_commitment` |
| New invariant | none | value conservation: Σ in == Σ out |
| Operator txs | PollCreate, PollClose | Mint, Burn, RegisterAsset |
| IDV | Didit biometric | wallet ECDSA (RegisterAccount) |

---

## TODO(circuit)

`Amount` and `Balance` fields are plaintext in this scaffold. The production circuit
replaces them with Pedersen commitments over BN254, proving value conservation without
revealing individual amounts. All replacement points are marked `TODO(circuit)` in
[types/transfer.go](types/transfer.go) and [tx/tx.go](tx/tx.go).

---

## Tiered access model

| Party | Access |
|-------|--------|
| Public | Supply totals (`/supply/{asset_id}`), transfer count |
| Counterparty | Nothing — cannot see balance or direction |
| Operator | Account registry via admin SDK |
| Authorities | Full records under legal process (subpoena / MLAT) |

---

## Deployers

shyware is agnostic. Example deployers:

- **Stablecoin issuer** — shielded USDC-equivalent, FinCEN-compliant
- **Neobank** — privacy-preserving account layer; bank holds the audit key
- **Sovereign digital currency** — cash-equivalent privacy without surrendering AML capability
- **Revenue-share / income-share finance** — goal-gated percentage-interest servicing with matched remittance sources and staged investor tranches

---

## Claims coverage

The two-list structural invariant is proprietary to Shyware LLC. License required for commercial deployment.
The value conservation circuit is additional claim surface already described for the transfer embodiments.
Contact nick@populist.vote for licensing.
