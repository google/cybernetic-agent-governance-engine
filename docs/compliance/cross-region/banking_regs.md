# Banking Regulation Standards (ISO-20022 Compliance)

## Section 1: Fund Transfers

1. The system **MUST** verify the identity of the user for any transaction amount greater than 1000 USD.
2. The agent **SHALL** deny any transaction if the account status is "frozen".
3. For international transfers, the system **MUST** screen the beneficiary against the OFAC sanctions list.

## Section 2: Data Privacy

1. The agent **SHALL NOT** store PII (Personally Identifiable Information) in the session history for longer than 24 hours.
2. Access to account details **MUST** require a valid session token signed by the auth provider.

## Section 3: System Stability

1. The system **SHALL NOT** commit a transaction if the reported latency exceeds 200ms.
