# Finance Domain Narrowers

This directory contains domain-specific narrowing strategies for the finance domain.

## AmountNarrower

The [`AmountNarrower`](amount_narrower.py) handles `NARROWABLE` violations where a trade amount exceeds a soft threshold. It clamps the amount to the maximum allowed value while preserving all other action parameters.

### Example

```python
from src.cage_finance.narrowers import AmountNarrower
from src.gateway.governance.contracts import Violation, ViolationKind

narrower = AmountNarrower()

# Violation from a fiscal tier
violation = Violation(
    tier="fiscal",
    code="SOFT_LIMIT_EXCEEDED",
    message="Amount $50000 exceeds soft limit of $25000",
    kind=ViolationKind.NARROWABLE,
)

# Original action parameters
params = {
    "amount": 50000,
    "symbol": "AAPL",
    "side": "buy",
}

# Check if narrowable
if narrower.can_narrow(violation, "execute_trade", params):
    # Compute narrowed parameters
    result = narrower.narrow(violation, "execute_trade", params)
    
    print(result.narrowed_params)
    # {'amount': 25000.0, 'symbol': 'AAPL', 'side': 'buy'}
    
    print(result.constraints_applied)
    # ['amount <= 25000.0']
    
    print(result.narrowing_reason)
    # 'Clamped amount from 50000 to 25000.0 (max: 25000.0)'
```

### Supported Message Formats

The narrower extracts thresholds from violation messages using regex patterns:

- `"Amount $50000 exceeds soft limit of $25000"` → `25000.0`
- `"Amount exceeds soft limit of 10000"` → `10000.0`
- `"Amount exceeds limit of $12500.50"` → `12500.50`

### Integration with NarrowerRegistry

```python
from src.gateway.governance.narrower import NarrowerRegistry
from src.cage_finance.narrowers import AmountNarrower

# Register the narrower
registry = NarrowerRegistry()
registry.register(AmountNarrower())

# Find a narrower for a violation
narrower = registry.find_narrower(violation, action, params)
if narrower:
    result = narrower.narrow(violation, action, params)
```

### Testing

Run the test suite:

```bash
uv run pytest tests/test_amount_narrower.py -v
```

All tests validate:
- NARROWABLE violation acceptance
- HARD violation rejection
- Missing amount field rejection
- Message parsing edge cases
- Decimal amount handling
- Parameter preservation
- Graceful fallback on unparseable messages
