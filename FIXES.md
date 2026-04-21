# Sunbeam-M Bug Fixes

Three bugs were found preventing the client from connecting to the server.

## Fix 1: State machine missing transition (DISCONNECTED -> HANDSHAKE_SENT)

**File:** `sunbeam_m/masquerade/base.py`
**Line:** ~170

All three protocol implementations (`tls.py`, `http.py`, `ssh.py`) call `transition_to(ProtocolState.HANDSHAKE_SENT)` in their `client_handshake()` method while in the `DISCONNECTED` state, but the state machine only allowed `DISCONNECTED -> HANDSHAKE_INIT` and `DISCONNECTED -> ESTABLISHED`.

**Change:**

```python
# Before
ProtocolState.DISCONNECTED: [
    ProtocolState.HANDSHAKE_INIT,
    ProtocolState.ESTABLISHED,
],

# After
ProtocolState.DISCONNECTED: [
    ProtocolState.HANDSHAKE_INIT,
    ProtocolState.HANDSHAKE_SENT,
    ProtocolState.ESTABLISHED,
],
```

## Fix 2: struct.pack format mismatch in TLS supported groups

**File:** `sunbeam_m/masquerade/tls.py`
**Line:** ~262

`struct.pack` format string `"!HHHH"` expects 4 values but only 3 were provided.

**Change:**

```python
# Before
groups = struct.pack("!HHHH", 6, TLS_GROUP_X25519, TLS_GROUP_SECP256R1)

# After
groups = struct.pack("!HHH", 6, TLS_GROUP_X25519, TLS_GROUP_SECP256R1)
```

## Fix 3: struct.pack format mismatch in TLS signature algorithms

**File:** `sunbeam_m/masquerade/tls.py`
**Line:** ~268

Same issue — format string `"!HHHH"` expects 4 values but only 3 were provided.

**Change:**

```python
# Before
sig_algs = struct.pack(
    "!HHHH",
    4,
    TLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
    TLS_SIGNATURE_ED25519,
)

# After
sig_algs = struct.pack(
    "!HHH",
    4,
    TLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
    TLS_SIGNATURE_ED25519,
)
```
