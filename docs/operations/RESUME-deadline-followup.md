# Resume: observer transport deadline follow-up

This branch retains the observer deadline changes excluded from
`paykit/residuals-part2-subset`.

Do not claim the existing stalled-listener probe test proves the deadline
boundary. A reverted lazy `StreamOwned::new` implementation still passes it
because the probe's outer timeout also wraps the first RPC, where rustls lazily
performs its handshake.

Before shipping this branch:

1. Add a discriminating TLS test that proves the behavioral difference:
   eager handshake failure must surface as the endpoint-level connect/unavailable
   path in `observations`, while the pre-fix lazy client reaches the per-address
   deadline path. The test must fail against the pre-fix boundary.
2. Add a deterministic TCP connect-phase test. `TcpStream::connect_timeout` is
   currently concrete and OS-network behavior cannot be made deterministic with
   a public non-routable address or a local listener alone. Introduce a narrow
   test-only connector/clock seam at the transport boundary, then prove a stalled
   connect is included in `address_deadline`, classified as unavailable, never
   reused, and followed by a healthy probe.
3. Re-run the observer suite, full workspace gate, independent Sol review, and
   fresh Kimi audit.
