# Contributing to WINEX Core

We welcome contributions to WINEX Core from developers around the world!

## Development Workflow

1. **Fork the Repository:** Create your own fork of `Winexcoin/winex-core`.
2. **Clone and Branch:**
   ```bash
   git clone https://github.com/<your-username>/winex-core.git
   cd winex-core
   git checkout -b feature/your-feature-name
   ```
3. **Coding Standards:**
   - Follow standard Go formatting guidelines (`gofmt -s -w .`).
   - Cryptographic primitives must use verified constant-time algorithms.
   - All network endpoints must enforce input limits (`http.MaxBytesReader`) and strict timeout policies.
   - Avoid external dependencies wherever standard library or audited cryptographic modules (`btcec/v2`) suffice.
4. **Compile and Test:**
   ```bash
   chmod +x scripts/*.sh
   ./scripts/build_all.sh
   ```
5. **Submit a Pull Request:**
   - Clearly describe what problem the change solves and provide test cases.
   - Ensure PR branch is rebased on current `main`.
