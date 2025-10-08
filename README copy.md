## Fuzz Protobuf Parser (dynamic Unmarshal)

### Requirements
- Go >= 1.18, `protoc` (Homebrew: `brew install protobuf`).

### Build descriptor_set.pb
```bash
./build_descriptors.sh
```
- Script will merge `api.proto`, `realtime.proto` and automatically include `apigrpc.proto` (if exists) via shim import.
- Result written to: `fuzz/descriptor_set.pb`.

### Run fuzz quickly (5–10s)
```bash
cd fuzz
go test -run TestNonExist -fuzz=Fuzz_DynamicUnmarshal -fuzztime=10s ./...
```

### Fuzzer mechanism (enhanced)
- Use `go:embed` to embed `descriptor_set.pb` (no hard path). Can be overridden by env `DESCRIPTOR_SET_PATH`.
- Pick message by `idx` parameter from fuzz engine, help cover more uniformly instead of hash by bytes.
- In danh sách message types nếu đặt `FUZZ_LIST_TYPES=1`.
- Round-trip 2 lần: Unmarshal → Marshal → Unmarshal → Marshal, phát hiện inconsistency/parsing bug/panic.
- Limit input > 1MiB to avoid DoS when mutate too large.

### Suggestions
- Add seed corpus: create directory `testdata/fuzz/Fuzz_DynamicUnmarshal` containing valid protobuf samples from staging/prod.
- Combine black-box fuzz via gRPC/HTTP (SSRF/Injection) by other harness as described in Phase 3.

### Env vars
- `DESCRIPTOR_SET_PATH`: path to replace file descriptor if not using embed.
- `FUZZ_LIST_TYPES=1`: log fully-qualified message names when starting test.
