# verdifax, R SDK and Reproducible-Research Toolkit

R client for the Verdifax cryptographic attestation pipeline. Designed
for researchers who want to attest computational results with the same
cryptographic rigor financial-services and AI governance customers
receive.

## Install

From a local clone (typical during early development):

```r
remotes::install_local("path/to/verdifax-sdk-r")
```

From GitHub (once published):

```r
remotes::install_github("Verdifax/verdifax-sdk-r")
```

## Usage

```r
library(verdifax)

# 1. Construct a client (reads VERDIFAX_API_URL / VERDIFAX_API_KEY
#    from environment by default)
client <- verdifax_client()

# 2. Auto-capture the current R research environment
ctx <- verdifax_capture_environment(
  declared_seeds = list(rng = 42, torch = 1337)
)
# ctx is a list with: runtime_name="R", runtime_version="4.x.x",
# pinned_dependencies=c(...), git_commit_sha="...", platform="...",
# random_seeds=c("rng=42", "torch=1337"), declared=TRUE

# 3. Attest a result with the environment fingerprint bound in
result <- verdifax_attest(
  client = client,
  payload = "my-analysis-output",
  program_id = strrep("0", 64),
  route_id = "paper-figure-3",
  registry_record_hash = strrep("0", 64),
  reproducibility_context = ctx
)
cat("manifest_hash:", result$manifest$ManifestHash, "\n")

# 4. Verify two replays produce the same manifest hash
det <- verdifax_verify_determinism(
  client = client,
  payload = "my-analysis-output",
  program_id = strrep("0", 64),
  route_id = "paper-figure-3-verify",
  registry_record_hash = strrep("0", 64),
  reproducibility_context = ctx
)
stopifnot(det$deterministic)
```

## What `verdifax_capture_environment()` records

| Field                  | Source                                    |
|------------------------|-------------------------------------------|
| `runtime_name`         | hardcoded `"R"`                           |
| `runtime_version`      | `R.version$major.minor`                   |
| `pinned_dependencies`  | `installed.packages()` (name + version)   |
| `git_commit_sha`       | `git rev-parse HEAD` (best-effort)        |
| `random_seeds`         | caller-supplied list, sorted              |
| `platform`             | GOOS/GOARCH from `Sys.info()`             |
| `container_image_hash` | `/proc/self/cgroup` on Linux (best-effort)|

All fields are optional. Auto-detection failures silently leave the
field `NULL`; the orchestrator records `NULL` as "not declared"
rather than fabricating an environment claim.

## What the determinism check answers

`verdifax_verify_determinism()` runs your payload through the
pipeline twice and reports whether both invocations produced
byte-identical canonical manifest hashes. The `deterministic` flag
is grounded on **manifest hash** equality, the seal of the pipeline
output. Bundle hash differences (when surfaced in
`diff$differing_fields`) indicate server-observed timing variation
and are labeled `(informational)`.

## Dependencies

- `httr2 (>= 1.0.0)`, HTTP client
- `jsonlite (>= 1.8.0)`, JSON serialization

Both are available on CRAN.

## License

MIT, see `LICENSE`.
