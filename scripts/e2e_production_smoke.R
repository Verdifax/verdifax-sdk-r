# End-to-end production smoke test for the verdifax R SDK.
#
# Mirrors the Python e2e test that confirmed `deterministic: TRUE`
# against api.verdifax.com. Run with:
#
#   export VFA_KEY=...        # your production API key
#   Rscript scripts/e2e_production_smoke.R
#
# Exits non-zero on any failure. Prints a concise verdict on success.

suppressPackageStartupMessages(library(verdifax))

`%||%` <- function(x, y) if (is.null(x)) y else x

api_url <- Sys.getenv("VERDIFAX_API_URL", unset = "https://api.verdifax.com")
api_key <- Sys.getenv("VFA_KEY", unset = Sys.getenv("VERDIFAX_API_KEY"))

if (!nzchar(api_key)) {
  stop("VFA_KEY (or VERDIFAX_API_KEY) must be set in the environment.")
}

cat("── verdifax R SDK end-to-end production smoke ──\n")
cat("Endpoint:", api_url, "\n\n")

# Helper that prints the orchestrator's actual response body on HTTP
# failures so we don't lose the diagnostic detail. Returns the value
# of `expr` on success or NULL on failure (caller assigns the result
# explicitly — avoids `<<-` aliasing of base-namespace bindings like
# `det()`).
.run_with_diag <- function(label, expr) {
  tryCatch(
    force(expr),
    error = function(e) {
      cat("\n!! ", label, " FAILED: ", conditionMessage(e), "\n", sep = "")
      resp <- tryCatch(httr2::last_response(), error = function(.) NULL)
      if (!is.null(resp)) {
        cat("   HTTP status: ", httr2::resp_status(resp), "\n", sep = "")
        body <- tryCatch(httr2::resp_body_string(resp), error = function(.) "")
        if (nzchar(body)) {
          cat("   Response body:\n")
          cat(body, "\n")
        }
      }
      NULL
    }
  )
}

client <- verdifax_client(base_url = api_url, api_key = api_key)

# Step 1 — capture environment
ctx <- verdifax_capture_environment(declared_seeds = list(rng = 42))
cat("[1/3] capture_environment OK — runtime",
    ctx$runtime_name, ctx$runtime_version,
    "/ deps:", length(ctx$pinned_dependencies), "\n")

# Step 2 — attest
attest_res <- .run_with_diag("verdifax_attest", verdifax_attest(
  client = client,
  payload = "r-research-e2e-smoke",
  program_id = strrep("0", 64),
  route_id = "r-e2e-attest",
  registry_record_hash = strrep("0", 64),
  reproducibility_context = ctx
))
if (is.null(attest_res)) stop("attest failed; see diagnostic above")
mh <- attest_res$manifest$ManifestHash %||% attest_res$manifest$manifest_hash
cat("[2/3] verdifax_attest OK — manifest_hash:", substr(mh, 1, 16), "...\n")

# Step 3 — determinism. (We use `determinism_res` rather than `det`
# because `det` shadows base::det and confuses some scope tooling.)
determinism_res <- .run_with_diag(
  "verdifax_verify_determinism",
  verdifax_verify_determinism(
    client = client,
    payload = "r-research-e2e-smoke",
    program_id = strrep("0", 64),
    route_id = "r-e2e-verify",
    registry_record_hash = strrep("0", 64),
    reproducibility_context = ctx
  )
)
if (is.null(determinism_res)) stop("verify-determinism failed; see diagnostic above")
cat("[3/3] verify_determinism — deterministic:",
    determinism_res$deterministic, "\n")
if (!isTRUE(determinism_res$deterministic)) {
  cat("  diff$differing_fields:\n")
  print(determinism_res$diff$differing_fields)
  stop("Determinism check failed.")
}

cat("\n✅ R SDK end-to-end production smoke PASSED\n")
