# Every remaining route and the local helpers. Requests are captured by
# a mock, so nothing reaches the network.

.program_id <- strrep("1", 64)
.registry_record_hash <- strrep("2", 64)
.seed <- as.raw(rep(1L, 32))
.ok <- "{\"ok\":true,\"report\":{\"run_id\":7},\"receipts\":[{\"id\":1}],\"keys\":[{\"id\":2}],\"manifest\":{\"ManifestHash\":\"m\"},\"deletion_receipt\":{\"receipt_hash\":\"r\"}}"

need_sodium <- function() {
  if (!nzchar(Sys.getenv("CI"))) {
    testthat::skip_if_not_installed("sodium")
  }
}

test_client <- function() {
  verdifax_client(base_url = "http://mock.invalid", api_key = "k")
}

reply <- function(text = .ok, status = 200) {
  httr2::response(
    status_code = status,
    headers = "Content-Type: application/json",
    body = charToRaw(text)
  )
}

capture <- function(code, respond = function(req) reply()) {
  sent <- list()
  mock <- function(req) {
    body <- httr2::req_get_body(req)
    json <- if (is.null(body)) NULL else jsonlite::toJSON(body, auto_unbox = TRUE)
    sent[[length(sent) + 1]] <<- list(
      method = httr2::req_get_method(req),
      raw_url = httr2::req_get_url(req),
      url = httr2::url_parse(httr2::req_get_url(req)),
      body = if (is.null(json)) NULL else jsonlite::fromJSON(json, simplifyVector = FALSE)
    )
    respond(req)
  }
  httr2::with_mocked_responses(mock, code)
  sent
}

test_that("every remaining GET route calls its path", {
  client <- test_client()
  routes <- list(
    list(function() verdifax_health(client), "/health"),
    list(function() verdifax_version(client), "/version"),
    list(function() verdifax_get_openapi(client), "/openapi.json"),
    list(function() verdifax_get_stats(client), "/stats"),
    list(function() verdifax_list_attestations(client), "/attestations"),
    list(function() verdifax_get_attestation(client, 7), "/attestations/7"),
    list(function() verdifax_get_allow_token(client, 7), "/runs/7/allow-token"),
    list(function() verdifax_get_deny_receipt(client, 7), "/runs/7/deny-receipt"),
    list(function() verdifax_get_ccv_halt_receipt(client, 7), "/runs/7/ccv-halt-receipt"),
    list(function() verdifax_get_macc_halt_receipt(client, 7), "/runs/7/macc-halt-receipt"),
    list(function() verdifax_get_aivp_t4_halt_receipt(client, 7), "/runs/7/aivp-t4-halt-receipt"),
    list(function() verdifax_get_attestation_gap_receipt(client, 7), "/runs/7/attestation-gap-receipt"),
    list(function() verdifax_get_ces_audit_record(client, 7), "/runs/7/ces-audit-record"),
    list(function() verdifax_get_run_report(client, 7), "/runs/7/report"),
    list(function() verdifax_get_run_artifacts(client, 7), "/runs/7/artifacts"),
    list(function() verdifax_get_public_bundle(client, 7), "/runs/7/bundle.json"),
    list(function() verdifax_list_deletion_receipts(client, 7), "/runs/7/deletion-receipts"),
    list(function() verdifax_admin_list_keys(client), "/admin/keys")
  )
  for (route in routes) {
    sent <- capture(route[[1]]())
    expect_equal(sent[[1]]$method, "GET")
    expect_equal(sent[[1]]$url$path, route[[2]])
  }
})

test_that("a share token is escaped in the path", {
  sent <- capture(verdifax_get_public_bundle_by_token(test_client(), "a b/c"))
  expect_match(sent[[1]]$raw_url, "/public/runs/a%20b%2Fc/bundle.json", fixed = TRUE)
  sent <- capture(verdifax_get_public_receipt_by_token(test_client(), "a b/c"))
  expect_match(sent[[1]]$raw_url, "/public/runs/a%20b%2Fc/receipt.json", fixed = TRUE)
  expect_error(verdifax_get_public_receipt_by_token(test_client(), ""), "token")
})

test_that("attestation paging reaches the query", {
  sent <- capture(verdifax_list_attestations(test_client(), limit = 5, offset = 10))
  expect_equal(sent[[1]]$url$query, list(limit = "5", offset = "10"))
})

test_that("reports and lists are unwrapped", {
  capture({
    expect_equal(verdifax_get_run_report(test_client(), 7), list(run_id = 7))
    expect_equal(verdifax_list_deletion_receipts(test_client(), 7), list(list(id = 1)))
    expect_equal(verdifax_admin_list_keys(test_client()), list(list(id = 2)))
  })
})

test_that("bundle functions return the exact text", {
  text <- "{\"input_nonce\": 1780000000123456789 ,\n \"hash\":\"a\"}"
  capture({
    expect_identical(verdifax_get_run_artifacts(test_client(), 7), text)
    expect_identical(verdifax_get_public_bundle(test_client(), 7), text)
    expect_identical(verdifax_get_public_bundle_by_token(test_client(), "t"), text)
  }, function(req) reply(text))
})

test_that("public bundle routes work without a key", {
  client <- verdifax_client(base_url = "http://mock.invalid", api_key = "")
  expect_null(client$api_key)
  sent <- capture(verdifax_get_public_bundle(client, 7), function(req) reply("{}"))
  expect_length(sent, 1)
})

test_that("verdifax_download_audit_pdf returns raw bytes", {
  pdf <- as.raw(c(0x25, 0x50, 0x44, 0x46, 0xff, 0x00))
  sent <- capture(
    out <- verdifax_download_audit_pdf(test_client(), 7, format = "brief"),
    function(req) httr2::response(
      status_code = 200,
      headers = "Content-Type: application/pdf",
      body = pdf
    )
  )
  expect_equal(sent[[1]]$url$path, "/runs/7/report.pdf")
  expect_equal(sent[[1]]$url$query, list(format = "brief"))
  expect_identical(out, pdf)
})

test_that("reports carry the answer when given, and the public report goes by token", {
  pdf_reply <- function(req) {
    body <- httr2::req_get_body(req)
    if (!is.null(body) && identical(body$ai_output_text, "wrong")) {
      return(reply("{\"error\":\"supplied answer refused: nothing was printed\"}", status = 422))
    }
    httr2::response(status_code = 200, headers = "Content-Type: application/pdf", body = charToRaw("%PDF-report"))
  }
  client <- test_client()
  sent <- capture({
    verdifax_download_audit_pdf(client, 7, "brief", ai_output_text = "the answer")
    verdifax_download_public_audit_pdf(client, "a b/c", "legal")
    verdifax_download_public_audit_pdf(client, "tok", ai_output_text = "the answer")
  }, pdf_reply)
  expect_length(sent, 3)
  expect_equal(sent[[1]]$method, "POST")
  expect_equal(sent[[1]]$url$path, "/runs/7/report.pdf")
  expect_equal(sent[[1]]$body, list(format = "brief", ai_output_text = "the answer"))
  expect_equal(sent[[2]]$method, "GET")
  expect_match(sent[[2]]$raw_url, "/public/runs/a%20b%2Fc/report.pdf?format=legal", fixed = TRUE)
  expect_equal(sent[[3]]$method, "POST")
  expect_match(sent[[3]]$raw_url, "/public/runs/tok/report.pdf", fixed = TRUE)
  expect_equal(sent[[3]]$body, list(format = "comprehensive", ai_output_text = "the answer"))
  expect_error(
    httr2::with_mocked_responses(pdf_reply, verdifax_download_audit_pdf(client, 7, ai_output_text = "wrong")),
    "nothing was printed"
  )
  expect_error(verdifax_download_audit_pdf(client, 7, ai_output_text = ""), "ai_output_text")
  expect_error(verdifax_download_public_audit_pdf(client, ""), "token")
})

test_that("a report format fallback is the caller's choice", {
  pdf_reply <- function(req) {
    if (grepl("format=breif", req$url, fixed = TRUE) && !grepl("fallback=", req$url, fixed = TRUE) &&
        is.null(httr2::req_get_body(req))) {
      return(reply("{\"error\":\"unknown report format: use brief, auditor, legal or comprehensive\"}", status = 400))
    }
    httr2::response(status_code = 200, headers = "Content-Type: application/pdf", body = charToRaw("%PDF-report"))
  }
  client <- test_client()
  expect_error(
    httr2::with_mocked_responses(pdf_reply, verdifax_download_audit_pdf(client, 7, "breif")),
    "brief, auditor, legal or comprehensive"
  )
  sent <- capture({
    verdifax_download_audit_pdf(client, 7, "breif", fallback = "comprehensive")
    verdifax_download_public_audit_pdf(client, "tok", "breif", fallback = "comprehensive")
    verdifax_download_public_audit_pdf(client, "tok", "breif", ai_output_text = "the answer", fallback = "comprehensive")
  }, pdf_reply)
  expect_length(sent, 3)
  expect_equal(sent[[1]]$url$query, list(format = "breif", fallback = "comprehensive"))
  expect_match(sent[[2]]$raw_url, "/public/runs/tok/report.pdf?format=breif&fallback=comprehensive", fixed = TRUE)
  expect_equal(sent[[3]]$method, "POST")
  expect_equal(sent[[3]]$body, list(format = "breif", fallback = "comprehensive", ai_output_text = "the answer"))
  expect_error(verdifax_download_audit_pdf(client, 7, "breif", fallback = c("a", "b")), "fallback")
})

test_that("lists and searches send lenient=1 only when asked", {
  client <- test_client()
  ok <- function(req) reply("{\"ok\":true,\"runs\":[],\"total\":0,\"attestations\":[]}")
  sent <- capture({
    verdifax_list_runs(client, lenient = TRUE)
    verdifax_list_account_runs(client, limit = 5, lenient = TRUE)
    verdifax_search_runs(client, from = "2026-11-11", lenient = TRUE)
    verdifax_list_attestations(client, lenient = TRUE)
    verdifax_list_runs(client, limit = 5)
  }, ok)
  expect_length(sent, 5)
  expect_equal(sent[[1]]$url$query, list(lenient = "1"))
  expect_equal(sent[[2]]$url$query, list(limit = "5", lenient = "1"))
  expect_equal(sent[[3]]$url$query, list(from = "2026-11-11", lenient = "1"))
  expect_equal(sent[[4]]$url$query, list(lenient = "1"))
  expect_equal(sent[[5]]$url$query, list(limit = "5"))
})

test_that("the public sign-off routes need no key", {
  client <- verdifax_client(base_url = "https://api.example.test", api_key = NULL)
  answer <- "{\"ok\":true,\"run_id\":7,\"read\":true,\"signoffs\":[],\"decision_in_force\":{\"decision\":\"approve\",\"run_id\":9,\"on\":\"job_final_step\"}}"
  sent <- capture({
    out <- verdifax_get_public_signoff_by_token(client, "a b/c")
    verdifax_get_public_signoff(client, 7)
  }, function(req) reply(answer))
  expect_equal(out$decision_in_force$run_id, 9)
  expect_match(sent[[1]]$raw_url, "/public/runs/a%20b%2Fc/signoff.json", fixed = TRUE)
  expect_equal(sent[[2]]$url$path, "/runs/7/signoff.json")
  expect_null(sent[[1]]$headers[["X-Verdifax-Key"]])
  expect_error(verdifax_get_public_signoff_by_token(client, ""), "token")
  expect_error(verdifax_get_public_signoff(client, 0), "run_id")
})

test_that("verdifax_dcae_verify posts the bundle", {
  bundle <- list(envelope_id = "e", manifest_hash = strrep("a", 64))
  sent <- capture(
    out <- verdifax_dcae_verify(test_client(), bundle),
    function(req) reply("{\"verified\":true}")
  )
  expect_equal(sent[[1]]$method, "POST")
  expect_equal(sent[[1]]$url$path, "/dcae/verify")
  expect_equal(sent[[1]]$body, bundle)
  expect_true(out$verified)
})

test_that("verdifax_execute returns the manifest", {
  sent <- capture(out <- verdifax_execute(
    test_client(), "hello", .program_id, "r", .registry_record_hash,
    ai_output_text = "o"
  ))
  expect_equal(sent[[1]]$url$path, "/execute")
  expect_equal(sent[[1]]$body$ai_output_text, "o")
  expect_equal(out, list(ManifestHash = "m"))
})

test_that("admin helpers call their routes", {
  client <- test_client()
  sent <- capture({
    verdifax_admin_create_key(client, "name")
    expect_null(verdifax_admin_revoke_key(client, 2))
    receipt <- verdifax_admin_erase(client, 7, "request.email", strrep("c", 64), "D1")
    expect_equal(receipt, list(receipt_hash = "r"))
  })
  expect_equal(sent[[1]]$method, "POST")
  expect_equal(sent[[1]]$url$path, "/admin/keys")
  expect_equal(sent[[1]]$body, list(name = "name"))
  expect_equal(sent[[2]]$method, "DELETE")
  expect_equal(sent[[2]]$url$path, "/admin/keys/2")
  expect_equal(sent[[3]]$url$path, "/admin/erase")
  expect_equal(sent[[3]]$body, list(
    run_id = 7, field_path = "request.email",
    ciphertext_hash = strrep("c", 64), dsar_reference = "D1"
  ))
})

test_that("verdifax_admin_clear_request_key calls its route", {
  sent <- capture(result <- verdifax_admin_clear_request_key(test_client(), 7))
  expect_equal(sent[[1]]$method, "DELETE")
  expect_equal(sent[[1]]$url$path, "/admin/keys/7/request-key")
  expect_null(sent[[1]]$body)
  expect_true(result$ok)
})

test_that("verdifax_admin_clear_request_key writes a large id in full", {
  sent <- capture(verdifax_admin_clear_request_key(test_client(), 1e5))
  expect_equal(sent[[1]]$url$path, "/admin/keys/100000/request-key")
})

test_that("verdifax_admin_clear_request_key refuses a bad id without a request", {
  sent <- capture(expect_error(verdifax_admin_clear_request_key(test_client(), 0), "key_id"))
  expect_length(sent, 0)
})

test_that("admin_erase leaves out an unset reference", {
  sent <- capture(verdifax_admin_erase(test_client(), 7, "f", strrep("c", 64)))
  expect_null(sent[[1]]$body$dsar_reference)
})

test_that("bad input is refused without a request", {
  client <- test_client()
  sent <- capture({
    expect_error(verdifax_get_attestation(client, 0), "attestation_id")
    expect_error(verdifax_get_deny_receipt(client, -1), "run_id")
    expect_error(verdifax_get_public_bundle_by_token(client, ""), "token")
    expect_error(verdifax_admin_create_key(client, ""), "name")
    expect_error(verdifax_admin_revoke_key(client, 0), "key_id")
    expect_error(verdifax_admin_erase(client, 7, "", strrep("c", 64)), "field_path")
    expect_error(verdifax_admin_erase(client, 7, "f", "short"), "ciphertext_hash")
    expect_error(
      verdifax_attest_claude_response(client, "p", "", .program_id, "r", .registry_record_hash),
      "response is required"
    )
  })
  expect_length(sent, 0)
})

test_that("new routes stop with the server's message", {
  capture(
    expect_error(
      verdifax_get_deny_receipt(test_client(), 7),
      "run not found",
      class = "httr2_http_404"
    ),
    function(req) reply("{\"error\":\"run not found\"}", 404)
  )
  capture(
    expect_error(
      verdifax_admin_create_key(test_client(), "n"),
      "admin key required",
      class = "httr2_http_403"
    ),
    function(req) reply("{\"error\":\"admin key required\"}", 403)
  )
})

test_that("provider helpers send the payload, and AI output only with govern", {
  client <- test_client()
  sent <- capture({
    verdifax_attest_claude_response(client, "p", "r", .program_id, "x", .registry_record_hash)
    verdifax_attest_openai_response(client, "p", "r", .program_id, "x", .registry_record_hash)
    verdifax_attest_claude_response(
      client, "p", "r", .program_id, "x", .registry_record_hash, govern = TRUE
    )
    verdifax_attest_openai_response(
      client, "p", "r", .program_id, "x", .registry_record_hash, govern = TRUE
    )
  })
  expect_equal(sent[[1]]$url$path, "/execute")
  expect_equal(
    sent[[1]]$body$payload_text,
    verdifax_format_provider_payload("anthropic", "p", "r")
  )
  expect_null(sent[[1]]$body$ai_output_text)
  expect_null(sent[[2]]$body$ai_output_text)
  expect_equal(sent[[3]]$body$ai_output_text, "r")
  expect_equal(sent[[4]]$body$ai_output_text, "r")
  expect_equal(sent[[1]]$body$attested_context, list(
    actor_role = "ai_assistant", model_provider = "anthropic", attested = TRUE
  ))
  expect_equal(sent[[2]]$body$attested_context$model_provider, "openai")
})

# The vector shared by the four SDKs, so they cannot disagree.
test_that("shared provider payload vector", {
  prompt <- "Say \"hi\" to <b>&\n"
  response <- "caf\u00e9\t\\ / \u2028 \u0001 \U0001F600"
  expected <- paste0(
    "{\"prompt\":\"Say \\\"hi\\\" to <b>&\\n\",\"provider\":\"anthropic\",",
    "\"response\":\"caf\u00e9\\t\\\\ / \u2028 \\u0001 \U0001F600\"}"
  )
  payload <- verdifax_format_provider_payload("anthropic", prompt, response)
  expect_identical(enc2utf8(payload), enc2utf8(expected))
  expect_equal(
    paste(as.character(openssl::sha256(charToRaw(payload))), collapse = ""),
    "3adc179eb067ac68d290b78eaf48442bab6f580fbf4198ce7a7a56cc9c632425"
  )
  plain <- verdifax_format_provider_payload("openai", "p", "r")
  expect_identical(plain, "{\"prompt\":\"p\",\"provider\":\"openai\",\"response\":\"r\"}")
  expect_equal(
    paste(as.character(openssl::sha256(charToRaw(plain))), collapse = ""),
    "f642f9972df7037832635f8bcf43675d1d1da9fb6e1af2667e53ca38717ce301"
  )
})

test_that("the payload refuses text that is not valid UTF-8", {
  expect_error(verdifax_format_provider_payload("openai", "\xff", "r"), "UTF-8")
})

test_that("the four execute blocks reach every path", {
  blocks <- list(
    request_substance = list(prompt = list(template_id = "t")),
    authorization_chain = list(approvers = list(list(actor_id = "a"))),
    regulatory_scaffolding = list(right_to_explanation = "yes"),
    causal_graph = list(parent_run_id = 3)
  )
  client <- test_client()
  call_with <- function(fn) {
    do.call(fn, c(list(client, "x", .program_id, "r", .registry_record_hash), blocks))
  }
  sent <- capture({
    call_with(verdifax_attest)
    call_with(verdifax_execute)
    call_with(verdifax_verify_determinism)
    verdifax_execute_batch(client, list(c(list(
      payload = "x", program_id = .program_id, route_id = "r",
      registry_record_hash = .registry_record_hash
    ), blocks)))
  })
  bodies <- list(sent[[1]]$body, sent[[2]]$body, sent[[3]]$body, sent[[4]]$body$runs[[1]])
  for (body in bodies) {
    for (name in names(blocks)) {
      expect_equal(body[[name]], blocks[[name]])
    }
  }
})

test_that("origin hashes are refused without a request", {
  client <- test_client()
  sent <- capture({
    for (name in c("source_ip_hash", "user_agent_hash")) {
      substance <- list(origin = stats::setNames(list("x"), name))
      expect_error(
        verdifax_attest(client, "x", .program_id, "r", .registry_record_hash,
          request_substance = substance),
        "computed by the server"
      )
      expect_error(
        verdifax_verify_determinism(client, "x", .program_id, "r", .registry_record_hash,
          request_substance = substance),
        "computed by the server"
      )
    }
  })
  expect_length(sent, 0)
  sent <- capture(verdifax_attest(
    client, "x", .program_id, "r", .registry_record_hash,
    request_substance = list(origin = list(client_app = "a", source_ip_hash = ""))
  ))
  expect_length(sent, 1)
})

test_that("declared is derived from the fields", {
  sent <- capture({
    verdifax_attest(test_client(), "x", .program_id, "r", .registry_record_hash,
      reproducibility_context = list(declared = FALSE, runtime_name = "R"))
    verdifax_attest(test_client(), "x", .program_id, "r", .registry_record_hash,
      reproducibility_context = list(declared = TRUE, runtime_name = ""))
  })
  expect_true(sent[[1]]$body$reproducibility_context$declared)
  expect_false(sent[[2]]$body$reproducibility_context$declared)
})

test_that("attest applies the strict validators without a request", {
  client <- test_client()
  sent <- capture({
    expect_error(
      verdifax_attest(client, "x", strrep("A", 64), "r", .registry_record_hash),
      "lowercase hex"
    )
    expect_error(
      verdifax_attest(client, "x", .program_id, "caf\u00e9", .registry_record_hash),
      "non-printable"
    )
  })
  expect_length(sent, 0)
})

test_that("GET, HEAD and OPTIONS carry the retry policy and POST does not", {
  client <- verdifax_client(base_url = "http://mock.invalid", max_retries = 2, retry_base_delay = 1)
  for (method in c("GET", "HEAD", "OPTIONS")) {
    policies <- verdifax:::.build_request(client, "/x", NULL, method = method)$policies
    expect_equal(policies$retry_max_tries, 3)
    expect_true(policies$retry_on_failure)
    expect_true(all(policies$retry_backoff(2) <= 2))
    expect_true(policies$retry_is_transient(httr2::response(status_code = 503)))
    expect_true(policies$retry_is_transient(httr2::response(status_code = 429)))
    expect_false(policies$retry_is_transient(httr2::response(status_code = 404)))
  }
  for (method in c("POST", "DELETE")) {
    policies <- verdifax:::.build_request(client, "/x", NULL, method = method)$policies
    expect_null(policies$retry_max_tries)
  }
  off <- verdifax_client(base_url = "http://mock.invalid", max_retries = 0)
  expect_null(verdifax:::.build_request(off, "/x", NULL, method = "GET")$policies$retry_max_tries)
})

test_that("the default user agent names version 1.16.0", {
  client <- verdifax_client(base_url = "http://mock.invalid")
  req <- verdifax:::.build_request(client, "/x", NULL, method = "GET")
  expect_equal(httr2::req_get_headers(req)[["User-Agent"]], "verdifax-r/1.16.0")
})

test_that("user_agent reaches the request", {
  client <- verdifax_client(base_url = "http://mock.invalid", user_agent = "agent/2")
  req <- verdifax:::.build_request(client, "/x", NULL, method = "GET")
  expect_equal(httr2::req_get_headers(req)[["User-Agent"]], "agent/2")
})

test_that("attested_context reaches attest, determinism and batch", {
  context <- list(actor_role = "reviewer", decision_note = "")
  client <- test_client()
  sent <- capture({
    verdifax_attest(client, "x", .program_id, "r", .registry_record_hash, attested_context = context)
    verdifax_verify_determinism(
      client, "x", .program_id, "r", .registry_record_hash, attested_context = context
    )
    verdifax_execute_batch(client, list(list(
      payload = "x", program_id = .program_id, route_id = "r",
      registry_record_hash = .registry_record_hash, attested_context = context
    )))
  })
  expect_true(sent[[1]]$body$attested_context$attested)
  expect_true(sent[[2]]$body$attested_context$attested)
  expect_true(sent[[3]]$body$runs[[1]]$attested_context$attested)
})

test_that("an empty attested_context is not marked attested", {
  sent <- capture(verdifax_attest(
    test_client(), "x", .program_id, "r", .registry_record_hash,
    attested_context = list(decision_note = "")
  ))
  expect_false(sent[[1]]$body$attested_context$attested)
})

test_that("verdifax_run_statuses is the set the server uses", {
  expect_setequal(verdifax_run_statuses(), c(
    "ok", "probe", "pepg_deny", "ccv_halt", "macc_halt",
    "aivp_t4_halt", "attestation_gap", "stage_error"
  ))
})

test_that("verdifax_from_env reads the environment", {
  withr::local_envvar(
    VERDIFAX_BASE_URL = NA,
    VERDIFAX_API_URL = "http://env.invalid/",
    VERDIFAX_API_KEY = "envkey",
    VERDIFAX_TIMEOUT_MS = "5000",
    VERDIFAX_USER_AGENT = "agent/1",
    VERDIFAX_MAX_RETRIES = "0"
  )
  client <- verdifax_from_env()
  expect_equal(client$base_url, "http://env.invalid")
  expect_equal(client$api_key, "envkey")
  expect_equal(client$timeout, 5)
  expect_equal(client$user_agent, "agent/1")
  expect_equal(client$max_retries, 0)
  withr::local_envvar(VERDIFAX_BASE_URL = "http://first.invalid")
  expect_equal(verdifax_from_env()$base_url, "http://first.invalid")
  expect_equal(verdifax_client()$base_url, "http://first.invalid")
})

test_that("verdifax_from_env refuses a setting that is not an integer", {
  withr::local_envvar(VERDIFAX_TIMEOUT_MS = "soon")
  expect_error(verdifax_from_env(), "VERDIFAX_TIMEOUT_MS")
})

test_that("section0 hashes match the vectors the Go and Python code share", {
  expect_equal(
    verdifax_dse_dispatch_hash(
      "env-fixture-v1-aaaaaaaaaaaaaaaa", "seq-fixture-v1-1",
      strrep("1", 64), strrep("2", 64)
    ),
    "e66378381a9dea8ee0475ddc5b55a81f256aac523dd523c02c08e25ab34bae6b"
  )
  expect_equal(
    verdifax_dcae_closure_hash(
      strrep("3", 64), strrep("4", 64), "env-fixture-dcae-v1",
      strrep("5", 64), "VERIFIED_SOUND_COMPLETE_ZK"
    ),
    "e34cee0fcc6ebf9eafc3ef5479fd0fffd5a4de5c60039ba42b009f0c05b8fc93"
  )
  receipt <- list(
    "env-fixture-cres-v1", "request.payload.customer_email",
    "2026-05-07T00:00:00.000000000Z", "ops-fixture", strrep("6", 64), "DSAR-FIXTURE-001"
  )
  expected <- "1bb128c1f86cc6c7d63d44cc49bbdfc1185c8105d5bc270838af63814901bee5"
  expect_equal(do.call(verdifax_cres_receipt_hash, receipt), expected)
  expect_false(identical(do.call(verdifax_cres_receipt_hash, c(receipt, "other")), expected))
})

test_that("the hashes need only openssl, not sodium", {
  helper <- paste(deparse(verdifax:::.sha256_hex), collapse = "\n")
  expect_false(grepl("sodium", helper, fixed = TRUE))
  expect_true(grepl("openssl::sha256", helper, fixed = TRUE))
  testthat::local_mocked_bindings(.sodium_available = function() FALSE, .package = "verdifax")
  expect_equal(
    verdifax_dse_dispatch_hash(
      "env-fixture-v1-aaaaaaaaaaaaaaaa", "seq-fixture-v1-1",
      strrep("1", 64), strrep("2", 64)
    ),
    "e66378381a9dea8ee0475ddc5b55a81f256aac523dd523c02c08e25ab34bae6b"
  )
  expect_equal(
    verdifax:::.sha256_hex("hello"),
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
  )
  expect_equal(
    verdifax:::.sha256_hex("caf\u00e9"),
    paste(as.character(openssl::sha256(charToRaw(enc2utf8("caf\u00e9")))), collapse = "")
  )
})

test_that("section0 refuses a value that is not 64 lowercase hex", {
  expect_error(verdifax_dse_dispatch_hash("e", "s", strrep("A", 64), strrep("2", 64)), "program_id")
  expect_error(
    verdifax_dcae_closure_hash("short", strrep("4", 64), "e", strrep("5", 64), "s"),
    "manifest_hash"
  )
  expect_error(verdifax_cres_receipt_hash("e", "f", "c", "a", "x", "d"), "ciphertext")
})

test_that("the validators accept and refuse", {
  expect_true(verdifax_validate_hex64(strrep("a", 64), "field"))
  expect_error(verdifax_validate_hex64(strrep("A", 64), "field"), "field")
  expect_error(verdifax_validate_hex64(NA_character_, "field"), "field")
  expect_true(verdifax_validate_route_id("route-1"))
  expect_error(verdifax_validate_route_id(""), "required")
  expect_error(verdifax_validate_route_id(strrep("a", 257)), "too long")
  expect_error(verdifax_validate_route_id("café"), "non-printable")
})

test_that("the preimage joins its fields with zero bytes", {
  preimage <- verdifax_request_signature_preimage("h", "p", "r", "c", "t", "n")
  expect_equal(sum(preimage == as.raw(0)), 6)
  expect_equal(rawToChar(preimage[1:19]), "verdifax.request.v1")
})

test_that("the public signing helpers match the shared vector", {
  need_sodium()
  body <- list(
    payload_text = "hello", program_id = .program_id, route_id = "r",
    registry_record_hash = .registry_record_hash
  )
  signed <- verdifax_sign_request(
    .seed, body, "2026-11-05T00:00:00Z", "00112233445566778899aabbccddeeff"
  )
  expect_equal(
    signed$signature,
    "PWKn9IplkfrPmXSN+EfJX7aUPoRR0GHqjCvOLG2l1BAvPgupr7ZsJGNujNh6Wk2w/Y1zRaBVeNqOZ1QVrrBvCw=="
  )
  expect_equal(verdifax_request_key_registration_body(.seed), list(
    public_key = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=",
    proof = "Vc0TtZ8UbLQgWVnUcwSFPzl3jMn1neQqYQEpbepGa7IYfJJ7kh5QcU0FT5tC5EDoAJNDZNxkLA2Dtf2JHsppBA=="
  ))
})
