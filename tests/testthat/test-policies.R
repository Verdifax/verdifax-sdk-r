# Customer policies and the policy fields of a run. Requests are captured by
# a mock, so nothing reaches the network.

.program_id <- strrep("1", 64)
.registry_record_hash <- strrep("2", 64)
.seed <- as.raw(rep(1L, 32))
.public_key <- "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="
.document_hash <- strrep("d", 64)
.newest <- strrep("e", 64)
.policy_hash <- strrep("f", 64)
.document <- "{\n  \"policy_id\": \"loans\",\n  \"note\": \"café \\\"quoted\\\"\"\n}\n"

need_sodium <- function() {
  if (!nzchar(Sys.getenv("CI"))) {
    testthat::skip_if_not_installed("sodium")
  }
}

unsigned_client <- function() {
  verdifax_client(base_url = "http://mock.invalid", api_key = "k")
}

signed_client <- function() {
  verdifax_client(base_url = "http://mock.invalid", api_key = "k", signing_key = .seed)
}

json_response <- function(text, status = 200) {
  httr2::response(
    status_code = status,
    headers = "Content-Type: application/json",
    body = charToRaw(enc2utf8(text))
  )
}

.upload_reply <- sprintf(
  paste0(
    "{\"policy_id\":\"loans\",\"policy_version\":\"1\",\"policy_hash\":\"%s\",",
    "\"document_hash\":\"%s\",\"created_at\":\"2026-11-06T12:00:00Z\"}"
  ),
  .policy_hash, .document_hash
)
.list_reply <- sprintf(
  paste0(
    "{\"ok\":true,\"chain_id\":\"api-key-7\",\"newest_activation_hash\":\"%s\",",
    "\"active_document_hash\":\"\",\"policies\":[%s]}"
  ),
  .newest, .upload_reply
)
.activation_reply <- sprintf(
  paste0(
    "{\"ok\":true,\"activation\":{\"format\":\"verdifax.policy-activation.v1\",",
    "\"chain_id\":\"api-key-7\",\"sequence\":2,\"previous_activation_hash\":\"%s\",",
    "\"document_hash\":\"%s\",\"activation_hash\":\"%s\"}}"
  ),
  .newest, .document_hash, strrep("9", 64)
)

# Answers like the server: each route by its method and path.
policy_server <- function(req) {
  method <- httr2::req_get_method(req)
  path <- httr2::url_parse(httr2::req_get_url(req))$path
  if (method == "GET" && path == "/policies") {
    return(json_response(.list_reply))
  }
  if (method == "POST" && path == "/policies") {
    return(json_response(.upload_reply, 201))
  }
  if (method == "GET" && path == "/policies/history") {
    return(json_response("[]"))
  }
  if (method == "GET" && grepl("^/policies/[0-9a-f]{64}$", path)) {
    return(json_response(sub("}$", ",\"document\":\"text\"}", .upload_reply)))
  }
  if (method == "POST" && path == "/policies/test") {
    return(json_response(
      "{\"ok\":true,\"sealed\":false,\"outcome\":\"deny\",\"fired_rule_id\":\"r1\",\"reason_code\":\"LIMIT\"}"
    ))
  }
  if (method == "POST" && grepl("/activate$", path)) {
    return(json_response(.activation_reply))
  }
  json_response("{\"ok\":true,\"run_id\":1,\"record_hash\":\"aa\"}")
}

# Runs `code` and returns what was sent, with the JSON text the request
# puts on the wire, written with the options req_body_json() uses.
capture <- function(code, respond = policy_server) {
  sent <- list()
  mock <- function(req) {
    body <- httr2::req_get_body(req)
    json <- if (is.null(body)) NULL else
      jsonlite::toJSON(body, auto_unbox = TRUE, digits = 22, null = "null")
    sent[[length(sent) + 1]] <<- list(
      method = httr2::req_get_method(req),
      path = httr2::url_parse(httr2::req_get_url(req))$path,
      json = if (is.null(json)) NULL else as.character(json),
      body = if (is.null(json)) NULL else jsonlite::fromJSON(json, simplifyVector = FALSE)
    )
    respond(req)
  }
  httr2::with_mocked_responses(mock, code)
  sent
}

# Checks an activation approval the way the server does, written out
# independently of the SDK.
activation_verifies <- function(signature, chain_id, document_hash, previous,
                                public_key = .public_key) {
  fields <- lapply(list(
    "verdifax.policy-activation.v1", chain_id, document_hash, previous,
    signature$signed_at, signature$nonce
  ), function(text) charToRaw(enc2utf8(text)))
  signed <- Reduce(function(a, b) c(a, as.raw(0), b), fields)
  sodium::sig_verify(
    signed, jsonlite::base64_dec(signature$signature), jsonlite::base64_dec(public_key)
  )
}

.actor <- list(actor_id = "u-17", actor_role = "loan_officer")
.context <- list(
  actor_type = "user",
  mfa_satisfied = TRUE,
  session_age_seconds = 120,
  object_type = "transaction",
  object_id = "loan-42",
  classification = "CONFIDENTIAL"
)

run_attest <- function(client, ..., attested_context = .actor) {
  verdifax_attest(
    client, "hello", .program_id, "route", .registry_record_hash,
    attested_context = attested_context, ...
  )
}

run_determinism <- function(client, ..., attested_context = .actor) {
  verdifax_verify_determinism(
    client, "hello", .program_id, "route", .registry_record_hash,
    attested_context = attested_context, ...
  )
}

batch_row <- function(...) {
  list(
    payload = "hello", program_id = .program_id, route_id = "route",
    registry_record_hash = .registry_record_hash, attested_context = .actor, ...
  )
}


# ── Policy routes ───────────────────────────────────────────────────────────

test_that("upload sends the exact text as one JSON string and returns the server's object", {
  sent <- capture(result <- verdifax_upload_policy(unsigned_client(), .document))
  expect_equal(sent[[1]]$method, "POST")
  expect_equal(sent[[1]]$path, "/policies")
  expect_named(sent[[1]]$body, "document")
  expect_identical(sent[[1]]$body$document, enc2utf8(.document))
  expect_true(startsWith(sent[[1]]$json, "{\"document\":\"{"))
  expect_equal(result, jsonlite::fromJSON(.upload_reply, simplifyVector = FALSE))
})

test_that("upload sends a wrapped or named string as a plain string", {
  for (document in list(I("text"), c(name = "text"))) {
    sent <- capture(verdifax_upload_policy(unsigned_client(), document))
    expect_identical(sent[[1]]$json, "{\"document\":\"text\"}")
  }
})

test_that("upload refuses anything that is not a single string, without a request", {
  bad <- list(
    list(policy_id = "loans"), list("text"), c("a", "b"), character(0),
    NA_character_, 5, NULL, charToRaw("text")
  )
  sent <- capture(for (document in bad) {
    expect_error(verdifax_upload_policy(unsigned_client(), document), "single string")
  })
  expect_length(sent, 0)
  sent <- capture(expect_error(verdifax_upload_policy(unsigned_client(), "\xff"), "UTF-8"))
  expect_length(sent, 0)
})

test_that("list calls GET /policies and returns the server's object", {
  sent <- capture(result <- verdifax_list_policies(unsigned_client()))
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/policies")
  expect_null(sent[[1]]$body)
  expect_equal(result, jsonlite::fromJSON(.list_reply, simplifyVector = FALSE))
  expect_equal(result$chain_id, "api-key-7")
})

test_that("get calls GET /policies/{document_hash} and returns the document", {
  sent <- capture(result <- verdifax_get_policy(unsigned_client(), .document_hash))
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, paste0("/policies/", .document_hash))
  expect_equal(result$document, "text")
  expect_equal(result$document_hash, .document_hash)
})

.bad_hashes <- list(
  strrep("D", 64), strrep("d", 63), strrep("d", 65), paste0(strrep("d", 64), "\n"),
  c(.document_hash, .document_hash), NA_character_, "", NULL, 5
)

test_that("get and activate refuse a bad hash without a request", {
  sent <- capture(for (hash in .bad_hashes) {
    expect_error(verdifax_get_policy(unsigned_client(), hash), "document_hash")
    expect_error(verdifax_activate_policy(unsigned_client(), hash), "document_hash")
  })
  expect_length(sent, 0)
})

test_that("test sends the inputs with the document and returns the server's object", {
  inputs <- list(subject_id = "u-1", subject_type = "user", verb = "approve")
  sent <- capture(result <- verdifax_test_policy(unsigned_client(), inputs, document = .document))
  expect_equal(sent[[1]]$method, "POST")
  expect_equal(sent[[1]]$path, "/policies/test")
  expect_setequal(names(sent[[1]]$body), c("inputs", "document"))
  expect_equal(sent[[1]]$body$inputs, inputs)
  expect_identical(sent[[1]]$body$document, enc2utf8(.document))
  expect_false(result$sealed)
  expect_equal(result$outcome, "deny")
  expect_equal(result$fired_rule_id, "r1")
  expect_equal(result$reason_code, "LIMIT")
})

test_that("test sends the inputs with a document hash", {
  inputs <- list(verb = "approve", mfa_satisfied = TRUE)
  sent <- capture(verdifax_test_policy(unsigned_client(), inputs, document_hash = .document_hash))
  expect_setequal(names(sent[[1]]$body), c("inputs", "document_hash"))
  expect_equal(sent[[1]]$body$document_hash, .document_hash)
  expect_match(sent[[1]]$json, "\"mfa_satisfied\":true", fixed = TRUE)
})

test_that("test sends empty inputs as a JSON object", {
  sent <- capture(verdifax_test_policy(unsigned_client(), list(), document_hash = .document_hash))
  expect_match(sent[[1]]$json, "\"inputs\":{}", fixed = TRUE)
})

test_that("test refuses both or neither of document and document_hash, without a request", {
  client <- unsigned_client()
  sent <- capture({
    expect_error(verdifax_test_policy(client, list()), "exactly one")
    expect_error(
      verdifax_test_policy(client, list(), document = "x", document_hash = .document_hash),
      "exactly one"
    )
    expect_error(verdifax_test_policy(client, list(), document_hash = "short"), "document_hash")
    expect_error(verdifax_test_policy(client, list(), document = list(a = 1)), "single string")
    expect_error(verdifax_test_policy(client, list("x"), document = "x"), "named list")
    expect_error(verdifax_test_policy(client, "x", document = "x"), "named list")
  })
  expect_length(sent, 0)
})

test_that("history returns the server's text exactly, to save for verdifax-verify", {
  text <- "[{\"sequence\":1,\"tree_size\": 9007199254740993 ,\"anchor\":{}}]\n"
  sent <- capture(
    result <- verdifax_get_policy_history(unsigned_client()),
    function(req) json_response(text)
  )
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/policies/history")
  expect_identical(result, text)
})


# ── Activate ────────────────────────────────────────────────────────────────

test_that("an unsigned activate reads the chain, then names its newest change", {
  sent <- capture(result <- verdifax_activate_policy(unsigned_client(), .document_hash))
  expect_length(sent, 2)
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/policies")
  expect_equal(sent[[2]]$method, "POST")
  expect_equal(sent[[2]]$path, paste0("/policies/", .document_hash, "/activate"))
  expect_equal(sent[[2]]$body, list(previous_activation_hash = .newest))
  expect_null(sent[[2]]$body$signature)
  expected <- jsonlite::fromJSON(.activation_reply, simplifyVector = FALSE)$activation
  expect_equal(result, expected)
})

test_that("a signed activate sends an approval that verifies for this chain, document and change", {
  need_sodium()
  sent <- capture(result <- verdifax_activate_policy(signed_client(), .document_hash))
  expect_length(sent, 2)
  body <- sent[[2]]$body
  expect_setequal(names(body), c("previous_activation_hash", "signature"))
  expect_equal(body$previous_activation_hash, .newest)
  signature <- body$signature
  expect_setequal(names(signature), c("signature", "signed_at", "nonce"))
  expect_match(signature$signed_at, "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$")
  expect_match(signature$nonce, "^[0-9a-f]{32}$")
  expect_false(grepl("\n", signature$signature, fixed = TRUE))
  expect_true(activation_verifies(signature, "api-key-7", .document_hash, .newest))
  expect_error(activation_verifies(signature, "api-key-8", .document_hash, .newest))
  expect_error(activation_verifies(signature, "api-key-7", strrep("c", 64), .newest))
  expect_error(activation_verifies(signature, "api-key-7", .document_hash, strrep("0", 64)))
  expect_equal(result$sequence, 2)
})

test_that("a first activation names 64 zeros as the previous change", {
  need_sodium()
  first <- sub(.newest, strrep("0", 64), .list_reply, fixed = TRUE)
  respond <- function(req) {
    if (httr2::req_get_method(req) == "GET") json_response(first) else policy_server(req)
  }
  sent <- capture(verdifax_activate_policy(signed_client(), .document_hash), respond)
  body <- sent[[2]]$body
  expect_equal(body$previous_activation_hash, strrep("0", 64))
  expect_true(activation_verifies(body$signature, "api-key-7", .document_hash, strrep("0", 64)))
})

test_that("after a key is cleared, activate sends no signature", {
  need_sodium()
  client <- signed_client()
  capture(verdifax_clear_request_key(client))
  sent <- capture(verdifax_activate_policy(client, .document_hash))
  expect_equal(sent[[2]]$body, list(previous_activation_hash = .newest))
})

test_that("a 409 from activate stops with the server's message and is not retried", {
  respond <- function(req) {
    if (httr2::req_get_method(req) == "GET") {
      return(json_response(.list_reply))
    }
    json_response("{\"ok\":false,\"error\":\"previous_activation_hash is not the newest change\"}", 409)
  }
  sent <- capture(expect_error(
    verdifax_activate_policy(unsigned_client(), .document_hash),
    "not the newest change",
    class = "httr2_http_409"
  ), respond)
  expect_length(sent, 2)
})

test_that("activate stops before the change when the chain cannot be read", {
  respond <- function(req) json_response("{\"ok\":true,\"policies\":[]}")
  sent <- capture(
    expect_error(verdifax_activate_policy(unsigned_client(), .document_hash), "newest_activation_hash"),
    respond
  )
  expect_length(sent, 1)
})

test_that("a signed activate stops before the change without a chain_id", {
  need_sodium()
  no_chain <- sprintf("{\"ok\":true,\"newest_activation_hash\":\"%s\",\"policies\":[]}", .newest)
  sent <- capture(
    expect_error(verdifax_activate_policy(signed_client(), .document_hash), "chain_id"),
    function(req) json_response(no_chain)
  )
  expect_length(sent, 1)
})


# ── policy_context and expected_policy_hash on runs ─────────────────────────

test_that("policy_context and expected_policy_hash reach attest, execute, determinism, batch rows, job steps and provider helpers", {
  client <- unsigned_client()
  object_only <- list(object_type = "text", classification = "PUBLIC")
  sent <- capture({
    run_attest(client, policy_context = .context, expected_policy_hash = .policy_hash)
    verdifax_execute(
      client, "hello", .program_id, "route", .registry_record_hash,
      attested_context = .actor, policy_context = .context, expected_policy_hash = .policy_hash
    )
    run_determinism(client, policy_context = .context, expected_policy_hash = .policy_hash)
    verdifax_execute_batch(client, list(
      batch_row(policy_context = .context, expected_policy_hash = .policy_hash)
    ))
    job <- verdifax_job(client, "loan-1")
    verdifax_job_step(
      job, "one", "hello", .program_id, "route", .registry_record_hash,
      attested_context = .actor, policy_context = .context, expected_policy_hash = .policy_hash
    )
    verdifax_attest_claude_response(
      client, "p", "r", .program_id, "route", .registry_record_hash,
      policy_context = object_only, expected_policy_hash = .policy_hash
    )
    verdifax_attest_openai_response(
      client, "p", "r", .program_id, "route", .registry_record_hash,
      policy_context = object_only, expected_policy_hash = .policy_hash
    )
  })
  paths <- vapply(sent, function(s) s$path, "")
  expect_equal(paths, c(
    "/execute", "/execute", "/execute/verify-determinism", "/execute/batch",
    "/execute", "/execute", "/execute"
  ))
  bodies <- list(
    sent[[1]]$body, sent[[2]]$body, sent[[3]]$body, sent[[4]]$body$runs[[1]], sent[[5]]$body
  )
  for (body in bodies) {
    expect_equal(body$policy_context, .context)
    expect_equal(body$expected_policy_hash, .policy_hash)
  }
  for (i in 6:7) {
    expect_equal(sent[[i]]$body$policy_context, object_only)
    expect_equal(sent[[i]]$body$expected_policy_hash, .policy_hash)
  }
})

test_that("policy values are written as JSON scalars", {
  context <- list(
    actor_type = I("user"), mfa_satisfied = TRUE, session_age_seconds = 100000,
    object_id = c(name = "loan-42")
  )
  sent <- capture(run_attest(
    unsigned_client(), policy_context = context, expected_policy_hash = I(.policy_hash)
  ))
  json <- sent[[1]]$json
  expect_match(
    json,
    "\"policy_context\":{\"actor_type\":\"user\",\"mfa_satisfied\":true,\"session_age_seconds\":100000,\"object_id\":\"loan-42\"}",
    fixed = TRUE
  )
  expect_match(json, sprintf("\"expected_policy_hash\":\"%s\"", .policy_hash), fixed = TRUE)
})

test_that("a batch row sends each policy field once, as checked", {
  sent <- capture(verdifax_execute_batch(unsigned_client(), list(
    batch_row(policy_context = list(object_id = I("x")), expected_policy_hash = .policy_hash)
  )))
  expect_setequal(names(sent[[1]]$body$runs[[1]]), c(
    "payload_text", "program_id", "route_id", "registry_record_hash", "attested_context",
    "policy_context", "expected_policy_hash"
  ))
  json <- sent[[1]]$json
  expect_equal(lengths(regmatches(json, gregexpr("\"policy_context", json, fixed = TRUE))), 1)
  expect_equal(lengths(regmatches(json, gregexpr("\"expected_policy_hash", json, fixed = TRUE))), 1)
  expect_match(json, "\"policy_context\":{\"object_id\":\"x\"}", fixed = TRUE)
})

test_that("a call without them sends neither field", {
  sent <- capture({
    run_attest(unsigned_client())
    run_determinism(unsigned_client())
    verdifax_execute_batch(unsigned_client(), list(batch_row()))
    run_attest(unsigned_client(), policy_context = list(), attested_context = NULL)
    run_attest(unsigned_client(), policy_context = list(object_id = NULL), attested_context = NULL)
  })
  bodies <- list(sent[[1]]$body, sent[[2]]$body, sent[[3]]$body$runs[[1]], sent[[4]]$body, sent[[5]]$body)
  for (body in bodies) {
    expect_false("policy_context" %in% names(body))
    expect_false("expected_policy_hash" %in% names(body))
  }
})

test_that("a signed call carries them inside signed_request", {
  need_sodium()
  client <- signed_client()
  sent <- capture({
    run_attest(client, policy_context = .context, expected_policy_hash = .policy_hash)
    run_determinism(client, policy_context = .context, expected_policy_hash = .policy_hash)
    verdifax_execute_batch(client, list(
      batch_row(policy_context = .context, expected_policy_hash = .policy_hash)
    ))
  })
  bodies <- list(sent[[1]]$body, sent[[2]]$body, sent[[3]]$body$runs[[1]])
  for (body in bodies) {
    expect_setequal(names(body), c("signed_request", "request_signature"))
    request <- jsonlite::fromJSON(body$signed_request, simplifyVector = FALSE)
    expect_equal(request$policy_context, .context)
    expect_equal(request$expected_policy_hash, .policy_hash)
    preimage <- verdifax:::.request_preimage_v2(
      body_hash = verdifax:::.sha256_hex(body$signed_request),
      payload_hash = verdifax:::.sha256_hex("hello"),
      program_id = .program_id, route_id = "route",
      registry_record_hash = .registry_record_hash, ai_output_hash = "", job = NULL,
      signed_at = body$request_signature$signed_at, nonce = body$request_signature$nonce
    )
    expect_true(sodium::sig_verify(
      preimage,
      jsonlite::base64_dec(body$request_signature$signature),
      jsonlite::base64_dec(.public_key)
    ))
  }
})

test_that("the object fields need no attested actor", {
  context <- list(object_type = "file", object_id = "f-1", classification = "TS_SCI")
  sent <- capture(run_attest(unsigned_client(), policy_context = context, attested_context = NULL))
  expect_equal(sent[[1]]$body$policy_context, context)
  expect_null(sent[[1]]$body$attested_context)
})

test_that("every listed value is accepted", {
  values <- c(
    lapply(c("agent", "user", "service", "system"), function(v) list(actor_type = v)),
    lapply(c("text", "transaction", "code", "data", "model", "file"), function(v) list(object_type = v)),
    lapply(c("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "TOP_SECRET", "TS_SCI"),
      function(v) list(classification = v)),
    list(list(mfa_satisfied = FALSE), list(session_age_seconds = 0), list(session_age_seconds = 5L),
      list(object_id = ""), list(object_id = strrep("a", 256)), list(object_id = strrep("é", 128)))
  )
  for (context in values) {
    sent <- capture(run_attest(unsigned_client(), policy_context = context))
    expect_equal(sent[[1]]$body$policy_context, context)
  }
})

test_that("a bad policy_context or expected_policy_hash is refused without a request", {
  client <- unsigned_client()
  bad_contexts <- list(
    list(list(mfa = TRUE), "unknown field: mfa"),
    list(list(actor_type = "user", actortype = "user"), "unknown field: actortype"),
    list(list(actor_type = "user", actor_type = "agent"), "twice"),
    list(list(actor_type = "robot"), "actor_type must be one of"),
    list(list(actor_type = "User"), "actor_type must be one of"),
    list(list(actor_type = ""), "actor_type must be one of"),
    list(list(actor_type = c("user", "agent")), "actor_type must be one of"),
    list(list(object_type = "image"), "object_type must be one of"),
    list(list(classification = "SECRET"), "classification must be one of"),
    list(list(classification = "public"), "classification must be one of"),
    list(list(classification = factor("PUBLIC")), "classification must be one of"),
    list(list(mfa_satisfied = "yes"), "mfa_satisfied must be TRUE or FALSE"),
    list(list(mfa_satisfied = NA), "mfa_satisfied must be TRUE or FALSE"),
    list(list(mfa_satisfied = 1), "mfa_satisfied must be TRUE or FALSE"),
    list(list(session_age_seconds = -1), "session_age_seconds"),
    list(list(session_age_seconds = 1.5), "session_age_seconds"),
    list(list(session_age_seconds = "60"), "session_age_seconds"),
    list(list(session_age_seconds = Inf), "session_age_seconds"),
    list(list(session_age_seconds = NA_real_), "session_age_seconds"),
    list(list(object_id = strrep("a", 257)), "longer than 256 bytes"),
    list(list(object_id = strrep("é", 129)), "longer than 256 bytes"),
    list(list(object_id = 42), "object_id must be a single string"),
    list(c(actor_type = "user"), "named list"),
    list(list("user"), "named list"),
    list("user", "named list")
  )
  sent <- capture(for (case in bad_contexts) {
    expect_error(run_attest(client, policy_context = case[[1]]), case[[2]])
    expect_error(run_determinism(client, policy_context = case[[1]]), case[[2]])
    expect_error(
      verdifax_execute_batch(client, list(batch_row(policy_context = case[[1]]))),
      case[[2]]
    )
  })
  expect_length(sent, 0)
  for (hash in list(strrep("F", 64), "short", paste0(.policy_hash, "\n"), c(.policy_hash, .policy_hash), 5)) {
    sent <- capture({
      expect_error(run_attest(client, expected_policy_hash = hash), "expected_policy_hash")
      expect_error(run_determinism(client, expected_policy_hash = hash), "expected_policy_hash")
      expect_error(
        verdifax_execute_batch(client, list(batch_row(expected_policy_hash = hash))),
        "expected_policy_hash"
      )
    })
    expect_length(sent, 0)
  }
})

test_that("actor values are refused without an attested context, as the server does", {
  client <- unsigned_client()
  not_attested <- list(NULL, list(), list(actor_id = ""), list(decision_note = ""),
    list(attested = TRUE), list(actor_id = NULL))
  values <- list(
    list(actor_type = "user"), list(mfa_satisfied = TRUE), list(session_age_seconds = 60),
    list(object_type = "text", session_age_seconds = 1)
  )
  message <- "need an attested_context with the actor"
  sent <- capture(for (field in values) {
    for (attested in not_attested) {
      expect_error(run_attest(client, policy_context = field, attested_context = attested), message)
      expect_error(run_determinism(client, policy_context = field, attested_context = attested), message)
      row <- batch_row(policy_context = field)
      row["attested_context"] <- list(attested)
      expect_error(verdifax_execute_batch(client, list(row)), message)
    }
    job <- verdifax_job(client, "loan-1")
    expect_error(
      verdifax_job_step(job, "one", "hello", .program_id, "route", .registry_record_hash,
        policy_context = field),
      message
    )
  })
  expect_length(sent, 0)
})

test_that("zero actor values need no attested context", {
  context <- list(mfa_satisfied = FALSE, session_age_seconds = 0, object_type = "code")
  sent <- capture({
    run_attest(unsigned_client(), policy_context = context, attested_context = NULL)
    run_determinism(unsigned_client(), policy_context = context, attested_context = NULL)
    row <- batch_row(policy_context = context)
    row$attested_context <- NULL
    verdifax_execute_batch(unsigned_client(), list(row))
  })
  expect_equal(sent[[1]]$body$policy_context, context)
  expect_equal(sent[[2]]$body$policy_context, context)
  expect_equal(sent[[3]]$body$runs[[1]]$policy_context, context)
  expect_null(sent[[1]]$body$attested_context)
})

test_that("any set attested_context field counts as the actor", {
  attested <- list(
    list(actor_role = "loan_officer"), list(model_provider = "anthropic"),
    list(actor_id = "u-17"), list(decision_kind = "approve", decision_note = "")
  )
  for (context in attested) {
    sent <- capture({
      run_attest(unsigned_client(), policy_context = .context, attested_context = context)
      row <- batch_row(policy_context = .context)
      row$attested_context <- context
      verdifax_execute_batch(unsigned_client(), list(row))
    })
    expect_equal(sent[[1]]$body$policy_context, .context)
    expect_true(sent[[1]]$body$attested_context$attested)
    expect_equal(sent[[2]]$body$runs[[1]]$policy_context, .context)
  }
})

test_that("the provider helpers count as attested, so they carry actor values", {
  client <- unsigned_client()
  sent <- capture({
    verdifax_attest_claude_response(
      client, "p", "r", .program_id, "route", .registry_record_hash, policy_context = .context
    )
    verdifax_attest_openai_response(
      client, "p", "r", .program_id, "route", .registry_record_hash, policy_context = .context
    )
  })
  for (request in sent) {
    expect_equal(request$body$policy_context, .context)
    expect_true(request$body$attested_context$attested)
  }
})

test_that("a refused run stops with the server's message on every execute path", {
  cases <- list(
    list(409, "another policy is active", list(expected_policy_hash = .policy_hash)),
    list(400, "policy_context: classification is not a known level",
      list(policy_context = list(classification = "PUBLIC"))),
    list(422, "policy denied", list())
  )
  for (case in cases) {
    status <- case[[1]]
    text <- case[[2]]
    respond <- function(req) {
      json_response(sprintf(
        "{\"ok\":false,\"record_hash\":\"%s\",\"error\":\"%s\"}", strrep("a", 64), text
      ), status)
    }
    class <- paste0("httr2_http_", status)
    sent <- capture({
      error <- tryCatch(do.call(run_attest, c(list(unsigned_client()), case[[3]])), error = identity)
      expect_s3_class(error, class)
      expect_match(conditionMessage(error), text, fixed = TRUE)
      expect_equal(error$record_hash, strrep("a", 64))
      expect_error(
        do.call(verdifax_execute, c(
          list(unsigned_client(), "hello", .program_id, "route", .registry_record_hash), case[[3]]
        )),
        text, fixed = TRUE, class = class
      )
      expect_error(
        do.call(run_determinism, c(list(unsigned_client()), case[[3]])),
        text, fixed = TRUE, class = class
      )
      expect_error(
        verdifax_attest_claude_response(
          unsigned_client(), "p", "r", .program_id, "route", .registry_record_hash
        ),
        text, fixed = TRUE, class = class
      )
    }, respond)
    expect_length(sent, 4)
  }
})

test_that("a refused signed run keeps its message and its signed text", {
  need_sodium()
  respond <- function(req) {
    json_response("{\"ok\":false,\"error\":\"another policy is active\"}", 409)
  }
  sent <- capture(
    error <- tryCatch(
      run_attest(signed_client(), expected_policy_hash = .policy_hash),
      error = identity
    ),
    respond
  )
  expect_s3_class(error, "httr2_http_409")
  expect_match(conditionMessage(error), "another policy is active", fixed = TRUE)
  expect_identical(error$signed_request, sent[[1]]$body$signed_request)
})


# ── No silently dropped request field ───────────────────────────────────────

# The copy beside this test is the shared file. Where the shared file is
# also present, as in the Verdifax workspace, the copy must match it.
test_that("the SDK's execute fields are execute_fields in sdk-parity.json", {
  copy <- testthat::test_path("sdk-parity.json")
  parity <- jsonlite::fromJSON(copy, simplifyVector = FALSE)
  expect_identical(verdifax:::.EXECUTE_FIELDS, unlist(parity$execute_fields))
  shared <- file.path(testthat::test_path(), "..", "..", "..", "scripts", "sdk-parity.json")
  if (file.exists(shared)) {
    expect_identical(readBin(copy, "raw", file.size(copy)), readBin(shared, "raw", file.size(shared)))
  }
})

test_that("a batch row with a field the server does not know is refused, naming it", {
  client <- unsigned_client()
  sent <- capture({
    expect_error(
      verdifax_execute_batch(client, list(batch_row(), batch_row(policy_contxt = list()))),
      "unknown field: policy_contxt"
    )
    expect_error(
      verdifax_execute_batch(client, list(batch_row(jobs = list(job_id = "j", step_id = "s")))),
      "unknown field: jobs"
    )
    expect_error(verdifax_execute_batch(client, list(c(batch_row(), list("x")))), "named list")
  })
  expect_length(sent, 0)
})

test_that("a batch row may hold any execute field", {
  sent <- capture(verdifax_execute_batch(unsigned_client(), list(list(
    payload_text = "hello", program_id = .program_id, route_id = "route",
    registry_record_hash = .registry_record_hash
  ))))
  expect_equal(sent[[1]]$body$runs[[1]]$payload_text, "hello")
})

test_that("an attested_context field outside the listed set is refused everywhere", {
  client <- unsigned_client()
  typo <- list(actor_id = "u-17", actorrole = "loan_officer")
  sent <- capture({
    expect_error(run_attest(client, attested_context = typo), "unknown field: actorrole")
    expect_error(run_determinism(client, attested_context = typo), "unknown field: actorrole")
    expect_error(
      verdifax_execute(client, "hello", .program_id, "route", .registry_record_hash,
        attested_context = typo),
      "unknown field: actorrole"
    )
    row <- batch_row()
    row$attested_context <- typo
    expect_error(verdifax_execute_batch(client, list(row)), "unknown field: actorrole")
    job <- verdifax_job(client, "loan-1")
    expect_error(
      verdifax_job_step(job, "one", "hello", .program_id, "route", .registry_record_hash,
        attested_context = typo),
      "unknown field: actorrole"
    )
    expect_error(run_attest(client, attested_context = list("u-17")), "named list")
  })
  expect_length(sent, 0)
})

test_that("every listed attested_context field is sent", {
  context <- list(
    actor_id = "u-17", actor_role = "r", authorization_policy = "p", actor_signature = "c2ln",
    model_provider = "anthropic", model_name = "m", model_version = "1",
    model_temperature = 0.5, prompt_hash = strrep("a", 64), decision_kind = "approve",
    decision_result = "approved", decision_note = "n"
  )
  sent <- capture(run_attest(unsigned_client(), attested_context = context))
  expect_equal(sent[[1]]$body$attested_context, c(context, attested = TRUE))
})

test_that("a misspelt argument to attest or the determinism check is refused by R, naming it", {
  client <- unsigned_client()
  sent <- capture({
    expect_error(run_attest(client, policy_contxt = list()), "policy_contxt")
    expect_error(run_determinism(client, expected_policy_hsh = .policy_hash), "expected_policy_hsh")
  })
  expect_length(sent, 0)
})
