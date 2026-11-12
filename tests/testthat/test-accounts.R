# The account routes, used with an account's owner key, and the admin account
# routes. Requests are captured by a mock, so nothing reaches the network.

.seed <- as.raw(rep(1L, 32))
.public_key <- "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="
.document_hash <- strrep("d", 64)
.newest <- strrep("e", 64)
.policy_hash <- strrep("f", 64)
.document <- "{\n  \"policy_id\": \"company\",\n  \"note\": \"café \\\"quoted\\\"\"\n}\n"
.csv <- paste0(
  "run_id,status,job_id,step_id,api_key_id\n",
  "1,ok,loan-1,decide,12\n",
  "2,ok,,,9007199254740993\n"
)

need_sodium <- function() {
  if (!nzchar(Sys.getenv("CI"))) {
    testthat::skip_if_not_installed("sodium")
  }
}

owner_client <- function() {
  verdifax_client(base_url = "http://mock.invalid", api_key = "owner")
}

signed_owner_client <- function() {
  verdifax_client(base_url = "http://mock.invalid", api_key = "owner", signing_key = .seed)
}

json_response <- function(text, status = 200) {
  httr2::response(
    status_code = status,
    headers = "Content-Type: application/json",
    body = charToRaw(enc2utf8(text))
  )
}

csv_response <- function(total = "1", truncated = "false") {
  headers <- list("Content-Type" = "text/csv; charset=utf-8")
  headers[["X-Verdifax-Total"]] <- total
  headers[["X-Verdifax-Truncated"]] <- truncated
  httr2::response(status_code = 200, headers = headers, body = charToRaw(.csv))
}

.account <- paste0(
  "{\"account_id\":\"account-7\",\"id\":7,\"name\":\"Acme\",\"tier\":\"trial\",",
  "\"created_at\":\"2026-11-07T12:00:00Z\",\"member_keys\":2,\"owner_keys\":1,",
  "\"chain_id\":\"account-7\"}"
)
.account_reply <- sub("^\\{", "{\"ok\":true,", .account)
.key <- paste0(
  "{\"ok\":true,\"id\":12,\"name\":\"customer:loans\",\"account_id\":\"account-7\",",
  "\"owner\":false,\"tier\":\"trial\",\"created_at\":\"2026-11-07T12:00:00Z\",",
  "\"secret\":\"vfx_secret\",\"request_key_required\":true,",
  "\"hint\":\"Store this secret now, it will never be shown again.\"}"
)
.keys_reply <- paste0(
  "{\"ok\":true,\"account_id\":\"account-7\",\"keys\":[",
  "{\"id\":11,\"name\":\"customer:Acme owner\",\"account_id\":\"account-7\",\"owner\":true,",
  "\"tier\":\"trial\",\"created_at\":\"2026-11-07T12:00:00Z\",\"last_used_at\":\"0001-01-01T00:00:00Z\",",
  "\"run_count\":0,\"revoked\":false},",
  "{\"id\":12,\"name\":\"customer:loans\",\"account_id\":\"account-7\",\"owner\":false,",
  "\"tier\":\"trial\",\"created_at\":\"2026-11-07T12:00:00Z\",\"last_used_at\":\"0001-01-01T00:00:00Z\",",
  "\"run_count\":3,\"revoked\":false,\"expires_at\":\"2027-01-01T23:59:59Z\"}]}"
)
.upload_reply <- sprintf(
  paste0(
    "{\"policy_id\":\"company\",\"policy_version\":\"1\",\"policy_hash\":\"%s\",",
    "\"document_hash\":\"%s\",\"created_at\":\"2026-11-07T12:00:00Z\"}"
  ),
  .policy_hash, .document_hash
)
.list_reply <- sprintf(
  paste0(
    "{\"ok\":true,\"chain_id\":\"account-7\",\"newest_activation_hash\":\"%s\",",
    "\"active_document_hash\":\"\",\"policies\":[%s]}"
  ),
  .newest, .upload_reply
)
.activation_reply <- sprintf(
  paste0(
    "{\"ok\":true,\"activation\":{\"format\":\"verdifax.policy-activation.v1\",",
    "\"chain_id\":\"account-7\",\"sequence\":2,\"previous_activation_hash\":\"%s\",",
    "\"document_hash\":\"%s\",\"activation_hash\":\"%s\"}}"
  ),
  .newest, .document_hash, strrep("9", 64)
)
.export_reply <- paste0(
  "{\"ok\":true,\"to\":\"2026-11-07T12:00:00Z\",\"total\":2,\"returned\":2,\"truncated\":false,",
  "\"by_status\":{\"ok\":2},\"runs\":[{\"run_id\":1,\"api_key_id\":12},{\"run_id\":2,\"api_key_id\":13}],",
  "\"account_id\":\"account-7\",",
  "\"account_policy_documents\":[{\"document_hash\":\"", .document_hash, "\"}],",
  "\"account_policy_history\":[{\"sequence\":1}]}"
)

# Answers like the server: each route by its method and path.
account_server <- function(req) {
  method <- httr2::req_get_method(req)
  path <- httr2::url_parse(httr2::req_get_url(req))$path
  route <- paste(method, path)
  if (route == "GET /account") {
    return(json_response(.account_reply))
  }
  if (route == "POST /account/keys") {
    return(json_response(.key, 201))
  }
  if (route == "GET /account/keys") {
    return(json_response(.keys_reply))
  }
  if (method == "DELETE" && grepl("^/account/keys/[0-9]+$", path)) {
    return(json_response(sprintf("{\"ok\":true,\"id\":%s,\"revoked\":true}", sub(".*/", "", path))))
  }
  if (route == "POST /account/request-key") {
    return(json_response(sprintf("{\"ok\":true,\"public_key\":\"%s\"}", .public_key)))
  }
  if (route == "DELETE /account/request-key") {
    return(json_response("{\"ok\":true}"))
  }
  if (route == "GET /account/runs") {
    return(json_response(
      "{\"total\":2,\"limit\":50,\"offset\":0,\"runs\":[{\"id\":1,\"api_key_id\":12},{\"id\":2,\"api_key_id\":13}]}"
    ))
  }
  if (route == "GET /account/runs/export") {
    format <- httr2::url_parse(httr2::req_get_url(req))$query$format
    return(if (identical(format, "csv")) csv_response("2") else json_response(.export_reply))
  }
  if (route == "GET /account/policies") {
    return(json_response(.list_reply))
  }
  if (route == "POST /account/policies") {
    return(json_response(.upload_reply, 201))
  }
  if (route == "GET /account/policies/history") {
    return(json_response("[]"))
  }
  if (route == "POST /account/policies/test") {
    return(json_response(
      "{\"ok\":true,\"sealed\":false,\"outcome\":\"allow\",\"fired_rule_id\":\"r2\",\"reason_code\":\"OK\"}"
    ))
  }
  if (method == "GET" && grepl("^/account/policies/[0-9a-f]{64}$", path)) {
    return(json_response(sub("}$", ",\"document\":\"text\"}", .upload_reply)))
  }
  if (method == "POST" && grepl("^/account/policies/[0-9a-f]{64}/activate$", path)) {
    return(json_response(.activation_reply))
  }
  if (route == "POST /admin/accounts") {
    owner <- sub("\"owner\":false", "\"owner\":true", .key)
    return(json_response(sprintf("{\"ok\":true,\"account\":%s,\"owner_key\":%s}", .account, owner), 201))
  }
  if (route == "GET /admin/accounts") {
    return(json_response(sprintf("{\"ok\":true,\"accounts\":[%s]}", .account)))
  }
  if (route == "POST /admin/keys") {
    return(json_response(sub("\"owner\":false,", "", .key), 201))
  }
  json_response("{\"ok\":false,\"error\":\"not found\"}", 404)
}

# Runs `code` and returns what was sent, with the JSON text the request
# puts on the wire, written with the options req_body_json() uses.
capture <- function(code, respond = account_server) {
  sent <- list()
  mock <- function(req) {
    body <- httr2::req_get_body(req)
    json <- if (is.null(body)) NULL else
      jsonlite::toJSON(body, auto_unbox = TRUE, digits = 22, null = "null")
    url <- httr2::url_parse(httr2::req_get_url(req))
    sent[[length(sent) + 1]] <<- list(
      method = httr2::req_get_method(req),
      path = url$path,
      query = url$query,
      key = httr2::req_get_headers(req, "reveal")[["X-Verdifax-Key"]],
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

parsed <- function(text) jsonlite::fromJSON(text, simplifyVector = FALSE)


# ── Account and member keys ─────────────────────────────────────────────────

test_that("get_account calls GET /account with the owner key and returns the account", {
  sent <- capture(result <- verdifax_get_account(owner_client()))
  expect_length(sent, 1)
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/account")
  expect_equal(sent[[1]]$key, "owner")
  expect_null(sent[[1]]$body)
  expect_equal(result, parsed(.account_reply))
  expect_equal(result$account_id, "account-7")
  expect_equal(result$chain_id, "account-7")
})

test_that("create_account_key posts the name, and expires_at only when given", {
  sent <- capture({
    result <- verdifax_create_account_key(owner_client(), "loans")
    verdifax_create_account_key(owner_client(), "batch", expires_at = "2027-01-01")
  })
  expect_equal(sent[[1]]$method, "POST")
  expect_equal(sent[[1]]$path, "/account/keys")
  expect_identical(sent[[1]]$json, "{\"name\":\"loans\"}")
  expect_equal(sent[[2]]$body, list(name = "batch", expires_at = "2027-01-01"))
  expect_equal(result, parsed(.key))
  expect_equal(result$secret, "vfx_secret")
  expect_false(result$owner)
  expect_true(result$request_key_required)
})

test_that("list_account_keys calls GET /account/keys and keeps account_id", {
  sent <- capture(result <- verdifax_list_account_keys(owner_client()))
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/account/keys")
  expect_equal(result, parsed(.keys_reply))
  expect_equal(result$account_id, "account-7")
  expect_length(result$keys, 2)
  expect_true(result$keys[[1]]$owner)
  expect_null(result$keys[[1]]$expires_at)
  expect_equal(result$keys[[2]]$expires_at, "2027-01-01T23:59:59Z")
})

test_that("revoke_account_key calls DELETE /account/keys/{id} and writes a large id in full", {
  sent <- capture({
    result <- verdifax_revoke_account_key(owner_client(), 12)
    verdifax_revoke_account_key(owner_client(), 1e5)
  })
  expect_equal(sent[[1]]$method, "DELETE")
  expect_equal(sent[[1]]$path, "/account/keys/12")
  expect_null(sent[[1]]$body)
  expect_equal(result, list(ok = TRUE, id = 12L, revoked = TRUE))
  expect_equal(sent[[2]]$path, "/account/keys/100000")
})

test_that("a revoke outside the account stops with the server's 404 message", {
  respond <- function(req) json_response("{\"ok\":false,\"error\":\"no such member key in this account\"}", 404)
  sent <- capture(expect_error(
    verdifax_revoke_account_key(owner_client(), 11),
    "no such member key in this account",
    class = "httr2_http_404"
  ), respond)
  expect_length(sent, 1)
})

test_that("bad account key input is refused without a request", {
  client <- owner_client()
  sent <- capture({
    for (name in list("", NA_character_, c("a", "b"), 5, NULL)) {
      expect_error(verdifax_create_account_key(client, name), "name")
    }
    expect_error(verdifax_create_account_key(client, "n", expires_at = 20270101), "expires_at")
    expect_error(verdifax_create_account_key(client, "n", expires_at = ""), "expires_at")
    for (id in list(0, -1, 1.5, NA, Inf, "12", c(1, 2), TRUE)) {
      expect_error(verdifax_revoke_account_key(client, id), "key_id")
    }
  })
  expect_length(sent, 0)
})


# ── The owner key's request key ─────────────────────────────────────────────

test_that("register_account_request_key posts the public key and its proof", {
  need_sodium()
  sent <- capture(result <- verdifax_register_account_request_key(signed_owner_client()))
  expect_equal(sent[[1]]$method, "POST")
  expect_equal(sent[[1]]$path, "/account/request-key")
  expect_equal(sent[[1]]$body, verdifax_request_key_registration_body(.seed))
  expect_equal(sent[[1]]$body$public_key, .public_key)
  expect_equal(result$public_key, .public_key)
})

test_that("register_account_request_key needs a signing key and sends nothing without one", {
  sent <- capture(expect_error(
    verdifax_register_account_request_key(owner_client()), "signing_key"
  ))
  expect_length(sent, 0)
})

test_that("clear_account_request_key sends the current key's approval, then drops the key", {
  need_sodium()
  client <- signed_owner_client()
  sent <- capture(verdifax_clear_account_request_key(client))
  expect_equal(sent[[1]]$method, "DELETE")
  expect_equal(sent[[1]]$path, "/account/request-key")
  change <- sent[[1]]$body$change
  expect_setequal(names(change), c("signature", "signed_at", "nonce"))
  signed <- Reduce(function(a, b) c(a, as.raw(0), b), lapply(
    list("verdifax.request-key-change.v1", "", change$signed_at, change$nonce),
    function(text) charToRaw(text)
  ))
  expect_true(sodium::sig_verify(
    signed, jsonlite::base64_dec(change$signature), jsonlite::base64_dec(.public_key)
  ))
  expect_error(verdifax_register_account_request_key(client), "signing_key")
})

test_that("a refused account clear keeps the key", {
  need_sodium()
  client <- signed_owner_client()
  respond <- function(req) {
    json_response("{\"ok\":false,\"error\":\"the current request key must approve this change\"}", 403)
  }
  capture(expect_error(verdifax_clear_account_request_key(client), "must approve"), respond)
  sent <- capture(verdifax_register_account_request_key(client))
  expect_equal(sent[[1]]$body$public_key, .public_key)
})

test_that("clear_account_request_key on an unsigned client sends no body", {
  sent <- capture(verdifax_clear_account_request_key(owner_client()))
  expect_equal(sent[[1]]$method, "DELETE")
  expect_equal(sent[[1]]$path, "/account/request-key")
  expect_null(sent[[1]]$body)
})


# ── The account's runs ──────────────────────────────────────────────────────

test_that("list_account_runs calls GET /account/runs with limit and offset", {
  sent <- capture({
    result <- verdifax_list_account_runs(owner_client(), limit = 100000, offset = 5)
    verdifax_list_account_runs(owner_client())
  })
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/account/runs")
  expect_equal(sent[[1]]$query, list(limit = "100000", offset = "5"))
  expect_null(sent[[2]]$query)
  expect_equal(result$runs[[1]]$id, 1)
  expect_identical(vapply(result$runs, function(run) run$api_key_id, integer(1)), c(12L, 13L))
})

test_that("export_account_runs sends the period and job, and keeps the account fields", {
  sent <- capture(result <- verdifax_export_account_runs(
    owner_client(), from = "2026-11-01T00:00:00Z", to = "2026-12-01T00:00:00Z", job_id = "loan-1"
  ))
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/account/runs/export")
  expect_equal(sent[[1]]$query, list(
    from = "2026-11-01T00:00:00Z", to = "2026-12-01T00:00:00Z", job_id = "loan-1", format = "json"
  ))
  expect_equal(result, parsed(.export_reply))
  expect_equal(result$account_id, "account-7")
  expect_equal(result$account_policy_documents[[1]]$document_hash, .document_hash)
  expect_length(result$account_policy_history, 1)
  expect_identical(vapply(result$runs, function(row) row$api_key_id, integer(1)), c(12L, 13L))
})

test_that("export_account_runs_csv returns the CSV text unparsed with its counts", {
  sent <- capture(result <- verdifax_export_account_runs_csv(owner_client(), from = "2026-11-01T00:00:00Z"))
  expect_equal(sent[[1]]$path, "/account/runs/export")
  expect_equal(sent[[1]]$query, list(from = "2026-11-01T00:00:00Z", format = "csv"))
  expect_identical(result, list(csv = .csv, total = 2, truncated = FALSE))
  # api_key_id is the last column, after step_id, and reaches the caller as
  # the server wrote it, even past the doubles' exact range.
  rows <- utils::read.csv(text = result$csv, colClasses = "character")
  expect_identical(utils::tail(names(rows), 2), c("step_id", "api_key_id"))
  expect_identical(rows$api_key_id, c("12", "9007199254740993"))
})

test_that("export_account_runs_csv refuses a response without its counts", {
  respond <- function(req) {
    httr2::response(status_code = 200, headers = "Content-Type: text/csv", body = charToRaw(.csv))
  }
  capture(expect_error(
    verdifax_export_account_runs_csv(owner_client()),
    "verdifax_export_account_runs\\(\\) instead"
  ), respond)
})

test_that("an account export with a bad job_id is refused without a request", {
  sent <- capture({
    expect_error(verdifax_export_account_runs(owner_client(), job_id = "a b"), "job_id")
    expect_error(verdifax_export_account_runs_csv(owner_client(), job_id = ""), "job_id")
  })
  expect_length(sent, 0)
})


# ── The account's policy ────────────────────────────────────────────────────

test_that("upload_account_policy sends the exact text to POST /account/policies", {
  sent <- capture(result <- verdifax_upload_account_policy(owner_client(), .document))
  expect_equal(sent[[1]]$method, "POST")
  expect_equal(sent[[1]]$path, "/account/policies")
  expect_equal(names(sent[[1]]$body), "document")
  expect_identical(sent[[1]]$body$document, enc2utf8(.document))
  expect_equal(result, parsed(.upload_reply))
})

test_that("upload_account_policy refuses anything that is not a single string, without a request", {
  sent <- capture(for (document in list(list(a = 1), c("a", "b"), NA_character_, 5)) {
    expect_error(verdifax_upload_account_policy(owner_client(), document), "single string")
  })
  expect_length(sent, 0)
})

test_that("list_account_policies calls GET /account/policies and names the account chain", {
  sent <- capture(result <- verdifax_list_account_policies(owner_client()))
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/account/policies")
  expect_equal(result, parsed(.list_reply))
  expect_equal(result$chain_id, "account-7")
})

test_that("get_account_policy calls GET /account/policies/{document_hash}", {
  sent <- capture(result <- verdifax_get_account_policy(owner_client(), .document_hash))
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, paste0("/account/policies/", .document_hash))
  expect_equal(result$document, "text")
})

test_that("test_account_policy sends the inputs with a document or a document hash", {
  inputs <- list(subject_id = "u-1", verb = "approve")
  sent <- capture({
    result <- verdifax_test_account_policy(owner_client(), inputs, document = .document)
    verdifax_test_account_policy(owner_client(), list(), document_hash = .document_hash)
  })
  expect_equal(sent[[1]]$method, "POST")
  expect_equal(sent[[1]]$path, "/account/policies/test")
  expect_setequal(names(sent[[1]]$body), c("inputs", "document"))
  expect_equal(sent[[1]]$body$inputs, inputs)
  expect_identical(sent[[1]]$body$document, enc2utf8(.document))
  expect_match(sent[[2]]$json, "\"inputs\":{}", fixed = TRUE)
  expect_equal(sent[[2]]$body$document_hash, .document_hash)
  expect_false(result$sealed)
  expect_equal(result$outcome, "allow")
})

test_that("test_account_policy refuses both or neither of document and document_hash", {
  client <- owner_client()
  sent <- capture({
    expect_error(verdifax_test_account_policy(client, list()), "verdifax_test_account_policy needs exactly one")
    expect_error(
      verdifax_test_account_policy(client, list(), document = "x", document_hash = .document_hash),
      "exactly one"
    )
    expect_error(verdifax_test_account_policy(client, list(), document_hash = "short"), "document_hash")
    expect_error(verdifax_test_account_policy(client, "x", document = "x"), "named list")
  })
  expect_length(sent, 0)
})

test_that("get_account_policy_history returns the server's text exactly", {
  text <- "[{\"sequence\":1,\"tree_size\": 9007199254740993 ,\"anchor\":{}}]\n"
  sent <- capture(
    result <- verdifax_get_account_policy_history(owner_client()),
    function(req) json_response(text)
  )
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/account/policies/history")
  expect_identical(result, text)
})

test_that("get and activate on the account refuse a bad hash without a request", {
  sent <- capture(for (hash in list(strrep("D", 64), strrep("d", 63), NA_character_, "", NULL, 5)) {
    expect_error(verdifax_get_account_policy(owner_client(), hash), "document_hash")
    expect_error(verdifax_activate_account_policy(signed_owner_client(), hash), "document_hash")
  })
  expect_length(sent, 0)
})


# ── Activate the account's policy ───────────────────────────────────────────

test_that("activate_account_policy reads the account chain, then signs over it", {
  need_sodium()
  sent <- capture(result <- verdifax_activate_account_policy(signed_owner_client(), .document_hash))
  expect_length(sent, 2)
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/account/policies")
  expect_equal(sent[[2]]$method, "POST")
  expect_equal(sent[[2]]$path, paste0("/account/policies/", .document_hash, "/activate"))
  body <- sent[[2]]$body
  expect_setequal(names(body), c("previous_activation_hash", "signature"))
  expect_equal(body$previous_activation_hash, .newest)
  signature <- body$signature
  expect_setequal(names(signature), c("signature", "signed_at", "nonce"))
  expect_match(signature$signed_at, "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$")
  expect_match(signature$nonce, "^[0-9a-f]{32}$")
  expect_true(activation_verifies(signature, "account-7", .document_hash, .newest))
  # Not over the owner key's own chain, nor another account's.
  expect_error(activation_verifies(signature, "api-key-7", .document_hash, .newest))
  expect_error(activation_verifies(signature, "account-8", .document_hash, .newest))
  expect_error(activation_verifies(signature, "account-7", strrep("c", 64), .newest))
  expect_error(activation_verifies(signature, "account-7", .document_hash, strrep("0", 64)))
  expect_equal(result, parsed(.activation_reply)$activation)
})

test_that("activate_account_policy signs whatever chain the account route names", {
  need_sodium()
  other <- sub("account-7", "account-31", .list_reply, fixed = TRUE)
  respond <- function(req) {
    if (httr2::req_get_method(req) == "GET") json_response(other) else account_server(req)
  }
  sent <- capture(verdifax_activate_account_policy(signed_owner_client(), .document_hash), respond)
  expect_true(activation_verifies(sent[[2]]$body$signature, "account-31", .document_hash, .newest))
})

test_that("a first account activation names 64 zeros as the previous change", {
  need_sodium()
  first <- sub(.newest, strrep("0", 64), .list_reply, fixed = TRUE)
  respond <- function(req) {
    if (httr2::req_get_method(req) == "GET") json_response(first) else account_server(req)
  }
  sent <- capture(verdifax_activate_account_policy(signed_owner_client(), .document_hash), respond)
  body <- sent[[2]]$body
  expect_equal(body$previous_activation_hash, strrep("0", 64))
  expect_true(activation_verifies(body$signature, "account-7", .document_hash, strrep("0", 64)))
})

test_that("an account activation without a signing key is refused before any request", {
  sent <- capture(expect_error(
    verdifax_activate_account_policy(owner_client(), .document_hash),
    "must be signed by the owner key's request key"
  ))
  expect_length(sent, 0)
})

test_that("after the owner's request key is cleared, account activation is refused locally", {
  need_sodium()
  client <- signed_owner_client()
  capture(verdifax_clear_account_request_key(client))
  sent <- capture(expect_error(
    verdifax_activate_account_policy(client, .document_hash), "must be signed"
  ))
  expect_length(sent, 0)
})

test_that("a 409 from the account activation stops with the server's message and is not retried", {
  need_sodium()
  respond <- function(req) {
    if (httr2::req_get_method(req) == "GET") {
      return(json_response(.list_reply))
    }
    json_response("{\"ok\":false,\"error\":\"previous_activation_hash is not the newest change\"}", 409)
  }
  sent <- capture(expect_error(
    verdifax_activate_account_policy(signed_owner_client(), .document_hash),
    "not the newest change",
    class = "httr2_http_409"
  ), respond)
  expect_length(sent, 2)
})

test_that("the account activation stops before the change without the chain or its newest change", {
  need_sodium()
  sent <- capture(
    expect_error(verdifax_activate_account_policy(signed_owner_client(), .document_hash), "newest_activation_hash"),
    function(req) json_response("{\"ok\":true,\"policies\":[]}")
  )
  expect_length(sent, 1)
  no_chain <- sprintf("{\"ok\":true,\"newest_activation_hash\":\"%s\",\"policies\":[]}", .newest)
  sent <- capture(
    expect_error(verdifax_activate_account_policy(signed_owner_client(), .document_hash), "chain_id"),
    function(req) json_response(no_chain)
  )
  expect_length(sent, 1)
})

test_that("an owner key refused on a run route stops with the server's 403 message", {
  respond <- function(req) {
    json_response(paste0(
      "{\"ok\":false,\"error\":\"an account owner key manages the account and cannot run ",
      "or read runs itself; use a member key, or the /account routes\"}"
    ), 403)
  }
  capture(expect_error(
    verdifax_list_policies(owner_client()), "cannot run or read runs itself", class = "httr2_http_403"
  ), respond)
})


# ── Admin ───────────────────────────────────────────────────────────────────

test_that("admin_create_account posts the name, and tier and expires_at only when given", {
  sent <- capture({
    result <- verdifax_admin_create_account(owner_client(), "Acme")
    verdifax_admin_create_account(owner_client(), "Beta", tier = "production", expires_at = "2027-01-01")
  })
  expect_equal(sent[[1]]$method, "POST")
  expect_equal(sent[[1]]$path, "/admin/accounts")
  expect_identical(sent[[1]]$json, "{\"name\":\"Acme\"}")
  expect_equal(sent[[2]]$body, list(name = "Beta", tier = "production", expires_at = "2027-01-01"))
  expect_true(result$ok)
  expect_equal(result$account, parsed(.account))
  expect_true(result$owner_key$owner)
  expect_equal(result$owner_key$secret, "vfx_secret")
  expect_equal(result$owner_key$account_id, "account-7")
})

test_that("admin_list_accounts calls GET /admin/accounts and returns the accounts", {
  sent <- capture(result <- verdifax_admin_list_accounts(owner_client()))
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/admin/accounts")
  expect_equal(result, list(parsed(.account)))
})

test_that("admin_create_key sends account_id as a JSON number only when given", {
  sent <- capture({
    result <- verdifax_admin_create_key(owner_client(), "loans", account_id = 7)
    verdifax_admin_create_key(owner_client(), "big", account_id = 1e5)
    verdifax_admin_create_key(owner_client(), "own")
  })
  expect_equal(sent[[1]]$path, "/admin/keys")
  expect_identical(sent[[1]]$json, "{\"name\":\"loans\",\"account_id\":7}")
  expect_identical(sent[[2]]$json, "{\"name\":\"big\",\"account_id\":100000}")
  expect_identical(sent[[3]]$json, "{\"name\":\"own\"}")
  expect_equal(result$account_id, "account-7")
})

test_that("bad admin account input is refused without a request", {
  client <- owner_client()
  sent <- capture({
    for (name in list("", NA_character_, c("a", "b"), 5, NULL)) {
      expect_error(verdifax_admin_create_account(client, name), "name")
    }
    expect_error(verdifax_admin_create_account(client, "n", tier = c("trial", "production")), "tier")
    expect_error(verdifax_admin_create_account(client, "n", expires_at = 1), "expires_at")
    for (id in list(0, -7, 1.5, NA, Inf, "account-7", "7", c(7, 8), TRUE)) {
      expect_error(verdifax_admin_create_key(client, "n", account_id = id), "account_id")
    }
  })
  expect_length(sent, 0)
})


# ── Parity ──────────────────────────────────────────────────────────────────

# Every R name in the shared map is an exported function, and every export
# is in the map, so no route or helper is missing from this SDK or extra in it.
test_that("the exports are exactly the R names in sdk-parity.json", {
  parity <- jsonlite::fromJSON(testthat::test_path("sdk-parity.json"), simplifyVector = FALSE)
  mapped <- c(
    unlist(lapply(parity$routes, function(entry) entry$r)),
    unlist(lapply(parity$admin_routes, function(entry) entry$r)),
    unlist(lapply(parity$helpers, function(entry) entry$r))
  )
  exports <- getNamespaceExports("verdifax")
  expect_setequal(exports, unique(unname(mapped)))
  for (name in exports) {
    expect_true(is.function(getExportedValue("verdifax", name)), info = name)
  }
})

test_that("every account route in sdk-parity.json has its R function", {
  parity <- jsonlite::fromJSON(testthat::test_path("sdk-parity.json"), simplifyVector = FALSE)
  routes <- c(parity$routes, parity$admin_routes)
  account <- routes[grepl(" /(account|admin/accounts)", names(routes))]
  expect_length(account, 36)
  for (route in names(account)) {
    for (name in unlist(account[[route]]$r)) {
      expect_true(name %in% getNamespaceExports("verdifax"), info = paste(route, name))
    }
  }
})
