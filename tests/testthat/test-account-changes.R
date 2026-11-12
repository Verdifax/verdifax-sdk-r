# The settings and deletions the account's owner decides, each signed by the
# owner key's request key, and the admin routes that replace an owner key and
# delete a record. Requests are captured by a mock, so nothing reaches the
# network.

.seed <- as.raw(rep(1L, 32))
.public_key <- "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="
.record_hash <- strrep("a", 64)

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

.account_reply <- paste0(
  "{\"ok\":true,\"account_id\":\"account-7\",\"id\":7,\"name\":\"Acme\",\"tier\":\"trial\",",
  "\"created_at\":\"2026-11-07T12:00:00Z\",\"member_keys\":2,\"owner_keys\":1,",
  "\"chain_id\":\"account-7\",\"owner_replacement\":\"allowed\",\"verdifax_deletion\":\"allowed\"}"
)
.change <- paste0(
  "{\"format\":\"verdifax.account-change.v1\",\"action\":\"setting.verdifax_deletion\",",
  "\"decided_by\":\"owner\",\"value\":\"blocked\",\"changed_at\":\"2026-11-12T18:00:00.1Z\",",
  "\"signal\":{\"signal_account\":\"account-7\",\"signal_sequence\":9},",
  "\"account_change_hash\":\"", strrep("c", 64), "\"}"
)
.admin_deletion_reply <- paste0(
  "{\"ok\":true,\"run_id\":42,\"deleted\":true,\"run_deletion\":{\"format\":\"verdifax.run-deletion.v1\",",
  "\"decided_by\":\"verdifax_admin\",\"run_id\":42,\"record_hash\":\"", .record_hash, "\",",
  "\"deletion_hash\":\"", strrep("d", 64), "\"}}"
)
.replace_reply <- paste0(
  "{\"ok\":true,\"account_id\":\"account-7\",\"claim_expires\":\"2026-11-15T18:00:00Z\",",
  "\"account_change\":", .change, ",\"email\":{\"ok\":true,\"stage\":\"sent\"}}"
)

# The record the server seals for an owner's change: what was sent, with the
# owner's public key in owner_signature. `tamper` changes the record first.
sealed_reply <- function(req, tamper = identity) {
  path <- httr2::url_parse(httr2::req_get_url(req))$path
  body <- httr2::req_get_body(req)
  signature <- c(list(public_key = .public_key), body$owner_signature)
  if (grepl("^/account/settings/", path)) {
    setting <- sub(".*/", "", path)
    record <- list(
      format = "verdifax.account-change.v1",
      action = paste0("setting.", gsub("-", "_", setting)),
      decided_by = "owner", key_id = 0, value = body$value,
      changed_at = "2026-11-12T18:00:00.1Z", owner_signature = signature,
      signal = list(signal_account = "account-7", signal_sequence = 9),
      account_change_hash = strrep("c", 64)
    )
    reply <- list(ok = TRUE, setting = setting, value = body$value, account_change = tamper(record))
  } else {
    run_id <- as.numeric(sub("^/account/runs/([0-9]+)/delete$", "\\1", path))
    record <- list(
      format = "verdifax.run-deletion.v1", decided_by = "owner", run_id = run_id,
      record_hash = body$record_hash, changed_at = "2026-11-12T18:00:00.1Z",
      owner_signature = signature,
      signal = list(signal_account = "account-7", signal_sequence = 10),
      deletion_hash = strrep("d", 64)
    )
    reply <- list(ok = TRUE, run_id = run_id, deleted = TRUE, run_deletion = tamper(record))
  }
  json_response(as.character(jsonlite::toJSON(reply, auto_unbox = TRUE, digits = 22, null = "null")))
}

# Answers like the server: each route by its method and path.
change_server <- function(req) {
  method <- httr2::req_get_method(req)
  path <- httr2::url_parse(httr2::req_get_url(req))$path
  route <- paste(method, path)
  if (route == "GET /account") {
    return(json_response(.account_reply))
  }
  if (method == "PUT" && grepl("^/account/settings/", path)) {
    return(sealed_reply(req))
  }
  if (method == "POST" && grepl("^/account/runs/[0-9]+/delete$", path)) {
    return(sealed_reply(req))
  }
  if (method == "POST" && grepl("^/admin/runs/[0-9]+/delete$", path)) {
    return(json_response(.admin_deletion_reply))
  }
  if (method == "POST" && grepl("^/admin/accounts/[0-9]+/owner-key/replace$", path)) {
    return(json_response(.replace_reply))
  }
  json_response("{\"ok\":false,\"error\":\"not found\"}", 404)
}

# Runs `code` and returns what was sent.
capture <- function(code, respond = change_server) {
  sent <- list()
  mock <- function(req) {
    body <- httr2::req_get_body(req)
    json <- if (is.null(body)) NULL else
      jsonlite::toJSON(body, auto_unbox = TRUE, digits = 22, null = "null")
    url <- httr2::url_parse(httr2::req_get_url(req))
    sent[[length(sent) + 1]] <<- list(
      method = httr2::req_get_method(req),
      path = url$path,
      key = httr2::req_get_headers(req, "reveal")[["X-Verdifax-Key"]],
      json = if (is.null(json)) NULL else as.character(json),
      body = if (is.null(json)) NULL else jsonlite::fromJSON(json, simplifyVector = FALSE)
    )
    respond(req)
  }
  httr2::with_mocked_responses(mock, code)
  sent
}

parsed <- function(text) jsonlite::fromJSON(text, simplifyVector = FALSE)

# Checks an owner signature the way the server does, written out
# independently of the SDK.
owner_signature_verifies <- function(signature, account, change, subject, public_key = .public_key) {
  fields <- lapply(list(
    "verdifax.owner-change-signature.v1", account, change, subject,
    signature$signed_at, signature$nonce
  ), function(text) charToRaw(enc2utf8(text)))
  signed <- Reduce(function(a, b) c(a, as.raw(0), b), fields)
  sodium::sig_verify(
    signed, jsonlite::base64_dec(signature$signature), jsonlite::base64_dec(public_key)
  )
}

expect_signature_shape <- function(signature) {
  expect_setequal(names(signature), c("signature", "signed_at", "nonce"))
  expect_match(signature$signed_at, "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$")
  expect_match(signature$nonce, "^[0-9a-f]{32}$")
}


# ── The shared test vector ──────────────────────────────────────────────────

test_that("the owner change signature is the shared test vector", {
  need_sodium()
  signer <- verdifax:::.request_signer(as.raw(rep(0x6f, 32)))
  expect_identical(verdifax:::.base64(signer$public_key), "yG0BrYsvtpSyL/YOPJ2eftkNtWBHcrdEUNQJE7mpy68=")
  preimage <- verdifax_owner_change_preimage(
    "account-7", "setting.verdifax_deletion", "blocked", "2026-11-12T18:00:00Z",
    "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
  )
  expected <- c(
    charToRaw("verdifax.owner-change-signature.v1"), as.raw(0), charToRaw("account-7"), as.raw(0),
    charToRaw("setting.verdifax_deletion"), as.raw(0), charToRaw("blocked"), as.raw(0),
    charToRaw("2026-11-12T18:00:00Z"), as.raw(0), charToRaw("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")
  )
  expect_identical(preimage, expected)
  signature <- verdifax:::.owner_signature(
    signer, "account-7", "setting.verdifax_deletion", "blocked",
    signed_at = "2026-11-12T18:00:00Z", nonce = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
  )
  expect_identical(signature, list(
    signature = "LuDMETlzleMt3lXhdED4f3qAy5tdgEsGW4uJmvJlv9Ld0mNlY0v8aIDLXxq1npkW3v5/gdPjIBent1yt5P/9Bw==",
    signed_at = "2026-11-12T18:00:00Z",
    nonce = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
  ))
})


test_that("owner_change_preimage refuses a field that is not a single string", {
  good <- list("account-7", "run.deleted", paste0("42:", .record_hash), "2026-11-12T18:00:00Z", strrep("0", 32))
  fields <- c("account", "change", "subject", "signed_at", "nonce")
  for (i in seq_along(fields)) {
    for (bad in list(NULL, NA_character_, 7, c("a", "b"))) {
      args <- good
      args[i] <- list(bad)
      expect_error(do.call(verdifax_owner_change_preimage, args), paste0(fields[[i]], " must be a single string"))
    }
  }
})


# ── Owner settings ──────────────────────────────────────────────────────────

test_that("set_account_setting reads the account label, then puts the signed value", {
  need_sodium()
  sent <- capture(result <- verdifax_set_account_setting(signed_owner_client(), "verdifax-deletion", "blocked"))
  expect_length(sent, 2)
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/account")
  expect_equal(sent[[2]]$method, "PUT")
  expect_equal(sent[[2]]$path, "/account/settings/verdifax-deletion")
  expect_equal(sent[[2]]$key, "owner")
  body <- sent[[2]]$body
  expect_identical(names(body), c("value", "owner_signature"))
  expect_equal(body$value, "blocked")
  expect_signature_shape(body$owner_signature)
  expect_true(owner_signature_verifies(body$owner_signature, "account-7", "setting.verdifax_deletion", "blocked"))
  # Not over another account, change or value.
  expect_error(owner_signature_verifies(body$owner_signature, "account-8", "setting.verdifax_deletion", "blocked"))
  expect_error(owner_signature_verifies(body$owner_signature, "account-7", "setting.owner_replacement", "blocked"))
  expect_error(owner_signature_verifies(body$owner_signature, "account-7", "setting.verdifax_deletion", "allowed"))
  expect_true(result$ok)
  expect_equal(result$value, "blocked")
  expect_equal(result$account_change$action, "setting.verdifax_deletion")
  expect_equal(result$account_change$owner_signature$signature, body$owner_signature$signature)
})

test_that("owner-replacement signs the change setting.owner_replacement", {
  need_sodium()
  sent <- capture(verdifax_set_account_setting(signed_owner_client(), "owner-replacement", "allowed"))
  expect_equal(sent[[2]]$path, "/account/settings/owner-replacement")
  body <- sent[[2]]$body
  expect_equal(body$value, "allowed")
  expect_true(owner_signature_verifies(body$owner_signature, "account-7", "setting.owner_replacement", "allowed"))
})

test_that("set_account_setting signs the account_id given, with no account read", {
  need_sodium()
  sent <- capture(verdifax_set_account_setting(
    signed_owner_client(), "verdifax-deletion", "blocked", account_id = "account-31"
  ))
  expect_length(sent, 1)
  expect_equal(sent[[1]]$method, "PUT")
  expect_true(owner_signature_verifies(sent[[1]]$body$owner_signature, "account-31", "setting.verdifax_deletion", "blocked"))
})

test_that("each call signs with a fresh nonce", {
  need_sodium()
  client <- signed_owner_client()
  sent <- capture({
    verdifax_set_account_setting(client, "verdifax-deletion", "blocked", account_id = "account-7")
    verdifax_set_account_setting(client, "verdifax-deletion", "blocked", account_id = "account-7")
  })
  expect_false(identical(sent[[1]]$body$owner_signature$nonce, sent[[2]]$body$owner_signature$nonce))
})

test_that("a value already set returns account_change as NULL", {
  need_sodium()
  same <- "{\"ok\":true,\"setting\":\"verdifax-deletion\",\"value\":\"blocked\",\"account_change\":null}"
  respond <- function(req) {
    if (httr2::req_get_method(req) == "PUT") json_response(same) else change_server(req)
  }
  capture(result <- verdifax_set_account_setting(signed_owner_client(), "verdifax-deletion", "blocked"), respond)
  expect_true(result$ok)
  expect_null(result$account_change)
})

test_that("set_account_setting refuses bad input and an unsigned client before any request", {
  sent <- capture({
    for (setting in list("owner_replacement", "verdifax_deletion", "Owner-Replacement", "", NA_character_,
                         c("owner-replacement", "verdifax-deletion"), NULL, 1)) {
      expect_error(verdifax_set_account_setting(signed_owner_client(), setting, "blocked"), "setting must be")
    }
    for (value in list("Blocked", "block", "allow", "", NA_character_, c("allowed", "blocked"), NULL, TRUE)) {
      expect_error(verdifax_set_account_setting(signed_owner_client(), "verdifax-deletion", value), "value must be")
    }
    for (label in list("7", "account-0", "account-07", "Account-7", "api-key-7", NA_character_, 7, c("account-7", "account-8"))) {
      expect_error(
        verdifax_set_account_setting(signed_owner_client(), "verdifax-deletion", "blocked", account_id = label),
        "account_id must be"
      )
    }
    expect_error(
      verdifax_set_account_setting(owner_client(), "verdifax-deletion", "blocked"),
      "must be signed by the owner key's request key"
    )
  })
  expect_length(sent, 0)
})

test_that("after the owner's request key is cleared, a setting is refused locally", {
  need_sodium()
  client <- signed_owner_client()
  capture(verdifax_clear_account_request_key(client), function(req) json_response("{\"ok\":true}"))
  sent <- capture(expect_error(
    verdifax_set_account_setting(client, "verdifax-deletion", "blocked"), "must be signed"
  ))
  expect_length(sent, 0)
})

test_that("an account read with no label stops before the change", {
  need_sodium()
  for (reply in c("{\"ok\":true}", "{\"ok\":true,\"account_id\":7}", "{\"ok\":true,\"account_id\":\"x\"}")) {
    sent <- capture(
      expect_error(verdifax_set_account_setting(signed_owner_client(), "verdifax-deletion", "blocked"), "account_id"),
      function(req) json_response(reply)
    )
    expect_length(sent, 1)
    expect_equal(sent[[1]]$method, "GET")
  }
})

test_that("a refused setting stops with the server's message and is not retried", {
  need_sodium()
  respond <- function(req) {
    if (httr2::req_get_method(req) == "GET") {
      return(change_server(req))
    }
    json_response("{\"ok\":false,\"error\":\"owner_signature does not verify over this change with the owner key's request key\"}", 400)
  }
  sent <- capture(expect_error(
    verdifax_set_account_setting(signed_owner_client(), "verdifax-deletion", "blocked"),
    "owner_signature does not verify",
    class = "httr2_http_400"
  ), respond)
  expect_length(sent, 2)
})


# ── Owner deletion ──────────────────────────────────────────────────────────

test_that("delete_run posts the record hash, signed over the run and the hash", {
  need_sodium()
  sent <- capture(result <- verdifax_delete_run(signed_owner_client(), 42, .record_hash))
  expect_length(sent, 2)
  expect_equal(sent[[1]]$path, "/account")
  expect_equal(sent[[2]]$method, "POST")
  expect_equal(sent[[2]]$path, "/account/runs/42/delete")
  body <- sent[[2]]$body
  expect_identical(names(body), c("record_hash", "owner_signature"))
  expect_equal(body$record_hash, .record_hash)
  expect_signature_shape(body$owner_signature)
  subject <- paste0("42:", .record_hash)
  expect_true(owner_signature_verifies(body$owner_signature, "account-7", "run.deleted", subject))
  expect_error(owner_signature_verifies(body$owner_signature, "account-7", "run.deleted", paste0("43:", .record_hash)))
  expect_error(owner_signature_verifies(body$owner_signature, "account-7", "run.deleted", .record_hash))
  expect_error(owner_signature_verifies(body$owner_signature, "account-7", "setting.verdifax_deletion", subject))
  expect_true(result$deleted)
  expect_equal(result$run_deletion$run_id, 42)
  expect_equal(result$run_deletion$owner_signature$nonce, body$owner_signature$nonce)
})

test_that("delete_run writes a large run id in decimal, in the path and the subject", {
  need_sodium()
  sent <- capture(verdifax_delete_run(signed_owner_client(), 9007199254740991, .record_hash, account_id = "account-7"))
  expect_length(sent, 1)
  expect_equal(sent[[1]]$path, "/account/runs/9007199254740991/delete")
  expect_true(owner_signature_verifies(
    sent[[1]]$body$owner_signature, "account-7", "run.deleted", paste0("9007199254740991:", .record_hash)
  ))
})

test_that("delete_run refuses bad input and an unsigned client before any request", {
  sent <- capture({
    for (hash in list(strrep("A", 64), strrep("a", 63), strrep("a", 65), paste0(strrep("a", 63), "g"),
                      NA_character_, "", NULL, 5, c(.record_hash, .record_hash))) {
      expect_error(verdifax_delete_run(signed_owner_client(), 42, hash), "record_hash")
    }
    for (id in list(0, -1, 1.5, NA, Inf, "42", c(1, 2), NULL)) {
      expect_error(verdifax_delete_run(signed_owner_client(), id, .record_hash), "run_id")
    }
    expect_error(
      verdifax_delete_run(signed_owner_client(), 42, .record_hash, account_id = "7"), "account_id must be"
    )
    expect_error(verdifax_delete_run(owner_client(), 42, .record_hash), "must be signed by the owner key's request key")
  })
  expect_length(sent, 0)
})

test_that("a 409 from the owner deletion stops with the server's message and is not retried", {
  need_sodium()
  respond <- function(req) {
    if (httr2::req_get_method(req) == "GET") {
      return(change_server(req))
    }
    json_response("{\"ok\":false,\"error\":\"record_hash is not this run's record hash\"}", 409)
  }
  sent <- capture(expect_error(
    verdifax_delete_run(signed_owner_client(), 42, .record_hash),
    "not this run's record hash",
    class = "httr2_http_409"
  ), respond)
  expect_length(sent, 2)
})


# ── The returned record carries what was sent ───────────────────────────────

# Answers the change with the record the server seals, changed by `tamper`.
tampered <- function(tamper) {
  function(req) {
    if (httr2::req_get_method(req) == "GET") change_server(req) else sealed_reply(req, tamper)
  }
}

.other_signature <- function(record) {
  record$owner_signature$signature <- jsonlite::base64_enc(as.raw(rep(7L, 64)))
  record
}

test_that("a returned account change that carries what was sent is returned", {
  need_sodium()
  capture(result <- verdifax_set_account_setting(signed_owner_client(), "owner-replacement", "blocked"))
  expect_equal(result$account_change$decided_by, "owner")
  expect_equal(result$account_change$owner_signature$public_key, .public_key)
})

test_that("an account change that does not carry what was sent stops with an error", {
  need_sodium()
  tampers <- list(
    value = function(record) { record$value <- "allowed"; record },
    action = function(record) { record$action <- "setting.owner_replacement"; record },
    signature = .other_signature,
    signed_at = function(record) { record$owner_signature$signed_at <- "2000-01-01T00:00:00Z"; record },
    nonce = function(record) { record$owner_signature$nonce <- strrep("0", 32); record },
    public_key = function(record) { record$owner_signature$public_key <- "yG0BrYsvtpSyL/YOPJ2eftkNtWBHcrdEUNQJE7mpy68="; record },
    no_signature = function(record) { record$owner_signature <- NULL; record },
    verdifax_admin = function(record) { record$decided_by <- "verdifax_admin"; record },
    not_a_record = function(record) "sealed"
  )
  for (name in names(tampers)) {
    capture(expect_error(
      verdifax_set_account_setting(signed_owner_client(), "verdifax-deletion", "blocked"),
      "does not carry the action, value, decided_by owner and owner_signature that were sent",
      info = name
    ), tampered(tampers[[name]]))
  }
})

test_that("a returned run deletion that carries what was sent is returned", {
  need_sodium()
  capture(result <- verdifax_delete_run(signed_owner_client(), 9007199254740991, .record_hash))
  expect_equal(result$run_deletion$run_id, 9007199254740991)
  expect_equal(result$run_deletion$decided_by, "owner")
})

test_that("a run deletion that does not carry what was sent stops with an error", {
  need_sodium()
  tampers <- list(
    run_id = function(record) { record$run_id <- 43; record },
    run_id_text = function(record) { record$run_id <- "42"; record },
    record_hash = function(record) { record$record_hash <- strrep("b", 64); record },
    signature = .other_signature,
    nonce = function(record) { record$owner_signature$nonce <- strrep("0", 32); record },
    public_key = function(record) { record$owner_signature$public_key <- "yG0BrYsvtpSyL/YOPJ2eftkNtWBHcrdEUNQJE7mpy68="; record },
    no_signature = function(record) { record$owner_signature <- NULL; record },
    verdifax_admin = function(record) { record$decided_by <- "verdifax_admin"; record },
    missing = function(record) NULL
  )
  for (name in names(tampers)) {
    capture(expect_error(
      verdifax_delete_run(signed_owner_client(), 42, .record_hash),
      "does not carry the run_id, record_hash, decided_by owner and owner_signature that were sent",
      info = name
    ), tampered(tampers[[name]]))
  }
})


# ── Admin ───────────────────────────────────────────────────────────────────

test_that("admin_delete_run posts with no body and returns the answer", {
  admin <- verdifax_client(base_url = "http://mock.invalid", api_key = "admin")
  sent <- capture(result <- verdifax_admin_delete_run(admin, 42))
  expect_length(sent, 1)
  expect_equal(sent[[1]]$method, "POST")
  expect_equal(sent[[1]]$path, "/admin/runs/42/delete")
  expect_equal(sent[[1]]$key, "admin")
  expect_null(sent[[1]]$body)
  expect_equal(result, parsed(.admin_deletion_reply))
})

test_that("admin_replace_owner_key posts the numeric account id with no body", {
  admin <- verdifax_client(base_url = "http://mock.invalid", api_key = "admin")
  sent <- capture(result <- verdifax_admin_replace_owner_key(admin, 7))
  expect_length(sent, 1)
  expect_equal(sent[[1]]$method, "POST")
  expect_equal(sent[[1]]$path, "/admin/accounts/7/owner-key/replace")
  expect_null(sent[[1]]$body)
  expect_equal(result, parsed(.replace_reply))
  expect_setequal(names(result), c("ok", "account_id", "claim_expires", "account_change", "email"))
})

test_that("the admin routes refuse a bad id before any request", {
  admin <- verdifax_client(base_url = "http://mock.invalid", api_key = "admin")
  sent <- capture({
    for (id in list(0, -7, 1.5, NA, Inf, "account-7", "7", c(7, 8), TRUE, NULL)) {
      expect_error(verdifax_admin_replace_owner_key(admin, id), "account_id")
      expect_error(verdifax_admin_delete_run(admin, id), "run_id")
    }
  })
  expect_length(sent, 0)
})

test_that("a blocked admin change stops with the server's 409 message", {
  admin <- verdifax_client(base_url = "http://mock.invalid", api_key = "admin")
  respond <- function(req) {
    json_response("{\"ok\":false,\"error\":\"the account's owner has blocked Verdifax deletion\"}", 409)
  }
  sent <- capture(expect_error(
    verdifax_admin_delete_run(admin, 42), "has blocked Verdifax deletion", class = "httr2_http_409"
  ), respond)
  expect_length(sent, 1)
})


# ── Signal kinds ────────────────────────────────────────────────────────────

test_that("account.changed and run.deleted are signal kinds a webhook takes", {
  expect_true(all(c("account.changed", "run.deleted") %in% verdifax:::.SIGNAL_KINDS))
  sent <- capture(
    verdifax_create_webhook(owner_client(), "https://hooks.example.com/v", types = c("account.changed", "run.deleted")),
    function(req) json_response("{\"ok\":true}")
  )
  expect_identical(sent[[1]]$json, "{\"url\":\"https://hooks.example.com/v\",\"types\":[\"account.changed\",\"run.deleted\"]}")
})

# Where the server's source is present, as in the Verdifax workspace, the
# SDK's kinds are the server's, in its order.
test_that("the signal kinds are the server's SignalKinds", {
  source <- file.path(
    testthat::test_path(), "..", "..", "..", "verdifax-orchestrator", "internal", "artifacts", "signal.go"
  )
  skip_if_not(file.exists(source), "the orchestrator source is not beside this repository")
  text <- paste(readLines(source, warn = FALSE), collapse = "\n")
  constants <- regmatches(text, gregexpr("Signal[A-Za-z]+ *= *\"[a-z.]+\"", text))[[1]]
  values <- stats::setNames(sub(".*\"([a-z.]+)\"", "\\1", constants), sub(" *=.*", "", constants))
  others <- list.files(dirname(source), pattern = "\\.go$", full.names = TRUE)
  for (file in others[!grepl("_test\\.go$", others)]) {
    more <- paste(readLines(file, warn = FALSE), collapse = "\n")
    found <- regmatches(more, gregexpr("Signal[A-Za-z]+ *= *\"[a-z.]+\"", more))[[1]]
    values[sub(" *=.*", "", found)] <- sub(".*\"([a-z.]+)\"", "\\1", found)
  }
  list_text <- regmatches(text, regexpr("var SignalKinds = \\[\\]string\\{[^}]*\\}", text))
  names_in_order <- regmatches(list_text, gregexpr("Signal[A-Za-z]+", list_text))[[1]]
  names_in_order <- setdiff(names_in_order, "SignalKinds")
  expect_identical(verdifax:::.SIGNAL_KINDS, unname(values[names_in_order]))
})
