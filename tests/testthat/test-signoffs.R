# Customer sign-off: the owner's approver keys and an approver's signed
# decision on one exact result. Requests are captured by a mock, so nothing
# reaches the network.

# The client's own request key, and the approver key from the shared vector.
.request_seed <- as.raw(rep(1L, 32))
.vector <- jsonlite::fromJSON(testthat::test_path("sdk-signature-vector.json"))
.approver_seed_hex <- "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
.approver_seed <- as.raw(strtoi(substring(.approver_seed_hex, seq(1, 63, 2), seq(2, 64, 2)), 16L))
.approver_public <- "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="
.newest <- strrep("e", 64)
.digest <- strrep("a", 64)
.note <- "checked against the loan file"
.note_hash <- "326381f36e7fb0c3a99217dc3e78e3b246d593ff25c53f5168be1d94e153def3"

need_sodium <- function() {
  if (!nzchar(Sys.getenv("CI"))) {
    testthat::skip_if_not_installed("sodium")
  }
}

member_client <- function() {
  verdifax_client(base_url = "http://mock.invalid", api_key = "member")
}

owner_client <- function() {
  verdifax_client(base_url = "http://mock.invalid", api_key = "owner")
}

signed_member_client <- function() {
  verdifax_client(base_url = "http://mock.invalid", api_key = "member", signing_key = .request_seed)
}

json_response <- function(text, status = 200) {
  httr2::response(
    status_code = status,
    headers = "Content-Type: application/json",
    body = charToRaw(enc2utf8(text))
  )
}

.approver <- paste0(
  "{\"id\":3,\"public_key\":\"", .approver_public, "\",\"name\":\"Dana, credit review\",",
  "\"account_id\":\"account-7\",\"registered_at\":\"2026-11-07T12:00:00Z\",\"revoked\":false}"
)
.approvers_reply <- paste0(
  "{\"ok\":true,\"account_id\":\"account-7\",\"approvers\":[", .approver, ",",
  "{\"id\":2,\"public_key\":\"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=\",\"name\":\"Old\",",
  "\"account_id\":\"account-7\",\"registered_at\":\"2026-11-01T12:00:00Z\",\"revoked\":true,",
  "\"revoked_at\":\"2026-11-02T12:00:00Z\"}]}"
)
.newest_reply <- sprintf(
  "{\"ok\":true,\"chain_id\":\"account-7\",\"newest_signoff_hash\":\"%s\",\"sequence\":4}", .newest
)
.signoff <- sprintf(
  paste0(
    "{\"format\":\"verdifax.signoff.v1\",\"chain_id\":\"account-7\",\"sequence\":5,",
    "\"previous_signoff_hash\":\"%s\",\"target\":{\"kind\":\"record\",\"run_id\":42,\"digest\":\"%s\"},",
    "\"decision\":\"approve\",\"note_hash\":\"%s\",\"approver_key\":\"%s\",\"signature\":\"c2ln\",",
    "\"signed_at\":\"2026-11-07T12:00:00Z\",\"nonce\":\"%s\",\"recorded_at\":\"2026-11-07T12:00:01Z\",",
    "\"signoff_hash\":\"%s\",\"anchor\":{\"tree_size\":12}}"
  ),
  .newest, .digest, .note_hash, .approver_public, strrep("0f", 16), strrep("9", 64)
)

# The record the server makes from a submitted sign-off: what was sent, with
# its place in the chain, its hash and its anchor. `change` alters it.
echo_signoff <- function(req, change = identity) {
  sent <- httr2::req_get_body(req)
  record <- c(
    list(format = "verdifax.signoff.v1", chain_id = "account-7", sequence = 5L),
    sent,
    list(recorded_at = "2026-11-07T12:00:01Z", signoff_hash = strrep("9", 64), anchor = list(tree_size = 12L))
  )
  json_response(as.character(jsonlite::toJSON(
    list(ok = TRUE, signoff = change(record)), auto_unbox = TRUE, digits = 22
  )), 201)
}

# Answers like the server: each route by its method and path.
signoff_server <- function(req) {
  method <- httr2::req_get_method(req)
  path <- httr2::url_parse(httr2::req_get_url(req))$path
  route <- paste(method, path)
  if (route == "POST /account/approvers") {
    return(json_response(sub("^\\{", "{\"ok\":true,", .approver), 201))
  }
  if (route == "GET /account/approvers") {
    return(json_response(.approvers_reply))
  }
  if (method == "DELETE" && grepl("^/account/approvers/[0-9]+$", path)) {
    return(json_response(sprintf("{\"ok\":true,\"id\":%s,\"revoked\":true}", sub(".*/", "", path))))
  }
  if (route %in% c("GET /signoffs/newest", "GET /account/signoffs/newest")) {
    return(json_response(.newest_reply))
  }
  if (route %in% c("POST /signoffs", "POST /account/signoffs")) {
    return(echo_signoff(req))
  }
  if (method == "GET" && grepl("^(/account)?/runs/[0-9]+/signoffs$", path)) {
    return(json_response(sprintf("[%s]", .signoff)))
  }
  if (route == "GET /account/runs/export") {
    return(json_response(sprintf(
      "{\"ok\":true,\"total\":0,\"truncated\":false,\"runs\":[],\"account_id\":\"account-7\",\"signoffs\":[%s]}",
      .signoff
    )))
  }
  json_response("{\"ok\":false,\"error\":\"not found\"}", 404)
}

# Runs `code` and returns what was sent, with the JSON text the request
# puts on the wire, written with the options req_body_json() uses.
capture <- function(code, respond = signoff_server) {
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

zero_joined <- function(fields) {
  Reduce(function(a, b) c(a, as.raw(0), b), lapply(fields, function(text) charToRaw(enc2utf8(text))))
}

# Checks a submitted sign-off the way the server does, written out
# independently of the SDK.
signoff_verifies <- function(body, chain_id, previous) {
  target <- body$target
  signed <- zero_joined(list(
    "verdifax.signoff.v1", chain_id, previous, target$kind,
    format(target$run_id, scientific = FALSE), target$digest, target$job_id %||% "",
    body$decision, body$note_hash %||% "", body$signed_at, body$nonce
  ))
  sodium::sig_verify(
    signed, jsonlite::base64_dec(body$signature), jsonlite::base64_dec(body$approver_key)
  )
}

`%||%` <- function(a, b) if (is.null(a)) b else a

record_target <- function() list(kind = "record", run_id = 42, digest = .digest)


# ── Approver keys ───────────────────────────────────────────────────────────

test_that("register_approver posts the public key, the name and a proof made here", {
  need_sodium()
  sent <- capture(result <- verdifax_register_approver(owner_client(), .approver_seed, "Dana, credit review"))
  expect_length(sent, 1)
  expect_equal(sent[[1]]$method, "POST")
  expect_equal(sent[[1]]$path, "/account/approvers")
  expect_equal(sent[[1]]$key, "owner")
  body <- sent[[1]]$body
  expect_equal(names(body), c("public_key", "name", "proof"))
  expect_equal(body$public_key, .approver_public)
  expect_equal(body$name, "Dana, credit review")
  expect_true(sodium::sig_verify(
    zero_joined(list("verdifax.approver-key.v1", .approver_public)),
    jsonlite::base64_dec(body$proof), jsonlite::base64_dec(.approver_public)
  ))
  expect_equal(body$proof, verdifax_approver_key_proof(.approver_seed)$proof)
  expect_false(grepl(.approver_seed_hex, sent[[1]]$json, fixed = TRUE))
  expect_false(grepl(verdifax:::.base64(.approver_seed), sent[[1]]$json, fixed = TRUE))
  expect_true(result$ok)
  expect_equal(result$id, 3L)
  expect_equal(result$public_key, .approver_public)
  expect_false(result$revoked)
})

test_that("register_approver refuses bad input and the client's own request key, without a request", {
  need_sodium()
  sent <- capture({
    for (name in list("", "   ", NA_character_, c("a", "b"), 5, NULL, strrep("n", 201))) {
      expect_error(verdifax_register_approver(owner_client(), .approver_seed, name), "name")
    }
    for (key in list(as.raw(rep(1L, 31)), as.raw(rep(1L, 64)))) {
      expect_error(verdifax_register_approver(owner_client(), key, "Dana"), "approver_key")
    }
    for (key in list(NULL, "key", 1:32, list(), list(public_key = .approver_public))) {
      expect_error(verdifax_register_approver(owner_client(), key, "Dana"), "verdifax_approver_key_proof")
    }
    expect_error(
      verdifax_register_approver(signed_member_client(), .request_seed, "Dana"),
      "must be a different key"
    )
    expect_error(
      verdifax_register_approver(signed_member_client(), verdifax_approver_key_proof(.request_seed), "Dana"),
      "must be a different key"
    )
  })
  expect_length(sent, 0)
  sent <- capture(verdifax_register_approver(owner_client(), .approver_seed, strrep("n", 200)))
  expect_length(sent, 1)
})

test_that("register_approver takes a ready-made proof, so the owner never holds the private key", {
  need_sodium()
  # The approver runs this on their own machine and hands over the list.
  proof <- verdifax_approver_key_proof(.approver_seed)
  expect_equal(names(proof), c("public_key", "proof"))
  sent <- capture({
    from_proof <- verdifax_register_approver(owner_client(), proof, "Dana, credit review")
    verdifax_register_approver(owner_client(), .approver_seed, "Dana, credit review")
    verdifax_register_approver(owner_client(), rev(proof), "Dana, credit review")
  })
  expect_length(sent, 3)
  expect_equal(sent[[1]]$path, "/account/approvers")
  expect_equal(names(sent[[1]]$body), c("public_key", "name", "proof"))
  expect_identical(sent[[1]]$json, sent[[2]]$json)
  expect_identical(sent[[3]]$json, sent[[2]]$json)
  expect_equal(from_proof$public_key, .approver_public)
})

test_that("a ready-made proof that does not verify is refused before sending", {
  need_sodium()
  proof <- verdifax_approver_key_proof(.approver_seed)
  other <- verdifax_approver_key_proof(as.raw(rep(9L, 32)))
  signature <- jsonlite::base64_dec(proof$proof)
  signature[1] <- xor(signature[1], as.raw(1))
  bad <- list(
    # Another key's proof under this key, and this proof under another key.
    list(public_key = proof$public_key, proof = other$proof),
    list(public_key = other$public_key, proof = proof$proof),
    # One flipped bit.
    list(public_key = proof$public_key, proof = verdifax:::.base64(signature))
  )
  malformed <- list(
    list(public_key = proof$public_key, proof = "not base64!"),
    list(public_key = "AAAA", proof = proof$proof),
    list(public_key = proof$public_key, proof = substr(proof$proof, 1, 40)),
    list(public_key = NA_character_, proof = proof$proof),
    list(public_key = proof$public_key, proof = c(proof$proof, proof$proof))
  )
  sent <- capture({
    for (item in bad) {
      expect_error(verdifax_register_approver(owner_client(), item, "Dana"), "does not verify")
    }
    for (item in malformed) {
      expect_error(verdifax_register_approver(owner_client(), item, "Dana"), "base64 Ed25519")
    }
    expect_error(
      verdifax_register_approver(owner_client(), c(proof, list(name = "x")), "Dana"),
      "verdifax_approver_key_proof"
    )
  })
  expect_length(sent, 0)
})

test_that("a request key registered as an approver stops with the server's 409 message", {
  need_sodium()
  respond <- function(req) {
    json_response(paste0(
      "{\"ok\":false,\"error\":\"this key is a request key in the account; ",
      "an approver key must be a different key\"}"
    ), 409)
  }
  sent <- capture(expect_error(
    verdifax_register_approver(owner_client(), .approver_seed, "Dana"),
    "this key is a request key in the account",
    class = "httr2_http_409"
  ), respond)
  expect_length(sent, 1)
})

test_that("list_approvers calls GET /account/approvers and keeps revoked keys", {
  sent <- capture(result <- verdifax_list_approvers(owner_client()))
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/account/approvers")
  expect_null(sent[[1]]$body)
  expect_equal(result, parsed(.approvers_reply))
  expect_equal(result$account_id, "account-7")
  expect_length(result$approvers, 2)
  expect_null(result$approvers[[1]]$revoked_at)
  expect_true(result$approvers[[2]]$revoked)
  expect_equal(result$approvers[[2]]$revoked_at, "2026-11-02T12:00:00Z")
})

test_that("revoke_approver calls DELETE /account/approvers/{id} and writes a large id in full", {
  sent <- capture({
    result <- verdifax_revoke_approver(owner_client(), 3)
    verdifax_revoke_approver(owner_client(), 1e5)
  })
  expect_equal(sent[[1]]$method, "DELETE")
  expect_equal(sent[[1]]$path, "/account/approvers/3")
  expect_null(sent[[1]]$body)
  expect_equal(result, list(ok = TRUE, id = 3L, revoked = TRUE))
  expect_equal(sent[[2]]$path, "/account/approvers/100000")
})

test_that("revoke_approver refuses a bad id without a request and passes on a 404", {
  sent <- capture(for (id in list(0, -1, 1.5, NA, Inf, "3", c(1, 2), TRUE, NULL)) {
    expect_error(verdifax_revoke_approver(owner_client(), id), "approver_id")
  })
  expect_length(sent, 0)
  respond <- function(req) json_response("{\"ok\":false,\"error\":\"no such active approver in this account\"}", 404)
  sent <- capture(expect_error(
    verdifax_revoke_approver(owner_client(), 9), "no such active approver", class = "httr2_http_404"
  ), respond)
  expect_length(sent, 1)
})


# ── The newest sign-off ─────────────────────────────────────────────────────

test_that("get_newest_signoff reads the member route, or the owner route with as_owner", {
  sent <- capture({
    member <- verdifax_get_newest_signoff(member_client())
    owner <- verdifax_get_newest_signoff(owner_client(), as_owner = TRUE)
  })
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/signoffs/newest")
  expect_equal(sent[[1]]$key, "member")
  expect_equal(sent[[2]]$path, "/account/signoffs/newest")
  expect_equal(sent[[2]]$key, "owner")
  expect_equal(member, parsed(.newest_reply))
  expect_equal(owner$chain_id, "account-7")
  expect_equal(owner$newest_signoff_hash, .newest)
  expect_equal(owner$sequence, 4L)
})

test_that("as_owner must be TRUE or FALSE, and a bad one sends nothing", {
  need_sodium()
  sent <- capture(for (flag in list(NA, "yes", 1, c(TRUE, FALSE), NULL)) {
    expect_error(verdifax_get_newest_signoff(member_client(), as_owner = flag), "as_owner")
    expect_error(verdifax_get_signoffs(member_client(), 42, as_owner = flag), "as_owner")
    expect_error(
      verdifax_sign_off(member_client(), record_target(), "approve", .approver_seed, as_owner = flag),
      "as_owner"
    )
  })
  expect_length(sent, 0)
})


# ── Sign off ────────────────────────────────────────────────────────────────

test_that("sign_off reads the newest sign-off, then submits a signed decision over it", {
  need_sodium()
  sent <- capture(result <- verdifax_sign_off(
    member_client(), record_target(), "approve", .approver_seed, note = .note
  ))
  expect_length(sent, 2)
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/signoffs/newest")
  expect_equal(sent[[2]]$method, "POST")
  expect_equal(sent[[2]]$path, "/signoffs")
  expect_equal(sent[[2]]$key, "member")
  body <- sent[[2]]$body
  expect_equal(names(body), c(
    "previous_signoff_hash", "target", "decision", "note_hash", "approver_key",
    "signature", "signed_at", "nonce"
  ))
  expect_equal(body$previous_signoff_hash, .newest)
  expect_equal(body$target, list(kind = "record", run_id = 42L, digest = .digest))
  expect_match(sent[[2]]$json, "\"target\":{\"kind\":\"record\",\"run_id\":42,\"digest\":\"", fixed = TRUE)
  expect_equal(body$decision, "approve")
  expect_equal(body$note_hash, .note_hash)
  expect_equal(body$approver_key, .approver_public)
  expect_match(body$signed_at, "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$")
  expect_match(body$nonce, "^[0-9a-f]{32}$")
  expect_true(signoff_verifies(body, "account-7", .newest))
  # Not over another account, another place in the chain or another result.
  expect_error(signoff_verifies(body, "account-8", .newest))
  expect_error(signoff_verifies(body, "account-7", strrep("0", 64)))
  other <- body
  other$target$run_id <- 43
  expect_error(signoff_verifies(other, "account-7", .newest))
  other <- body
  other$decision <- "reject"
  expect_error(signoff_verifies(other, "account-7", .newest))
  expect_equal(result$sequence, 5L)
  expect_equal(result$signoff_hash, strrep("9", 64))
  expect_equal(result$signature, body$signature)
  expect_equal(result$target, body$target)
})

test_that("a returned record that does not carry what was sent stops with an error", {
  need_sodium()
  changes <- list(
    function(r) { r$signature <- "c2ln"; r },
    function(r) { r$approver_key <- "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="; r },
    function(r) { r$decision <- "reject"; r },
    function(r) { r$previous_signoff_hash <- strrep("0", 64); r },
    function(r) { r$target$kind <- "receipt"; r },
    function(r) { r$target$run_id <- 43; r },
    function(r) { r$target$digest <- strrep("b", 64); r },
    function(r) { r$target$job_id <- "loan-1"; r },
    function(r) { r$target <- NULL; r },
    function(r) { r$signature <- NULL; r }
  )
  for (change in changes) {
    respond <- function(req) {
      if (httr2::req_get_method(req) == "POST") echo_signoff(req, change) else signoff_server(req)
    }
    sent <- capture(expect_error(
      verdifax_sign_off(member_client(), record_target(), "approve", .approver_seed),
      "does not carry the signature"
    ), respond)
    expect_length(sent, 2)
  }
  # The fixed record of another sign-off is refused too.
  respond <- function(req) {
    if (httr2::req_get_method(req) == "POST") {
      json_response(sprintf("{\"ok\":true,\"signoff\":%s}", .signoff), 201)
    } else {
      signoff_server(req)
    }
  }
  capture(expect_error(
    verdifax_sign_off(member_client(), record_target(), "approve", .approver_seed),
    "does not carry the signature"
  ), respond)
  # A response with no record is refused.
  respond <- function(req) {
    if (httr2::req_get_method(req) == "POST") json_response("{\"ok\":true}", 201) else signoff_server(req)
  }
  capture(expect_error(
    verdifax_sign_off(member_client(), record_target(), "approve", .approver_seed),
    "does not carry the signature"
  ), respond)
})

test_that("a job's returned record must name the same job", {
  need_sodium()
  job <- list(kind = "job", run_id = 77L, digest = strrep("c", 64), job_id = "loan-1")
  sent <- capture(result <- verdifax_sign_off(member_client(), job, "approve", .approver_seed))
  expect_equal(result$target$job_id, "loan-1")
  respond <- function(req) {
    if (httr2::req_get_method(req) == "POST") {
      echo_signoff(req, function(r) { r$target$job_id <- "loan-2"; r })
    } else {
      signoff_server(req)
    }
  }
  capture(expect_error(
    verdifax_sign_off(member_client(), job, "approve", .approver_seed), "does not carry the signature"
  ), respond)
})

test_that("the note's text and the approver's private key are never sent", {
  need_sodium()
  note <- "Matches the file. Café owner verified by phone, ref 77."
  sent <- capture(verdifax_sign_off(member_client(), record_target(), "reject", .approver_seed, note = note))
  for (request in sent) {
    text <- request$json %||% ""
    expect_false(grepl(note, text, fixed = TRUE))
    expect_false(grepl("Matches the file", text, fixed = TRUE))
    expect_false(grepl("phone", text, fixed = TRUE))
    expect_false(grepl(.approver_seed_hex, text, fixed = TRUE))
    expect_false(grepl(verdifax:::.base64(.approver_seed), text, fixed = TRUE))
  }
  body <- sent[[2]]$body
  expect_equal(body$note_hash, verdifax:::.sha256_hex(enc2utf8(note)))
  expect_equal(body$decision, "reject")
  expect_true(signoff_verifies(body, "account-7", .newest))
})

test_that("a sign-off with no note leaves note_hash out and signs it as empty", {
  need_sodium()
  sent <- capture(verdifax_sign_off(member_client(), record_target(), "approve", .approver_seed))
  body <- sent[[2]]$body
  expect_false("note_hash" %in% names(body))
  expect_false(grepl("note_hash", sent[[2]]$json, fixed = TRUE))
  expect_true(signoff_verifies(body, "account-7", .newest))
})

test_that("an empty note is refused, not hashed, before any request", {
  need_sodium()
  sent <- capture(expect_error(
    verdifax_sign_off(member_client(), record_target(), "approve", .approver_seed, note = ""),
    "note must be a non-empty single string"
  ))
  expect_length(sent, 0)
  expect_error(verdifax:::.signoff_note_hash(""), "non-empty")
})

test_that("sign_off with as_owner reads and submits on the owner key's routes", {
  need_sodium()
  sent <- capture(verdifax_sign_off(
    owner_client(), record_target(), "approve", .approver_seed, as_owner = TRUE
  ))
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/account/signoffs/newest")
  expect_equal(sent[[2]]$method, "POST")
  expect_equal(sent[[2]]$path, "/account/signoffs")
  expect_equal(sent[[2]]$key, "owner")
  expect_true(signoff_verifies(sent[[2]]$body, "account-7", .newest))
})

test_that("sign_off signs whatever chain and newest sign-off the server names", {
  need_sodium()
  first <- sprintf(
    "{\"ok\":true,\"chain_id\":\"account-31\",\"newest_signoff_hash\":\"%s\",\"sequence\":0}",
    strrep("0", 64)
  )
  respond <- function(req) {
    if (httr2::req_get_method(req) == "GET") json_response(first) else signoff_server(req)
  }
  sent <- capture(verdifax_sign_off(member_client(), record_target(), "approve", .approver_seed), respond)
  body <- sent[[2]]$body
  expect_equal(body$previous_signoff_hash, strrep("0", 64))
  expect_true(signoff_verifies(body, "account-31", strrep("0", 64)))
  expect_error(signoff_verifies(body, "account-7", strrep("0", 64)))
})

test_that("a receipt target and a job target are sent and signed as given", {
  need_sodium()
  receipt <- list(kind = "receipt", run_id = 9007199254740991, digest = strrep("b", 64))
  job <- list(kind = "job", run_id = 77L, digest = strrep("c", 64), job_id = "loan-1")
  sent <- capture({
    verdifax_sign_off(member_client(), receipt, "reject", .approver_seed)
    verdifax_sign_off(member_client(), job, "approve", .approver_seed)
  })
  expect_match(
    sent[[2]]$json,
    sprintf("\"target\":{\"kind\":\"receipt\",\"run_id\":9007199254740991,\"digest\":\"%s\"}", strrep("b", 64)),
    fixed = TRUE
  )
  expect_true(signoff_verifies(sent[[2]]$body, "account-7", .newest))
  expect_equal(sent[[4]]$body$target, list(kind = "job", run_id = 77L, digest = strrep("c", 64), job_id = "loan-1"))
  expect_true(signoff_verifies(sent[[4]]$body, "account-7", .newest))
  # The job_id is signed: without it the signature does not verify.
  other <- sent[[4]]$body
  other$target$job_id <- NULL
  expect_error(signoff_verifies(other, "account-7", .newest))
})

test_that("bad sign-off input is refused before any request", {
  need_sodium()
  client <- member_client()
  sign <- function(target = record_target(), decision = "approve", key = .approver_seed, note = NULL) {
    verdifax_sign_off(client, target, decision, key, note = note)
  }
  sent <- capture({
    for (target in list(NULL, list(), "record", list("record", 42, .digest))) {
      expect_error(sign(target = target), "target")
    }
    expect_error(sign(target = c(record_target(), list(extra = 1))), "unknown field: extra")
    expect_error(sign(target = c(record_target(), list(kind = "record"))), "twice")
    for (kind in list("Record", "bundle", NA_character_, NULL, c("record", "job"))) {
      expect_error(sign(target = modifyList(record_target(), list(kind = kind))), "target\\$kind")
    }
    for (id in list(0, -1, 1.5, NA, Inf, "42", c(1, 2), TRUE, 2^53, NULL)) {
      target <- record_target()
      target["run_id"] <- list(id)
      expect_error(sign(target = target), "target\\$run_id")
    }
    for (digest in list(strrep("A", 64), strrep("a", 63), "", NA_character_, NULL, 5)) {
      target <- record_target()
      target["digest"] <- list(digest)
      expect_error(sign(target = target), "target\\$digest")
    }
    expect_error(sign(target = c(record_target(), list(job_id = "loan-1"))), "job target only")
    expect_error(sign(target = list(kind = "job", run_id = 1, digest = .digest)), "target\\$job_id")
    expect_error(
      sign(target = list(kind = "job", run_id = 1, digest = .digest, job_id = "bad id")),
      "target\\$job_id"
    )
    for (decision in list("approved", "APPROVE", "", NA_character_, NULL, TRUE, c("approve", "reject"))) {
      expect_error(sign(decision = decision), "decision")
    }
    for (note in list("", NA_character_, c("a", "b"), 5, list("a"))) {
      expect_error(sign(note = note), "note")
    }
    for (key in list(NULL, "key", as.raw(rep(1L, 31)), as.raw(rep(1L, 64)), 1:32)) {
      expect_error(sign(key = key), "approver_key")
    }
    expect_error(
      verdifax_sign_off(signed_member_client(), record_target(), "approve", .request_seed),
      "must be a different key"
    )
  })
  expect_length(sent, 0)
})

test_that("sign_off stops before submitting without the chain or its newest sign-off", {
  need_sodium()
  replies <- list(
    sprintf("{\"ok\":true,\"newest_signoff_hash\":\"%s\"}", .newest),
    sprintf("{\"ok\":true,\"chain_id\":\"api-key-7\",\"newest_signoff_hash\":\"%s\"}", .newest),
    "{\"ok\":true,\"chain_id\":\"account-7\"}",
    sprintf("{\"ok\":true,\"chain_id\":\"account-7\",\"newest_signoff_hash\":\"%s\"}", toupper(.newest))
  )
  for (reply in replies) {
    sent <- capture(
      expect_error(
        verdifax_sign_off(member_client(), record_target(), "approve", .approver_seed),
        "nothing was signed"
      ),
      function(req) json_response(reply)
    )
    expect_length(sent, 1)
  }
})

test_that("a 409 from the submit stops with the server's message and is not retried", {
  need_sodium()
  respond <- function(req) {
    if (httr2::req_get_method(req) == "GET") {
      return(json_response(.newest_reply))
    }
    json_response(paste0(
      "{\"ok\":false,\"error\":\"previous_signoff_hash is not the account's newest sign-off; ",
      "read GET /signoffs/newest and sign again\"}"
    ), 409)
  }
  sent <- capture(expect_error(
    verdifax_sign_off(member_client(), record_target(), "approve", .approver_seed),
    "not the account's newest sign-off",
    class = "httr2_http_409"
  ), respond)
  expect_length(sent, 2)
})


# ── Reading sign-offs ───────────────────────────────────────────────────────

test_that("get_signoffs returns a run's sign-offs as the server's exact text, on the member route", {
  text <- sprintf("[%s,\n {\"sequence\": 9007199254740993 , \"anchor\":{}}]\n", .signoff)
  sent <- capture(
    result <- verdifax_get_signoffs(member_client(), 42),
    function(req) json_response(text)
  )
  expect_length(sent, 1)
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/runs/42/signoffs")
  expect_equal(sent[[1]]$key, "member")
  expect_null(sent[[1]]$body)
  expect_type(result, "character")
  expect_length(result, 1)
  expect_identical(result, text)
  expect_equal(parsed(result)[[1]], parsed(.signoff))
})

test_that("get_signoffs with as_owner reads the owner route and returns the exact text", {
  text <- sprintf("[%s]\n", .signoff)
  sent <- capture(
    result <- verdifax_get_signoffs(owner_client(), 1e5, as_owner = TRUE),
    function(req) json_response(text)
  )
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/account/runs/100000/signoffs")
  expect_equal(sent[[1]]$key, "owner")
  expect_identical(result, text)
  record <- parsed(result)[[1]]
  expect_equal(record$target$run_id, 42L)
  expect_equal(record$decision, "approve")
  expect_equal(record$anchor$tree_size, 12L)
})

test_that("get_signoffs text saved with writeLines(sep = \"\") is byte for byte what was sent", {
  text <- sprintf("[%s]\n", .signoff)
  capture(result <- verdifax_get_signoffs(member_client(), 42), function(req) json_response(text))
  path <- tempfile(fileext = ".json")
  on.exit(unlink(path))
  writeLines(result, path, sep = "")
  expect_identical(readBin(path, "raw", file.size(path)), charToRaw(enc2utf8(text)))
})

test_that("get_signoffs passes on the server's 404 message", {
  respond <- function(req) json_response("{\"ok\":false,\"error\":\"run not found\"}", 404)
  sent <- capture(expect_error(
    verdifax_get_signoffs(member_client(), 7), class = "httr2_http_404"
  ), respond)
  expect_length(sent, 1)
})

test_that("get_signoffs refuses a bad run id without a request", {
  sent <- capture(for (id in list(0, -1, 1.5, NA, "42", c(1, 2), NULL)) {
    expect_error(verdifax_get_signoffs(member_client(), id), "run_id")
  })
  expect_length(sent, 0)
})

test_that("get_signoff_history returns the server's text exactly from the owner route", {
  text <- "[{\"sequence\":1,\"tree_size\": 9007199254740993 ,\"anchor\":{}}]\n"
  sent <- capture(
    result <- verdifax_get_signoff_history(owner_client()),
    function(req) json_response(text)
  )
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/account/signoffs/history")
  expect_equal(sent[[1]]$key, "owner")
  expect_identical(result, text)
})

test_that("the owner's account export keeps the account's sign-offs", {
  sent <- capture(result <- verdifax_export_account_runs(owner_client()))
  expect_equal(sent[[1]]$path, "/account/runs/export")
  expect_equal(result$signoffs, list(parsed(.signoff)))
})


# ── The shared vector ───────────────────────────────────────────────────────

vector_target <- function() {
  list(kind = .vector$signoff_target_kind, run_id = .vector$signoff_target_run_id,
       digest = .vector$signoff_target_digest)
}

test_that("vector: the approver seed is the shared seed", {
  expect_equal(.vector$seed_hex, .approver_seed_hex)
  expect_equal(.vector$public_key, .approver_public)
})

test_that("vector: the note hash is the SHA-256 of the note's text", {
  expect_equal(verdifax:::.signoff_note_hash(.note), .vector$signoff_note_hash)
  expect_equal(.vector$signoff_note_hash, .note_hash)
})

test_that("vector: the sign-off preimage, byte for byte", {
  preimage <- verdifax_signoff_preimage(
    .vector$signoff_chain_id, .vector$signoff_previous_hash, vector_target(),
    .vector$signoff_decision, .vector$signoff_note_hash, .vector$signed_at, .vector$nonce
  )
  expect_type(preimage, "raw")
  expect_equal(paste(as.character(preimage), collapse = ""), .vector$signoff_preimage_hex)
})

test_that("vector: the sign-off signature, byte for byte", {
  need_sodium()
  signer <- verdifax:::.approver_signer(.approver_seed)
  body <- verdifax:::.signoff_body(
    signer, .vector$signoff_chain_id, .vector$signoff_previous_hash,
    verdifax:::.signoff_target(vector_target()), .vector$signoff_decision,
    .vector$signoff_note_hash, .vector$signed_at, .vector$nonce
  )
  expect_equal(body$signature, .vector$signoff_signature)
  expect_equal(body$approver_key, .vector$public_key)
  expect_equal(body$signed_at, .vector$signed_at)
  expect_equal(body$nonce, .vector$nonce)
  expect_equal(body$previous_signoff_hash, .vector$signoff_previous_hash)
  expect_equal(body$note_hash, .vector$signoff_note_hash)
})

test_that("vector: the approver key proof preimage and proof, byte for byte", {
  preimage <- verdifax:::.approver_proof_preimage(.vector$public_key)
  expect_equal(paste(as.character(preimage), collapse = ""), .vector$approver_proof_preimage_hex)
  need_sodium()
  expect_equal(
    verdifax_approver_key_proof(.approver_seed),
    list(public_key = .vector$public_key, proof = .vector$approver_proof)
  )
})


# ── The preimage helper ─────────────────────────────────────────────────────

test_that("signoff_preimage puts job_id in its place for a job, and the empty string otherwise", {
  job <- list(kind = "job", run_id = 7, digest = .digest, job_id = "loan-1")
  preimage <- verdifax_signoff_preimage("account-7", .newest, job, "reject", "", "t", "n")
  expect_identical(preimage, zero_joined(list(
    "verdifax.signoff.v1", "account-7", .newest, "job", "7", .digest, "loan-1", "reject", "", "t", "n"
  )))
  record <- verdifax_signoff_preimage("account-7", .newest, record_target(), "approve", "", "t", "n")
  expect_identical(record, zero_joined(list(
    "verdifax.signoff.v1", "account-7", .newest, "record", "42", .digest, "", "approve", "", "t", "n"
  )))
})

test_that("signoff_preimage refuses bad fields", {
  good <- list("account-7", .newest, record_target(), "approve", "", "t", "n")
  call <- function(i, value) {
    args <- good
    args[i] <- list(value)
    do.call(verdifax_signoff_preimage, args)
  }
  expect_error(call(1, NA_character_), "chain_id")
  expect_error(call(1, 7), "chain_id")
  expect_error(call(2, strrep("E", 64)), "previous_signoff_hash")
  expect_error(call(3, list(kind = "record", run_id = 42)), "target\\$digest")
  expect_error(call(4, "maybe"), "decision")
  expect_error(call(5, NULL), "note_hash")
  expect_error(call(5, "abc"), "note_hash")
  expect_error(call(6, NULL), "signed_at")
  expect_error(call(7, 5), "nonce")
})
