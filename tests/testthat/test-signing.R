# Optional customer request signing. Requests are captured by a mock,
# so nothing reaches the network.

# The vector shared by the four SDKs, so they cannot disagree.
.seed <- as.raw(rep(1L, 32))
.program_id <- strrep("1", 64)
.route_id <- "r"
.registry_record_hash <- strrep("2", 64)
.signed_at <- "2026-11-05T00:00:00Z"
.nonce <- "00112233445566778899aabbccddeeff"
.payload_hash <- "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
.public_key <- "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="
.proof <- "Vc0TtZ8UbLQgWVnUcwSFPzl3jMn1neQqYQEpbepGa7IYfJJ7kh5QcU0FT5tC5EDoAJNDZNxkLA2Dtf2JHsppBA=="
.signature <- "PWKn9IplkfrPmXSN+EfJX7aUPoRR0GHqjCvOLG2l1BAvPgupr7ZsJGNujNh6Wk2w/Y1zRaBVeNqOZ1QVrrBvCw=="

# CI installs sodium, so there a missing package fails rather than skips.
need_sodium <- function() {
  if (!nzchar(Sys.getenv("CI"))) {
    testthat::skip_if_not_installed("sodium")
  }
}

signed_client <- function() {
  verdifax_client(base_url = "http://mock.invalid", api_key = "k", signing_key = .seed)
}

unsigned_client <- function() {
  verdifax_client(base_url = "http://mock.invalid", api_key = "k")
}

# Runs `code`, answers each request with `{"ok":true}`, and returns what
# was sent, decoded from the JSON the request would put on the wire.
capture_requests <- function(code) {
  sent <- list()
  mock <- function(req) {
    json <- jsonlite::toJSON(httr2::req_get_body(req), auto_unbox = TRUE, digits = 22, null = "null")
    sent[[length(sent) + 1]] <<- list(
      method = httr2::req_get_method(req),
      url = httr2::req_get_url(req),
      json = as.character(json),
      body = jsonlite::fromJSON(json, simplifyVector = FALSE)
    )
    httr2::response(
      status_code = 200,
      headers = "Content-Type: application/json",
      body = charToRaw("{\"ok\":true}")
    )
  }
  httr2::with_mocked_responses(mock, code)
  sent
}

attest <- function(client, payload) {
  verdifax_attest(
    client = client,
    payload = payload,
    program_id = .program_id,
    route_id = .route_id,
    registry_record_hash = .registry_record_hash
  )
}

# The request inside a signed body, read as the server reads it.
signed_fields <- function(body) {
  jsonlite::fromJSON(body$signed_request, simplifyVector = FALSE)
}

sha256_text <- function(text) {
  sodium::bin2hex(sodium::sha256(charToRaw(enc2utf8(text))))
}

# Rebuilds the signed bytes from a sent body, as the server does,
# written out independently of the SDK.
signature_verifies <- function(body, public_key = jsonlite::base64_dec(.public_key)) {
  request <- signed_fields(body)
  payload <- if (is.null(request$payload_text)) request[["payload"]] else request$payload_text
  fields <- list(
    charToRaw("verdifax.request.v2"),
    charToRaw(sha256_text(body$signed_request)),
    charToRaw(sha256_text(payload)),
    charToRaw(request$program_id),
    charToRaw(request$route_id),
    charToRaw(request$registry_record_hash),
    raw(0),
    charToRaw("verdifax.job.v1"),
    raw(0), raw(0), raw(0), raw(0),
    charToRaw("false"),
    charToRaw(body$request_signature$signed_at),
    charToRaw(body$request_signature$nonce)
  )
  signed <- Reduce(function(a, b) c(a, as.raw(0), b), fields)
  sodium::sig_verify(signed, jsonlite::base64_dec(body$request_signature$signature), public_key)
}

.vector <- jsonlite::fromJSON(testthat::test_path("sdk-signature-vector.json"))
vector_seed <- function() sodium::hex2bin(.vector$seed_hex)
vector_signer <- function() verdifax:::.request_signer(vector_seed())

test_that("vector: hashes come from the exact text", {
  need_sodium()
  text <- .vector$signed_request
  expect_equal(verdifax:::.sha256_hex(text), .vector$body_hash)
  request <- jsonlite::fromJSON(text, simplifyVector = FALSE)
  expect_equal(verdifax:::.payload_hash(request), .vector$payload_hash)
  expect_equal(verdifax:::.ai_output_hash(request), .vector$ai_output_hash)
})

test_that("vector: the preimage, byte for byte", {
  need_sodium()
  preimage <- verdifax:::.signed_text_preimage(.vector$signed_request, .vector$signed_at, .vector$nonce)
  expect_equal(sodium::bin2hex(preimage), .vector$preimage_hex)
})

test_that("vector: the no-job preimage, byte for byte", {
  need_sodium()
  preimage <- verdifax:::.request_preimage_v2(
    body_hash = verdifax:::.sha256_hex("{\"payload_text\":\"hello\"}"),
    payload_hash = .vector$payload_hash,
    program_id = strrep("1", 64),
    route_id = "route-a",
    registry_record_hash = strrep("2", 64),
    ai_output_hash = "",
    job = NULL,
    signed_at = .vector$signed_at,
    nonce = .vector$nonce
  )
  expect_equal(sodium::bin2hex(preimage), .vector$no_job_preimage_hex)
})

test_that("vector: the signature and the public key", {
  need_sodium()
  signer <- vector_signer()
  expect_equal(verdifax:::.base64(signer$public_key), .vector$public_key)
  body <- verdifax:::.signed_body(signer, .vector$signed_request, .vector$signed_at, .vector$nonce)
  expect_identical(body$signed_request, .vector$signed_request)
  expect_equal(body$request_signature, list(
    version = "2",
    signature = .vector$signature,
    signed_at = .vector$signed_at,
    nonce = .vector$nonce
  ))
})

test_that("vector: the key change, byte for byte", {
  need_sodium()
  signer <- vector_signer()
  preimage <- verdifax:::.join_with_zero(list(
    verdifax:::.REQUEST_KEY_CHANGE_FORM, .vector$public_key, .vector$signed_at, .vector$nonce
  ))
  expect_equal(sodium::bin2hex(preimage), .vector$key_change_preimage_hex)
  change <- verdifax:::.key_change(signer, .vector$public_key, .vector$signed_at, .vector$nonce)
  expect_equal(change, list(
    signature = .vector$key_change_signature,
    signed_at = .vector$signed_at,
    nonce = .vector$nonce
  ))
})

test_that("vector: the policy activation preimage, byte for byte", {
  preimage <- verdifax_policy_activation_preimage(
    .vector$activation_chain_id, .vector$activation_document_hash,
    .vector$activation_previous_hash, .vector$signed_at, .vector$nonce
  )
  expect_type(preimage, "raw")
  expect_equal(paste(as.character(preimage), collapse = ""), .vector$activation_preimage_hex)
})

test_that("vector: the policy activation approval, byte for byte", {
  need_sodium()
  approval <- verdifax_policy_activation_approval(
    vector_seed(), .vector$activation_chain_id, .vector$activation_document_hash,
    .vector$activation_previous_hash, .vector$signed_at, .vector$nonce
  )
  expect_equal(approval, list(
    signature = .vector$activation_signature,
    signed_at = .vector$signed_at,
    nonce = .vector$nonce
  ))
  internal <- verdifax:::.policy_activation(
    vector_signer(), .vector$activation_chain_id, .vector$activation_document_hash,
    .vector$activation_previous_hash, .vector$signed_at, .vector$nonce
  )
  expect_equal(internal, approval)
})

test_that("vector: the account policy activation preimage, byte for byte", {
  expect_equal(.vector$account_activation_chain_id, "account-7")
  preimage <- verdifax_policy_activation_preimage(
    .vector$account_activation_chain_id, .vector$activation_document_hash,
    .vector$activation_previous_hash, .vector$signed_at, .vector$nonce
  )
  expect_type(preimage, "raw")
  expect_equal(paste(as.character(preimage), collapse = ""), .vector$account_activation_preimage_hex)
  expect_false(identical(.vector$account_activation_preimage_hex, .vector$activation_preimage_hex))
})

test_that("vector: the account policy activation approval, byte for byte", {
  need_sodium()
  approval <- verdifax_policy_activation_approval(
    vector_seed(), .vector$account_activation_chain_id, .vector$activation_document_hash,
    .vector$activation_previous_hash, .vector$signed_at, .vector$nonce
  )
  expect_equal(approval, list(
    signature = .vector$account_activation_signature,
    signed_at = .vector$signed_at,
    nonce = .vector$nonce
  ))
  internal <- verdifax:::.policy_activation(
    vector_signer(), .vector$account_activation_chain_id, .vector$activation_document_hash,
    .vector$activation_previous_hash, .vector$signed_at, .vector$nonce
  )
  expect_equal(internal, approval)
})

test_that("a policy activation approval defaults to now and a fresh nonce", {
  need_sodium()
  first <- verdifax_policy_activation_approval(
    vector_seed(), "api-key-7", strrep("a", 64), strrep("0", 64)
  )
  second <- verdifax_policy_activation_approval(
    vector_seed(), "api-key-7", strrep("a", 64), strrep("0", 64)
  )
  expect_match(first$signed_at, "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$")
  expect_match(first$nonce, "^[0-9a-f]{32}$")
  expect_false(identical(first$nonce, second$nonce))
  expect_false(grepl("\n", first$signature, fixed = TRUE))
})

test_that("the policy activation helpers refuse bad fields", {
  expect_error(
    verdifax_policy_activation_preimage("c", strrep("A", 64), strrep("0", 64), "t", "n"),
    "document_hash"
  )
  expect_error(
    verdifax_policy_activation_preimage("c", strrep("a", 64), "short", "t", "n"),
    "previous_activation_hash"
  )
  expect_error(
    verdifax_policy_activation_preimage(c("a", "b"), strrep("a", 64), strrep("0", 64), "t", "n"),
    "chain_id"
  )
  expect_error(
    verdifax_policy_activation_approval(raw(3), "c", strrep("a", 64), strrep("0", 64)),
    "32 raw bytes"
  )
})

test_that("the job block the SDK builds gives the vector's job fields", {
  need_sodium()
  job <- verdifax:::.job_block(list(
    job_id = "loan-1",
    step_id = "decide",
    previous_record_hashes = c(strrep("b", 64), strrep("a", 64), strrep("b", 64)),
    external_previous = strrep("c", 64),
    final = TRUE
  ))
  request <- jsonlite::fromJSON(.vector$signed_request, simplifyVector = FALSE)
  expect_equal(job, request$job)
})

test_that("shared vector: signed bytes", {
  need_sodium()
  body <- list(
    payload_text = "hello",
    program_id = .program_id,
    route_id = .route_id,
    registry_record_hash = .registry_record_hash
  )
  expect_equal(verdifax:::.payload_hash(body), .payload_hash)
  preimage <- verdifax:::.join_with_zero(list(
    "verdifax.request.v1", .payload_hash, .program_id, .route_id,
    .registry_record_hash, .signed_at, .nonce
  ))
  zeros <- which(preimage == as.raw(0))
  expect_length(zeros, 6)
  expect_equal(rawToChar(preimage[1:(zeros[1] - 1)]), "verdifax.request.v1")
  expect_equal(rawToChar(preimage[(zeros[3] + 1):(zeros[4] - 1)]), "r")
  expect_equal(rawToChar(preimage[(zeros[6] + 1):length(preimage)]), .nonce)
})

test_that("shared vector: signature", {
  need_sodium()
  body <- list(
    payload_text = "hello",
    program_id = .program_id,
    route_id = .route_id,
    registry_record_hash = .registry_record_hash
  )
  signed <- verdifax:::.request_signature(signed_client()$signer, body, .signed_at, .nonce)
  expect_equal(signed, list(signature = .signature, signed_at = .signed_at, nonce = .nonce))
})

test_that("shared vector: proof", {
  need_sodium()
  body <- verdifax:::.request_key_body(signed_client()$signer)
  expect_equal(body, list(public_key = .public_key, proof = .proof))
  message <- c(charToRaw("verdifax.request-key.v1"), as.raw(0), charToRaw(.public_key))
  expect_true(sodium::sig_verify(
    message, jsonlite::base64_dec(.proof), jsonlite::base64_dec(.public_key)
  ))
})

test_that("an unsigned client sends no request_signature and needs no sodium", {
  testthat::local_mocked_bindings(.sodium_available = function() FALSE, .package = "verdifax")
  client <- unsigned_client()
  expect_null(client$signer)
  sent <- capture_requests(attest(client, "hello"))
  expect_null(sent[[1]]$body$request_signature)
})

test_that("verdifax_attest sends exactly signed_request and request_signature", {
  need_sodium()
  sent <- capture_requests(attest(signed_client(), "hello"))
  body <- sent[[1]]$body
  expect_setequal(names(body), c("signed_request", "request_signature"))
  expect_setequal(names(body$request_signature), c("version", "signature", "signed_at", "nonce"))
  expect_identical(body$request_signature$version, "2")
  expect_type(body$signed_request, "character")
  expect_null(signed_fields(body)$request_signature)
  expect_equal(signed_fields(body)$payload_text, "hello")
})

test_that("verdifax_attest signs, and the signature verifies", {
  need_sodium()
  sent <- capture_requests(attest(signed_client(), "hello"))
  body <- sent[[1]]$body
  expect_match(sent[[1]]$url, "/execute$")
  expect_true(signature_verifies(body))
  expect_match(body$request_signature$signed_at, "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$")
  expect_match(body$request_signature$nonce, "^[0-9a-f]{32}$")
})

test_that("the result holds the exact text that was signed", {
  need_sodium()
  sent <- capture_requests(result <- attest(signed_client(), "caf\u00e9"))
  expect_identical(result$signed_request, sent[[1]]$body$signed_request)
  expect_true(signature_verifies(sent[[1]]$body))
})

test_that("an unsigned result has no signed_request", {
  capture_requests(result <- attest(unsigned_client(), "hello"))
  expect_null(result$signed_request)
})

test_that("ai_output_text is signed", {
  need_sodium()
  client <- signed_client()
  sent <- capture_requests(result <- verdifax_attest(
    client = client,
    payload = "hello",
    program_id = .program_id,
    route_id = .route_id,
    registry_record_hash = .registry_record_hash,
    ai_output_text = "the answer"
  ))
  body <- sent[[1]]$body
  preimage <- verdifax:::.request_preimage_v2(
    body_hash = verdifax:::.sha256_hex(body$signed_request),
    payload_hash = .payload_hash,
    program_id = .program_id,
    route_id = .route_id,
    registry_record_hash = .registry_record_hash,
    ai_output_hash = sha256_text("the answer"),
    job = NULL,
    signed_at = body$request_signature$signed_at,
    nonce = body$request_signature$nonce
  )
  expect_true(sodium::sig_verify(
    preimage,
    jsonlite::base64_dec(body$request_signature$signature),
    jsonlite::base64_dec(.public_key)
  ))
})

test_that("verdifax_verify_determinism signs", {
  need_sodium()
  sent <- capture_requests(result <- verdifax_verify_determinism(
    client = signed_client(),
    payload = "hello",
    program_id = .program_id,
    route_id = .route_id,
    registry_record_hash = .registry_record_hash
  ))
  expect_match(sent[[1]]$url, "/execute/verify-determinism$")
  expect_setequal(names(sent[[1]]$body), c("signed_request", "request_signature"))
  expect_true(signature_verifies(sent[[1]]$body))
  expect_identical(result$signed_request, sent[[1]]$body$signed_request)
})

test_that("an unsigned determinism check sends no request_signature", {
  sent <- capture_requests(verdifax_verify_determinism(
    client = unsigned_client(),
    payload = "hello",
    program_id = .program_id,
    route_id = .route_id,
    registry_record_hash = .registry_record_hash
  ))
  expect_null(sent[[1]]$body$request_signature)
})

test_that("non-ASCII text hashes its UTF-8 bytes", {
  need_sodium()
  text <- "café 世界 \U0001f600"
  sent <- capture_requests(attest(signed_client(), text))
  expect_equal(signed_fields(sent[[1]]$body)$payload_text, enc2utf8(text))
  expect_true(signature_verifies(sent[[1]]$body))
})

test_that("Latin-1 text is signed as the UTF-8 that is sent", {
  need_sodium()
  text <- "caf\xe9"
  Encoding(text) <- "latin1"
  sent <- capture_requests(attest(signed_client(), text))
  expect_equal(signed_fields(sent[[1]]$body)$payload_text, "café")
  expect_true(signature_verifies(sent[[1]]$body))
})

test_that("a UTF-8 raw payload is sent and hashed as text", {
  need_sodium()
  sent <- capture_requests(attest(signed_client(), charToRaw("hello")))
  expect_equal(signed_fields(sent[[1]]$body)$payload_text, "hello")
  expect_true(signature_verifies(sent[[1]]$body))
})

test_that("a binary raw payload hashes the base64 string, not the decoded bytes", {
  need_sodium()
  sent <- capture_requests(attest(signed_client(), as.raw(c(0xff, 0xfe, 0x00))))
  body <- sent[[1]]$body
  request <- signed_fields(body)
  expect_null(request[["payload_text"]])
  expect_equal(request[["payload"]], "//4A")
  expect_true(signature_verifies(body))
})

test_that("a long binary payload hashes its base64 line breaks as sent", {
  need_sodium()
  sent <- capture_requests(attest(signed_client(), as.raw(rep(c(0xff, 0x00), 100))))
  body <- sent[[1]]$body
  expect_match(signed_fields(body)[["payload"]], "\n", fixed = TRUE)
  expect_true(signature_verifies(body))
})

test_that("signatures and proofs are unwrapped base64", {
  need_sodium()
  client <- signed_client()
  sent <- capture_requests({
    verdifax_register_request_key(client)
    attest(client, "hello")
  })
  expect_false(grepl("\n", sent[[1]]$body$proof, fixed = TRUE))
  expect_false(grepl("\n", sent[[2]]$body$request_signature$signature, fixed = TRUE))
})

test_that("non-empty payload_text wins over payload, and an empty one does not", {
  need_sodium()
  expected <- function(text) sodium::bin2hex(sodium::sha256(charToRaw(text)))
  expect_equal(
    verdifax:::.payload_hash(list(payload_text = "text", payload = "b64")),
    expected("text")
  )
  expect_equal(
    verdifax:::.payload_hash(list(payload_text = "", payload = "b64")),
    expected("b64")
  )
  # body$payload would partially match payload_text.
  expect_equal(verdifax:::.payload_hash(list(payload = "b64")), expected("b64"))
})

test_that("the nonce differs between calls", {
  need_sodium()
  client <- signed_client()
  sent <- capture_requests({
    attest(client, "hello")
    attest(client, "hello")
  })
  first <- sent[[1]]$body$request_signature
  second <- sent[[2]]$body$request_signature
  expect_match(first$signed_at, "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$")
  expect_false(identical(first$nonce, second$nonce))
  expect_false(identical(first$signature, second$signature))
})

# Checks an approval the way the server does: signed by `public_key` over
# the new key, written out independently of the SDK.
change_verifies <- function(change, new_key, public_key = .public_key) {
  fields <- lapply(
    list("verdifax.request-key-change.v1", new_key, change$signed_at, change$nonce),
    charToRaw
  )
  signed <- Reduce(function(a, b) c(a, as.raw(0), b), fields)
  sodium::sig_verify(
    signed, jsonlite::base64_dec(change$signature), jsonlite::base64_dec(public_key)
  )
}

test_that("register sends the public key and proof", {
  need_sodium()
  client <- signed_client()
  sent <- capture_requests(verdifax_register_request_key(client))
  expect_equal(sent[[1]]$method, "POST")
  expect_match(sent[[1]]$url, "/keys/request-key$")
  expect_equal(sent[[1]]$body, list(public_key = .public_key, proof = .proof))
})

test_that("clear sends the current key's approval as the DELETE body", {
  need_sodium()
  sent <- capture_requests(verdifax_clear_request_key(signed_client()))
  expect_equal(sent[[1]]$method, "DELETE")
  expect_match(sent[[1]]$url, "/keys/request-key$")
  expect_named(sent[[1]]$body, "change")
  change <- sent[[1]]$body$change
  expect_setequal(names(change), c("signature", "signed_at", "nonce"))
  expect_match(change$nonce, "^[0-9a-f]{32}$")
  expect_true(change_verifies(change, ""))
})

test_that("after a clear the client and its copies send unsigned requests", {
  need_sodium()
  client <- signed_client()
  copy <- client
  capture_requests(verdifax_clear_request_key(client))
  sent <- capture_requests({
    result <- attest(client, "hello")
    attest(copy, "hello")
    verdifax_execute_batch(client, list(list(
      payload = "x", program_id = .program_id, route_id = .route_id,
      registry_record_hash = .registry_record_hash
    )))
    verdifax_verify_determinism(
      client = client, payload = "hello", program_id = .program_id,
      route_id = .route_id, registry_record_hash = .registry_record_hash
    )
  })
  expect_equal(sent[[1]]$body$payload_text, "hello")
  expect_null(sent[[1]]$body$signed_request)
  expect_null(sent[[1]]$body$request_signature)
  expect_null(sent[[2]]$body$request_signature)
  expect_null(sent[[3]]$body$runs[[1]]$request_signature)
  expect_null(sent[[4]]$body$request_signature)
  expect_null(result$signed_request)
})

test_that("an admin clear keeps the client's key, because the id can be any API key", {
  need_sodium()
  client <- signed_client()
  sent <- capture_requests({
    verdifax_admin_clear_request_key(client, 7)
    attest(client, "hello")
  })
  expect_equal(sent[[1]]$method, "DELETE")
  expect_match(sent[[1]]$url, "/admin/keys/7/request-key$")
  expect_null(sent[[1]]$body)
  expect_true(signature_verifies(sent[[2]]$body))
})

test_that("a client that dropped its key cannot register, rotate or approve", {
  need_sodium()
  client <- signed_client()
  sent <- capture_requests({
    verdifax_clear_request_key(client)
    verdifax_clear_request_key(client)
    expect_error(verdifax_register_request_key(client), "signing_key")
    expect_error(verdifax_rotate_request_key(client, as.raw(rep(2L, 32))), "signing_key")
  })
  expect_length(sent, 2)
  expect_null(sent[[2]]$body)
})

test_that("a refused clear keeps signing", {
  need_sodium()
  client <- signed_client()
  refuse <- function(req) {
    httr2::response(
      status_code = 403,
      headers = "Content-Type: application/json",
      body = charToRaw("{\"ok\":false,\"error\":\"the current request key must approve this change\"}")
    )
  }
  httr2::with_mocked_responses(refuse, expect_error(
    verdifax_clear_request_key(client),
    "must approve",
    class = "httr2_http_403"
  ))
  sent <- capture_requests(attest(client, "hello"))
  expect_true(signature_verifies(sent[[1]]$body))
})

test_that("clear on an unsigned client sends no body, as before", {
  sent <- capture_requests(verdifax_clear_request_key(unsigned_client()))
  expect_equal(sent[[1]]$method, "DELETE")
  expect_null(sent[[1]]$body)
})

test_that("rotate sends the new key, its proof and the current key's approval", {
  need_sodium()
  client <- signed_client()
  new_key <- as.raw(rep(2L, 32))
  registration <- verdifax_request_key_registration_body(new_key)
  sent <- capture_requests(result <- verdifax_rotate_request_key(client, new_key))
  expect_equal(sent[[1]]$method, "POST")
  expect_match(sent[[1]]$url, "/keys/request-key$")
  body <- sent[[1]]$body
  expect_setequal(names(body), c("public_key", "proof", "change"))
  expect_equal(body$public_key, registration$public_key)
  expect_equal(body$proof, registration$proof)
  expect_true(change_verifies(body$change, body$public_key))
  expect_error(change_verifies(body$change, body$public_key, public_key = body$public_key))
  expect_true(result$ok)
})

test_that("after a rotate the client and its copies sign with the new key", {
  need_sodium()
  client <- signed_client()
  copy <- client
  new_key <- as.raw(rep(2L, 32))
  new_public <- jsonlite::base64_dec(verdifax_request_key_registration_body(new_key)$public_key)
  capture_requests(verdifax_rotate_request_key(client, new_key))
  sent <- capture_requests({
    attest(client, "hello")
    attest(copy, "hello")
  })
  expect_true(signature_verifies(sent[[1]]$body, new_public))
  expect_true(signature_verifies(sent[[2]]$body, new_public))
  expect_error(signature_verifies(sent[[1]]$body))
})

test_that("a refused rotate keeps the current key", {
  need_sodium()
  client <- signed_client()
  refuse <- function(req) {
    httr2::response(
      status_code = 403,
      headers = "Content-Type: application/json",
      body = charToRaw("{\"ok\":false,\"error\":\"the current request key must approve this change\"}")
    )
  }
  httr2::with_mocked_responses(refuse, expect_error(
    verdifax_rotate_request_key(client, as.raw(rep(2L, 32))),
    "must approve",
    class = "httr2_http_403"
  ))
  sent <- capture_requests(attest(client, "hello"))
  expect_true(signature_verifies(sent[[1]]$body))
})

test_that("rotate is refused before sending when it cannot be approved", {
  sent <- capture_requests(
    expect_error(verdifax_rotate_request_key(unsigned_client(), as.raw(rep(2L, 32))), "signing_key")
  )
  expect_length(sent, 0)
})

test_that("rotate refuses a bad new key before sending", {
  need_sodium()
  sent <- capture_requests(
    expect_error(verdifax_rotate_request_key(signed_client(), raw(3)), "32 raw bytes")
  )
  expect_length(sent, 0)
})

test_that("register needs a signing key", {
  expect_error(verdifax_register_request_key(unsigned_client()), "signing_key")
})

test_that("verdifax_generate_request_key returns raw keys that work", {
  need_sodium()
  pair <- verdifax_generate_request_key()
  expect_type(pair$public_key, "raw")
  expect_length(pair$public_key, 32)
  expect_type(pair$private_key, "raw")
  expect_length(pair$private_key, 32)
  client <- verdifax_client(
    base_url = "http://mock.invalid", api_key = "k", signing_key = pair$private_key
  )
  sent <- capture_requests(attest(client, "hello"))
  expect_true(signature_verifies(sent[[1]]$body, pair$public_key))
})

test_that("a bad signing key is refused without echoing it", {
  for (bad in list(raw(0), charToRaw("short"), raw(33), strrep("0", 32))) {
    err <- tryCatch(verdifax_client(signing_key = bad), error = function(e) e)
    expect_s3_class(err, "error")
    expect_match(conditionMessage(err), "32 raw bytes")
    expect_false(grepl("short", conditionMessage(err)))
  }
})

test_that("a missing sodium package gives a clear error", {
  testthat::local_mocked_bindings(.sodium_available = function() FALSE, .package = "verdifax")
  expect_error(verdifax_generate_request_key(), "install.packages")
  expect_error(verdifax_client(signing_key = .seed), "install.packages")
})

test_that("the private key is not printed or sent", {
  need_sodium()
  client <- signed_client()
  secrets <- c(paste(as.character(.seed), collapse = ""), paste(as.character(.seed), collapse = " "),
               jsonlite::base64_enc(.seed))
  printed <- paste(c(capture.output(print(client)), capture.output(str(client))), collapse = "\n")
  sent <- capture_requests({
    verdifax_register_request_key(client)
    attest(client, "hello")
  })
  wire <- paste(vapply(sent, function(s) s$json, ""), collapse = "\n")
  for (secret in secrets) {
    expect_false(grepl(secret, printed, fixed = TRUE))
    expect_false(grepl(secret, wire, fixed = TRUE))
  }
})


# ── The owner key's request key, replaced (round 61) ────────────────────────

test_that("rotate_account_request_key sends the new key, its proof and the current key's approval", {
  need_sodium()
  client <- signed_client()
  new_key <- as.raw(rep(2L, 32))
  registration <- verdifax_request_key_registration_body(new_key)
  sent <- capture_requests(result <- verdifax_rotate_account_request_key(client, new_key))
  expect_length(sent, 1)
  expect_equal(sent[[1]]$method, "POST")
  expect_match(sent[[1]]$url, "/account/request-key$")
  body <- sent[[1]]$body
  expect_setequal(names(body), c("public_key", "proof", "change"))
  expect_equal(body$public_key, registration$public_key)
  expect_equal(body$proof, registration$proof)
  expect_true(change_verifies(body$change, body$public_key))
  expect_error(change_verifies(body$change, body$public_key, public_key = body$public_key))
  expect_true(result$ok)
})

test_that("after an account rotate the client and its copies sign with the new key", {
  need_sodium()
  client <- signed_client()
  copy <- client
  new_key <- as.raw(rep(2L, 32))
  new_public <- jsonlite::base64_dec(verdifax_request_key_registration_body(new_key)$public_key)
  capture_requests(verdifax_rotate_account_request_key(client, new_key))
  sent <- capture_requests({
    attest(client, "hello")
    attest(copy, "hello")
  })
  expect_true(signature_verifies(sent[[1]]$body, new_public))
  expect_true(signature_verifies(sent[[2]]$body, new_public))
  expect_error(signature_verifies(sent[[1]]$body))
})

test_that("a refused account rotate keeps the current key", {
  need_sodium()
  for (refusal in list(
    list(403, "the current request key must approve this change", "httr2_http_403"),
    list(409, "the request key changed since this change was signed", "httr2_http_409")
  )) {
    client <- signed_client()
    refuse <- function(req) {
      httr2::response(
        status_code = refusal[[1]],
        headers = "Content-Type: application/json",
        body = charToRaw(sprintf("{\"ok\":false,\"error\":\"%s\"}", refusal[[2]]))
      )
    }
    httr2::with_mocked_responses(refuse, expect_error(
      verdifax_rotate_account_request_key(client, as.raw(rep(2L, 32))),
      refusal[[2]],
      class = refusal[[3]]
    ))
    sent <- capture_requests(attest(client, "hello"))
    expect_true(signature_verifies(sent[[1]]$body))
  }
})

test_that("account rotate is refused before sending without a key or with a bad new key", {
  sent <- capture_requests(
    expect_error(
      verdifax_rotate_account_request_key(unsigned_client(), as.raw(rep(2L, 32))),
      "verdifax_rotate_account_request_key needs a client with signing_key"
    )
  )
  expect_length(sent, 0)
  need_sodium()
  sent <- capture_requests(
    expect_error(verdifax_rotate_account_request_key(signed_client(), raw(3)), "32 raw bytes")
  )
  expect_length(sent, 0)
})
