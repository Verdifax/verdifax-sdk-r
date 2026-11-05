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

# Rebuilds the signed bytes from a sent body, as the server does,
# written out independently of the SDK.
signature_verifies <- function(body, public_key = jsonlite::base64_dec(.public_key)) {
  payload <- if (is.null(body$payload_text)) body[["payload"]] else body$payload_text
  fields <- list(
    charToRaw("verdifax.request.v1"),
    charToRaw(sodium::bin2hex(sodium::sha256(charToRaw(enc2utf8(payload))))),
    charToRaw(body$program_id),
    charToRaw(body$route_id),
    charToRaw(body$registry_record_hash),
    charToRaw(body$request_signature$signed_at),
    charToRaw(body$request_signature$nonce)
  )
  signed <- Reduce(function(a, b) c(a, as.raw(0), b), fields)
  sodium::sig_verify(signed, jsonlite::base64_dec(body$request_signature$signature), public_key)
}

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
  expect_named(client, c("base_url", "api_key", "timeout"))
  sent <- capture_requests(attest(client, "hello"))
  expect_null(sent[[1]]$body$request_signature)
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

test_that("verdifax_verify_determinism signs", {
  need_sodium()
  sent <- capture_requests(verdifax_verify_determinism(
    client = signed_client(),
    payload = "hello",
    program_id = .program_id,
    route_id = .route_id,
    registry_record_hash = .registry_record_hash
  ))
  expect_match(sent[[1]]$url, "/execute/verify-determinism$")
  expect_true(signature_verifies(sent[[1]]$body))
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
  expect_equal(sent[[1]]$body$payload_text, enc2utf8(text))
  expect_true(signature_verifies(sent[[1]]$body))
})

test_that("Latin-1 text is signed as the UTF-8 that is sent", {
  need_sodium()
  text <- "caf\xe9"
  Encoding(text) <- "latin1"
  sent <- capture_requests(attest(signed_client(), text))
  expect_equal(sent[[1]]$body$payload_text, "café")
  expect_true(signature_verifies(sent[[1]]$body))
})

test_that("a UTF-8 raw payload is sent and hashed as text", {
  need_sodium()
  sent <- capture_requests(attest(signed_client(), charToRaw("hello")))
  expect_equal(sent[[1]]$body$payload_text, "hello")
  expect_true(signature_verifies(sent[[1]]$body))
})

test_that("a binary raw payload hashes the base64 string, not the decoded bytes", {
  need_sodium()
  sent <- capture_requests(attest(signed_client(), as.raw(c(0xff, 0xfe, 0x00))))
  body <- sent[[1]]$body
  expect_null(body[["payload_text"]])
  expect_equal(body[["payload"]], "//4A")
  expect_true(signature_verifies(body))
})

test_that("a long binary payload hashes its base64 line breaks as sent", {
  need_sodium()
  sent <- capture_requests(attest(signed_client(), as.raw(rep(c(0xff, 0x00), 100))))
  body <- sent[[1]]$body
  expect_match(body[["payload"]], "\n", fixed = TRUE)
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
  expect_false(identical(first$nonce, second$nonce))
  expect_false(identical(first$signature, second$signature))
})

test_that("register sends the public key and proof, and clear clears it", {
  need_sodium()
  client <- signed_client()
  sent <- capture_requests({
    verdifax_register_request_key(client)
    verdifax_clear_request_key(client)
  })
  expect_equal(sent[[1]]$method, "POST")
  expect_match(sent[[1]]$url, "/keys/request-key$")
  expect_equal(sent[[1]]$body, list(public_key = .public_key, proof = .proof))
  expect_equal(sent[[2]]$method, "DELETE")
  expect_match(sent[[2]]$url, "/keys/request-key$")
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
