# Pure-function tests for verdifax_capture_environment() and
# verdifax_client(). These don't hit the network, only verify the
# local-environment introspection logic.

test_that("verdifax_capture_environment returns expected core fields", {
  ctx <- verdifax_capture_environment()

  expect_true(is.list(ctx))
  expect_equal(ctx$runtime_name, "R")
  expect_true(nzchar(ctx$runtime_version))
  expect_true(grepl("/", ctx$platform))
  expect_true(ctx$declared)
})

test_that("declared_seeds are recorded sorted by name", {
  ctx <- verdifax_capture_environment(
    declared_seeds = list(torch = 1337, rng = 42, numpy = 12)
  )
  expect_equal(ctx$random_seeds, c("numpy=12", "rng=42", "torch=1337"))
})

test_that("pinned_dependencies is a sorted character vector when present", {
  ctx <- verdifax_capture_environment(include_dependencies = TRUE)
  if (!is.null(ctx$pinned_dependencies)) {
    expect_type(ctx$pinned_dependencies, "character")
    expect_equal(
      ctx$pinned_dependencies,
      ctx$pinned_dependencies[order(tolower(ctx$pinned_dependencies))]
    )
  }
})

test_that("include_dependencies=FALSE skips dep enumeration", {
  ctx <- verdifax_capture_environment(include_dependencies = FALSE)
  expect_null(ctx$pinned_dependencies)
})

test_that("verdifax_client honors explicit base_url over env", {
  Sys.setenv(VERDIFAX_API_URL = "http://from-env:1234/")
  on.exit(Sys.unsetenv("VERDIFAX_API_URL"))

  client <- verdifax_client(base_url = "http://explicit:9090")
  expect_equal(client$base_url, "http://explicit:9090")
})

test_that("verdifax_client falls back to env when base_url not given", {
  Sys.setenv(VERDIFAX_API_URL = "http://from-env:1234/")
  on.exit(Sys.unsetenv("VERDIFAX_API_URL"))

  client <- verdifax_client()
  expect_equal(client$base_url, "http://from-env:1234")
})

test_that("verdifax_client strips trailing slashes from base_url", {
  client <- verdifax_client(base_url = "http://example.com////")
  expect_equal(client$base_url, "http://example.com")
})
