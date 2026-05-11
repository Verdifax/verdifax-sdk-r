# Standard R package test entry point.
# Run with: Rscript -e 'testthat::test_dir("tests/testthat")'
library(testthat)
library(verdifax)

test_check("verdifax")
