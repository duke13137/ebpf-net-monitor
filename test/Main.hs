module Main (main) where

import Test.Tasty (defaultMain, testGroup)

import qualified FFITest
import qualified StreamTest

main :: IO ()
main = defaultMain $ testGroup "ebpf-net-monitor"
  [ FFITest.tests
  , StreamTest.tests
  ]
