module StreamTest (tests) where

import FFI
import Stream

import qualified Data.Map.Strict as Map
import Data.Word
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, (@?=))

tests :: TestTree
tests = testGroup "Stream"
  [ updateAggTests
  , aggRowKeyTests
  ]

-- -------------------------------------------------------------------
-- Helpers
-- -------------------------------------------------------------------

mkEvent :: Word32 -> Word32 -> Protocol -> Direction -> Word32 -> NetEvent
mkEvent src dst proto dir plen = NetEvent
  { evTimestampNs = 0
  , evSrcIp       = src
  , evDstIp       = dst
  , evPktLen      = plen
  , evProtocol    = proto
  , evDirection   = dir
  }

ip :: Word8 -> Word8 -> Word8 -> Word8 -> Word32
ip a b c d = fromIntegral a
         + fromIntegral b * 256
         + fromIntegral c * 65536
         + fromIntegral d * 16777216

localhost :: Word32
localhost = ip 127 0 0 1

-- -------------------------------------------------------------------
-- updateAgg (pure aggregation)
-- -------------------------------------------------------------------

updateAggTests :: TestTree
updateAggTests = testGroup "updateAgg"
  [ testCase "empty batch yields empty map" $
      updateAgg Map.empty [] @?= Map.empty

  , testCase "single event creates one row" $ do
      let evt = mkEvent localhost localhost ICMP Ingress 64
          m   = updateAgg Map.empty [evt]
      Map.size m @?= 1
      let [row] = Map.elems m
      aggPktCount row  @?= 1
      aggByteCount row @?= 64

  , testCase "two identical-flow events merge" $ do
      let evt1 = mkEvent localhost localhost TCP Ingress 100
          evt2 = mkEvent localhost localhost TCP Ingress 200
          m    = updateAgg Map.empty [evt1, evt2]
      Map.size m @?= 1
      let [row] = Map.elems m
      aggPktCount row  @?= 2
      aggByteCount row @?= 300

  , testCase "different flows stay separate" $ do
      let dst2 = ip 10 0 0 1
          evt1 = mkEvent localhost localhost TCP Ingress 100
          evt2 = mkEvent localhost dst2      TCP Ingress 200
          m    = updateAgg Map.empty [evt1, evt2]
      Map.size m @?= 2

  , testCase "direction distinguishes flows" $ do
      let evt1 = mkEvent localhost localhost TCP Ingress 50
          evt2 = mkEvent localhost localhost TCP Egress  50
          m    = updateAgg Map.empty [evt1, evt2]
      Map.size m @?= 2

  , testCase "protocol distinguishes flows" $ do
      let evt1 = mkEvent localhost localhost TCP  Ingress 50
          evt2 = mkEvent localhost localhost UDP  Ingress 50
          evt3 = mkEvent localhost localhost ICMP Ingress 50
          m    = updateAgg Map.empty [evt1, evt2, evt3]
      Map.size m @?= 3

  , testCase "incremental aggregation across batches" $ do
      let evt1 = mkEvent localhost localhost TCP Ingress 100
          evt2 = mkEvent localhost localhost TCP Ingress 200
          m1   = updateAgg Map.empty [evt1]
          m2   = updateAgg m1 [evt2]
      Map.size m2 @?= 1
      let [row] = Map.elems m2
      aggPktCount row  @?= 2
      aggByteCount row @?= 300

  , testCase "large batch (1000 events)" $ do
      let evts = [ mkEvent localhost localhost TCP Ingress (fromIntegral i)
                  | i <- [1..1000 :: Int] ]
          m    = updateAgg Map.empty evts
      Map.size m @?= 1
      let [row] = Map.elems m
      aggPktCount row  @?= 1000
      -- sum 1..1000 = 500500
      aggByteCount row @?= 500500
  ]

-- -------------------------------------------------------------------
-- aggRowKey
-- -------------------------------------------------------------------

aggRowKeyTests :: TestTree
aggRowKeyTests = testGroup "aggRowKey"
  [ testCase "extracts correct key" $ do
      let row = AggRow
            { aggSrcIp     = localhost
            , aggDstIp     = ip 10 0 0 1
            , aggProtocol  = UDP
            , aggDirection = Egress
            , aggPktCount  = 42
            , aggByteCount = 12345
            }
      aggRowKey row @?= (localhost, ip 10 0 0 1, UDP, Egress)

  , testCase "counters do not affect key" $ do
      let row1 = AggRow localhost localhost TCP Ingress 1 100
          row2 = AggRow localhost localhost TCP Ingress 999 999999
      aggRowKey row1 @?= aggRowKey row2
  ]
