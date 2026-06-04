module StreamTest (tests) where

import FFI
import Stream

import Data.Word
import qualified Data.Map.Strict as Map
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, (@?=))

tests :: TestTree
tests = testGroup "Stream"
  [ updateAggTests
  , aggRowKeyTests
  ]

mkEvent :: IPv4 -> IPv4 -> Port -> Port -> Protocol -> Direction -> PacketBytes -> NetEvent
mkEvent src dst srcPort dstPort proto dir plen = NetEvent
  { evTimestampNs = TimestampNs 0
  , evSrcIp       = src
  , evDstIp       = dst
  , evSrcPort     = srcPort
  , evDstPort     = dstPort
  , evPktLen      = plen
  , evProtocol    = proto
  , evDirection   = dir
  }

ip :: Word8 -> Word8 -> Word8 -> Word8 -> IPv4
ip a b c d = IPv4 $
     fromIntegral a
  +  fromIntegral b * 256
  +  fromIntegral c * 65536
  +  fromIntegral d * 16777216

localhost :: IPv4
localhost = ip 127 0 0 1

updateAggTests :: TestTree
updateAggTests = testGroup "updateAgg"
  [ testCase "empty batch yields empty map" $
      updateAgg Map.empty [] @?= Map.empty

  , testCase "single event creates one row" $ do
      let evt = mkEvent localhost localhost (HostPort 0) (HostPort 0) ICMP Ingress (PacketBytes 64)
          m   = updateAgg Map.empty [evt]
      Map.size m @?= 1
      let [row] = Map.elems m
      aggSrcPort row   @?= HostPort 0
      aggDstPort row   @?= HostPort 0
      aggPktCount row  @?= 1
      aggByteCount row @?= 64

  , testCase "two identical-flow events merge" $ do
      let evt1 = mkEvent localhost localhost (HostPort 443) (HostPort 12345) TCP Ingress (PacketBytes 100)
          evt2 = mkEvent localhost localhost (HostPort 443) (HostPort 12345) TCP Ingress (PacketBytes 200)
          m    = updateAgg Map.empty [evt1, evt2]
      Map.size m @?= 1
      let [row] = Map.elems m
      aggPktCount row  @?= 2
      aggByteCount row @?= 300

  , testCase "same IPs but different ports stay separate" $ do
      let evt1 = mkEvent localhost localhost (HostPort 443) (HostPort 12345) TCP Ingress (PacketBytes 100)
          evt2 = mkEvent localhost localhost (HostPort 443) (HostPort 23456) TCP Ingress (PacketBytes 200)
          m    = updateAgg Map.empty [evt1, evt2]
      Map.size m @?= 2

  , testCase "different flows stay separate" $ do
      let dst2 = ip 10 0 0 1
          evt1 = mkEvent localhost localhost (HostPort 443) (HostPort 12345) TCP Ingress (PacketBytes 100)
          evt2 = mkEvent localhost dst2      (HostPort 443) (HostPort 12345) TCP Ingress (PacketBytes 200)
          m    = updateAgg Map.empty [evt1, evt2]
      Map.size m @?= 2

  , testCase "direction distinguishes flows" $ do
      let evt1 = mkEvent localhost localhost (HostPort 443) (HostPort 12345) TCP Ingress (PacketBytes 50)
          evt2 = mkEvent localhost localhost (HostPort 443) (HostPort 12345) TCP Egress  (PacketBytes 50)
          m    = updateAgg Map.empty [evt1, evt2]
      Map.size m @?= 2

  , testCase "protocol distinguishes flows" $ do
      let evt1 = mkEvent localhost localhost (HostPort 443) (HostPort 12345) TCP  Ingress (PacketBytes 50)
          evt2 = mkEvent localhost localhost (HostPort 443) (HostPort 12345) UDP  Ingress (PacketBytes 50)
          evt3 = mkEvent localhost localhost (HostPort 0)   (HostPort 0)     ICMP Ingress (PacketBytes 50)
          m    = updateAgg Map.empty [evt1, evt2, evt3]
      Map.size m @?= 3

  , testCase "non-TCP/UDP events aggregate under port 0" $ do
      let evt1 = mkEvent localhost localhost (HostPort 0) (HostPort 0) ICMP Ingress (PacketBytes 10)
          evt2 = mkEvent localhost localhost (HostPort 0) (HostPort 0) ICMP Ingress (PacketBytes 20)
          m    = updateAgg Map.empty [evt1, evt2]
      Map.size m @?= 1
      let [row] = Map.elems m
      aggSrcPort row   @?= HostPort 0
      aggDstPort row   @?= HostPort 0
      aggPktCount row  @?= 2
      aggByteCount row @?= 30

  , testCase "incremental aggregation across batches" $ do
      let evt1 = mkEvent localhost localhost (HostPort 443) (HostPort 12345) TCP Ingress (PacketBytes 100)
          evt2 = mkEvent localhost localhost (HostPort 443) (HostPort 12345) TCP Ingress (PacketBytes 200)
          m1   = updateAgg Map.empty [evt1]
          m2   = updateAgg m1 [evt2]
      Map.size m2 @?= 1
      let [row] = Map.elems m2
      aggPktCount row  @?= 2
      aggByteCount row @?= 300

  , testCase "large batch (1000 events)" $ do
      let evts = [ mkEvent localhost localhost (HostPort 443) (HostPort 12345) TCP Ingress (PacketBytes (fromIntegral i))
                  | i <- [1..1000 :: Int] ]
          m    = updateAgg Map.empty evts
      Map.size m @?= 1
      let [row] = Map.elems m
      aggPktCount row  @?= 1000
      aggByteCount row @?= 500500
  ]

aggRowKeyTests :: TestTree
aggRowKeyTests = testGroup "aggRowKey"
  [ testCase "extracts correct key" $ do
      let row = AggRow
            { aggSrcIp     = localhost
            , aggDstIp     = ip 10 0 0 1
            , aggSrcPort   = HostPort 443
            , aggDstPort   = HostPort 12345
            , aggProtocol  = UDP
            , aggDirection = Egress
            , aggPktCount  = 42
            , aggByteCount = 12345
            }
      aggRowKey row @?= AggKey
        { keySrcIp     = localhost
        , keyDstIp     = ip 10 0 0 1
        , keySrcPort   = HostPort 443
        , keyDstPort   = HostPort 12345
        , keyProtocol  = UDP
        , keyDirection = Egress
        }

  , testCase "counters do not affect key" $ do
      let row1 = AggRow localhost localhost (HostPort 443) (HostPort 12345) TCP Ingress 1 100
          row2 = AggRow localhost localhost (HostPort 443) (HostPort 12345) TCP Ingress 999 999999
      aggRowKey row1 @?= aggRowKey row2
  ]
