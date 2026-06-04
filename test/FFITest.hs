{-# LANGUAGE ScopedTypeVariables #-}

module FFITest (tests) where

import FFI

import Data.Word
import Foreign
import Test.QuickCheck (Gen, choose, elements, ioProperty, suchThat)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, testCase, (@?=))
import Test.Tasty.QuickCheck (Arbitrary (..), testProperty)

tests :: TestTree
tests = testGroup "FFI"
  [ storableTests
  , rawBatchTests
  , ipTests
  , protocolTests
  , directionTests
  , arenaFFITests
  ]

-- -------------------------------------------------------------------
-- Storable roundtrip
-- -------------------------------------------------------------------

sampleEvent :: NetEvent
sampleEvent = NetEvent
  { evTimestampNs = TimestampNs 1234567890
  , evSrcIp       = IPv4 0x0100007F  -- 127.0.0.1 in network byte order
  , evDstIp       = IPv4 0x0200007F  -- 127.0.0.2
  , evSrcPort     = HostPort 443
  , evDstPort     = HostPort 12345
  , evPktLen      = PacketBytes 64
  , evProtocol    = TCP
  , evDirection   = Ingress
  }

storableTests :: TestTree
storableTests = testGroup "Storable NetEvent"
  [ testCase "sizeOf is 32" $
      sizeOf (undefined :: NetEvent) @?= 32

  , testCase "alignment is 8" $
      alignment (undefined :: NetEvent) @?= 8

  , testCase "poke then peek roundtrips" $ do
      alloca $ \ptr -> do
        poke ptr sampleEvent
        got <- peek ptr
        got @?= sampleEvent

  , testCase "peek reads correct offsets" $ do
      allocaBytes 32 $ \ptr -> do
        -- Write raw bytes matching sampleEvent
        pokeByteOff ptr 0  (1234567890 :: Word64)
        pokeByteOff ptr 8  (0x0100007F :: Word32)
        pokeByteOff ptr 12 (0x0200007F :: Word32)
        pokeByteOff ptr 16 (byteSwap16 443 :: Word16)
        pokeByteOff ptr 18 (byteSwap16 12345 :: Word16)
        pokeByteOff ptr 20 (64 :: Word32)
        pokeByteOff ptr 24 (6 :: Word8)   -- TCP
        pokeByteOff ptr 25 (0 :: Word8)   -- Ingress
        pokeByteOff ptr 26 (0 :: Word8)
        pokeByteOff ptr 27 (0 :: Word8)
        got <- peek (castPtr ptr :: Ptr NetEvent)
        evTimestampNs got @?= TimestampNs 1234567890
        evSrcIp got       @?= IPv4 0x0100007F
        evDstIp got       @?= IPv4 0x0200007F
        evSrcPort got     @?= HostPort 443
        evDstPort got     @?= HostPort 12345
        evPktLen got      @?= PacketBytes 64
        evProtocol got    @?= TCP
        evDirection got   @?= Ingress

  , testCase "poke zeroes padding bytes" $ do
      allocaBytes 32 $ \ptr -> do
        _ <- memset (castPtr ptr) 0xFF 32
        poke (castPtr ptr :: Ptr NetEvent) sampleEvent
        pad0 <- peekByteOff ptr 26 :: IO Word8
        pad1 <- peekByteOff ptr 27 :: IO Word8
        pad0 @?= 0
        pad1 @?= 0

  , testProperty "arbitrary roundtrip" $ \(evt :: NetEvent) ->
      ioProperty $ alloca $ \ptr -> do
        poke ptr evt
        got <- peek ptr
        pure (got == evt)
  ]

rawBatchTests :: TestTree
rawBatchTests = testGroup "RawBatch"
  [ testCase "count is preserved" $
      alloca $ \ptr -> do
        poke ptr sampleEvent
        rawCount (RawBatch ptr 1) @?= 1

  , testCase "field accessors read raw arena layout" $
      allocaArray 2 $ \ptr -> do
        let sampleEvent2 = sampleEvent
              { evTimestampNs = TimestampNs 99
              , evSrcIp       = IPv4 0x04030201
              , evDstIp       = IPv4 0x08070605
              , evSrcPort     = HostPort 80
              , evDstPort     = HostPort 443
              , evPktLen      = PacketBytes 1500
              , evProtocol    = UDP
              , evDirection   = Egress
              }
            batch = RawBatch ptr 2
        pokeElemOff ptr 0 sampleEvent
        pokeElemOff ptr 1 sampleEvent2

        rawTimestampNs batch 0 @?= TimestampNs 1234567890
        rawSrcIp       batch 0 @?= IPv4 0x0100007F
        rawDstIp       batch 0 @?= IPv4 0x0200007F
        rawSrcPort     batch 0 @?= HostPort 443
        rawDstPort     batch 0 @?= HostPort 12345
        rawPktLen      batch 0 @?= PacketBytes 64
        rawProtocol    batch 0 @?= TCP
        rawDirection   batch 0 @?= Ingress

        rawTimestampNs batch 1 @?= TimestampNs 99
        rawSrcIp       batch 1 @?= IPv4 0x04030201
        rawDstIp       batch 1 @?= IPv4 0x08070605
        rawSrcPort     batch 1 @?= HostPort 80
        rawDstPort     batch 1 @?= HostPort 443
        rawPktLen      batch 1 @?= PacketBytes 1500
        rawProtocol    batch 1 @?= UDP
        rawDirection   batch 1 @?= Egress
  ]

foreign import ccall unsafe "string.h memset"
  memset :: Ptr a -> Int -> Word64 -> IO (Ptr a)

instance Arbitrary NetEvent where
  arbitrary = NetEvent
    <$> (TimestampNs <$> arbitrary)
    <*> (IPv4 <$> arbitrary)
    <*> (IPv4 <$> arbitrary)
    <*> arbitraryPort
    <*> arbitraryPort
    <*> (PacketBytes <$> arbitrary)
    <*> arbitraryProtocol
    <*> arbitraryDirection

arbitraryPort :: Gen Port
arbitraryPort = HostPort <$> arbitrary

arbitraryProtocol :: Gen Protocol
arbitraryProtocol = do
  tag <- choose (0 :: Int, 3)
  case tag of
    0 -> pure TCP
    1 -> pure UDP
    2 -> pure ICMP
    _ -> OtherProto <$> (choose (0, 255) `suchThat` (\n -> n /= 1 && n /= 6 && n /= 17))

arbitraryDirection :: Gen Direction
arbitraryDirection = elements [Ingress, Egress]

-- -------------------------------------------------------------------
-- IP string conversion
-- -------------------------------------------------------------------

ipTests :: TestTree
ipTests = testGroup "ipToString"
  [ testCase "loopback" $
      ipToString (IPv4 0x0100007F) @?= "127.0.0.1"

  , testCase "zeros" $
      ipToString (IPv4 0x00000000) @?= "0.0.0.0"

  , testCase "broadcast" $
      ipToString (IPv4 0xFFFFFFFF) @?= "255.255.255.255"

  , testCase "10.0.0.1 (network order)" $
      ipToString (IPv4 0x0100000A) @?= "10.0.0.1"

  , testCase "192.168.1.100 (network order)" $
      ipToString (IPv4 0x6401A8C0) @?= "192.168.1.100"
  ]

protocolTests :: TestTree
protocolTests = testGroup "Protocol"
  [ testCase "TCP roundtrip"  $ toProtocol (fromProtocol TCP)  @?= TCP
  , testCase "UDP roundtrip"  $ toProtocol (fromProtocol UDP)  @?= UDP
  , testCase "ICMP roundtrip" $ toProtocol (fromProtocol ICMP) @?= ICMP
  , testCase "OtherProto 47"  $ toProtocol 47 @?= OtherProto 47
  , testCase "OtherProto roundtrip" $
      toProtocol (fromProtocol (OtherProto 132)) @?= OtherProto 132
  ]

directionTests :: TestTree
directionTests = testGroup "Direction"
  [ testCase "Ingress = 0" $ fromDirection Ingress @?= 0
  , testCase "Egress = 1"  $ fromDirection Egress  @?= 1
  , testCase "0 -> Ingress" $ toDirection 0 @?= Ingress
  , testCase "1 -> Egress"  $ toDirection 1 @?= Egress
  , testCase "255 -> Egress (any nonzero)" $ toDirection 255 @?= Egress
  ]

arenaFFITests :: TestTree
arenaFFITests = testGroup "Arena FFI"
  [ testCase "init and release" $
      withArena (1024 * 1024) $ \arena -> do
        assertBool "arena pointer is non-null" (arena /= nullPtr)

  , testCase "used starts at 0" $
      withArena (1024 * 1024) $ \arena -> do
        used <- arenaUsed arena
        used @?= 0

  , testCase "reset returns used to 0" $
      withArena (1024 * 1024) $ \arena -> do
        arenaReset arena
        used <- arenaUsed arena
        used @?= 0
  ]
