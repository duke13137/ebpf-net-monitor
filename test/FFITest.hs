{-# LANGUAGE ScopedTypeVariables #-}

module FFITest (tests) where

import FFI

import Data.Word
import Foreign
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, (@?=), assertBool)
import Test.Tasty.QuickCheck (testProperty, Arbitrary(..))
import Test.QuickCheck (Gen, choose, elements, ioProperty)

tests :: TestTree
tests = testGroup "FFI"
  [ storableTests
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
  { evTimestampNs = 1234567890
  , evSrcIp       = 0x0100007F  -- 127.0.0.1 in network byte order
  , evDstIp       = 0x0200007F  -- 127.0.0.2
  , evPktLen      = 64
  , evProtocol    = TCP
  , evDirection   = Ingress
  }

storableTests :: TestTree
storableTests = testGroup "Storable NetEvent"
  [ testCase "sizeOf is 24" $
      sizeOf (undefined :: NetEvent) @?= 24

  , testCase "alignment is 8" $
      alignment (undefined :: NetEvent) @?= 8

  , testCase "poke then peek roundtrips" $ do
      alloca $ \ptr -> do
        poke ptr sampleEvent
        got <- peek ptr
        got @?= sampleEvent

  , testCase "peek reads correct offsets" $ do
      allocaBytes 24 $ \ptr -> do
        -- Write raw bytes matching sampleEvent
        pokeByteOff ptr 0  (1234567890 :: Word64)
        pokeByteOff ptr 8  (0x0100007F :: Word32)
        pokeByteOff ptr 12 (0x0200007F :: Word32)
        pokeByteOff ptr 16 (64 :: Word32)
        pokeByteOff ptr 20 (6 :: Word8)   -- TCP
        pokeByteOff ptr 21 (0 :: Word8)   -- Ingress
        pokeByteOff ptr 22 (0 :: Word8)
        pokeByteOff ptr 23 (0 :: Word8)
        got <- peek (castPtr ptr :: Ptr NetEvent)
        evTimestampNs got @?= 1234567890
        evSrcIp got       @?= 0x0100007F
        evDstIp got       @?= 0x0200007F
        evPktLen got      @?= 64
        evProtocol got    @?= TCP
        evDirection got   @?= Ingress

  , testCase "poke zeroes padding bytes" $ do
      allocaBytes 24 $ \ptr -> do
        -- Fill with 0xFF first
        _ <- memset (castPtr ptr) 0xFF 24
        poke (castPtr ptr :: Ptr NetEvent) sampleEvent
        pad0 <- peekByteOff ptr 22 :: IO Word8
        pad1 <- peekByteOff ptr 23 :: IO Word8
        pad0 @?= 0
        pad1 @?= 0

  , testProperty "arbitrary roundtrip" $ \(evt :: NetEvent) ->
      ioProperty $ alloca $ \ptr -> do
        poke ptr evt
        got <- peek ptr
        pure (got == evt)
  ]

-- Minimal memset via FFI for the padding test
foreign import ccall unsafe "string.h memset"
  memset :: Ptr a -> Int -> Word64 -> IO (Ptr a)

-- -------------------------------------------------------------------
-- Arbitrary instance for QuickCheck
-- -------------------------------------------------------------------

instance Arbitrary NetEvent where
  arbitrary = NetEvent
    <$> arbitrary
    <*> arbitrary
    <*> arbitrary
    <*> arbitrary
    <*> arbitraryProtocol
    <*> arbitraryDirection

arbitraryProtocol :: Gen Protocol
arbitraryProtocol = do
  tag <- choose (0 :: Int, 3)
  case tag of
    0 -> pure TCP
    1 -> pure UDP
    2 -> pure ICMP
    _ -> OtherProto <$> arbitrary

arbitraryDirection :: Gen Direction
arbitraryDirection = elements [Ingress, Egress]

-- -------------------------------------------------------------------
-- IP string conversion
-- -------------------------------------------------------------------

ipTests :: TestTree
ipTests = testGroup "ipToString"
  [ testCase "loopback" $
      ipToString 0x0100007F @?= "127.0.0.1"

  , testCase "zeros" $
      ipToString 0x00000000 @?= "0.0.0.0"

  , testCase "broadcast" $
      ipToString 0xFFFFFFFF @?= "255.255.255.255"

  , testCase "10.0.0.1 (network order)" $
      -- 10.0.0.1 in network byte order = 0x0100000A
      ipToString 0x0100000A @?= "10.0.0.1"

  , testCase "192.168.1.100 (network order)" $
      -- 192.168.1.100 -> bytes: C0.A8.01.64 -> little-endian u32: 0x6401A8C0
      ipToString 0x6401A8C0 @?= "192.168.1.100"
  ]

-- -------------------------------------------------------------------
-- Protocol conversions
-- -------------------------------------------------------------------

protocolTests :: TestTree
protocolTests = testGroup "Protocol"
  [ testCase "TCP roundtrip"  $ toProtocol (fromProtocol TCP)  @?= TCP
  , testCase "UDP roundtrip"  $ toProtocol (fromProtocol UDP)  @?= UDP
  , testCase "ICMP roundtrip" $ toProtocol (fromProtocol ICMP) @?= ICMP
  , testCase "OtherProto 47"  $ toProtocol 47 @?= OtherProto 47
  , testCase "OtherProto roundtrip" $
      toProtocol (fromProtocol (OtherProto 132)) @?= OtherProto 132
  ]

-- -------------------------------------------------------------------
-- Direction conversions
-- -------------------------------------------------------------------

directionTests :: TestTree
directionTests = testGroup "Direction"
  [ testCase "Ingress = 0" $ fromDirection Ingress @?= 0
  , testCase "Egress = 1"  $ fromDirection Egress  @?= 1
  , testCase "0 -> Ingress" $ toDirection 0 @?= Ingress
  , testCase "1 -> Egress"  $ toDirection 1 @?= Egress
  , testCase "255 -> Egress (any nonzero)" $ toDirection 255 @?= Egress
  ]

-- -------------------------------------------------------------------
-- Arena FFI wrappers (non-Linux safe: init/used/reset/release)
-- -------------------------------------------------------------------

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
        -- Poke an event to bump the cursor
        -- (We can't call New from Haskell, but monitor_poll is stubbed on macOS,
        --  so just test that reset is idempotent.)
        arenaReset arena
        used <- arenaUsed arena
        used @?= 0
  ]
