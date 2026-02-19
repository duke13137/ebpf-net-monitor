{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ForeignFunctionInterface #-}

module FFI
  ( Arena
  , NetEvent(..)
  , Direction(..)
  , Protocol(..)
  , withArena
  , monitorInit
  , monitorPoll
  , monitorCleanup
  , arenaReset
  , arenaUsed
  , ipToString
  , toProtocol
  , fromProtocol
  , toDirection
  , fromDirection
  ) where

import Control.Exception (bracket, throwIO)
import Data.Bits (shiftR, (.&.))
import Data.List (intercalate)
import Data.Word
import Foreign
import Foreign.C
import System.IO.Error (mkIOError, userErrorType)

-- | Opaque arena type. We only ever pass @Ptr Arena@ through FFI.
data Arena

data Direction = Ingress | Egress
  deriving (Show, Eq, Ord, Enum, Bounded)

data Protocol = TCP | UDP | ICMP | OtherProto !Word8
  deriving (Show, Eq, Ord)

data NetEvent = NetEvent
  { evTimestampNs :: {-# UNPACK #-} !Word64
  , evSrcIp       :: {-# UNPACK #-} !Word32
  , evDstIp       :: {-# UNPACK #-} !Word32
  , evPktLen      :: {-# UNPACK #-} !Word32
  , evProtocol    :: !Protocol
  , evDirection   :: !Direction
  } deriving (Show, Eq)

-- | Storable instance matching the C @struct net_event@ layout (24 bytes).
--
-- Offsets:
--   0: timestamp_ns  (Word64)
--   8: src_ip        (Word32)
--  12: dst_ip        (Word32)
--  16: pkt_len       (Word32)
--  20: protocol      (Word8)
--  21: direction     (Word8)
--  22: _pad[2]       (2x Word8)
instance Storable NetEvent where
  sizeOf    _ = 24
  alignment _ = 8

  peek ptr = do
    ts    <- peekByteOff ptr 0
    sip   <- peekByteOff ptr 8
    dip   <- peekByteOff ptr 12
    plen  <- peekByteOff ptr 16
    proto <- peekByteOff ptr 20 :: IO Word8
    dir   <- peekByteOff ptr 21 :: IO Word8
    pure $ NetEvent ts sip dip plen (toProtocol proto) (toDirection dir)

  poke ptr (NetEvent ts sip dip plen proto dir) = do
    pokeByteOff ptr 0  ts
    pokeByteOff ptr 8  sip
    pokeByteOff ptr 12 dip
    pokeByteOff ptr 16 plen
    pokeByteOff ptr 20 (fromProtocol proto)
    pokeByteOff ptr 21 (fromDirection dir)
    pokeByteOff ptr 22 (0 :: Word8)
    pokeByteOff ptr 23 (0 :: Word8)

toProtocol :: Word8 -> Protocol
toProtocol 1  = ICMP
toProtocol 6  = TCP
toProtocol 17 = UDP
toProtocol n  = OtherProto n

fromProtocol :: Protocol -> Word8
fromProtocol ICMP           = 1
fromProtocol TCP            = 6
fromProtocol UDP            = 17
fromProtocol (OtherProto n) = n

toDirection :: Word8 -> Direction
toDirection 0 = Ingress
toDirection _ = Egress

fromDirection :: Direction -> Word8
fromDirection Ingress = 0
fromDirection Egress  = 1

-- | Convert network-byte-order IPv4 to "a.b.c.d" string.
ipToString :: Word32 -> String
ipToString ip = intercalate "."
  [ show  (ip           .&. 0xFF)
  , show ((ip `shiftR`  8) .&. 0xFF)
  , show ((ip `shiftR` 16) .&. 0xFF)
  , show ((ip `shiftR` 24) .&. 0xFF)
  ]

-- -------------------------------------------------------------------
-- FFI imports
-- -------------------------------------------------------------------

-- Arena ops: unsafe (non-blocking, < 100ns)
foreign import ccall unsafe "arena_init_ffi"
  c_arenaInit :: Ptr () -> Word64 -> IO (Ptr Arena)

foreign import ccall unsafe "arena_reset_ffi"
  c_arenaReset :: Ptr Arena -> IO ()

foreign import ccall unsafe "arena_release_ffi"
  c_arenaRelease :: Ptr Arena -> IO ()

foreign import ccall unsafe "arena_used_ffi"
  c_arenaUsed :: Ptr Arena -> IO Word64

-- Monitor lifecycle: safe (kernel interaction, may block)
foreign import ccall safe "monitor_init"
  c_monitorInit :: CString -> IO CInt

foreign import ccall safe "monitor_cleanup"
  c_monitorCleanup :: IO ()

-- Poll: safe (blocks up to timeout_ms on ring_buffer__poll)
foreign import ccall safe "monitor_poll"
  c_monitorPoll :: Ptr Arena -> CInt -> Ptr CInt -> IO (Ptr NetEvent)

-- -------------------------------------------------------------------
-- High-level wrappers
-- -------------------------------------------------------------------

-- | Bracket pattern for arena lifecycle.
-- @size@ is the virtual reservation in bytes (physical pages committed on demand).
withArena :: Int -> (Ptr Arena -> IO a) -> IO a
withArena size = bracket acquire c_arenaRelease
  where
    acquire = c_arenaInit nullPtr (fromIntegral size)

-- | Initialize the monitor on the given interface.
-- Throws 'IOError' on failure.
monitorInit :: String -> IO ()
monitorInit ifname = do
  ret <- withCString ifname c_monitorInit
  if ret /= 0
    then throwIO $ mkIOError userErrorType
           ("monitor_init failed on " ++ ifname ++ ": error " ++ show ret)
           Nothing Nothing
    else pure ()

-- | Poll for events, writing them into the arena.
-- Returns list of events. Does NOT reset the arena; caller must call 'arenaReset'.
monitorPoll :: Ptr Arena -> Int -> IO [NetEvent]
monitorPoll arena timeoutMs = alloca $ \countPtr -> do
  evtPtr <- c_monitorPoll arena (fromIntegral timeoutMs) countPtr
  count  <- peek countPtr
  if count <= 0 || evtPtr == nullPtr
    then pure []
    else peekArray (fromIntegral count) evtPtr

-- | Reset arena bump pointer to start. Invalidates all prior event pointers.
arenaReset :: Ptr Arena -> IO ()
arenaReset = c_arenaReset

-- | Return the number of bytes currently used in the arena.
arenaUsed :: Ptr Arena -> IO Word64
arenaUsed = c_arenaUsed
