{-# LANGUAGE CApiFFI                  #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MagicHash                #-}
{-# LANGUAGE PatternSynonyms          #-}
{-# LANGUAGE ViewPatterns             #-}

module FFI
  ( Arena
  , TimestampNs(..)
  , IPv4(..)
  , Port(..)
  , pattern HostPort
  , portToHost
  , PacketBytes(..)
  , NetEvent(..)
  , RawBatch(..)
  , Direction(..)
  , Protocol(..)
  , withArena
  , monitorInit
  , monitorPoll
  , monitorCleanup
  , arenaReset
  , arenaUsed
  , rawTimestampNs
  , rawSrcIp
  , rawDstIp
  , rawSrcPort
  , rawDstPort
  , rawPktLen
  , rawProtocol
  , rawDirection
  , ipToString
  , toProtocol
  , fromProtocol
  , toDirection
  , fromDirection
  ) where

import Control.Exception (bracket, throwIO)
import Control.Monad (when)
import Data.List (intercalate)
import Data.Word
import Foreign
import Foreign.C
import GHC.Exts
  ( Int (I#)
  , indexWord8OffAddr#
  , indexWord16OffAddr#
  , indexWord32OffAddr#
  , indexWord64OffAddr#
  )
import GHC.Ptr (Ptr (Ptr))
import GHC.Word (Word8 (W8#), Word16 (W16#), Word32 (W32#), Word64 (W64#))
import System.IO.Error (mkIOError, userErrorType)

-- | Opaque arena type. We only ever pass @Ptr Arena@ through FFI.
data Arena

newtype TimestampNs = TimestampNs { unTimestampNs :: Word64 }
  deriving (Eq, Ord, Storable)

instance Show TimestampNs where
  show (TimestampNs ns) = show ns

newtype IPv4 = IPv4 { unIPv4 :: Word32 }
  deriving (Eq, Ord, Storable)

instance Show IPv4 where
  show = ipToString

newtype Port = Port { unPort :: Word16 }
  deriving (Eq, Ord, Storable)

instance Show Port where
  show = show . portToHost

newtype PacketBytes = PacketBytes { unPacketBytes :: Word32 }
  deriving (Eq, Ord, Storable)

instance Show PacketBytes where
  show (PacketBytes n) = show n

{-# INLINE portToHost #-}
portToHost :: Port -> Word16
portToHost (Port p) = byteSwap16 p

{-# INLINE hostToPort #-}
hostToPort :: Word16 -> Port
hostToPort = Port . byteSwap16

pattern HostPort :: Word16 -> Port
pattern HostPort p <- (portToHost -> p)
  where
    HostPort p = hostToPort p

{-# COMPLETE HostPort #-}

data Direction = Ingress | Egress
  deriving (Show, Eq, Ord, Enum, Bounded)

data Protocol = TCP | UDP | ICMP | OtherProto !Word8
  deriving (Show, Eq, Ord)

data NetEvent = NetEvent
  { evTimestampNs :: {-# UNPACK #-} !TimestampNs
  , evSrcIp       :: {-# UNPACK #-} !IPv4
  , evDstIp       :: {-# UNPACK #-} !IPv4
  , evSrcPort     :: {-# UNPACK #-} !Port
  , evDstPort     :: {-# UNPACK #-} !Port
  , evPktLen      :: {-# UNPACK #-} !PacketBytes
  , evProtocol    :: !Protocol
  , evDirection   :: !Direction
  } deriving (Show, Eq)

-- | Raw batch of contiguous @struct net_event@ records living in the arena.
--
-- The pointer remains valid until the next 'arenaReset' on the same arena.
-- Consumers must finish reading the batch before polling again.
data RawBatch = RawBatch
  { rawPtr         :: !(Ptr NetEvent)
  , rawCount       :: {-# UNPACK #-} !Int
  }

-- | Storable instance matching the C @struct net_event@ layout (32 bytes).
--
-- Offsets:
--   0: timestamp_ns  (Word64)
--   8: src_ip        (Word32)
--  12: dst_ip        (Word32)
--  16: src_port      (Word16)
--  18: dst_port      (Word16)
--  20: pkt_len       (Word32)
--  24: protocol      (Word8)
--  25: direction     (Word8)
--  26: _pad[2]       (2x Word8)
instance Storable NetEvent where
  sizeOf    _ = 32
  alignment _ = 8

  peek ptr = do
    ts    <- peekByteOff ptr 0
    sip   <- peekByteOff ptr 8
    dip   <- peekByteOff ptr 12
    sport <- peekByteOff ptr 16
    dport <- peekByteOff ptr 18
    plen  <- peekByteOff ptr 20
    proto <- peekByteOff ptr 24 :: IO Word8
    dir   <- peekByteOff ptr 25 :: IO Word8
    pure $ NetEvent ts sip dip sport dport plen (toProtocol proto) (toDirection dir)

  poke ptr (NetEvent ts sip dip sport dport plen proto dir) = do
    pokeByteOff ptr 0  ts
    pokeByteOff ptr 8  sip
    pokeByteOff ptr 12 dip
    pokeByteOff ptr 16 sport
    pokeByteOff ptr 18 dport
    pokeByteOff ptr 20 plen
    pokeByteOff ptr 24 (fromProtocol proto)
    pokeByteOff ptr 25 (fromDirection dir)
    pokeByteOff ptr 26 (0 :: Word8)
    pokeByteOff ptr 27 (0 :: Word8)

{-# INLINE toProtocol #-}
toProtocol :: Word8 -> Protocol
toProtocol 1  = ICMP
toProtocol 6  = TCP
toProtocol 17 = UDP
toProtocol n  = OtherProto n

{-# INLINE fromProtocol #-}
fromProtocol :: Protocol -> Word8
fromProtocol ICMP           = 1
fromProtocol TCP            = 6
fromProtocol UDP            = 17
fromProtocol (OtherProto n) = n

{-# INLINE toDirection #-}
toDirection :: Word8 -> Direction
toDirection 0 = Ingress
toDirection _ = Egress

{-# INLINE fromDirection #-}
fromDirection :: Direction -> Word8
fromDirection Ingress = 0
fromDirection Egress  = 1

-- | Convert network-byte-order IPv4 to "a.b.c.d" string.
ipToString :: IPv4 -> String
ipToString (IPv4 ip) = intercalate "."
  [ show  (ip           .&. 0xFF)
  , show ((ip `shiftR`  8) .&. 0xFF)
  , show ((ip `shiftR` 16) .&. 0xFF)
  , show ((ip `shiftR` 24) .&. 0xFF)
  ]

{-# INLINE rawTimestampNs #-}
rawTimestampNs :: RawBatch -> Int -> TimestampNs
rawTimestampNs (RawBatch ptr _) i = TimestampNs (indexWord64OffPtr ptr (i * 4))

{-# INLINE rawSrcIp #-}
rawSrcIp :: RawBatch -> Int -> IPv4
rawSrcIp (RawBatch ptr _) i = IPv4 (indexWord32OffPtr ptr (i * 8 + 2))

{-# INLINE rawDstIp #-}
rawDstIp :: RawBatch -> Int -> IPv4
rawDstIp (RawBatch ptr _) i = IPv4 (indexWord32OffPtr ptr (i * 8 + 3))

{-# INLINE rawSrcPort #-}
rawSrcPort :: RawBatch -> Int -> Port
rawSrcPort (RawBatch ptr _) i = Port (indexWord16OffPtr ptr (i * 16 + 8))

{-# INLINE rawDstPort #-}
rawDstPort :: RawBatch -> Int -> Port
rawDstPort (RawBatch ptr _) i = Port (indexWord16OffPtr ptr (i * 16 + 9))

{-# INLINE rawPktLen #-}
rawPktLen :: RawBatch -> Int -> PacketBytes
rawPktLen (RawBatch ptr _) i = PacketBytes (indexWord32OffPtr ptr (i * 8 + 5))

{-# INLINE rawProtocol #-}
rawProtocol :: RawBatch -> Int -> Protocol
rawProtocol batch i = toProtocol (indexWord8OffPtr (rawPtr batch) (i * 32 + 24))

{-# INLINE rawDirection #-}
rawDirection :: RawBatch -> Int -> Direction
rawDirection batch i = toDirection (indexWord8OffPtr (rawPtr batch) (i * 32 + 25))

{-# INLINE indexWord8OffPtr #-}
indexWord8OffPtr :: Ptr a -> Int -> Word8
indexWord8OffPtr (Ptr addr#) (I# off#) = W8# (indexWord8OffAddr# addr# off#)

{-# INLINE indexWord16OffPtr #-}
indexWord16OffPtr :: Ptr a -> Int -> Word16
indexWord16OffPtr (Ptr addr#) (I# off#) = W16# (indexWord16OffAddr# addr# off#)

{-# INLINE indexWord32OffPtr #-}
indexWord32OffPtr :: Ptr a -> Int -> Word32
indexWord32OffPtr (Ptr addr#) (I# off#) = W32# (indexWord32OffAddr# addr# off#)

{-# INLINE indexWord64OffPtr #-}
indexWord64OffPtr :: Ptr a -> Int -> Word64
indexWord64OffPtr (Ptr addr#) (I# off#) = W64# (indexWord64OffAddr# addr# off#)

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
  when (ret /= 0) $
    throwIO $ mkIOError userErrorType
                 ("monitor_init failed on " ++ ifname ++ ": error " ++ show ret)
                 Nothing Nothing


-- | Poll for events, exposing the arena-backed batch directly.
--
-- The returned batch is only valid until the next 'arenaReset' on the same
-- arena.
monitorPoll :: Ptr Arena -> Int -> IO RawBatch
monitorPoll arena timeoutMs = alloca $ \countPtr -> do
  evtPtr <- c_monitorPoll arena (fromIntegral timeoutMs) countPtr
  count  <- fromIntegral <$> peek countPtr
  if count <= 0 || evtPtr == nullPtr
    then pure (RawBatch nullPtr 0)
    else pure (RawBatch evtPtr count)

-- | Detach TC hooks and close BPF object. Safe to call multiple times.
monitorCleanup :: IO ()
monitorCleanup = c_monitorCleanup

-- | Reset arena bump pointer to start. Invalidates all prior event pointers.
arenaReset :: Ptr Arena -> IO ()
arenaReset = c_arenaReset

-- | Return the number of bytes currently used in the arena.
arenaUsed :: Ptr Arena -> IO Word64
arenaUsed = c_arenaUsed
