{-# LANGUAGE BangPatterns #-}
{-# OPTIONS_GHC -Wno-deprecations #-}  -- S.scan is deprecated in favor of S.scanl (Scanl type)
module Stream
  ( AggKey(..)
  , AggRow(..)
  , aggRowKey
  , eventStream
  , aggregateStream
  , updateAgg
  ) where

import Control.Monad (when)
import FFI

import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Foreign (Ptr)
import Streamly.Data.Fold qualified as F
import Streamly.Data.Stream (Stream)
import Streamly.Data.Stream qualified as S

-- | Aggregation key for one flow.
data AggKey = AggKey
  { keySrcIp     :: {-# UNPACK #-} !IPv4
  , keyDstIp     :: {-# UNPACK #-} !IPv4
  , keySrcPort   :: {-# UNPACK #-} !Port
  , keyDstPort   :: {-# UNPACK #-} !Port
  , keyProtocol  :: !Protocol
  , keyDirection :: !Direction
  } deriving (Show, Eq, Ord)

-- | Accumulated counters for one flow.
data AggRow = AggRow
  { aggSrcIp     :: {-# UNPACK #-} !IPv4
  , aggDstIp     :: {-# UNPACK #-} !IPv4
  , aggSrcPort   :: {-# UNPACK #-} !Port
  , aggDstPort   :: {-# UNPACK #-} !Port
  , aggProtocol  :: !Protocol
  , aggDirection :: !Direction
  , aggPktCount  :: {-# UNPACK #-} !Int
  , aggByteCount :: {-# UNPACK #-} !Int
  } deriving (Show, Eq)

aggRowKey :: AggRow -> AggKey
aggRowKey r = AggKey
  { keySrcIp     = aggSrcIp r
  , keyDstIp     = aggDstIp r
  , keySrcPort   = aggSrcPort r
  , keyDstPort   = aggDstPort r
  , keyProtocol  = aggProtocol r
  , keyDirection = aggDirection r
  }

-- | Infinite stream of raw event batches from the ring buffer.
--
-- The arena is reset immediately before the next poll, so each yielded batch
-- remains valid for the duration of downstream processing of that element.
eventStream :: Ptr Arena -> Int -> Stream IO RawBatch
eventStream arena timeoutMs = S.unfoldrM step False
  where
    step shouldReset = do
      when shouldReset (arenaReset arena)
      batch <- monitorPoll arena timeoutMs
      pure (Just (batch, True))

-- | Fold batches into a running aggregation map.
aggregateStream :: Stream IO RawBatch -> Stream IO (Map AggKey AggRow)
aggregateStream = S.scan (F.foldl' updateAggRaw Map.empty)

-- | Pure aggregation step: fold a batch of events into an existing map.
-- Exported for testing without IO.
updateAgg :: Map AggKey AggRow -> [NetEvent] -> Map AggKey AggRow
updateAgg = foldl' updateAggEvent

updateAggRaw :: Map AggKey AggRow -> RawBatch -> Map AggKey AggRow
updateAggRaw !m batch = go 0 m
  where
    n = rawCount batch

    go !i !acc
      | i >= n = acc
      | otherwise =
          go (i + 1) $
            insertAgg
              (rawSrcIp batch i)
              (rawDstIp batch i)
              (rawSrcPort batch i)
              (rawDstPort batch i)
              (rawProtocol batch i)
              (rawDirection batch i)
              (rawPktLen batch i)
              acc

updateAggEvent :: Map AggKey AggRow -> NetEvent -> Map AggKey AggRow
updateAggEvent !m evt =
  insertAgg
    (evSrcIp evt)
    (evDstIp evt)
    (evSrcPort evt)
    (evDstPort evt)
    (evProtocol evt)
    (evDirection evt)
    (evPktLen evt)
    m

insertAgg
  :: IPv4
  -> IPv4
  -> Port
  -> Port
  -> Protocol
  -> Direction
  -> PacketBytes
  -> Map AggKey AggRow
  -> Map AggKey AggRow
insertAgg srcIp dstIp srcPort dstPort proto dir pktLen =
  Map.insertWith mergeRow key row
  where
    key = AggKey
      { keySrcIp     = srcIp
      , keyDstIp     = dstIp
      , keySrcPort   = srcPort
      , keyDstPort   = dstPort
      , keyProtocol  = proto
      , keyDirection = dir
      }
    row = AggRow
      { aggSrcIp     = srcIp
      , aggDstIp     = dstIp
      , aggSrcPort   = srcPort
      , aggDstPort   = dstPort
      , aggProtocol  = proto
      , aggDirection = dir
      , aggPktCount  = 1
      , aggByteCount = fromIntegral (unPacketBytes pktLen)
      }

mergeRow :: AggRow -> AggRow -> AggRow
mergeRow new old = old
  { aggPktCount  = aggPktCount old + aggPktCount new
  , aggByteCount = aggByteCount old + aggByteCount new
  }
