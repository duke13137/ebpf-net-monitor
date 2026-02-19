module Stream
  ( AggKey
  , AggRow(..)
  , aggRowKey
  , eventStream
  , aggregateStream
  , updateAgg
  ) where

import FFI

import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Word (Word32)
import Foreign (Ptr)
import Streamly.Data.Stream (Stream)
import qualified Streamly.Data.Fold as F
import qualified Streamly.Data.Stream as S

-- | Aggregation key: (src_ip, dst_ip, protocol, direction).
type AggKey = (Word32, Word32, Protocol, Direction)

-- | Accumulated counters for one flow.
data AggRow = AggRow
  { aggSrcIp     :: {-# UNPACK #-} !Word32
  , aggDstIp     :: {-# UNPACK #-} !Word32
  , aggProtocol  :: !Protocol
  , aggDirection :: !Direction
  , aggPktCount  :: {-# UNPACK #-} !Int
  , aggByteCount :: {-# UNPACK #-} !Int
  } deriving (Show, Eq)

aggRowKey :: AggRow -> AggKey
aggRowKey r = (aggSrcIp r, aggDstIp r, aggProtocol r, aggDirection r)

-- | Infinite stream of event batches from the ring buffer.
-- Each element is one poll cycle's worth of 'NetEvent's.
-- The arena is reset after each batch so pointers don't escape.
eventStream :: Ptr Arena -> Int -> Stream IO [NetEvent]
eventStream arena timeoutMs = S.repeatM pollAndReset
  where
    pollAndReset = do
      evts <- monitorPoll arena timeoutMs
      arenaReset arena
      pure evts

-- | Fold batches into a running aggregation map.
aggregateStream :: Stream IO [NetEvent] -> Stream IO (Map AggKey AggRow)
aggregateStream = S.postscan (F.foldl' step Map.empty)
  where
    step acc evts = foldl updateOne acc evts

    updateOne m evt =
      let key = (evSrcIp evt, evDstIp evt, evProtocol evt, evDirection evt)
          row = AggRow
            { aggSrcIp     = evSrcIp evt
            , aggDstIp     = evDstIp evt
            , aggProtocol  = evProtocol evt
            , aggDirection = evDirection evt
            , aggPktCount  = 1
            , aggByteCount = fromIntegral (evPktLen evt)
            }
      in Map.insertWith mergeRow key row m

    mergeRow new old = old
      { aggPktCount  = aggPktCount old + aggPktCount new
      , aggByteCount = aggByteCount old + aggByteCount new
      }

-- | Pure aggregation step: fold a batch of events into an existing map.
-- Exported for testing without IO.
updateAgg :: Map AggKey AggRow -> [NetEvent] -> Map AggKey AggRow
updateAgg = foldl go
  where
    go m evt =
      let key = (evSrcIp evt, evDstIp evt, evProtocol evt, evDirection evt)
          row = AggRow
            { aggSrcIp     = evSrcIp evt
            , aggDstIp     = evDstIp evt
            , aggProtocol  = evProtocol evt
            , aggDirection = evDirection evt
            , aggPktCount  = 1
            , aggByteCount = fromIntegral (evPktLen evt)
            }
      in Map.insertWith merge key row m

    merge new old = old
      { aggPktCount  = aggPktCount old + aggPktCount new
      , aggByteCount = aggByteCount old + aggByteCount new
      }
