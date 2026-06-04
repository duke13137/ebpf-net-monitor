module TUI
  ( AppEvent(..)
  , runTUI
  ) where

import FFI (Direction (..), Port, Protocol (..), ipToString, portToHost)
import Stream (AggKey, AggRow (..))

import Brick hiding (Direction (..))
import Brick.BChan (BChan)
import Brick.Widgets.Border (borderWithLabel)
import Brick.Widgets.Table (renderTable, table)
import Graphics.Vty qualified as Vty
import Graphics.Vty.CrossPlatform qualified as VtyCross

import Data.List (sortBy)
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Ord (Down (..), comparing)


type AppState = Map AggKey AggRow

-- | Custom event pushed from the Streamly pipeline via BChan.
newtype AppEvent = NewSnapshot AppState

-- | Widget name type. Single viewport, no focus ring needed.
data Name = MainViewport
  deriving (Eq, Ord, Show)

app :: App AppState AppEvent Name
app = App
  { appDraw         = drawUI
  , appChooseCursor = neverShowCursor
  , appHandleEvent  = handleEvent
  , appStartEvent   = pure ()
  , appAttrMap      = const $ attrMap Vty.defAttr
      [ (attrName "header", Vty.withStyle Vty.defAttr Vty.bold) ]
  }

drawUI :: AppState -> [Widget Name]
drawUI st =
  [ borderWithLabel (str " ebpf-net-monitor ") $
      renderTable tbl
  ]
  where
    rows     = sortBy (comparing (Down . aggByteCount)) (Map.elems st)
    header   = map str ["Src IP", "Src Port", "Dst IP", "Dst Port", "Proto", "Dir", "Packets", "Bytes"]
    dataRows = map rowWidgets (take 50 rows)
    tbl      = table (header : dataRows)

    rowWidgets r =
      [ str (ipToString (aggSrcIp r))
      , str (showPort (aggSrcPort r))
      , str (ipToString (aggDstIp r))
      , str (showPort (aggDstPort r))
      , str (showProto (aggProtocol r))
      , str (showDir (aggDirection r))
      , str (show (aggPktCount r))
      , str (show (aggByteCount r))
      ]

showProto :: Protocol -> String
showProto TCP            = "TCP"
showProto UDP            = "UDP"
showProto ICMP           = "ICMP"
showProto (OtherProto n) = show n

showDir :: Direction -> String
showDir Ingress = "IN"
showDir Egress  = "OUT"

showPort :: Port -> String
showPort = show . portToHost

handleEvent :: BrickEvent Name AppEvent -> EventM Name AppState ()
handleEvent (VtyEvent (Vty.EvKey (Vty.KChar 'q') [])) = halt
handleEvent (VtyEvent (Vty.EvKey Vty.KEsc []))        = halt
handleEvent (AppEvent (NewSnapshot snap))             = put snap
handleEvent _                                         = pure ()

-- | Run the brick TUI. Blocks until the user quits ('q' or Esc).
-- Reads 'AppEvent's from the 'BChan' (fed by the Streamly pipeline).
runTUI :: BChan AppEvent -> IO ()
runTUI chan = do
  let buildVty = VtyCross.mkVty Vty.defaultConfig
  initialVty <- buildVty
  _finalState <- customMain initialVty buildVty (Just chan) app Map.empty
  pure ()
