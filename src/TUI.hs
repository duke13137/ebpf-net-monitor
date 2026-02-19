module TUI
  ( AppEvent(..)
  , runTUI
  ) where

import FFI (ipToString, Direction(..), Protocol(..))
import Stream (AggRow(..), AggKey)

import Brick
import Brick.BChan (BChan)
import Brick.Widgets.Table (renderTable, table)
import Brick.Widgets.Border (borderWithLabel)
import qualified Graphics.Vty as Vty
import qualified Graphics.Vty.CrossPlatform as VtyCross

import Data.List (sortBy)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Ord (Down(..), comparing)

-- | Custom event pushed from the Streamly pipeline via BChan.
newtype AppEvent = NewSnapshot (Map AggKey AggRow)

-- | Widget name type. Single viewport, no focus ring needed.
data Name = MainViewport
  deriving (Eq, Ord, Show)

type AppState = Map AggKey AggRow

app :: App AppState AppEvent Name
app = App
  { appDraw         = drawUI
  , appChooseCursor = neverShowCursor
  , appHandleEvent  = handleEvent
  , appStartEvent   = pure ()
  , appAttrMap      = const $ attrMap
      [ (attrName "header", Vty.withStyle Vty.currentAttr Vty.bold) ]
  }

drawUI :: AppState -> [Widget Name]
drawUI st =
  [ borderWithLabel (str " ebpf-net-monitor ") $
      renderTable tbl
  ]
  where
    rows     = sortBy (comparing (Down . aggByteCount)) (Map.elems st)
    header   = map str ["Src IP", "Dst IP", "Proto", "Dir", "Packets", "Bytes"]
    dataRows = map rowWidgets (take 50 rows)
    tbl      = table (header : dataRows)

    rowWidgets r =
      [ str (ipToString (aggSrcIp r))
      , str (ipToString (aggDstIp r))
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

handleEvent :: BrickEvent Name AppEvent -> EventM Name AppState ()
handleEvent (VtyEvent (Vty.EvKey (Vty.KChar 'q') [])) = halt
handleEvent (VtyEvent (Vty.EvKey Vty.KEsc []))         = halt
handleEvent (AppEvent (NewSnapshot snap))               = put snap
handleEvent _                                           = pure ()

-- | Run the brick TUI. Blocks until the user quits ('q' or Esc).
-- Reads 'AppEvent's from the 'BChan' (fed by the Streamly pipeline).
runTUI :: BChan AppEvent -> IO ()
runTUI chan = do
  let buildVty = VtyCross.mkVty Vty.defaultConfig
  initialVty <- buildVty
  _finalState <- customMain initialVty buildVty (Just chan) app Map.empty
  pure ()
