module Main (main) where

import FFI (withArena, monitorInit, monitorCleanup)
import Stream (eventStream, aggregateStream)
import TUI (AppEvent(..), runTUI)

import Brick.BChan (newBChan, writeBChan)
import Control.Concurrent (forkIO)
import Control.Exception (bracket_)
import System.Environment (getArgs)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)
import qualified Streamly.Data.Stream as S

main :: IO ()
main = do
  args <- getArgs
  ifname <- case args of
    [iface] -> pure iface
    _       -> do
      hPutStrLn stderr "Usage: ebpf-net-monitor <interface>"
      exitFailure

  let arenaSize     = 4 * 1024 * 1024  -- 4 MB virtual reservation
      pollTimeoutMs = 100               -- 100ms poll timeout

  withArena arenaSize $ \arena ->
    bracket_ (monitorInit ifname) monitorCleanup $ do
      chan <- newBChan 16

      -- Streamly pipeline on a background thread:
      --   poll ring_buffer -> aggregate per-flow -> push snapshot to BChan
      _tid <- forkIO $
        S.mapM_ (writeBChan chan . NewSnapshot) $
          aggregateStream (eventStream arena pollTimeoutMs)

      -- brick needs the main thread for terminal signal handling
      runTUI chan
