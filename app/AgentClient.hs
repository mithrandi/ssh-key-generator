module Main (main) where

import           Conduit (Conduit, ConduitM, takeCE, sinkLazy, concatMapC, await, yield, (=$=), ($$), fuseUpstream)
import           Control.Applicative (pure, (<$>), (<*>))
import           Data.Binary.Get (runGet)
import           Data.Binary.Put (runPut)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as LB
import           Data.Conduit.Network.Unix (runUnixClient, clientSettings, AppDataUnix, appSink, appSource)
import           Data.Monoid ((<>))
import           Options.Applicative (Parser, strOption, long, short, metavar, help, subparser, command, progDesc, info, execParser, helper, fullDesc, header)
import           SSH.Agent (parseMessage, serializeMessage, Message(RequestIdentities))
import           SSH.Types (getWord32be', putWord32be')
import           System.Environment (getEnv)

data Options = Options
               { optCommand :: Command
               }

data Command = ListKeys ListOptions

data ListOptions = ListOptions

messageReceiver :: Conduit B.ByteString IO Message
messageReceiver = loop
  where
    loop = do
      lenBytes <- takeCE 4 =$= sinkLazy
      message <- takeCE (runGet getWord32be' lenBytes) =$= sinkLazy
      yield $ parseMessage message
      loop

messageSender :: Conduit Message IO B.ByteString
messageSender = concatMapC $ \message ->
  let messageBytes = serializeMessage message
      lenBytes = runPut $ putWord32be' (LB.length messageBytes)
  in map LB.toStrict [lenBytes, messageBytes]

runOneCommand :: Message -> ConduitM Message Message IO (Maybe Message)
runOneCommand request = do
  yield request
  response <- await
  return response

withAgent :: (AppDataUnix -> IO a) -> IO a
withAgent a = do
  sockPath <- getEnv "SSH_AUTH_SOCK"
  runUnixClient (clientSettings sockPath) a

parseOptions :: Parser Options
parseOptions = Options
  <$> subparser (
    command "list-keys" (
       info listOptions (progDesc "List the keys currently available from the agent"))
    )
  where listOptions :: Parser Command
        listOptions = pure $ ListKeys ListOptions


main :: IO ()
main = execParser opts >>= (run . optCommand)
  where opts = info (helper <*> parseOptions) (
          fullDesc
          <> progDesc "Simple SSH agent client"
          <> header "agent-client - a simple SSH agent client")
        run (ListKeys _) = withAgent $ \agent -> do
          response <- appSource agent $$ messageReceiver =$= runOneCommand RequestIdentities `fuseUpstream` messageSender `fuseUpstream` appSink agent
          print response
