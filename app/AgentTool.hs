module Main (main) where

import           Conduit (Conduit, takeCE, sinkLazy, concatMapC, await, yield, (=$=), ($$), fuseUpstream, mapMC)
import           Control.Applicative (pure, (<$>), (<*>))
import           Control.Monad (forever)
import           Data.Binary.Get (runGet)
import           Data.Binary.Put (runPut)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy as LB
import           Data.Conduit.Network.Unix (runUnixClient, clientSettings, runUnixServer, serverSettings, AppDataUnix, appSink, appSource)
import           Data.Monoid ((<>))
import           Options.Applicative (Parser, strOption, long, short, metavar, help, subparser, command, progDesc, info, execParser, helper, fullDesc, header)
import           SSH.Agent (parseMessage, serializeMessage, Message(RequestIdentities, IdentitiesAnswer, Failure, RequestIdentities1, IdentitiesAnswer1))
import qualified SSH.Agent as A
import           SSH.Key (PrivateKey, publicKey, putPublicKey, privateKeyComment)
import           SSH.Key.Derived (deriveKey)
import           SSH.Types (getWord32be', putWord32be', runStrictPut)
import           System.Environment (getEnv)
import qualified Data.Map.Strict as Map

data Options = Options
               { optCommand :: Command
               }

data Command = ListKeys
             | StartAgent
               { agentSock :: FilePath
               , agentSeed :: FilePath
               , agentHandles :: FilePath
               }

messageReceiver :: (Monad m) => Conduit B.ByteString m Message
messageReceiver = forever $ do
  lenBytes <- takeCE 4 =$= sinkLazy
  message <- takeCE (runGet getWord32be' lenBytes) =$= sinkLazy
  yield $ parseMessage message

messageSender :: (Monad m) => Conduit Message m B.ByteString
messageSender = concatMapC $ \message ->
  let messageBytes = serializeMessage message
      lenBytes = runPut $ putWord32be' (LB.length messageBytes)
  in map LB.toStrict [lenBytes, messageBytes]

runOneCommand :: Message -> IO (Maybe Message)
runOneCommand request =
  withAgent $ \agent -> appSource agent $$ messageReceiver =$= (yield request >> await) =$$= messageSender =$$= appSink agent
  where (=$$=) = fuseUpstream

runAgent :: FilePath -> (Message -> IO Message) -> IO ()
runAgent sockPath handle = runUnixServer (serverSettings sockPath)
  (\client -> appSource client $$ messageReceiver =$= mapMC handle =$= messageSender =$= appSink client)

withAgent :: (AppDataUnix -> IO a) -> IO a
withAgent a = do
  sockPath <- getEnv "SSH_AUTH_SOCK"
  runUnixClient (clientSettings sockPath) a

handleCommand :: [PrivateKey] -> Message -> Message
handleCommand keys = go
  where go RequestIdentities = IdentitiesAnswer $ Map.keys keyMap
        go RequestIdentities1 = IdentitiesAnswer1
        go _ = Failure
        wrapKey = A.PublicKey <$> runStrictPut . putPublicKey . publicKey <*> privateKeyComment
        keyMap = Map.fromList $ map (\k -> (wrapKey k, k)) keys

parseOptions :: Parser Options
parseOptions = Options
  <$> subparser (
    command "list-keys" (
       info listOptions (progDesc "List the keys currently available from the agent"))
    <> command "start" (
       info startOptions (progDesc "Start an agent serving deterministically generated keys"))
    )
  where listOptions = pure ListKeys
        startOptions = StartAgent
                       <$> strOption
                           ( long "sockpath"
                          <> short 'p'
                          <> metavar "PATH"
                          <> help "Location for the agent socket" )
                       <*> strOption
                           ( long "seed"
                          <> short 's'
                          <> metavar "SEED"
                          <> help "File containing the master seed" )
                       <*> strOption
                           ( long "handles"
                          <> short 'h'
                          <> metavar "HANDLES"
                          <> help "File containing a list of handles to serve" )

main :: IO ()
main = execParser opts >>= (run . optCommand)
  where opts = info (helper <*> parseOptions) (
          fullDesc
          <> progDesc "Simple SSH agent implementation"
          <> header "agent-tool - a simple and specialized SSH agent implementation")
        run (ListKeys) = print =<< runOneCommand RequestIdentities
        run (StartAgent sock seedFile handlesFile) = do
          seed <- B.readFile seedFile
          handles <- BC.lines <$> B.readFile handlesFile
          let keys = map (snd . deriveKey seed) handles
          runAgent sock (pure . handleCommand keys)
