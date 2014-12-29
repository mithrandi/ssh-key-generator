module Main (main) where

import           Control.Applicative ((<$>), (<*>))
import           Control.Monad (when)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import           Data.Monoid ((<>))
import           Options.Applicative (eitherReader, Parser, strOption, long, short, metavar, help, option, ReadM, execParser, info, fullDesc, progDesc, header, helper)
import           SSH.Key (PrivateKey(Ed25519PrivateKey), serialiseKey, parseKey, privateKeys)
import           SSH.Key.Derived (deriveKey)
import           System.Directory (doesFileExist)
import           System.Entropy (getEntropy)
import           System.Posix.Files (setFileCreationMask, groupModes, otherModes, unionFileModes)

data Args = Args
            { argsSeed :: FilePath
            , argsMode :: Modes
            , argsOutput :: FilePath
            , argsHandle :: String
            }

data Modes = Raw | Generate | PrivateKey

parseMode :: String -> Either String Modes
parseMode "raw" = Right Raw
parseMode "generate" = Right Generate
parseMode "key" = Right PrivateKey
parseMode _ = Left "unknown mode"

mode :: ReadM Modes
mode = eitherReader parseMode

parseArgs :: Parser Args
parseArgs = Args
  <$> strOption
      ( long "seed"
     <> short 's'
     <> metavar "SEEDFILE"
     <> help "File the seed is stored in" )
  <*> option mode
      ( long "mode"
     <> short 'm'
     <> metavar "MODE"
     <> help "Mode to handle the seed in: raw, generate, key" )
  <*> strOption
      ( long "output"
     <> short 'o'
     <> metavar "OUTPUT"
     <> help "File the generated key is stored in" )
  <*> strOption
      ( long "handle"
     <> short 'h'
     <> metavar "HANDLE"
     <> help "The key handle to use" )

getSeed :: Modes -> FilePath -> IO B.ByteString
getSeed Raw seedFile = do
  seed <- B.readFile seedFile
  when (B.length seed < 32) (fail "Seed is shorter than 32 bytes")
  return seed
getSeed Generate seedFile = do
  doesFileExist seedFile >>= flip when (fail "Refusing to overwrite seed")
  seed <- getEntropy 32
  B.writeFile seedFile seed
  return seed
getSeed PrivateKey seedFile = do
  Right box <- parseKey <$> B.readFile seedFile
  let Ed25519PrivateKey _ key _ = head . privateKeys $ box
  return $ B.take 32 key

main :: IO ()
main = do
  args <- execParser $ info (helper <*> parseArgs) (
    fullDesc
    <> progDesc "Generate an Ed25519 SSH key deterministically"
    <> header "ssh-key-generator - a deterministic SSH key generator")
  let handle = BC.pack (argsHandle args)
  seed <- getSeed (argsMode args) (argsSeed args)
  _ <- setFileCreationMask $ groupModes `unionFileModes` otherModes
  B.writeFile (argsOutput args) . serialiseKey . snd $ deriveKey seed handle
