module Main (main) where

import           Control.Monad (when)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import           Options.Applicative (eitherReader, Parser, strOption, long, short, metavar, help, option, ReadM, execParser, info, fullDesc, progDesc, header, helper)
import           SSH.Key (PrivateKey(Ed25519PrivateKey), serialiseKey, parseKey, privateKeys)
import           SSH.Key.Derived (deriveKey)
import           System.Directory (doesFileExist)
import           System.Entropy (getEntropy)
import           System.Posix.Files (setFileCreationMask, groupModes, otherModes, unionFileModes)
import           Data.ByteString.Base16 (decodeBase16)
import           Data.Either (isLeft, fromRight)

data Args = Args
            { argsSeed :: String
            , argsMode :: Modes
            , argsOutput :: FilePath
            , argsComment :: String
            }

data Modes = Hex | Raw | Generate | PrivateKey

parseMode :: String -> Either String Modes
parseMode "hex-literal" = Right Hex
parseMode "hex" = Right Hex
parseMode "raw-seed-file" = Right Raw
parseMode "raw" = Right Raw
parseMode "generate-randomly" = Right Generate
parseMode "generate" = Right Generate
parseMode "key-file" = Right PrivateKey
parseMode "key" = Right PrivateKey
parseMode _ = Left "unknown mode"

mode :: ReadM Modes
mode = eitherReader parseMode

parseArgs :: Parser Args
parseArgs = Args
  <$> strOption
      ( long "seed"
     <> short 's'
     <> metavar "SEED"
     <> help "Content of the seed, file path or string literal (depends on mode)" )
  <*> option mode
      ( long "mode"
     <> short 'm'
     <> metavar "MODE"
     <> help "Mode to get the seed: hex-literal (default), raw-seed-file, generate-randomly , key-file" )
  <*> strOption
      ( long "output"
     <> short 'o'
     <> metavar "OUTPUT"
     <> help "Path of file the generated key is stored in, file name should be specified also" )
  <*> strOption
      ( long "comment"
     <> short 'c'
     <> metavar "COMMENT"
     <> help "The key comment to use, also used as salt" )

getSeed :: Modes -> String -> IO B.ByteString
getSeed Hex seedString = do
  let eseed = decodeBase16 (BC.pack seedString)
  when (isLeft eseed) (fail "invalid hex literal, a valid hex literal should like 0a77ff")
  let seed = fromRight undefined eseed
  when (B.length seed < 32) (fail "Seed is shorter than 32 bytes")
  return seed
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
  let handle = BC.pack (argsComment args)
  seed <- getSeed (argsMode args) (argsSeed args)
  _ <- setFileCreationMask $ groupModes `unionFileModes` otherModes
  B.writeFile (argsOutput args) . serialiseKey . snd $ deriveKey seed handle
