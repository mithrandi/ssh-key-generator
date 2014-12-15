module Main (main) where

import Control.Applicative (pure, (<$>), (<*>))
import Control.Monad (replicateM, unless)
import Control.Exception (assert)
import Debug.Trace (traceShow)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Lazy as LB
import Data.Binary.Get (Get, runGet, getByteString, getWord32be, getRemainingLazyByteString)

data KeyBox = KeyBox
              { ciphername :: B.ByteString
              , kdfname :: B.ByteString
              , kdfoptions :: B.ByteString
              , boxKeys :: [Key]
              } deriving (Show)

auth_magic :: B.ByteString
auth_magic = BC.pack "openssh-key-v1\000"

expected_padding :: B.ByteString
expected_padding = BC.pack ['\001'..'\377']

data Key = PublicKey
           { keyAlg :: B.ByteString
           , publicKeyData :: B.ByteString
           }
         | PrivateKey
           { privateKeyAlg :: B.ByteString
           , privatePublicKeyData :: B.ByteString
           , privateKeyData :: B.ByteString
           , comment :: B.ByteString
           }
         deriving (Show)

dearmorPrivateKey :: B.ByteString -> Either String B.ByteString
dearmorPrivateKey =
    B64.decode
    . B.concat
    . takeWhile (/= BC.pack "-----END OPENSSH PRIVATE KEY-----")
    . drop 1
    . dropWhile (/= BC.pack "-----BEGIN OPENSSH PRIVATE KEY-----")
    . BC.lines

getPascalString :: Get BC.ByteString
getPascalString = do
  len <- getWord32be
  getByteString (fromIntegral len)

deserialiseKeyBox :: Get KeyBox
deserialiseKeyBox = do
  magic <- getByteString (B.length auth_magic)
  unless (magic == auth_magic) (fail "Magic does not match")
  let keys = do
        count <- fromIntegral <$> getWord32be
        -- Parse the private keys, but throw them away
        replicateM count getPublicKey
        privateKeys <- runGet (deserialisePrivateKeys count) <$> (LB.fromStrict <$> getPascalString)
        return privateKeys
      getPublicKey = runGet deserialisePublicKey <$> (LB.fromStrict <$> getPascalString)
  KeyBox
    <$> ((\x -> assert (x == BC.pack "none") x) <$> getPascalString)
    <*> getPascalString
    <*> getPascalString
    <*> keys

deserialisePublicKey :: Get Key
deserialisePublicKey = PublicKey <$> getPascalString <*> getPascalString

deserialisePrivateKeys :: Int -> Get [Key]
deserialisePrivateKeys count = do
  checkint1 <- getWord32be
  checkint2 <- getWord32be
  unless (checkint1 == checkint2) (fail "Decryption failed")
  keys <- replicateM count (PrivateKey <$> getPascalString <*> getPascalString <*> getPascalString <*> getPascalString)
  padding <- LB.toStrict <$> getRemainingLazyByteString
  unless (B.take (B.length padding) expected_padding == padding) (fail "Incorrect padding")
  return keys

parseKeyBox :: LB.ByteString -> KeyBox
parseKeyBox = runGet deserialiseKeyBox

main :: IO ()
main = do
  contents <- B.getContents
  box <- either error pure $ do
    b <- dearmorPrivateKey contents
    return . parseKeyBox . LB.fromStrict $ b
  putStrLn $ show box
