module SSH.Key
       ( KeyBox(..)
       , Key(..)
       , parseKey
       ) where

import Control.Applicative ((<$>), (<*>))
import Control.Monad (unless, replicateM)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Base64 as B64
import Data.ByteString.Lazy (fromStrict, toStrict)
import Data.Binary.Get (Get, runGet, getWord32be, getByteString, getRemainingLazyByteString)

data KeyBox = KeyBox
              { ciphername :: B.ByteString
              , kdfname :: B.ByteString
              , kdfoptions :: B.ByteString
              , boxPublicKeys  :: [Key]
              , boxPrivateKeys :: Maybe [Key]
              } deriving (Show)

auth_magic :: B.ByteString
auth_magic = "openssh-key-v1\000"

expected_padding :: B.ByteString
expected_padding = BC.pack ['\001'..'\377']

data Key = PublicKey
           { keyAlg :: B.ByteString
           , publicKeyData :: B.ByteString
           }
         | PrivateKey
           { privateKeyAlg :: B.ByteString
           , publicKeyData :: B.ByteString
           , privateKeyData :: B.ByteString
           , comment :: B.ByteString
           }
         deriving (Show)


runStrictGet :: Get c -> B.ByteString -> c
runStrictGet = (. fromStrict) . runGet

dearmorPrivateKey :: B.ByteString -> Either String B.ByteString
dearmorPrivateKey =
    B64.decode
    . B.concat
    . takeWhile (/= "-----END OPENSSH PRIVATE KEY-----")
    . drop 1
    . dropWhile (/= "-----BEGIN OPENSSH PRIVATE KEY-----")
    . BC.lines

getPascalString :: Get B.ByteString
getPascalString = do
  len <- getWord32be
  getByteString (fromIntegral len)

getKeyBox :: Get KeyBox
getKeyBox = do
  magic <- getByteString (B.length auth_magic)
  unless (magic == auth_magic) (fail "Magic does not match")
  cn <- getPascalString
  unless (cn == "none") (fail "Unsupported cipher")
  kn <- getPascalString
  unless (kn == "none") (fail "Unsupported kdf")
  ko <- getPascalString
  unless (ko == "") (fail "Invalid kdf options")
  count <- fromIntegral <$> getWord32be
  publicKeys <- replicateM count (runStrictGet getPublicKey <$> getPascalString)
  privateKeys <- runStrictGet (getPrivateKeys count) <$> getPascalString
  return $ KeyBox cn kn ko publicKeys (Just privateKeys)

getPublicKey :: Get Key
getPublicKey = PublicKey <$> getPascalString <*> getPascalString

getPrivateKey :: Get Key
getPrivateKey = PrivateKey
  <$> getPascalString
  <*> getPascalString
  <*> getPascalString
  <*> getPascalString

getPrivateKeys :: Int -> Get [Key]
getPrivateKeys count = do
  checkint1 <- getWord32be
  checkint2 <- getWord32be
  unless (checkint1 == checkint2) (fail "Decryption failed")
  keys <- replicateM count getPrivateKey
  padding <- toStrict <$> getRemainingLazyByteString
  unless (B.take (B.length padding) expected_padding == padding) (fail "Incorrect padding")
  return keys

parseKey :: BC.ByteString -> Either String KeyBox
parseKey = fmap (runStrictGet getKeyBox) . dearmorPrivateKey
