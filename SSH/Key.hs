module SSH.Key
       ( KeyBox
       , PublicKey(..)
       , PrivateKey(..)
       , parseKey
       , publicKeys
       , privateKeys
       ) where

import           Control.Applicative ((<$>), (<*>))
import           Control.Monad (unless, replicateM)
import           Data.Binary.Get (Get, runGet, getWord32be, getByteString, getRemainingLazyByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as BC
import           Data.ByteString.Lazy (fromStrict, toStrict)

data KeyBox = KeyBox
              { ciphername :: B.ByteString
              , _kdfname :: B.ByteString
              , _kdfoptions :: B.ByteString
              , keycount :: Int
              , boxPublicKeys :: B.ByteString
              , boxPrivateKeys :: B.ByteString
              } deriving (Show)

auth_magic :: B.ByteString
auth_magic = "openssh-key-v1\000"

expected_padding :: B.ByteString
expected_padding = BC.pack ['\001'..'\377']

data PublicKey = Ed25519PublicKey
                 { publicKeyData :: B.ByteString }
               deriving (Show)

data PrivateKey = Ed25519PrivateKey
                  { publicKey :: PublicKey
                  , privateKeyData :: B.ByteString
                  , privateKeyComment :: B.ByteString
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

getWord32be' :: (Integral a) => Get a
getWord32be' = fromIntegral <$> getWord32be

getPascalString :: Get B.ByteString
getPascalString = getWord32be' >>= getByteString

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
  count <- getWord32be'
  publicData <- getPascalString
  privateData <- getPascalString
  return $ KeyBox cn kn ko count publicData privateData

publicKeys :: KeyBox -> [PublicKey]
publicKeys box = flip runStrictGet (boxPublicKeys box) $
  replicateM (keycount box) $ do
    keyType <- getPascalString
    case keyType of
     "ssh-ed25519" -> Ed25519PublicKey <$> getPascalString
     _ -> fail "Unsupported key type"

getPrivateKey :: Get PrivateKey
getPrivateKey = do
  keyType <- getPascalString
  case keyType of
   "ssh-ed25519" -> Ed25519PrivateKey
                    <$> (Ed25519PublicKey <$> getPascalString)
                    <*> getPascalString
                    <*> getPascalString
   _ -> fail "Unsupported key type"

getPrivateKeys :: Int -> Get [PrivateKey]
getPrivateKeys count = do
  checkint1 <- getWord32be
  checkint2 <- getWord32be
  unless (checkint1 == checkint2) (fail "Decryption failed")
  keys <- replicateM count getPrivateKey
  padding <- toStrict <$> getRemainingLazyByteString
  unless (B.take (B.length padding) expected_padding == padding) (fail "Incorrect padding")
  return keys

privateKeys :: KeyBox -> [PrivateKey]
privateKeys box | ciphername box == "none" =
                    runStrictGet (getPrivateKeys $ keycount box) (boxPrivateKeys box)
                | otherwise = error "Unsupported encryption type"

parseKey :: BC.ByteString -> Either String KeyBox
parseKey = fmap (runStrictGet getKeyBox) . dearmorPrivateKey
