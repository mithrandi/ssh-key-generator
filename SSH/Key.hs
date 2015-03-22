module SSH.Key
       ( KeyBox
       , PublicKey(..)
       , PrivateKey(..)
       , parseKey
       , serialiseKey
       , publicKeys
       , privateKeys
       , putPublicKey
       ) where

import           Control.Applicative ((<$>), (<*>))
import           Control.Monad (unless, replicateM)
import           Data.Binary.Get (Get, getWord32be, getByteString, getRemainingLazyByteString)
import           Data.Binary.Put (Put, putWord32be, putByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as BC
import           Data.ByteString.Lazy (toStrict)
import           Data.Monoid ((<>))
import           SSH.Types (getWord32be', getString, putString, runStrictGet, runStrictPut)

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

armor_start :: B.ByteString
armor_start = "-----BEGIN OPENSSH PRIVATE KEY-----"

armor_end :: B.ByteString
armor_end = "-----END OPENSSH PRIVATE KEY-----"

data PublicKey = Ed25519PublicKey
                 { publicKeyData :: B.ByteString }
               deriving (Show)

data PrivateKey = Ed25519PrivateKey
                  { publicKey :: PublicKey
                  , privateKeyData :: B.ByteString
                  , privateKeyComment :: B.ByteString
                  }
                deriving (Show)

dearmorPrivateKey :: B.ByteString -> Either String B.ByteString
dearmorPrivateKey =
    B64.decode
    . B.concat
    . takeWhile (/= armor_end)
    . drop 1
    . dropWhile (/= armor_start)
    . BC.lines

armorPrivateKey :: B.ByteString -> B.ByteString
armorPrivateKey k =
  armor_start <> "\n"
  <> B64.joinWith "\n" 70 (B64.encode k)
  <> armor_end <> "\n"

getKeyBox :: Get KeyBox
getKeyBox = do
  magic <- getByteString (B.length auth_magic)
  unless (magic == auth_magic) (fail "Magic does not match")
  cn <- getString
  unless (cn == "none") (fail "Unsupported cipher")
  kn <- getString
  unless (kn == "none") (fail "Unsupported kdf")
  ko <- getString
  unless (ko == "") (fail "Invalid kdf options")
  count <- getWord32be'
  publicData <- getString
  privateData <- getString
  return $ KeyBox cn kn ko count publicData privateData

putKeyBox :: PrivateKey -> Put
putKeyBox key = do
  putByteString auth_magic
  putString "none"
  putString "none"
  putString ""
  putWord32be 1
  putPublicKeys [publicKey key]
  putPrivateKeys [key]

publicKeys :: KeyBox -> [PublicKey]
publicKeys box = flip runStrictGet (boxPublicKeys box) $
  replicateM (keycount box) $ do
    keyType <- getString
    case keyType of
     "ssh-ed25519" -> Ed25519PublicKey <$> getString
     _ -> fail "Unsupported key type"

putPublicKeys :: [PublicKey] -> Put
putPublicKeys = putString . runStrictPut . mapM_ putPublicKey

putPublicKey :: PublicKey -> Put
putPublicKey (Ed25519PublicKey k) = do
  putString "ssh-ed25519"
  putString k

getPrivateKey :: Get PrivateKey
getPrivateKey = do
  keyType <- getString
  case keyType of
   "ssh-ed25519" -> Ed25519PrivateKey
                    <$> (Ed25519PublicKey <$> getString)
                    <*> getString
                    <*> getString
   _ -> fail "Unsupported key type"

putPrivateKey :: PrivateKey -> Put
putPrivateKey (Ed25519PrivateKey pk k c) = do
  putString "ssh-ed25519"
  putString (publicKeyData pk)
  putString k
  putString c

getPrivateKeys :: Int -> Get [PrivateKey]
getPrivateKeys count = do
  checkint1 <- getWord32be
  checkint2 <- getWord32be
  unless (checkint1 == checkint2) (fail "Decryption failed")
  keys <- replicateM count getPrivateKey
  padding <- toStrict <$> getRemainingLazyByteString
  unless (B.take (B.length padding) expected_padding == padding) (fail "Incorrect padding")
  return keys

putPrivateKeys :: [PrivateKey] -> Put
putPrivateKeys keys = putString . pad 8 . runStrictPut $ do
  putWord32be 0
  putWord32be 0
  mapM_ putPrivateKey keys
  where pad a s | B.length s `rem` a == 0 = s
                | otherwise            = s <> B.take (a - B.length s `rem` a) expected_padding

privateKeys :: KeyBox -> [PrivateKey]
privateKeys box | ciphername box == "none" =
                    runStrictGet (getPrivateKeys $ keycount box) (boxPrivateKeys box)
                | otherwise = error "Unsupported encryption type"

parseKey :: BC.ByteString -> Either String KeyBox
parseKey = fmap (runStrictGet getKeyBox) . dearmorPrivateKey

serialiseKey :: PrivateKey -> B.ByteString
serialiseKey = armorPrivateKey . runStrictPut . putKeyBox
