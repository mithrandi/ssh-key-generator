module SSH.Key.Derived (deriveKey) where

import           Argh (seed_keypair)
import qualified Crypto.Hash.SHA256 as SHA256
import           Data.ByteString (ByteString)
import           Data.Monoid ((<>))
import           SSH.Key (PrivateKey(Ed25519PrivateKey), PublicKey(Ed25519PublicKey))

deriveKey :: ByteString -> ByteString -> (PublicKey, PrivateKey)
deriveKey seed handle = (publicKey, privateKey)
  where seed' = SHA256.hash (seed <> handle)
        (publicData, privateData) = seed_keypair seed'
        publicKey = Ed25519PublicKey publicData
        privateKey = Ed25519PrivateKey publicKey privateData handle
