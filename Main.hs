{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import           Argh (seed_keypair)
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import           Data.Monoid ((<>))
import           SSH.Key (PrivateKey(Ed25519PrivateKey), PublicKey(Ed25519PublicKey), serialiseKey)
import           System.Environment (getArgs)
import           System.Posix.Files (setFileCreationMask, groupModes, otherModes, unionFileModes)

main :: IO ()
main = do
  [secretFile, handleS, outputFile] <- getArgs
  let handle = BC.pack handleS
  secret <- B.readFile secretFile
  let seed = SHA256.hash (secret <> handle)
  let (publicKeyData, privateKeyData) = seed_keypair seed
  setFileCreationMask $ groupModes `unionFileModes` otherModes
  B.writeFile outputFile . serialiseKey
    $ Ed25519PrivateKey (Ed25519PublicKey publicKeyData) privateKeyData handle
