{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Control.Applicative (pure)
import qualified Data.ByteString as B
import SSH.Key (parseKey, publicKeys, privateKeys)

main :: IO ()
main = do
  contents <- B.getContents
  box <- either error pure (parseKey contents)
  print box
  print $ publicKeys box
  print $ privateKeys box
