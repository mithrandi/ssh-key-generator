module SSH.Types
       ( getWord32be'
       , putWord32be'
       , getString
       , putString
       , runStrictGet
       , runStrictPut
       ) where

import           Control.Applicative ((<$>))
import           Data.Binary.Get (Get, getWord32be, getByteString, runGet)
import           Data.Binary.Put (Put, putWord32be, putByteString, runPut)
import qualified Data.ByteString as B
import           Data.ByteString.Lazy (fromStrict, toStrict)

getWord32be' :: (Integral a) => Get a
getWord32be' = fromIntegral <$> getWord32be

putWord32be' :: (Integral a) => a -> Put
putWord32be' = putWord32be . fromIntegral

getString :: Get B.ByteString
getString = getWord32be' >>= getByteString

putString :: B.ByteString -> Put
putString s = do
  putWord32be (fromIntegral $ B.length s)
  putByteString s

runStrictGet :: Get c -> B.ByteString -> c
runStrictGet = (. fromStrict) . runGet

runStrictPut :: Put -> B.ByteString
runStrictPut = toStrict . runPut
