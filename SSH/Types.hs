module SSH.Types
       ( getWord32be'
       , putWord32be'
       , getString
       , putString
       ) where

import           Control.Applicative ((<$>))
import           Data.Binary.Get (Get, getWord32be, getByteString)
import           Data.Binary.Put (Put, putWord32be, putByteString)
import qualified Data.ByteString as B

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
