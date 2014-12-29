module SSH.Agent where

import           Control.Applicative ((<$>), (<*>))
import           Control.Monad (replicateM)
import           Data.Binary.Get (Get, runGet, getWord8, getWord32be)
import           Data.Binary.Put (Put, runPut, putWord8, putWord32be)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as LB
import           Data.Monoid ((<>))
import           Data.Word (Word8, Word32)
import           SSH.Types (getWord32be', getString, putWord32be', putString)

data Message = Success
             | Failure
             | RequestIdentities1
             | IdentitiesAnswer1
             | RequestIdentities
             | IdentitiesAnswer [PublicKey]
             | SignRequest
               { signKey :: B.ByteString
               , signData ::  B.ByteString
               , signFlags :: Word32
               }
             | SignResponse B.ByteString
             deriving (Show, Eq, Ord)

data PublicKey = PublicKey
                 { publicKeyData :: B.ByteString
                 , publicKeyComment :: B.ByteString
                 }
               deriving (Show, Eq, Ord)

ssh_agentc_request_rsa_identities :: Word8
ssh_agentc_request_rsa_identities = 1

ssh_agent_rsa_identities_answer :: Word8
ssh_agent_rsa_identities_answer = 2

ssh_agent_success :: Word8
ssh_agent_success = 5

ssh_agent_failure :: Word8
ssh_agent_failure = 6

ssh2_agentc_request_identities :: Word8
ssh2_agentc_request_identities = 11

ssh2_agent_identities_answer :: Word8
ssh2_agent_identities_answer = 12

ssh2_agentc_sign_request :: Word8
ssh2_agentc_sign_request = 13

ssh2_agent_sign_response :: Word8
ssh2_agent_sign_response = 14

getMessage :: Get Message
getMessage = getWord8 >>= getMessage' where
  getMessage' t
    | t == ssh_agentc_request_rsa_identities = return RequestIdentities1
    | t == ssh_agent_rsa_identities_answer = return IdentitiesAnswer1
    | t == ssh_agent_success = return Success
    | t == ssh_agent_failure = return Failure
    | t == ssh2_agentc_request_identities = return RequestIdentities
    | t == ssh2_agent_identities_answer = do
        count <- getWord32be'
        IdentitiesAnswer <$> replicateM count (PublicKey <$> getString <*> getString)
    | t == ssh2_agentc_sign_request = SignRequest <$> getString <*> getString <*> getWord32be
    | t == ssh2_agent_sign_response = SignResponse <$> getString
    | otherwise = fail ("unsupported message type: " <> (show t))

parseMessage :: LB.ByteString -> Message
parseMessage = runGet getMessage

putMessage :: Message -> Put
putMessage Success = putWord8 ssh_agent_success
putMessage Failure = putWord8 ssh_agent_failure
putMessage RequestIdentities1 = putWord8 ssh_agentc_request_rsa_identities
putMessage IdentitiesAnswer1 = do
  putWord8 ssh_agent_rsa_identities_answer
  putWord32be 0
putMessage RequestIdentities = putWord8 ssh2_agentc_request_identities
putMessage (IdentitiesAnswer keys) = do
  putWord8 ssh2_agent_identities_answer
  putWord32be' (length keys)
  mapM_ (\k -> putString (publicKeyData k) >> putString (publicKeyComment k)) keys
putMessage (SignRequest key d flags) = do
  putWord8 ssh2_agentc_sign_request
  putString key
  putString d
  putWord32be flags
putMessage (SignResponse d) = do
  putWord8 ssh2_agent_sign_response
  putString d

serializeMessage :: Message -> LB.ByteString
serializeMessage m = runPut $ putMessage m
