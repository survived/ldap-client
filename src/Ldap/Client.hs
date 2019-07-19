{-# LANGUAGE CPP #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE TupleSections, LambdaCase, RecordWildCards, OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE NamedFieldPuns #-}
-- | This module is intended to be imported qualified
--
-- @
-- import qualified Ldap.Client as Ldap
-- @
module Ldap.Client
  ( with
  , Host(..)
  , defaultTlsSettings
  , insecureTlsSettings
  , PortNumber
  , Ldap
  , LdapError(..)
  , ResponseError(..)
  , Type.ResultCode(..)
    -- * Bind
  , Password(..)
  , bind
  , externalBind
    -- * Search
  , search
  , SearchEntry(..)
    -- ** Search modifiers
  , Search
  , Mod
  , Type.Scope(..)
  , scope
  , size
  , enablePaging
  , time
  , typesOnly
  , Type.DerefAliases(..)
  , derefAliases
  , Filter(..)
    -- * Modify
  , modify
  , Operation(..)
    -- * Add
  , add
    -- * Delete
  , delete
    -- * ModifyDn
  , RelativeDn(..)
  , modifyDn
    -- * Compare
  , compare
    -- * Extended
  , Oid(..)
  , extended
    -- * Miscellanous
  , Dn(..)
  , Attr(..)
  , AttrValue
  , AttrList
    -- * Re-exports
  , NonEmpty
  ) where

#if __GLASGOW_HASKELL__ < 710
import           Control.Applicative ((<$>))
#endif
import qualified Control.Concurrent.Async as Async
import           Control.Concurrent.STM (atomically, throwSTM)
import           Control.Concurrent.STM.TMVar (putTMVar)
import           Control.Concurrent.STM.TQueue (TQueue, newTQueueIO, writeTQueue, readTQueue)
import           Control.Exception (Exception, Handler(..), bracket, throwIO, catch, catches)
import           Control.Monad (forever, join)
import qualified Data.ASN1.BinaryEncoding as Asn1
import qualified Data.ASN1.Encoding as Asn1
import qualified Data.ASN1.Error as Asn1
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as ByteString.Lazy
import           Data.Foldable (asum)
import           Data.Function (fix, (&))
import           Data.List (find)
import           Data.List.NonEmpty (NonEmpty((:|)))
import qualified Data.Map.Strict as Map
import           Data.Maybe (fromJust)
import           Data.Monoid (Endo(appEndo))
import           Data.Text (Text)
#if __GLASGOW_HASKELL__ < 710
import           Data.Traversable (traverse)
#endif
import           Data.Typeable (Typeable)
import           Network.Connection (Connection)
import qualified Network.Connection as Conn
import           Prelude hiding (compare)
import qualified System.IO.Error as IO

import           Ldap.Asn1.ToAsn1 (ToAsn1(toAsn1), encode)
import           Ldap.Asn1.FromAsn1 (FromAsn1, parseAsn1)
import qualified Ldap.Asn1.Type as Type
import           Ldap.Client.Internal
import           Ldap.Client.Bind (Password(..), bind, externalBind)
import           Ldap.Client.Search
  ( search
  , Search
  , Mod
  , scope
  , size
  , enablePaging
  , time
  , typesOnly
  , derefAliases
  , Filter(..)
  , SearchEntry(..)
  )
import           Ldap.Client.Modify (Operation(..), modify, RelativeDn(..), modifyDn)
import           Ldap.Client.Add (add)
import           Ldap.Client.Delete (delete)
import           Ldap.Client.Compare (compare)
import           Ldap.Client.Extended (Oid(..), extended, noticeOfDisconnectionOid)

{-# ANN module ("HLint: ignore Use first" :: String) #-}


newLdap :: IO Ldap
newLdap = Ldap
  <$> newTQueueIO

-- | Various failures that can happen when working with LDAP.
data LdapError =
    IOError !IOError             -- ^ Network failure.
  | ParseError !Asn1.ASN1Error   -- ^ Invalid ASN.1 data received from the server.
  | ResponseError !ResponseError -- ^ An LDAP operation failed.
  | DisconnectError !Disconnect  -- ^ Notice of Disconnection has been received.
    deriving (Show, Eq)

newtype WrappedIOError = WrappedIOError IOError
    deriving (Show, Eq, Typeable)

instance Exception WrappedIOError

data Disconnect = Disconnect !Type.ResultCode !Dn !Text
    deriving (Show, Eq, Typeable)

instance Exception Disconnect

-- | The entrypoint into LDAP.
--
-- It catches all LDAP-related exceptions.
with :: Host -> PortNumber -> (Ldap -> IO a) -> IO (Either LdapError a)
with host port f = do
  context <- Conn.initConnectionContext
  bracket (Conn.connectTo context params) Conn.connectionClose (\conn ->
    bracket newLdap unbindAsync (\l -> do
      inq  <- newTQueueIO
      outq <- newTQueueIO
      as   <- traverse Async.async
        [ input inq conn
        , output outq conn
        , dispatch l inq outq
        , f l
        ]
      fmap (Right . snd) (Async.waitAnyCancel as)))
 `catches`
  [ Handler (\(WrappedIOError e) -> return (Left (IOError e)))
  , Handler (return . Left . ParseError)
  , Handler (return . Left . ResponseError)
  ]
 where
  params = Conn.ConnectionParams
    { Conn.connectionHostname =
        case host of
          Plain h -> h
          Tls   h _ -> h
    , Conn.connectionPort = port
    , Conn.connectionUseSecure =
        case host of
          Plain  _ -> Nothing
          Tls _ settings -> pure settings
    , Conn.connectionUseSocks = Nothing
    }

defaultTlsSettings :: Conn.TLSSettings
defaultTlsSettings = Conn.TLSSettingsSimple
  { Conn.settingDisableCertificateValidation = False
  , Conn.settingDisableSession = False
  , Conn.settingUseServerName = False
  }

insecureTlsSettings :: Conn.TLSSettings
insecureTlsSettings = Conn.TLSSettingsSimple
  { Conn.settingDisableCertificateValidation = True
  , Conn.settingDisableSession = False
  , Conn.settingUseServerName = False
  }

input :: (Show a, FromAsn1 a) => TQueue a -> Connection -> IO b
input inq conn = wrap . flip fix [] $ \loop chunks -> do
  chunk <- Conn.connectionGet conn 8192
  case ByteString.length chunk of
    0 -> throwIO (IO.mkIOError IO.eofErrorType "Ldap.Client.input" Nothing Nothing)
    _ -> do
      let chunks' = chunk : chunks
      case Asn1.decodeASN1 Asn1.BER (ByteString.Lazy.fromChunks (reverse chunks')) of
        Left  Asn1.ParsingPartial
                   -> loop chunks'
        Left  e    -> throwIO e
        Right asn1 -> do
          flip fix asn1 $ \loop' asn1' ->
            case parseAsn1 asn1' of
              Nothing -> return ()
              Just (asn1'', a) -> do
                atomically (writeTQueue inq a)
                loop' asn1''
          loop []

output :: ToAsn1 a => TQueue a -> Connection -> IO b
output out conn = wrap . forever $ do
  msg <- atomically (readTQueue out)
  Conn.connectionPut conn (encode msg)

dispatch
  :: Ldap
  -> TQueue (Type.LdapMessage Type.ProtocolServerOp)
  -> TQueue (Type.LdapMessage Request)
  -> IO a
dispatch Ldap { client } inq outq =
  flip fix (Map.empty, 1) $ \loop (!req, !counter) ->
    loop =<< atomically (asum
      [ do New new controls var <- readTQueue client
           writeTQueue outq (Type.LdapMessage (Type.Id counter) new controls)
           return (Map.insert (Type.Id counter) ([], new, var) req, counter + 1)
      , do Type.LdapMessage mid op controls
               <- readTQueue inq
           (res, counter) <- case op of
             Type.BindResponse {}          -> (, counter) <$> done mid op req
             Type.SearchResultEntry {}     -> (, counter) <$> saveUp mid op req
             Type.SearchResultReference {} -> return (req, counter)
             Type.SearchResultDone {}      -> lookForMore mid op controls req counter
             Type.ModifyResponse {}        -> (, counter) <$> done mid op req
             Type.AddResponse {}           -> (, counter) <$> done mid op req
             Type.DeleteResponse {}        -> (, counter) <$> done mid op req
             Type.ModifyDnResponse {}      -> (, counter) <$> done mid op req
             Type.CompareResponse {}       -> (, counter) <$> done mid op req
             Type.ExtendedResponse {}      -> (, counter) <$> probablyDisconnect mid op req
             Type.IntermediateResponse {}  -> (, counter) <$> saveUp mid op req
           return (res, counter)
      ])
 where
  saveUp mid op res =
    return (Map.adjust (\(stack, r, var) -> (op : stack, r, var)) mid res)

  lookForMore mid op@Type.SearchResultDone{} (Just (Type.Controls controls)) res counter =
    controls
      &   find (\(Type.Control oid _ _) -> oid == Type.LdapOid "1.2.840.113556.1.4.319")
      >>= (\(Type.Control _ _ value) -> case value of Just (Type.PagedResultsCV p) -> Just p; _ -> Nothing)
      &   \case
            Just Type.PagedResultsControlValue{..} ->
              let (removed, res') = Map.updateLookupWithKey (\_ _ -> Nothing) mid res
                  controls' = Type.Controls $ pure $ Type.pagedResultsControl $
                    Type.PagedResultsControlValue
                      1000
                      pagedResultCookie
              in  case removed of
                    Just (stack, p, var)
                      | not (ByteString.null pagedResultCookie) -> do
                          writeTQueue outq (Type.LdapMessage (Type.Id counter) p (Just controls'))
                          return (Map.insert (Type.Id counter) (stack, p, var) res', counter + 1)
                    _ ->
                      (,) <$> done mid op res <*> pure counter
            _ -> (,) <$> done mid op res <*> pure counter
  lookForMore mid op _ res counter =
    (,) <$> done mid op res <*> pure counter

  done mid op req =
    case Map.lookup mid req of
      Nothing -> return req
      Just (stack, _, var) -> do
        putTMVar var (op :| stack)
        return (Map.delete mid req)

  probablyDisconnect (Type.Id 0)
                     (Type.ExtendedResponse
                       (Type.LdapResult code
                                        (Type.LdapDn (Type.LdapString dn))
                                        (Type.LdapString reason)
                                        _)
                       moid _)
                     req =
    case moid of
      Just (Type.LdapOid oid)
        | Oid oid == noticeOfDisconnectionOid -> throwSTM (Disconnect code (Dn dn) reason)
      _ -> return req
  probablyDisconnect mid op req = done mid op req

wrap :: IO a -> IO a
wrap m = m `catch` (throwIO . WrappedIOError)
