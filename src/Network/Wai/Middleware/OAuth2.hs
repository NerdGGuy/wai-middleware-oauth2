{-# LANGUAGE OverloadedStrings #-}
module Network.Wai.Middleware.OAuth2 (login, callback, basicCallback, getJSON, OAuth2, appendQueryParam, QueryParams, CheckState, OAuth2Result, AccessToken) where

import Network.Wai
import Network.OAuth.OAuth2
import qualified Data.ByteString.Char8 as BSC8
import qualified Data.ByteString.Lazy as L
import Data.ByteString
import Control.Error
import Control.Monad.IO.Class (MonadIO(liftIO))
import Data.Monoid (mempty)
import Network.HTTP.Types (status200, status302, status400, status404)
import Data.Aeson.Types
import Network.HTTP.Conduit (Manager, newManager, conduitManagerSettings)
import Data.Either

--instance (MonadIO m) => MonadIO (EitherT m) where
--  liftIO = lift . liftIO

type CheckState = BSC8.ByteString -> Bool

redirect302 :: URI -> Response
redirect302 uri = responseLBS status302 [("Location", uri)] mempty

login :: OAuth2 -> QueryParams -> Response
login config param = redirect302 $ authorizationUrl config `appendQueryParam` param

basicCallback :: Manager -> OAuth2 -> CheckState -> (L.ByteString -> Application) -> ((OAuth2Result AccessToken) -> Application) -> Application
basicCallback mgr config authcheckstate failapp successapp req sendResponse = do
    accessToken <- liftIO eAccessToken
    either runFailApp runSuccessApp accessToken
    where
        eAccessToken :: IO (Either ByteString (OAuth2Result AccessToken))
        eAccessToken = runEitherT (callback mgr config authcheckstate req)
        runFailApp :: ByteString -> IO ResponseReceived
        runFailApp = \x -> failapp (L.fromStrict x) req sendResponse
        runSuccessApp :: OAuth2Result AccessToken -> IO ResponseReceived
        runSuccessApp = \x -> successapp (x) req sendResponse

callback :: Manager -> OAuth2 -> CheckState -> Request -> EitherT ByteString IO (OAuth2Result AccessToken)
callback mgr config authcheckstate req = do
    hoistEither checkState -- SECURITY -- check state NONCE to check callback request is valid
    getAccessToken -- AccessToken can now be used to request user INFO
    where
        lookupQuery name = lookup name (queryString req)
        getState :: Either ByteString ByteString
        getState = note ("OhAuth sessionCallback getState" :: ByteString) $ do
            mstate <- lookupQuery "state"
            state <- mstate
            return state
        getCode :: Either ByteString ByteString
        getCode = note "OhAuth sessionCallback getCode" $ do
            mcode <- lookupQuery "code"
            code <- mcode
            return code
        checkState :: Either ByteString ByteString
        checkState = do
            state <- getState
            bool (Left "OhAuth sessionCallback checkState") (Right state) (authcheckstate state)
        getAccessToken :: EitherT ByteString IO (OAuth2Result AccessToken)
        getAccessToken = do
            code <- hoistEither getCode
            liftIO $ fetchAccessToken mgr config code

getJSON :: FromJSON a => Manager -> AccessToken -> URI -> IO (OAuth2Result a)
getJSON = authGetJSON
