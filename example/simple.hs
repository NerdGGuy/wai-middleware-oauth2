{-# LANGUAGE OverloadedStrings #-}
module Main where

import Network.Wai
import qualified Network.Wai.Middleware.OAuth2 as OAuth2
import Keys (googleKey)
import Data.Text (Text)
import Network.HTTP.Types (status200, status400, status404)
import Data.Monoid (mempty)
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Char8 as BSC8
import Network.Wai.Handler.Warp (defaultSettings, settingsPort)
import Network.Wai.Handler.WarpTLS (runTLS, tlsSettings)
import Network.Wai.Middleware.CleanPath (cleanPath)
import Control.Error
import Data.ByteString
import Network.HTTP.Conduit (Manager, newManager, conduitManagerSettings)

application :: L.ByteString -> Application
application x _ sendResponse = sendResponse $ responseLBS status200 [("Content-Type", "text/plain")] x

notFound _ sendResponse = sendResponse $ responseLBS status404 [("Content-Type", "text/plain")] "404 Not Found"

sessionApp :: Manager -> [Text] -> Application
sessionApp mgr _ _ sendResponse = sendResponse $ OAuth2.login googleKey (googleScopeEmail ++ state)
    where
        googleScopeEmail :: OAuth2.QueryParams
        googleScopeEmail = [("scope", "email")]
        state :: OAuth2.QueryParams
        state = [("state", "00000000")]
sessionApp mgr ["googleCallback"] req sendResponse = OAuth2.basicCallback mgr googleKey checkState application (\_ -> application "worked") req sendResponse
sessionApp _ _ req sendResponse = notFound req sendResponse

--buildResponse $ runEitherT $ OAuth2.callback googleKey checkState req
--    where
--        buildResponse :: IO (Either ByteString (OAuth2.OAuth2Result OAuth2.AccessToken)) -> IO Response
--        buildResponse x = do
--            eAccessToken <- x
--            case eAccessToken of
--                Left err -> application (L.fromStrict err) req
--                Right _ -> application "worked" req

error400 :: Application
error400 _ sendResponse = sendResponse $ responseLBS status400 [] mempty

checkState :: BSC8.ByteString -> Bool
checkState = (==) "00000000"

filterPath x = Right x

main = do
  mgr <- newManager conduitManagerSettings
  runTLS (tlsSettings  "certificate.pem" "key.pem") defaultSettings { settingsPort = 443 } $ cleanPath filterPath "" $ sessionApp mgr
