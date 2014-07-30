{-# LANGUAGE OverloadedStrings #-}
module Main where

import Network.Wai
import Network.Wai.Middleware.OAuth2 as OAuth2
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

application :: L.ByteString -> Application
application x _ = return $ responseLBS status200 [("Content-Type", "text/plain")] x

notFound _ = return $ responseLBS status404 [("Content-Type", "text/plain")] "404 Not Found"

sessionApp :: [Text] -> Application
sessionApp [] _ = do return $ OAuth2.login googleKey (googleScopeEmail ++ state)
    where
        googleScopeEmail :: QueryParams
        googleScopeEmail = [("scope", "email")]
        state :: QueryParams
        state = [("state", "00000000")]
sessionApp ["googleCallback"] req = OAuth2.basicCallback googleKey checkState application (\_ -> application "worked") req
sessionApp x req = return $ notFound x req

--buildResponse $ runEitherT $ OAuth2.callback googleKey checkState req
--    where
--        buildResponse :: IO (Either ByteString (OAuth2.OAuth2Result OAuth2.AccessToken)) -> IO Response
--        buildResponse x = do
--            eAccessToken <- x
--            case eAccessToken of
--                Left err -> application (L.fromStrict err) req
--                Right _ -> application "worked" req

error400 :: Application
error400 _ = return $ responseLBS status400 [] mempty

checkState :: BSC8.ByteString -> Bool
checkState = (==) "00000000"

filterPath x = Right x

main = runTLS (tlsSettings  "certificate.pem" "key.pem") defaultSettings { settingsPort = 443 } $ cleanPath filterPath "" sessionApp
