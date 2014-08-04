{-# LANGUAGE TemplateHaskell, OverloadedStrings #-}

import Network.Wai.Middleware.OAuth2 as OAuth2
import Network.OAuth.OAuth2
import Keys (googleKey)
import Data.ByteString

import Control.Monad (unless)
import System.Exit (exitFailure)
import Test.QuickCheck.All (quickCheckAll)
import Test.QuickCheck (Property)
import Test.QuickCheck.Monadic (assert, monadicIO, run)
import Network.Wai.Test (defaultRequest, request, runSession, simpleBody, simpleHeaders, SResponse)

googleScopeEmail :: QueryParams
googleScopeEmail = [("scope", "email")]

state :: QueryParams
state = [("state", "00000000")]

prop_login :: Property
prop_login = monadicIO $ do
    login <- run $ runSession (request defaultRequest) (\_ sendResponse -> sendResponse $ OAuth2.login googleKey (googleScopeEmail ++ state))
    run $ print (show $ simpleHeaders login)
    assert $ (simpleHeaders login) == locationHeader
    where
        --build it myself and check against OAuth2 answer
        locationHeader = [("Location",oauthOAuthorizeEndpoint googleKey `appendQueryParam` (transform' [("client_id",Just $ oauthClientId googleKey),("response_type",Just "code"),("redirect_uri",oauthCallback googleKey),("scope",Just "email"),("state",Just "00000000")]))]

main = do
    allPass <- $quickCheckAll -- Run QuickCheck on all prop_ functions
    unless allPass exitFailure
