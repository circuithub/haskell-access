{-# OPTIONS_HADDOCK not-home #-}
-- |
-- Module:      Data.Access.Unsafe
--
-- This module should not be imported by normal application code as it is used to construct Authorized values (which should only be obtainable through special-purpose authorization code).
-- As long as this module is not imported in a module the caller can be assured that access control will be correct by construction.
--
-- To match against authorizations, import Data.Access instead. (It re-exports 'AuthorizedIf')
--
module Data.Access.Unsafe
  ( AuthorizedIf
  , assumeAuthorized -- Unsafe!
  ) where

import           Data.Private (Private, private)
import           Data.Proxy   (Proxy (Proxy))

-- | A credential (priviledge/role/identity) that is "difficult to construct", meaning that it should only ever be constructed by trustworthy authorization code using 'assumeAuthorized'.
--   If an 'Authority' is improperly generated, then the associated safety contract will have been broken.
newtype Authority credential = Authority (Proxy credential)

-- | A value that can only be constructed using a special, trusted authorization function and can only be used once a witness is supplied for the guard.
type AuthorizedIf guard credential = Private guard (Authority credential)

-- | Construct a credential. Use with care!
assumeAuthorized :: AuthorizedIf guard credential
assumeAuthorized = private (Authority Proxy)

