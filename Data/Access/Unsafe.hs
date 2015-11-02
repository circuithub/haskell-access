{-# OPTIONS_HADDOCK not-home #-}
{-# LANGUAGE Safe #-}
-- experimental
-- {-# LANGUAGE NoImplicitPrelude #-}
-- {-# LANGUAGE PolyKinds         #-}
-- |
-- Module:      Data.Access.Unsafe
--
-- This module should not be imported by normal application code as it is used to construct Authority values (which should only be obtainable through special-purpose authorization code).
-- As long as this module is not imported in a module the caller can be assured that access control will be correct by construction.
--
-- To match against authorizations, import Data.Access instead. (It re-exports 'AuthorityIf')
--
module Data.Access.Unsafe
  ( Authority
  , authority  -- Unsafe!
  ) where

-- | A credential (priviledge/role/identity) that is "difficult to construct", meaning that it should only ever be constructed by trustworthy authorization code using 'authority' or 'authorized'.
--   If an 'Authority' is improperly generated, then the associated safety contract will have been broken.
--
--   Authority corresponds to Proxy with the constructor hidden in this module
data Authority credential = Authority

-- | Construct a credential (without a value). Use with care!
authority :: Authority credential
authority = Authority

