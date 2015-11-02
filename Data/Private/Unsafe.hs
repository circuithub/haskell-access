{-# OPTIONS_HADDOCK not-home #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE Safe              #-}
-- |
-- Module:      Data.Private.Unsafe
--
-- This module should not be imported by normal application code, except in special circumstances where it is highly convenient to circumvent access controls.
-- E.g. When serializing information for storage in a trusted database it can be very difficult to first unwrap all of the private data types being used in the schema.
--
module Data.Private.Unsafe
  ( Private ()
  , private
  , unPrivate -- Unsafe!
  ) where

import           Control.Applicative
import           Control.Monad
import           Data.Function       ((.))

-- | A secret value that is "difficult to reveal", meaning that it should only ever be exposed if a suitable value witness is supplied for the type denoted as the guard.
--
--   * If a 'Private' is improperly accessed, then the associated safety contract will have been broken.
--
--   * If an improperly constructed guard witness is constructed the contract will also have been broken.
--
--   For example, one way of violating the type-safety of this mechanism would be to use 'unsafeCoerce' to coerce either the "Private" type or the associated guard (so please don't do this!).
--   Passing ⊥ (bottom) as a witness to the guard will lead to undefined behaviour.
newtype Private guard secret = Private secret

instance Functor (Private guard) where
  fmap f = private . f . unPrivate
instance Applicative (Private guard) where
  pure = private
  pf <*> px = fmap (unPrivate pf) px
instance Monad (Private guard) where
  p >>= f = f (unPrivate p)
-- instance Show a => Show (Private a) where
--   show _ = "Private { ... }"
-- instance Read a => Read (Private a) where
--   readsPrec _ _ = error "Read instance on Private is not currently allowed"

-- | Construct a 'Private' value
private :: secret -> Private guard secret
private secret = Private secret

-- | Unwrap a private value without supplying a witness value. This circumvents the confidentiality of 'Private', so use with care!
unPrivate :: Private guard secret -> secret
unPrivate (Private secret) = secret

