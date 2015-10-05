-- |
-- Module:      Data.Private
--
module Data.Private
  ( Private.Private
  , Private'
  , Private.private
  , reveal
  ) where

import qualified Data.Private.Unsafe as Private (Private, private)
import qualified Data.Private.Unsafe as Unsafe (unPrivate)

import           Prelude             (seq)

-- | A secret that is easily revealed for use in situations where the data being protected is not very sensitive.
--   'Private'' can be used to prevent accidentally defining serialization instances (e.g. Show, ToJSON) on slightly sensitive data etc.
type Private' secret = Private.Private () secret

-- | Unwrap a private value by supplying a (non-bottom) witness value for the type that guards the secret.
-- TODO: should this use 'deepseq' in order to be especially safe? The only trouble with deepseq is that it requires an instance of 'NFData' which seems a bit impractical.
reveal :: guard -> Private.Private guard secret -> secret
reveal witness p = witness `seq` Unsafe.unPrivate p

