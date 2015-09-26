-- |
-- Module:      Data.Private
--
module Data.Private
  ( Private ()
  , private
  , reveal
  ) where

import           Prelude (seq)

-- | A secret value that is "difficult to reveal", meaning that it should only ever be exposed if a suitable value witness is supplied for the type denoted as the guard.
--
--   * If a 'Private' is improperly accessed, then the associated safety contract will have been broken.
--
--   * If an improperly constructed guard witness is constructed the contract will also have been broken.
--
--   For example, one way of violating the type-safety of this mechanism would be to use 'unsafeCoerce' to coerce either the "Private" type or the associated guard (so please don't do this!).
--   Passing ⊥ (bottom) as a witness to the guard will lead to undefined behaviour.
newtype Private guard secret = Private secret

-- | Construct a 'Private' value
private :: secret -> Private guard secret
private secret = Private secret

-- | Unwrap a private value by supplying a (non-bottom) witness value for the type that guards the secret.
-- TODO: should this use 'deepseq' in order to be especially safe? The only trouble with deepseq is that it requires an instance of 'NFData' which seems a bit impractical.
reveal :: guard -> Private guard secret -> secret
reveal witness (Private secret) = witness `seq` secret

