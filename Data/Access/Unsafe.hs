-- |
-- Module:      Data.Access.Unsafe
--
-- Used to construct Auth values. This module should not be imported by normal application code. It is used to construct
-- Authorization values (which should only be obtainable through special-purpose authorization code). As long as this module is not imported the caller can be assured that authorization are correct by construction.
--
-- To match against authorizations, import Data.Auth instead. It re-exports all necessary accessors.
--
module Data.Access.Unsafe
  ( Private ()
  , private
  , reveal
  , Authority ()
  , assumeAuthority -- Unsafe!
  ) where

import           Data.Proxy (Proxy (Proxy))
import           Prelude    (seq)

  -- ( Authorized ()       -- The constructor is 'assumeAuthorized' and the accessor is 'reveal'
  -- , AuthorizedFor ()    -- The constructor is 'assumeAuthorizedFor' and the accessor is 'revealFor'
  -- , reveal
  -- , assumeAuthorized
  -- , authorizeFor
  -- ) where


-- import           Data.Eq   (Eq ((==)))
-- import           Text.Show (Show (show))

-- newtype Authorized a = Authorized
--   { reveal :: a -- ^ Unwrap the Authorized value
--   }
--   deriving (Eq, Show)


-- | A value  that can only be constructed using an authorization function. protected by a 'preposition' (a type representing some kind of proof-of-access requirement).
--   To unwrap the value, it is necessary to provide a witness (a non-bottom value of the type) for the preposition.
--   One nice way of doing this is making the region itself be a Authorized type so that one authorization can be predicated on another authorization at the type level. E.g.
--
-- @
--     lookupSensitiveResource :: path -> AuthorizedFor (Authorized Admin) Resource
-- @
--
-- newtype AuthorizedFor preposition a = Authorized a


-- | A secret value that is "difficult to reveal", meaning that it should only ever be exposed if a suitable value witness is supplied for the type denoted as the guard.
--
--   If a 'Private' is improperly accessed, then the associated safety contract will have been broken.
--   If an improperly constructed guard witness is constructed the contract will also have been broken.
--
--   For example, one way of violating the type-safety of this mechanism would be to use 'unsafeCoerce' to coerce either the "Private" type or the associated guard (so please don't do this!).
--   Passing ⊥ (bottom) as a witness to the guard will lead to undefined behaviour.
--
--   Typically 'Private' will be used with an 'Authorized' type as the guard. E.g.
--
-- @
--     lookupAdminOnlyResource :: path -> Authorized Admin Resource
-- @
--
--   If an operation has undesirable side effects (e.g. 'IO') then the side effect can also be hidden.
--
-- @
--     generateAdminOnlyResource :: path -> Authorized Admin (IO Resource)
-- @
--
--   Alternatively,
--
-- @
--     adminOnlyOperation :: Private (Authorized Admin) (path -> IO ())
-- @
--
newtype Private guard secret = Private secret

-- | Construct a 'Private' value
private :: secret -> Private guard secret
private secret = Private secret

-- | Unwrap a private value by supplying a (non-bottom) witness value for the type that guards the secret.
reveal :: guard -> Private guard secret -> secret
reveal witness (Private secret) = witness `seq` secret

-- | A credential (priviledge/role/identity) that is "difficult to construct", meaning that it should only ever be constructed by trustworthy authorization code.
--   If an 'Authority' is improperly generated, then the associated safety contract will have been broken.
newtype Authority credential = Authority (Proxy credential)

type AuthorizedFor guard credential = Private guard (Authority credential)
type Authorized credential = AuthorizedFor () credential

-- -- | A value that can only be constructed using an authorization function.
-- --   Read this as "Authorized for whoever obtains this value".
-- --   A simple authorized value can be easily revealed, but should only be constructed by authorization code (probably inside your router)
-- type Authorized a = AuthorizedFor () a

-- -- Perhaps use TypeSynonymInstances to implement these:
-- -- instance Show a => Show (AuthorizedFor () a) where
-- --   show (Authorized x) = show x
-- -- instance Eq a => Eq (AuthorizedFor () a) where
-- --   Authorized x == Authorized y = x == y
-- -- instance Functor (AuthorizedFor () a) where
-- --   fmap f (Authorized x) = Authorized (f x)

-- -- | Convert an AuthorizedFor value into an Authorized value by providing a witness value for the region type.
-- --   This function also forces the region witness to ensure that ⊥ isn't passed in.
-- authorizeFor :: region -> AuthorizedFor region a -> Authorized a
-- authorizeFor r (Authorized x)  = r `seq` assumeAuthorized x

-- | Construct an authorized value for a region, by assumption. Use with care!
-- assumeAuthorized :: a -> AuthorizedFor region a
-- assumeAuthorized x = Authorized $! x

-- | Construct a credential. Use with care!
assumeAuthorized :: AuthorizedFor guard (Authority credential)
assumeAuthorized = Private (Authority Proxy
-- assumeAuthority :: Authority credential
-- assumeAuthority = Authority Proxy

-- | Unwrap a simple authorized value.
-- Note that the value is revealed automatically, 'Authorized' does not require a witness value (the witness value is '()').
-- reveal :: prop -> AuthorizedFor prop a -> a
-- reveal witness (Authorized x) = witness `seq` x

