{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE RankNTypes                #-}
-- |
-- Module:      Data.Access
--
-- Use this module to work with reasonably correct-by-construction authorized/authorization values.
--
module Data.Access
  ( -- * Guidelines
    -- $guidelines

    -- Authorized
  -- , Authorized'
  -- , Authorization
  -- , Authorization'
  -- , AuthorizedFor
  -- , AuthorizedFor'
  -- , AuthorizationFor
  -- , AuthorizationFor'
  -- , Private
  -- , revealFor
  -- , revealIf
  -- , revealIfFor
  -- , alwaysAuthorized

  Private
  -- Re-exports
  , Access.private
  , Access.reveal
  ) where

import qualified Data.Access.Unsafe as Access (Private, private, reveal)
import qualified Data.Access.Unsafe as Unsafe (Authority, assumeAuthority)
-- import           Data.Either
-- import           Data.Function      ((.))
-- import           Data.Functor       (fmap)
-- import           Data.Maybe         (Maybe (..))

-- $guidelines
--
-- This package provides a type safe scheme that maintainers of large systems can use to declaratively annotate values with access restrictions.
--
-- ** Disclaimer
--
-- Use this package at your own risk! It should be noted that this package is not intended to provide any "security" in the sense that it doesn't provide any security primitives.
-- You will need to implement authentication and cryptography separately. Even then, this package does not dictate how access controls should be implemented;
-- it merely provides a scheme that might help you to avoid making certain obvious mistakes in your application code.
-- This probably does not need to be said, but, of course, this package is in no way intended to be robust against an adversary with access to the source code.
-- There are many escape hatches in Haskell that you can use to circumvent the guarantees provided by this package (notably 'unsafeCoerce').
--
-- ** Privildege and/or Confidentiality
--
--
-- >           ("Difficult to construct")
-- >           Authorized                       AuthorizedFor
-- >           +  --  --  --  --  --  --  --  --  +
-- >
-- >           ↑                                  |
-- >           |
-- >           |                                  |
-- >         P |
-- >         R |                                  |
-- >         I |
-- >         V |                                  |
-- >         I |
-- >         L |                                  |
-- >         E |
-- >         D |                                  |
-- >         G |
-- >         E |                                  |
-- >           |
-- >           |                                  |
-- >           |
-- >            -------------------------------→  + Private ("Difficult to reveal")
-- >              C O N F I D E N T I A L I T Y
--
--
-- 'Authorized' annotates values with priviledges that need to be mindfully allotted.
-- 'Private' annotates values that need to be carefully revealed.
--
-- ** Using Data.Auth with Yesod
--
-- This package doesn't provide a function to convert to Yesod's 'AuthResult' to avoid the extra dependency, but it's very easy to do yourself:
--
-- >   module Data.Auth.Yesod
-- >     ( toYesodAuth
-- >     ) where
-- >
-- >   import           Data.Auth
-- >   import           Data.Either (Either (..))
-- >   import           Data.Text   (Text)
-- >   import           Prelude     (seq)
-- >   import qualified Yesod.Core  as Yesod (AuthResult (Authorized, Unauthorized))
-- >
-- >   -- | Convert authorization to a Yesod auth result
-- >   toYesodAuth :: Authorization Text a -> Yesod.AuthResult
-- >   toYesodAuth (Left e) = Yesod.Unauthorized e
-- >   toYesodAuth (Right x) = x `seq` Yesod.Authorized
--
-- ** Pre-authorized constants
--
-- As with any security primitive, auth-types cannot protect you from making excessively generous assumptions.
-- In particular, types will need to be carefully specified in order to protect you.
--
-- It is possible to create a pre-authorized values in certain situations where direct access is required.
-- However, this will give you an escape hatch.
--
-- >   -- | A unit value that is always authorized, regardless the circumstances. Use with care!
-- >   --   Use with care! This is a bit of an escape hatch right now since Authorization is a Functor
-- >   alwaysAuthorized :: {- Authorization' e -} Authorized'
-- >   alwaysAuthorized = {- pure -}  (Construct.assumeAuthorized ())
--
-- TODO: Some alternatives
--

-- ** Simple authorizations

type Private = Access.Private


{-
--
-- 'Authorization' is just a type synonym for @Either e (Authorized a)@, so they can be checked in a cascading fashion using all the usual combinators, 'runEitherT', etc.
--


type Authorized a = Auth.Authorized a
type Authorized' = Auth.Authorized ()
type Authorization e a = Either e (Authorized a)
type Authorization' e = Either e Authorized'

-- ** Authorizations restricted to some kind of region or role

type AuthorizedFor region a = Auth.AuthorizedFor region a
type AuthorizedFor' region = Auth.AuthorizedFor region ()
type AuthorizationFor region e a = Either e (AuthorizedFor region a)
type AuthorizationFor' region e = Either e (AuthorizedFor' region)




 -- ** Simple authorizations


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

-- -- | Unwrap a simple authorized value.
-- -- Note that the value is revealed automatically, 'Authorized' does not require a witness value (the witness value is '()').
-- reveal :: Authorized a -> a
-- reveal (Authorized x) = x




-- ** Private values


-- TODO: Private is in some sense the oposite of Authorized (it can be constructed easily, but not revealed)
--
-- | A less picky version of AuthorizedFor that can be unwrapped by supplying any authorized unit value
--

-- newtype Private_ a = Private_ a -- Don't export this constructor
-- type Private a = forall x . AuthorizedFor (AuthorizedFor' x) a
type Private a = AuthorizedFor Authorized' a

-- | Construct a private value
--
-- Note that private is a constructor and there is some opportunity to use 'private' as an escape hatch to
-- generate authorized values of the form @AuthorizedFor Authorized' a@ in order to bypass access in this form.
-- Technically 'private' should only be exported in 'Data.Auth.Unsafe'.
-- However, in practice specifying @AuthorizedFor (AuthorizedFor Authorized' a) b@ doesn't make any sense as an
-- access restriction since  @Authorized'@ is a rather permissive restriction, hence its use in 'Private'.
-- It is not possible to generate something like 'AuthorizedFor (Authorized Admin) Resource' with 'private'.
private :: a -> Private a
private = assumeAuthorized a

-- ** Accessors

-- | Unwrap an AuthorizedFor value by providing a witness value for the region type
--   This function also forces the region witness to ensure that bottom isn't passed in
revealFor :: region -> AuthorizedFor region a -> a
revealFor r = Auth.reveal . Auth.authorizeFor r

-- | Convert from an authorization to a value
revealIf :: Authorization e a -> Maybe a
revealIf (Left _) = Nothing
revealIf (Right x) = Just (Auth.reveal x)

-- | Convert from an authorization to a value by providing a witness for the region type
--   (This function may not be needed all that often)
revealIfFor :: region -> AuthorizationFor region e a -> Maybe a
revealIfFor r = revealIf . fmap (Auth.authorizeFor r)

-}
