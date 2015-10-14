{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE RankNTypes                #-}
{-# LANGUAGE Safe                      #-}
-- |
-- Module:      Data.Access
--
-- Use this module to work with correct-by-construction authorized/authorization values.
--
module Data.Access
  ( -- * Guidelines
    -- $guidelines

  -- Re-exports
    Access.AuthorizedIf
  , Private.Private
  , Private.Private'
  , Private.private
  , Private.reveal
  -- Exports
  , Authorized
  , AuthorizedIf'
  , Authorized'
  , authorize
  , Confidential
  , Confidential'
  , AuthorizedFor
  , Authorization
  , Authorization'
  , authorizeErr
  , revealFor
  ) where

import qualified Data.Access.Unsafe as Access (AuthorizedIf)
import qualified Data.Private       as Private (Private, Private', private,
                                                reveal)

-- $guidelines
--
-- This package provides a type safe scheme that maintainers of large systems can use to declaratively annotate values with access restrictions.
--
-- ** Disclaimer
--
-- It should be noted that this package is not intended to provide any "network security" whatsoever. You will need to implement authentication and cryptography separately.
-- This package also does not dictate how access controls should be implemented; it merely provides a scheme to help application programmers avoid making certain mistakes while specifying access control policies in application code.
--
-- This probably does not need to be said, but, of course, this package is in not intended to be robust against an adversary with access to the source code.
-- There are many escape hatches in Haskell that you can use to circumvent the guarantees provided by this package (notably 'unsafeCoerce').
--
-- ** Privilege and/or Confidentiality
--
-- >           Authorized ("Difficult to construct")
-- >           +
-- >
-- >           ↑
-- >           |
-- >           |
-- >           |
-- >         P |
-- >         R |
-- >         I |
-- >         V |
-- >         I |
-- >         L |
-- >         E |
-- >         G |
-- >         E |
-- >           |
-- >           |
-- >           |
-- >            -------------------------------→  +
-- >              C O N F I D E N T I A L I T Y     Private
-- >                                                ("Difficult to reveal")
--
-- 'Authorized' annotates values with privileges that need to be mindfully allotted.
-- 'Private' annotates values that need to be carefully revealed.
--
-- Since 'AuthorizedIf' builds on 'Private', we can go a little bit further using a slightly dubious understanding of the graphic above:
--
-- >           Authorized ("Difficult to construct")
-- >           +  --
-- >                  --
-- >           ↑          --
-- >           |              --
-- >           |                  --
-- >           |                      --
-- >         P |                          --        AuthorizedIf ("Can only use authority if a condition is met")
-- >         R |                              --  +-
-- >         I |                                  | \--
-- >         V |                                        --
-- >         I |                                  |   \    --
-- >         L |                                              +   AuthorizedFor ("Depends on another privilege/authorization")
-- >         E |                                  |     \
-- >         G |
-- >         E |                                  |       \
-- >           |
-- >           |                                  |         \
-- >           |
-- >            -------------------------------→  +  --  --  -+
-- >              C O N F I D E N T I A L I T Y     Private     Confidential ("Requires privilege/authorization to reveal")
-- >
--
-- ** Using Data.Access with Yesod
--
-- This package doesn't provide a function to convert to Yesod's 'AuthResult' to avoid the extra dependency, but it's very easy to do yourself:
--
-- >   module Data.Access.Yesod
-- >     ( toYesodAuth
-- >     ) where
-- >
-- >   import           Prelude     (seq)
-- >   import           Data.Access
-- >   import           Data.Either (Either (..))
-- >   import           Data.Text   (Text)
-- >   import qualified Yesod.Core  as Yesod (AuthResult (Authorized, Unauthorized))
-- >
-- >   -- | Convert authorization to a Yesod auth result
-- >   toYesodAuth :: Authorization Text credential -> Yesod.AuthResult
-- >   toYesodAuth (Left e) = Yesod.Unauthorized e
-- >   toYesodAuth (Right x) = x `seq` Yesod.Authorized
--
-- >   module Data.Access.Yesod.Unsafe
-- >     ( fromYesodAuth
-- >     ) where
-- >
-- >   import           Data.Access
-- >   import qualified Data.Access.Unsafe as Unsafe
-- >   import           Data.Either        (Either (..))
-- >   import           Data.Text          (Text)
-- >   import qualified Yesod.Core         as Yesod (AuthResult (..))
-- >
-- >   -- | Convert from a Yesod auth result to an authorization
-- >   fromYesodAuth :: Yesod.AuthResult -> Authorization Text credential
-- >   fromYesodAuth Yesod.Authorized = Right Unsafe.assumeAuthorized
-- >   fromYesodAuth (Yesod.Unauthorized msg) = Left msg
-- >   fromYesodAuth Yesod.AuthenticationRequired = Left "Authentication required"
--

-- ** Simple access policies

-- | Read this as "Authorized for whoever obtains this value".
-- A simple authorized value can be easily revealed by anyone (by simply supplying the '()' witness value),
-- but should only be constructed by authorization code (probably inside your router).
-- Once you have an 'Authorized' credential, it is possible to pass on a less permissive credential along by
-- using @private . reveal@ to construct a more restricted 'AuthorizedIf' credential.
type Authorized credential = Access.AuthorizedIf () credential

-- | An very simple and permissive authorization that can be used in situations where fine-grained credentials are not really a requirement.
type AuthorizedIf' guard = Access.AuthorizedIf guard ()

-- | An extremely simple and permissive authorization that can be used in situations where fine-grained control is not really a requirement.
type Authorized' = Authorized ()

-- TODO: Perhaps use TypeSynonymInstances to implement these?
--
-- instance Show a => Show (AuthorizedIf () a) where
--   show (Authorized x) = "Authorized"
-- instance Eq a => Eq (AuthorizedFor () a) where
--   Authorized x == Authorized y = x == y


-- | Grant the access specified by the credential by supplying the required witness.
--   This uses 'reveal' internally to re-authorize @AuthorizedIf guard@ to the most permissive authorization type, @AuthorizedIf ()@.
--   @AuthorizedIf ()@ is denoted, simply, as 'Authorized', since '()' can be supplied at any time.
authorize :: guard -> Access.AuthorizedIf guard credential -> Authorized credential
authorize witness = Private.private . Private.reveal witness

-- ** More sophisticated access policies

-- | A secret value that requrires authorization to reveal.
--
--   Often 'Private' will be used with an 'Authorized' type as the guard. E.g.
--
-- @
--     lookupAdminOnlyResource :: path -> Private (Authorized Admin) Resource
-- @
--
--   If an operation has undesirable side effects (e.g. 'IO') then the side effect can also be hidden.
--
-- @
--     generateAdminOnlyResource :: path -> Private (Authorized Admin) (IO Resource)
-- @
--
--   Alternatively,
--
-- @
--     adminOnlyOperation :: Private (Authorized Admin) (path -> IO ())
-- @
--
--   'Confidential' provides a type synonym in order to make this use case idiomatic:
--
-- @
--     lookupAdminOnlyResource :: path -> Confidential Admin Resource
--     generateAdminOnlyResource :: path -> Confidential Admin (IO Resource)
--     adminOnlyOperation :: Confidential Admin (path -> IO ())
-- @
--
type Confidential requiredCredential secret = Private.Private (Authorized requiredCredential) secret

-- | A simpler, more permissive confidential value that is protected by 'Authorized'' instead of 'Authorized' as the guard
type Confidential' secret = Private.Private Authorized' secret

-- | Predicates one authorization on another authorization
type AuthorizedFor requiredCredential credential = Access.AuthorizedIf (Authorized requiredCredential) credential

-- | 'Authorization' is just a type synonym for @Either e (Authorized guard credential)@, so that Authorizations can be checked in a cascading fashion using all the usual combinators, 'runEitherT', etc.
type Authorization e credential = Either e (Authorized credential)
type Authorization' e = Either e Authorized'

-- | Authorize a credential only if we have 'Just' the witness (similar to 'readErr','justErr',etc functions from 'Control.Error.Safe')
authorizeErr :: e -> Maybe guard -> Access.AuthorizedIf guard credential -> Authorization e credential
authorizeErr e Nothing _           = Left e
authorizeErr _ (Just witness) auth = Right (authorize witness auth)

-- | Reveal only for a valid authorization, the result is @Nothing@ otherwise
revealFor :: Authorization e credential -> Confidential credential secret -> Maybe secret
revealFor (Left _)     _ = Nothing
revealFor (Right auth) p = Just (Private.reveal auth p)

