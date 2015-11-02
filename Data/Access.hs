{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE Safe              #-}
-- experimental
-- {-# LANGUAGE ExistentialQuantification #-}
-- {-# LANGUAGE PolyKinds         #-}
-- {-# LANGUAGE RankNTypes        #-}
-- {-# LANGUAGE FlexibleInstances         #-}
-- {-# LANGUAGE TypeSynonymInstances      #-}
-- |
-- Module:      Data.Access
--
-- Use this module to work with correct-by-construction authorized/authorization values.
--
module Data.Access
  ( -- * Guidelines
    -- $guidelines

  -- Re-exports
    Access.Authority
  , Private.Private
  , Private.Private'
  , Private.private
  , Private.reveal
  -- Simple access policies
  , Authority'
  , diminishAuthority
  , Confidential
  , Confidential'
  , Authorized (unAuthorized)
  , Authorized'
  , authorize
  , diminishAuthorized
  , Authorization
  , Authorization'
  , AuthorizationT
  , AuthorizationT'
  , runAuthorizationT
  -- More sophisticated access policies
  -- TODO: Note that these are still somewhat experimental
  , AuthorityIf
  , AuthorityIf'
  , AuthorityFor
  , AuthorizedIf
  , AuthorizedIf'
  , AuthorizedFor
  , revealFor
  ) where

import           Prelude                    (seq)

-- import           Control.Category           (Category (..))
-- import           Control.Applicative        (pure)
import           Control.Monad.Trans.Except (Except, ExceptT, except, runExcept,
                                             runExceptT)
import qualified Data.Access.Unsafe         as Access (Authority)
import qualified Data.Access.Unsafe         as Unsafe (authority)
import           Data.Either                (Either (..))
import           Data.Functor               (Functor, fmap)
import           Data.Maybe                 (Maybe (..))
import qualified Data.Private               as Private (Private, Private',
                                                        private, reveal)

-- $guidelines
--
-- This package provides a type safe scheme that maintainers of large systems can use to declaratively annotate types with access restrictions.
--
-- ** Disclaimer
--
-- It should be noted that this package is not intended to provide any "network security" whatsoever. You will need to implement authentication and cryptography separately.
-- This package also does not dictate how access controls should be implemented; it merely provides a simple scheme corresponding to a more restricted form of 'Proxy' and 'Tagged'.
--
-- This package does not intended to be robust against an adversary with access to the source code either.
-- There are escape hatches in Haskell that you can use to circumvent the guarantees provided by this package.
--
-- ** Privilege and/or Confidentiality
--
-- >           Authority ("Difficult to construct")
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
-- 'Authority' annotates values with privileges that need to be mindfully allotted.
-- 'Private' annotates values that need to be carefully revealed.
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
-- >   import qualified Yesod.Core  as Yesod (AuthResult (Authority, Unauthorized))
-- >
-- >   -- | Convert authorization to a Yesod auth result
-- >   toYesodAuth :: Authorization Text credential -> Yesod.AuthResult
-- >   toYesodAuth (Left e) = Yesod.Unauthorized e
-- >   toYesodAuth (Right x) = x `seq` Yesod.Authority
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
-- >   fromYesodAuth Yesod.Authority = Right Unsafe.assumeAuthority
-- >   fromYesodAuth (Yesod.Unauthorized msg) = Left msg
-- >   fromYesodAuth Yesod.AuthenticationRequired = Left "Authentication required"
--

-- ** Simple access policies

-- | A simple, permissive 'Authority' that can be used in situations where fine-grained control is not really a requirement.
type Authority' = Access.Authority ()

-- | Diminish the credential provided by an authority to '()' in order to use it in a less confined setting
--   (Unit dentotes the credential with the least specification)
diminishAuthority :: Access.Authority credential -> Authority'
diminishAuthority acred = Private.reveal acred unitByCred
  where
    unitByCred = Private.private Unsafe.authority :: AuthorityFor credential ()

-- | A secret value that requrires authority to reveal.
--
--   Often 'Private' will be used with an 'Authority' type as the guard. E.g.
--
-- @
--     lookupAdminOnlyResource :: path -> Private (Authority Admin) Resource
-- @
--
--   If an operation has undesirable side effects (e.g. 'IO') then the side effect can also be hidden.
--
-- @
--     generateAdminOnlyResource :: path -> Private (Authority Admin) (IO Resource)
-- @
--
--   Alternatively,
--
-- @
--     adminOnlyOperation :: Private (Authority Admin) (path -> IO ())
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
type Confidential requiredCredential secret             = Private.Private (Access.Authority requiredCredential) secret

-- | A simpler, more permissive confidential value that is protected by 'Authority'' instead of 'Authority' as the guard
type Confidential' secret                               = Private.Private Authority' secret

-- | A value that can only be constructed using a special, trusted authorization function and can only be used once a witness is supplied for the guard.
--
--   Authorized corresponds to a more restricted Tagged
newtype Authorized credential value = Authorized { unAuthorized :: value }

-- | A simple, permissive 'Authorized' that can be used in situations where fine-grained control is not really a requirement.
type Authorized' value = Authorized () value

-- | Construct an authorized value along with the credential that authorizes it
authorize :: Access.Authority credential -> value -> Authorized credential value
authorize a s = a `seq` Authorized s

-- | Diminish the credential tagged onto a value to '()' in order to use it in a less confined setting
--   (Unit dentotes the credential with the least specification)
diminishAuthorized :: Authorized credential value -> Authorized credential value
diminishAuthorized aval = authorize Unsafe.authority (unAuthorized aval)

-- | 'Authorization' is just a type synonym for @Except e (Authority guard credential)@, so that Authorizations can be checked in a cascading fashion using all the usual combinators, 'runExceptT', etc.
type Authorization e credential                         = Except e (Access.Authority credential)
type Authorization' e                                   = Except e Authority'

-- | 'Authorization' is just a type synonym for @ExceptT e (Authority guard credential)@, so that Authorizations can be checked in a cascading fashion using all the usual combinators, 'runExceptT', etc.
type AuthorizationT e m credential                      = ExceptT e m (Access.Authority credential)
type AuthorizationT' e m                                = ExceptT e m Authority'

runAuthorizationT :: Functor m => AuthorizationT e m credential -> m (Authorization e credential)
runAuthorizationT auth = fmap except (runExceptT auth)

-- | Reveal only for a valid authorization, the result is @Nothing@ otherwise
--   TODO: A possible alternative:
--         authorizeWith :: AuthorizationT e m credential -> Confidential credential secret -> m (Authorized credential secret)
--         and then simply implement ToJSON, etc for Authorized
revealFor :: Authorization e credential -> Confidential credential secret -> Maybe secret
revealFor eauth c = case runExcept eauth of
  (Left _)     -> Nothing
  (Right auth) -> Just (Private.reveal auth c)

-- -- | Authorize a credential only if we have 'Just' the witness (similar to 'readErr','justErr',etc functions from 'Control.Error.Safe')
-- reauthErr :: e -> Maybe guard -> AuthorityIf guard credential -> Authorization e credential
-- reauthErr e Nothing _           = Left e
-- reauthErr _ (Just witness) auth = Right (reauth witness auth)

-- ** More sophisticated access policies
--
-- TODO: these are still somewhat experimental and may be altered or removed in future.
--

-- | A credential that can only be constructed by supplying a witness to the guard type
type AuthorityIf guard credential                       = Private.Private guard (Access.Authority credential)

-- | An very simple and permissive authorization that can be used in situations where fine-grained credentials are not really a requirement.
type AuthorityIf' guard                                 = AuthorityIf guard ()

-- | Predicates one authority on another
type AuthorityFor requiredCredential credential         = AuthorityIf (Access.Authority requiredCredential) credential

-- | An authorized value that can only be constructed by supplying a witness to the guard type
type AuthorizedIf guard credential secret               = Private.Private guard (Authorized credential secret)

-- | An authorized value that can only be constructed by supplying a witness to the guard type
type AuthorizedIf' guard secret                         = Private.Private guard (Authorized' secret)

-- | Predicates an authorized value on some authority
type AuthorizedFor requiredCredential credential secret = AuthorizedIf (Access.Authority requiredCredential) credential secret

-- instance Category AuthorityFor where
--   id = Private.private Unsafe.authority :: AuthorityFor a a
--   bc . ab = Private.private (Private.reveal (Unsafe.unPrivate ab) bc)

