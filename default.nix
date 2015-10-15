{ mkDerivation, base, stdenv }:
mkDerivation {
  pname = "access";
  version = "0.1.1";
  src = ./.;
  libraryHaskellDepends = [ base ];
  homepage = "https://github.com/circuithub/comparable-key";
  description = "A simple representation for type-safe access control";
  license = stdenv.lib.licenses.mit;
}
