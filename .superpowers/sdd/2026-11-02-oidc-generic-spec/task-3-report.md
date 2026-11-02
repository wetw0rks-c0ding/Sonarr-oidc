Task 3: OIDC fixtures adopted and OidcGroupMapping mapping-driven cases added.
Files: AuthenticationControllerOidcFixture.cs, OidcTokenValidationServiceFixture.cs, OidcGroupMappingFixture.cs.
Build: 0 warnings / 0 errors (Sonarr.Http.Test, net10.0, Platform=Posix, SolutionDir=src).
Adopted untracked fixtures (fixed static/instance, usings, ExchangeOidc signature, removed SetOptions).
Added mapping-driven cases: exact, case-insensitive, highest-wins, unmapped->null, empty->null, malformed ignored.
Concerns: pre-existing stylecop config requires SolutionDir; exact command without it reports SA1200 unrelated to changes.