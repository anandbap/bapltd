package authz

func IsWorkstationCredential(claims *GrantClaims) bool {
	legacy := claims.TokenUse == "" && claims.Iat>0 && claims.Exp-claims.Iat >= 300*24*60*60
	return (claims.TokenUse == "workstation" || legacy) && claims.SessionID == "" && claims.Action == "" && claims.Resource == ""
}
