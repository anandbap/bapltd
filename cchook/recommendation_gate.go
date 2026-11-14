package main

import "strings"

func isHumanRecommendationCommand(command string) bool {
	tokens := strings.Fields(strings.ReplaceAll(strings.ToLower(command), "\"", " "))
	for i := 0; i+1 < len(tokens); i++ {
		token := strings.ReplaceAll(tokens[i], "\\", "/")
		base := token[strings.LastIndex(token, "/")+1:]
		if base != "bap" && base != "bap.exe" && base != "bapedge" && base != "bapedge.exe" {
			continue
		}
		if tokens[i+1] == "recommend" || (tokens[i+1] == "review" && i+2 < len(tokens) && tokens[i+2] == "recommend") {
			return true
		}
	}
	return false
}
