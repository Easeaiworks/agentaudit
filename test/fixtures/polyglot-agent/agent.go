package main

// Go agent fixture
const apiKey = "sk-proj-gohardcodedkey1234567890abcdef" // ASI03

func runAgent(userInput string, retrievedDoc string) {
	systemPrompt := "You are an assistant. Context: " + retrievedDoc // ASI01
	exec.Command("sh", "-c", "echo "+userInput)                      // ASI05
	for {                                                            // ASI08
		invoke(systemPrompt)
	}
}
