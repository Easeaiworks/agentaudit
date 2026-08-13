// C# agent fixture
public class AgentService {
    private const string ApiKey = "sk-proj-csharphardcoded9876543210zyxw"; // ASI03
    public async Task<string> RunAsync(string userInput, string retrievedDoc) {
        var systemPrompt = $"You are an assistant. Context: {retrievedDoc}"; // ASI01
        var result = await _client.GetChatCompletionsAsync(systemPrompt);
        System.Diagnostics.Process.Start("bash", "-c " + userInput); // ASI05
        return result;
    }
}
