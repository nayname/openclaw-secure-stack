"""LLM client for governance plan generation."""

from anthropic import Anthropic


class LLMClient:
    """Simple LLM client wrapper."""

    def __init__(self, model: str = "claude-sonnet-4-20250514"):
        self.client = Anthropic()
        self.model_name = model

    def complete(self, prompt: str, temperature: float = 0) -> str:
        response = self.client.messages.create(
            model=self.model_name,
            max_tokens=4096,
            temperature=temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text