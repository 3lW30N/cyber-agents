import asyncio
import json
import logging
from typing import AsyncGenerator

from groq import AsyncGroq

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = "llama-3.3-70b-versatile"


class GroqClient:
    def __init__(self, api_key: str, model: str = _DEFAULT_MODEL):
        self.api_key = api_key
        self.model_name = model
        self.client = AsyncGroq(api_key=api_key)

    async def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float = 0.7,
        max_tokens: int = 512,
        **kwargs,
    ) -> dict:
        max_retries = 2
        delay = 0.5

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        for attempt in range(max_retries):
            try:
                response = await self.client.chat.completions.create(
                    model=self.model_name,
                    messages=messages,
                    response_format={"type": "json_object"},
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                content = response.choices[0].message.content
                return json.loads(content)

            except json.JSONDecodeError as e:
                logger.warning("Groq returned non-JSON on attempt %d: %s", attempt + 1, e)
                if attempt == max_retries - 1:
                    return {"error": f"JSON decode error after {max_retries} retries: {e}"}
                await asyncio.sleep(delay)
                delay *= 2

            except Exception as e:
                logger.warning("Groq request failed on attempt %d: %s", attempt + 1, e)
                if attempt == max_retries - 1:
                    return {"error": str(e)}
                await asyncio.sleep(delay)
                delay *= 2

        return {"error": "Max retries exceeded"}

    async def chat(
        self,
        user: str,
        system: str = "",
        temperature: float = 0.7,
        max_tokens: int = 512,
        **kwargs,
    ) -> dict:
        """Alias for complete() with blue-agent-style (system=, user=) signature."""
        return await self.complete(
            prompt=user,
            system_prompt=system,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    async def stream_complete(
        self, prompt: str, system_prompt: str = ""
    ) -> AsyncGenerator[str, None]:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        try:
            stream = await self.client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                stream=True,
            )
            async for chunk in stream:
                delta = chunk.choices[0].delta.content
                if delta:
                    yield delta
        except Exception as e:
            logger.error("Groq stream failed: %s", e)
            yield f"[ERROR: {e}]"

    def get_model_info(self) -> dict:
        return {
            "name": self.model_name,
            "provider": "Groq (Llama 3.1)",
            "is_free": True,
        }
