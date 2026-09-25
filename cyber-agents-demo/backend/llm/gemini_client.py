import asyncio
import json
import logging
from typing import AsyncGenerator

from google import genai
from google.genai import types

logger = logging.getLogger(__name__)


class GeminiClient:
    def __init__(self, api_key: str, model: str = "gemini-3.8-flash"):
        self.api_key = api_key
        self.model_name = model
        self.client = genai.Client(api_key=api_key)

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

        config = types.GenerateContentConfig(
            response_mime_type="application/json",
            system_instruction=system_prompt if system_prompt else None,
            temperature=temperature,
            max_output_tokens=max_tokens,
        )

        for attempt in range(max_retries):
            try:
                response = await asyncio.to_thread(
                    self.client.models.generate_content,
                    model=self.model_name,
                    contents=prompt,
                    config=config,
                )
                text = response.text
                return json.loads(text)

            except json.JSONDecodeError as e:
                logger.warning("Gemini returned non-JSON on attempt %d: %s", attempt + 1, e)
                if attempt == max_retries - 1:
                    return {"error": f"JSON decode error after {max_retries} retries: {e}"}
                await asyncio.sleep(delay)
                delay *= 2

            except Exception as e:
                logger.warning("Gemini request failed on attempt %d: %s", attempt + 1, e)
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
        try:
            config = types.GenerateContentConfig(
                system_instruction=system_prompt if system_prompt else None,
            )
            response = await asyncio.to_thread(
                self.client.models.generate_content_stream,
                model=self.model_name,
                contents=prompt,
                config=config,
            )
            for chunk in response:
                if chunk.text:
                    yield chunk.text
        except Exception as e:
            logger.error("Gemini stream failed: %s", e)
            yield f"[ERROR: {e}]"

    def get_model_info(self) -> dict:
        return {
            "name": self.model_name,
            "provider": "Google Gemini",
            "is_free": True,
        }
