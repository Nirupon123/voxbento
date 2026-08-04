from __future__ import annotations

import asyncio
import logging

from portal.database import get_session
from portal.models import DBBooth, Event, Room, TranscriptTranslation
from portal.translations.constants import OPENAI_COMPATIBLE_ENDPOINTS, TranslationProviderEnum
from portal.translations.keys import get_translation_api_key
from portal.translations.providers.anthropic import AnthropicProvider
from portal.translations.providers.gemini import GeminiProvider
from portal.translations.providers.local import LocalProvider
from portal.translations.providers.openai import OpenAIProvider

logger = logging.getLogger(__name__)

openai_provider = OpenAIProvider()

PROVIDERS = {
    TranslationProviderEnum.GEMINI.value: GeminiProvider(),
    TranslationProviderEnum.ANTHROPIC.value: AnthropicProvider(),
    TranslationProviderEnum.LOCAL.value: LocalProvider(),
}
for p in OPENAI_COMPATIBLE_ENDPOINTS.keys():
    PROVIDERS[p] = openai_provider


class TranslationWorker:
    """
    Handles fetching translations asynchronously for a given canonical segment.
    """

    def __init__(self, broadcast_callback):
        self.broadcast_callback = broadcast_callback

    async def handle_translation(self, room_id: int, segment_id: int, text: str, booth_id_str: str):
        """Called when a finalized STT segment is saved. Fires off LLM requests for enabled target languages."""
        from sqlalchemy import select
        from sqlalchemy.orm import selectinload

        from portal.models import TranscriptSegment

        async with get_session() as session:
            segment = await session.scalar(select(TranscriptSegment).where(TranscriptSegment.id == segment_id))
            if not segment:
                logger.error(f"[{booth_id_str}] handle_translation abort: segment {segment_id} not found")
                return

            logger.debug(
                "[%s] handle_translation triggered for segment %s (len=%s)", booth_id_str, segment_id, len(text)
            )

            provider = None
            model = None
            enabled_langs = []
            room = None

            if segment.booth_id is None:
                # Floor translation
                room = await session.scalar(
                    select(Room).options(selectinload(Room.translation_languages)).where(Room.id == room_id)
                )
                if not room or not room.floor_translation_enabled:
                    logger.error(
                        f"[{booth_id_str}] handle_translation abort: floor_translation_enabled is false for room {room_id}"
                    )
                    return
                provider = room.floor_translation_provider
                model = room.floor_translation_model
                enabled_langs = [lang for lang in room.translation_languages if lang.enabled]
                source_lang_code = room.floor_language_code
            else:
                # Booth translation
                booth = await session.scalar(
                    select(DBBooth)
                    .options(selectinload(DBBooth.translation_languages))
                    .where(DBBooth.id == segment.booth_id)
                )
                if not booth or not booth.translation_enabled:
                    return
                provider = booth.translation_provider
                model = booth.translation_model
                enabled_langs = [lang for lang in booth.translation_languages if lang.enabled]
                room = await session.scalar(select(Room).where(Room.id == room_id))
                source_lang_code = booth.language_code

            if not provider or not model or not enabled_langs or not room:
                logger.error(
                    f"[{booth_id_str}] handle_translation abort: missing config. provider={provider}, model={model}, langs={enabled_langs}"
                )
                return

            event = await session.scalar(select(Event).where(Event.id == room.event_id))
            if not event:
                return

            api_key = self._get_translation_api_key(event, provider)
            if not api_key and provider != TranslationProviderEnum.LOCAL.value:
                logger.error(f"[{booth_id_str}] Translation API key not found for provider {provider}")
                return

            import pycountry

            source_lang_obj = pycountry.languages.get(alpha_2=source_lang_code) if source_lang_code else None
            source_lang_name = source_lang_obj.name if source_lang_obj else (source_lang_code or "English")

            # Execute translation for all target languages concurrently
            tasks = [
                self._translate_and_broadcast(
                    event,
                    room,
                    provider,
                    model,
                    api_key,
                    lang.language_code,
                    lang.language_name,
                    source_lang_name,
                    segment_id,
                    text,
                    booth_id_str,
                )
                for lang in enabled_langs
            ]
            logger.error(f"[{booth_id_str}] Spawning {len(tasks)} translation tasks for {enabled_langs}")
            await asyncio.gather(*tasks)

    def _get_translation_api_key(self, event: Event, provider: str) -> str | None:
        return get_translation_api_key(event, provider)

    async def _translate_and_broadcast(
        self,
        event: Event,
        room: Room,
        provider: str,
        model: str,
        api_key: str,
        lang_code: str,
        lang_name: str,
        source_lang_name: str,
        segment_id: int,
        text: str,
        booth_id_str: str,
    ):
        try:
            translated_text = await self._call_llm(provider, model, api_key, text, lang_name, source_lang_name)
            if not translated_text:
                return

            # Save to DB using an independent session to avoid concurrent transaction crashes
            async with get_session() as local_session:
                translation = TranscriptTranslation(
                    segment_id=segment_id, language_code=lang_code, text=translated_text
                )
                local_session.add(translation)
                await local_session.commit()

            # Broadcast to WebSocket
            await self.broadcast_callback(
                booth_id_str, {"type": "translation", "language_code": lang_code, "text": translated_text}
            )

        except Exception as e:
            logger.error(f"[{booth_id_str}] Translation failed for {lang_code}: {e}")

    async def _call_llm(
        self,
        provider: str,
        model: str,
        api_key: str | None,
        text: str,
        target_lang_name: str,
        source_lang_name: str = "English",
    ) -> str | None:
        provider_instance = PROVIDERS.get(provider)
        if not provider_instance:
            logger.error(f"Translation provider {provider} not supported.")
            return None

        return await provider_instance.translate(
            provider_name=provider,
            text=text,
            target_lang_name=target_lang_name,
            target_lang_code="",  # Not explicitly passed from current DB schema
            source_lang_name=source_lang_name,
            model=model,
            api_key=api_key,
        )
