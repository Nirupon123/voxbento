from __future__ import annotations

import asyncio
import threading
import time
from unittest.mock import patch

import pytest

from portal.translations.providers.local import (
    LocalProvider,
    ModelEntry,
    _active_translations_per_model,
    _loaded_models,
    eviction_loop,
)


@pytest.mark.anyio
async def test_local_provider_translate_success():
    provider = LocalProvider()
    with patch.object(provider, "_run_inference", return_value="Bonjour") as mock_inference:
        result = await provider.translate(
            provider_name="local",
            text="Hello",
            target_lang_name="French",
            target_lang_code="fr",
            source_lang_name="English",
            model="nllb-200-distilled-600M",
            api_key=None,
        )
        assert result == "Bonjour"
        mock_inference.assert_called_once_with("Hello", "eng_Latn", "fra_Latn", "nllb-200-distilled-600M")


@pytest.mark.anyio
async def test_local_provider_translate_invalid_language():
    provider = LocalProvider()
    result = await provider.translate(
        provider_name="local",
        text="Hello",
        target_lang_name="UnknownLanguage",
        target_lang_code="xx",
        source_lang_name="English",
        model="nllb-200-distilled-600M",
        api_key=None,
    )
    assert result is None


def test_local_provider_ref_count_decrements_on_exception():
    provider = LocalProvider()
    model_size = "test-model-exception"

    _active_translations_per_model[model_size] = 0

    with patch("portal.translations.providers.local.get_model_and_tokenizer", side_effect=ValueError("Mock Error")):
        result = provider._run_inference("Hello", "eng_Latn", "fra_Latn", model_size)
        assert result is None

    assert _active_translations_per_model.get(model_size, 0) == 0


@pytest.mark.anyio
async def test_local_provider_eviction_respects_ref_count():
    model_size = "test-model-eviction"

    # Populate loaded models with an idle timestamp (older than 1 hour)
    _loaded_models[model_size] = ModelEntry(model=None, tokenizer=None, last_used=time.time() - 4000)

    # Active reference prevents eviction
    _active_translations_per_model[model_size] = 1

    with patch("asyncio.sleep", side_effect=[None, asyncio.CancelledError()]):
        try:
            await eviction_loop()
        except asyncio.CancelledError:
            pass

    assert model_size in _loaded_models

    # Releasing the reference allows eviction
    _active_translations_per_model[model_size] = 0

    with patch("asyncio.sleep", side_effect=[None, asyncio.CancelledError()]):
        try:
            await eviction_loop()
        except asyncio.CancelledError:
            pass

    assert model_size not in _loaded_models



@pytest.mark.anyio
async def test_eviction_loop_does_not_block_on_model_load():
    model_size = "test-model-slow-load"
    if model_size in _loaded_models:
        del _loaded_models[model_size]

    def slow_download(*args, **kwargs):
        time.sleep(2)
        return model_size

    def background_loader():
        with patch("huggingface_hub.snapshot_download", side_effect=slow_download), \
             patch("ctranslate2.Translator"), \
             patch("transformers.AutoTokenizer.from_pretrained"):
            from portal.translations.providers.local import get_model_and_tokenizer

            get_model_and_tokenizer(model_size)

    # Start the slow model load in a background thread
    t = threading.Thread(target=background_loader)
    t.start()

    # Yield control to let the thread acquire the locks and start sleeping
    await asyncio.sleep(0.2)

    start_time = time.time()

    # Run eviction loop for one pass, expecting it to NOT block on the slow download
    with patch("asyncio.sleep", side_effect=[None, asyncio.CancelledError()]):
        try:
            await asyncio.wait_for(eviction_loop(), timeout=1.0)
        except asyncio.CancelledError:
            pass
        except TimeoutError:
            pytest.fail("Eviction loop timed out because it was blocked by the model loading lock!")

    elapsed = time.time() - start_time
    assert elapsed < 1.0, f"Eviction loop blocked for {elapsed} seconds, indicating lock contention!"

    t.join()
