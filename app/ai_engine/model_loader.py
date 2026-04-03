"""
Model Loader Module
===================
Handles loading of pre-trained neural network models with resilience.
Rebuilds model architectures in TF 2.x and loads Keras 3.x-saved weights.
"""

import os
import pickle
from tensorflow.keras import Sequential, Model
from tensorflow.keras.layers import (
    Input, Embedding, SpatialDropout1D, Bidirectional,
    LSTM, Dropout, Dense, Conv2D, MaxPooling2D, UpSampling2D
)

# Global model registry
_url_model = None
_img_model = None
_tokenizer = None
_models_initialized = False

# Sequence length used for URL character encoding (must match training)
URL_SEQUENCE_LENGTH = 200


class _KerasCompatUnpickler(pickle.Unpickler):
    """Remaps Keras 3.x module paths to Keras 2.x equivalents for unpickling."""

    def find_class(self, module, name):
        if module.startswith('keras.src.legacy.'):
            module = 'keras.' + module[len('keras.src.legacy.'):]
        elif module.startswith('keras.src.'):
            module = 'keras.' + module[len('keras.src.'):]
        return super().find_class(module, name)


def _build_url_model():
    """Rebuild URL LSTM architecture matching the Keras 3.x-trained model."""
    model = Sequential([
        Embedding(100, 32, input_length=URL_SEQUENCE_LENGTH),
        SpatialDropout1D(0.2),
        Bidirectional(LSTM(64)),
        Dropout(0.3),
        Dense(32, activation='relu'),
        Dense(1, activation='sigmoid')
    ])
    model.build((None, URL_SEQUENCE_LENGTH))
    return model


def _build_image_model():
    """Rebuild Image Autoencoder architecture matching the Keras 3.x-trained model."""
    inp = Input(shape=(128, 128, 3))
    # Encoder
    x = Conv2D(32, (3, 3), activation='relu', padding='same')(inp)
    x = MaxPooling2D((2, 2), padding='same')(x)
    x = Conv2D(16, (3, 3), activation='relu', padding='same')(x)
    x = MaxPooling2D((2, 2), padding='same')(x)
    # Bottleneck
    x = Conv2D(16, (3, 3), activation='relu', padding='same')(x)
    # Decoder
    x = UpSampling2D((2, 2))(x)
    x = Conv2D(32, (3, 3), activation='relu', padding='same')(x)
    x = UpSampling2D((2, 2))(x)
    out = Conv2D(3, (3, 3), activation='sigmoid', padding='same')(x)
    return Model(inp, out)


def init_models(app) -> bool:
    """
    Initialize all AI models by rebuilding architectures and loading weights.

    Args:
        app: Flask application instance (for config access)

    Returns:
        True if all models loaded successfully, False otherwise
    """
    global _url_model, _img_model, _tokenizer, _models_initialized

    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    models_dir = os.path.join(root_dir, 'models')

    print("\n" + "="*60)
    print("INITIALIZING NEURAL ENGINES")
    print("="*60)
    print(f"Models directory: {models_dir}")

    # Load URL LSTM Model
    url_model_path = os.path.join(models_dir, 'url_lstm_v1.h5')
    if os.path.exists(url_model_path):
        try:
            _url_model = _build_url_model()
            _url_model.load_weights(url_model_path)
            print("[OK] URL LSTM Model loaded successfully")
        except Exception as e:
            print(f"[FAIL] URL LSTM Model failed to load: {e}")
            _url_model = None
    else:
        print(f"[WARN] URL LSTM Model not found: {url_model_path}")
        _url_model = None

    # Load Image Autoencoder Model
    img_model_path = os.path.join(models_dir, 'img_autoencoder_v1.h5')
    if os.path.exists(img_model_path):
        try:
            _img_model = _build_image_model()
            _img_model.load_weights(img_model_path)
            print("[OK] Image Autoencoder loaded successfully")
        except Exception as e:
            print(f"[FAIL] Image Autoencoder failed to load: {e}")
            _img_model = None
    else:
        print(f"[WARN] Image Autoencoder not found: {img_model_path}")
        _img_model = None

    # Load Tokenizer (with Keras 3.x compat unpickler)
    tokenizer_path = os.path.join(models_dir, 'tokenizer.pkl')
    if os.path.exists(tokenizer_path):
        try:
            with open(tokenizer_path, 'rb') as f:
                _tokenizer = _KerasCompatUnpickler(f).load()
            print("[OK] Tokenizer loaded successfully")
        except Exception as e:
            print(f"[FAIL] Tokenizer failed to load: {e}")
            _tokenizer = None
    else:
        print(f"[WARN] Tokenizer not found: {tokenizer_path}")
        _tokenizer = None

    _models_initialized = True

    # Summary
    print("-"*60)
    models_loaded = sum([
        _url_model is not None,
        _img_model is not None,
        _tokenizer is not None
    ])
    print(f"Status: {models_loaded}/3 models loaded")

    if models_loaded == 3:
        print("All neural engines online")
    elif models_loaded > 0:
        print("Running in degraded mode (some models unavailable)")
    else:
        print("All models unavailable - heuristic mode only")

    print("="*60 + "\n")

    return models_loaded == 3


def get_url_model():
    """Get URL LSTM model instance"""
    return _url_model


def get_image_model():
    """Get Image Autoencoder model instance"""
    return _img_model


def get_tokenizer():
    """Get character tokenizer instance"""
    return _tokenizer


def models_available() -> dict:
    """Check which models are available."""
    return {
        'url_model': _url_model is not None,
        'image_model': _img_model is not None,
        'tokenizer': _tokenizer is not None,
        'initialized': _models_initialized
    }
