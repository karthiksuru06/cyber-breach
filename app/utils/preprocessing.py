"""
Image Preprocessing Module
===========================
Prepares images for Autoencoder inference.
"""

import numpy as np
from PIL import Image
from typing import Tuple


def preprocess_image(image_path: str, target_size: Tuple[int, int] = (128, 128)) -> np.ndarray:
    """
    Preprocess image for Autoencoder inference.

    Args:
        image_path: Path to image file
        target_size: Target dimensions (width, height)

    Returns:
        Preprocessed numpy array ready for model inference
        Shape: (1, 128, 128, 3) with values in [0, 1]

    Processing Steps:
        1. Load image
        2. Convert to RGB (handle RGBA, grayscale, etc.)
        3. Resize to target_size
        4. Normalize to [0, 1]
        5. Add batch dimension
    """
    try:
        # Load and convert to RGB
        img = Image.open(image_path).convert('RGB')

        # Resize to model input size
        img = img.resize(target_size)

        # Convert to numpy array and normalize
        img_array = np.array(img).astype('float32') / 255.0

        # Add batch dimension: (128, 128, 3) → (1, 128, 128, 3)
        img_array = np.expand_dims(img_array, axis=0)

        return img_array

    except Exception as e:
        raise ValueError(f"Image preprocessing failed: {str(e)}")


def calculate_reconstruction_error(original: np.ndarray, reconstructed: np.ndarray) -> float:
    """
    Calculate Mean Squared Error between original and reconstructed image.

    Args:
        original: Original image array
        reconstructed: Reconstructed image from Autoencoder

    Returns:
        MSE value (float)

    Formula:
        MSE = (1/N) * Σ(original - reconstructed)²
    """
    mse = np.mean(np.power(original - reconstructed, 2))
    return float(mse)
