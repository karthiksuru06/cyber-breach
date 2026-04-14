import os
import pandas as pd
import numpy as np
import pickle
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, SpatialDropout1D, Bidirectional, LSTM, Dropout, Dense

# Configuration
URL_SEQUENCE_LENGTH = 200
MAX_NUM_WORDS = 100 # Important to match the '100' input_dim in model_loader.py

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, 'models')
DATA_PATH = os.path.join(BASE_DIR, 'data', 'malicious_dataset.csv')
TOKENIZER_PATH = os.path.join(MODELS_DIR, 'tokenizer.json')
MODEL_PATH = os.path.join(MODELS_DIR, 'url_lstm_v1.h5')

def train():
    os.makedirs(MODELS_DIR, exist_ok=True)

    print(f"Loading data from {DATA_PATH}...")
    df = pd.read_csv(DATA_PATH)

    urls = df['url'].astype(str).values
    # labels: benign -> 0, others (phishing, defacement, malware) -> 1
    labels = np.where(df['type'] == 'benign', 0, 1)

    print("Tokenizing URLs (Character Level)...")
    tokenizer = Tokenizer(char_level=True, lower=True, num_words=MAX_NUM_WORDS)
    tokenizer.fit_on_texts(urls)

    # Save tokenizer as JSON (avoids pickle versioning bugs between Keras 2/3)
    tokenizer_json = tokenizer.to_json()
    with open(TOKENIZER_PATH, 'w', encoding='utf-8') as f:
        f.write(tokenizer_json)
    print(f"Saved tokenizer to {TOKENIZER_PATH}")

    # Sequence padding
    X = tokenizer.texts_to_sequences(urls)
    X = pad_sequences(X, maxlen=URL_SEQUENCE_LENGTH)
    y = labels

    print("Building LSTM Model...")
    model = Sequential([
        Embedding(MAX_NUM_WORDS, 32, input_length=URL_SEQUENCE_LENGTH),
        SpatialDropout1D(0.2),
        Bidirectional(LSTM(64)),
        Dropout(0.3),
        Dense(32, activation='relu'),
        Dense(1, activation='sigmoid')
    ])

    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
    model.summary()

    print("Training Model...")
    model.fit(X, y, epochs=10, batch_size=8, validation_split=0.2)

    print(f"Saving Model to {MODEL_PATH}...")
    model.save(MODEL_PATH)
    print("Training complete! You can now run the app.")

if __name__ == "__main__":
    train()
