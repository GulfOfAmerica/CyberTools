import tensorflow as tf
import numpy as np
import logging
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Configure logging
logging.basicConfig(filename='ml_training_log.txt', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def generate_synthetic_data(n_samples: int = 1000) -> tuple:
    """Generate synthetic data for demonstration (replace with real data)."""
    np.random.seed(42)
    # Features: [file_size (KB), entropy, number_of_strings]
    benign = np.random.normal(loc=[500, 4.0, 100], scale=[100, 0.5, 20], size=(n_samples // 2, 3))
    malicious = np.random.normal(loc=[200, 6.5, 50], scale=[50, 0.7, 10], size=(n_samples // 2, 3))
    X = np.vstack([benign, malicious])
    y = np.array([0] * (n_samples // 2) + [1] * (n_samples // 2))  # 0 = benign, 1 = malicious
    return X, y

def build_model(input_dim: int) -> tf.keras.Model:
    """Build a simple neural network for malware classification."""
    model = tf.keras.Sequential([
        tf.keras.layers.Dense(64, activation='relu', input_dim=input_dim),
        tf.keras.layers.Dense(32, activation='relu'),
        tf.keras.layers.Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model

def train_model(X: np.ndarray, y: np.ndarray) -> tf.keras.Model:
    """Train the ML model."""
    try:
        # Split and scale data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X_train)
        X_test = scaler.transform(X_test)

        # Build and train model
        model = build_model(X_train.shape[1])
        history = model.fit(X_train, y_train, epochs=10, batch_size=32, validation_data=(X_test, y_test), verbose=1)

        # Evaluate model
        loss, accuracy = model.evaluate(X_test, y_test)
        logging.info(f"Model training complete. Test accuracy: {accuracy:.4f}, Test loss: {loss:.4f}")
        return model
    except Exception as e:
        logging.error(f"Model training error: {e}")
        raise

def main():
    """Main function to train and save the ML model."""
    try:
        # Generate synthetic data (replace with real dataset)
        X, y = generate_synthetic_data()
        model = train_model(X, y)

        # Save the model
        model.save('malware_detector.h5')
        logging.info("Model saved to malware_detector.h5")
        print("Model training complete and saved.")
    except Exception as e:
        print(f"An error occurred: {e}")
        logging.error(f"Main function error: {e}")

if __name__ == "__main__":
    main()
