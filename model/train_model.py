import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib
import os

# Load and preprocess the dataset
def preprocess_data(file_path):
    df = pd.read_csv(file_path)
    
    # Clean column names
    df.columns = df.columns.str.strip()
    
    # Replace infinity and NaN values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)
    
    # Select features (example subset for simplicity)
    features = [
        'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
        'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
        'Fwd Packet Length Mean', 'Bwd Packet Length Mean', 'Flow Bytes/s',
        'Flow Packets/s', 'Fwd IAT Total', 'Bwd IAT Total'
    ]
    
    # Label: Benign (0) or Attack (1)
    df['Label'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
    
    X = df[features]
    y = df['Label']
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    return X_train_scaled, X_test_scaled, y_train, y_test, scaler, features

# Train the model
def train_model(X_train, y_train, X_test, y_test):
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    print("Model Performance:")
    print(classification_report(y_test, y_pred))
    
    return model

# Main execution
if __name__ == "__main__":
    data_path = "data/cicids2017_sample.csv"
    X_train, X_test, y_train, y_test, scaler, features = preprocess_data(data_path)
    model = train_model(X_train, y_train, X_test, y_test)
    
    # Save model and preprocessor
    os.makedirs("model", exist_ok=True)
    joblib.dump(model, "model/model.pkl")
    joblib.dump(scaler, "model/preprocessor.pkl")
    joblib.dump(features, "model/features.pkl")