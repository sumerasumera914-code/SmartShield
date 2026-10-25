"""Train the SmartShield message classifier.

Run with:  python train_model.py

It reads the SMS Spam Collection dataset, trains a TF-IDF + Logistic Regression
model, prints the evaluation results, and saves the model in the 'model' folder.
"""
import os
import sys

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from text_utils import clean_text

DATA_FILE = os.path.join("data", "SMSSpamCollection")
MODEL_FILE = os.path.join("model", "scam_model.joblib")
REPORT_FILE = os.path.join("model", "evaluation_report.txt")


def load_data(path):
    """Load the dataset. Each line is:  label <TAB> message  (label = ham or spam)."""
    if not os.path.exists(path):
        print(f"ERROR: Dataset file not found at: {path}")
        print("Please download the SMS Spam Collection dataset first. See the README (Step: Get the dataset).")
        sys.exit(1)

    df = pd.read_csv(path, sep="\t", header=None, names=["label", "message"], encoding="utf-8", quoting=3)
    df = df.dropna(subset=["label", "message"])
    df["label"] = df["label"].astype(str).str.strip().str.lower()
    df = df[df["label"].isin(["ham", "spam"])]
    df = df[df["message"].astype(str).str.strip() != ""]
    df = df.drop_duplicates()
    if df["label"].nunique() < 2 or len(df) < 100:
        print("ERROR: The dataset looks empty or wrong. Please download it again.")
        sys.exit(1)
    return df


def main():
    df = load_data(DATA_FILE)
    print(f"Rows used after cleaning (duplicates removed): {len(df)}")
    print(df["label"].value_counts().to_string())

    X = df["message"]
    y = (df["label"] == "spam").astype(int)  # 1 = spam, 0 = ham

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = Pipeline([
        ("tfidf", TfidfVectorizer(preprocessor=clean_text, stop_words="english", ngram_range=(1, 2), min_df=2)),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
    ])

    print("\nTraining the model...")
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    report = classification_report(y_test, predictions, target_names=["Not Flagged (ham)", "Suspicious (spam)"], digits=3)
    matrix = confusion_matrix(y_test, predictions)

    text = (
        f"Training messages: {len(X_train)}\nTest messages: {len(X_test)}\n\n"
        f"Classification report (on the unseen test set):\n{report}\n"
        f"Confusion matrix (rows = real, columns = predicted)\n"
        f"                 predicted ham   predicted spam\n"
        f"real ham         {matrix[0][0]:<15} {matrix[0][1]}\n"
        f"real spam        {matrix[1][0]:<15} {matrix[1][1]}\n"
    )
    print("\n" + text)

    os.makedirs("model", exist_ok=True)
    joblib.dump(model, MODEL_FILE)
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"Model saved to: {MODEL_FILE}")
    print(f"Report saved to: {REPORT_FILE}")


if __name__ == "__main__":
    main()
