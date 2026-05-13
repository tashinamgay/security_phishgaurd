# backend/src/pattern_engine/ml_classifier.py
# Optional ML Extension - Phishing Email Classifier
# Member: Masaba (Pattern & Risk Engine Lead)
#
# Uses scikit-learn TF-IDF + Naive Bayes classifier
# Supports: Nazario phishing corpus, SpamAssassin, or any CSV dataset
# CSV format required: columns 'text' (email body) and 'label' (phishing/safe)

import os, pickle
import numpy as np

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.pipeline import Pipeline
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score
    import pandas as pd
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# Path where the trained model is saved
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'phishing_model.pkl')


def train_model(dataset_path):
    """
    Train a phishing classifier on a CSV dataset.

    Supported datasets:
    - Nazario Phishing Corpus (https://monkey.org/~jose/phishing/)
    - SpamAssassin Public Corpus
    - Any CSV with columns: 'text' and 'label' (phishing/safe)

    Steps:
    1. Load CSV dataset
    2. Split into 80% train / 20% test
    3. TF-IDF converts email text to numbers
    4. Naive Bayes learns phishing patterns
    5. Model saved as .pkl file for future predictions
    """
    if not ML_AVAILABLE:
        return {'error': 'scikit-learn not installed. Run: pip install scikit-learn pandas'}

    try:
        # Load dataset
        df = pd.read_csv(dataset_path)

        # Validate required columns exist
        if 'text' not in df.columns or 'label' not in df.columns:
            return {'error': 'CSV must have "text" and "label" columns'}

        # Clean data - remove empty rows
        df = df.dropna(subset=['text', 'label'])
        df['text']  = df['text'].astype(str)
        df['label'] = df['label'].astype(str).str.lower().str.strip()

        # Validate labels are phishing/safe
        valid_labels = {'phishing', 'safe', 'spam', 'ham', '1', '0'}
        unique_labels = set(df['label'].unique())
        if not unique_labels.issubset(valid_labels):
            # Try to standardize labels
            df['label'] = df['label'].map(
                lambda x: 'phishing' if x in {'phishing','spam','1'} else 'safe'
            )

        X = df['text']
        y = df['label']

        # Split: 80% training, 20% testing
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Build pipeline: TF-IDF + Naive Bayes
        # TF-IDF: converts email text into numerical feature vectors
        # Naive Bayes: probabilistic classifier - fast and effective for text
        pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(
                max_features=5000,      # top 5000 most important words
                stop_words='english',   # remove common words like "the", "is"
                ngram_range=(1, 2),     # use single words AND word pairs
                min_df=2,               # ignore very rare words
            )),
            ('clf', MultinomialNB(alpha=0.1)),  # Naive Bayes classifier
        ])

        # Train the model
        pipeline.fit(X_train, y_train)

        # Evaluate on test set
        y_pred   = pipeline.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        report   = classification_report(y_test, y_pred, output_dict=True)

        # Save trained model to disk
        with open(MODEL_PATH, 'wb') as f:
            pickle.dump(pipeline, f)

        return {
            'status':    'success',
            'accuracy':  f'{accuracy * 100:.1f}%',
            'samples':   len(df),
            'train_size': len(X_train),
            'test_size':  len(X_test),
            'phishing_precision': f'{report.get("phishing", {}).get("precision", 0)*100:.1f}%',
            'phishing_recall':    f'{report.get("phishing", {}).get("recall", 0)*100:.1f}%',
        }

    except Exception as e:
        return {'error': str(e)}


def predict(email_text):
    """
    Predict if an email is phishing using the trained model.
    Returns dict with prediction and confidence, or None if no model.
    """
    if not ML_AVAILABLE or not os.path.exists(MODEL_PATH):
        return None

    try:
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)

        proba    = model.predict_proba([email_text])[0]
        classes  = model.classes_
        pred_idx = np.argmax(proba)

        return {
            'prediction': classes[pred_idx],
            'confidence': round(float(proba[pred_idx]) * 100, 1),
        }
    except Exception:
        return None


def generate_sample_dataset(output_path):
    """
    Generate a sample CSV dataset for testing the ML classifier.
    Use this if you don't have the Nazario corpus yet.
    In production, replace with real phishing dataset.
    """
    sample_data = [
        # Phishing examples
        {'text': 'URGENT: Your account has been suspended. Verify now at http://bit.ly/secure-verify', 'label': 'phishing'},
        {'text': 'Your PayPal account will be closed. Click here immediately to verify your bank details', 'label': 'phishing'},
        {'text': 'Congratulations! You have won $5000. Send your bank account details to claim prize', 'label': 'phishing'},
        {'text': 'URGENT: Unauthorized access detected. Enter your password and credit card now', 'label': 'phishing'},
        {'text': 'Your Netflix account expired. Update payment info at http://netflix-secure.xyz/login', 'label': 'phishing'},
        {'text': 'Job offer: $5000/month salary. No interview required. Send passport copy and bank details', 'label': 'phishing'},
        {'text': 'IRS tax refund available. Verify your social security number to receive payment', 'label': 'phishing'},
        {'text': 'Dear customer your account will be permanently deleted within 24 hours verify now', 'label': 'phishing'},
        {'text': 'Wire transfer required immediately. Send your banking credentials to process payment', 'label': 'phishing'},
        {'text': 'Limited time offer expires soon. Click here to claim your lottery winnings now', 'label': 'phishing'},
        {'text': 'Microsoft security alert: Your account compromised. Enter OTP to secure account', 'label': 'phishing'},
        {'text': 'Amazon: Your order suspended. Update credit card details to resume delivery', 'label': 'phishing'},
        # Safe examples
        {'text': 'Hi team, meeting tomorrow at 10am. Please bring your project updates.', 'label': 'safe'},
        {'text': 'Your order has been shipped. Expected delivery date is Friday. Track here.', 'label': 'safe'},
        {'text': 'Monthly newsletter: Check out our latest blog posts and company updates.', 'label': 'safe'},
        {'text': 'Reminder: Your dentist appointment is scheduled for next Monday at 2pm.', 'label': 'safe'},
        {'text': 'Thank you for your purchase. Your receipt is attached for your records.', 'label': 'safe'},
        {'text': 'Hi, just following up on our meeting from last week. Hope all is well.', 'label': 'safe'},
        {'text': 'The project deadline has been extended to next Friday. Please update your tasks.', 'label': 'safe'},
        {'text': 'Your password was changed successfully. If this was not you, contact support.', 'label': 'safe'},
        {'text': 'Weekly team standup notes attached. Please review before our next meeting.', 'label': 'safe'},
        {'text': 'Happy birthday! Hope you have a wonderful day celebrating with family.', 'label': 'safe'},
        {'text': 'Your subscription has been renewed. View your invoice in the account portal.', 'label': 'safe'},
        {'text': 'Conference call at 3pm today. Dial-in details in the calendar invite.', 'label': 'safe'},
    ]

    import csv
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['text', 'label'])
        writer.writeheader()
        writer.writerows(sample_data)

    return len(sample_data)


def model_exists():
    """Check if a trained model file exists."""
    return os.path.exists(MODEL_PATH)
