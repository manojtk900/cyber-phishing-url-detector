import pickle
import re

# Load vectorizer and model
vectorizer = pickle.load(open("vectorizer_rf.pkl", "rb"))   # or vectorizer.pkl if that’s the name
model = pickle.load(open("phishing_rf.pkl", "rb"))          # or phishing.pkl

def clean_url(url: str) -> str:
    """Same cleaning as Flask app."""
    if not url:
        return ""
    u = url.strip()
    # remove http/https and optional www.
    u = re.sub(r"^https?://(www\.)?", "", u, flags=re.IGNORECASE)
    # remove trailing slash
    u = u.rstrip("/")
    return u

def predict_url(raw_url: str):
    cleaned = clean_url(raw_url)
    vec = vectorizer.transform([cleaned])
    pred = model.predict(vec)[0]
    return pred, cleaned

if __name__ == "__main__":
    while True:
        url = input("Enter URL (or 'q' to quit): ")
        if url.lower().strip() == "q":
            break
        pred, cleaned = predict_url(url)
        print(f"Cleaned: {cleaned}")
        print("Prediction:", pred)
        print("-" * 40)
