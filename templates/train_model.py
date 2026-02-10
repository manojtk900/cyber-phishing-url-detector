import json, datetime, os

meta = {
    "version": "lr_v1." + datetime.datetime.utcnow().strftime("%Y%m%d%H%M"),
    "trained_at": datetime.datetime.utcnow().isoformat() + "Z",
    "accuracy": acc,   # from your evaluation
    "notes": "Trained with char-ngram TF-IDF and LogisticRegression",
    "model_file": os.path.abspath("models/model_lr_new.pkl"),
    "vector_file": os.path.abspath("models/vectorizer_lr_new.pkl")
}
os.makedirs("models", exist_ok=True)
with open(os.path.join("models", "model_meta.json"), "w", encoding="utf-8") as f:
    json.dump(meta, f, indent=2)
print("Saved metadata to models/model_meta.json")
