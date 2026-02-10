# app8.py (full)
import os
import re
import traceback
from urllib.parse import urlparse, unquote
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, make_response
)
try:
    import pickle
except Exception:
    pickle = None

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret-change-me")

# Prefer the LR filenames first; keep other legacy names lower in the list if you want fallbacks.
CANDIDATE_VECTOR_NAMES = [
    os.path.join("models", "vectorizer_lr_new.pkl"),
    "vectorizer_lr_new.pkl",
    os.path.join("models", "vectorizer_lr.pkl"),
    "vectorizer_lr.pkl",
    os.path.join("models", "vectorizer.pkl"),
    "vectorizer.pkl"
]

CANDIDATE_MODEL_NAMES = [
    os.path.join("models", "model_lr_new.pkl"),
    "model_lr_new.pkl",
    os.path.join("models", "model_lr.pkl"),
    "model_lr.pkl",
    os.path.join("models", "phishing_rf.pkl"),
    "phishing_rf.pkl",
    os.path.join("models", "phishing.pkl"),
    "phishing.pkl"
]

vector = None
model = None
VECTOR_PATH = None
MODEL_PATH = None

# -----------------------
# Pickle loader / diagnostics
# -----------------------
def try_load_pickle(path):
    """Attempt to load a pickle and return (obj, err)."""
    if not os.path.exists(path):
        return None, f"not_found:{path}"
    try:
        with open(path, "rb") as f:
            obj = pickle.load(f)
        return obj, None
    except PermissionError as pe:
        return None, f"permission_error:{path}:{pe}"
    except Exception as e:
        tb = traceback.format_exc()
        return None, f"load_error:{path}:{e}\n{tb}"

def find_and_load():
    """
    Attempt to load the vectorizer and model from candidate paths.
    Updates global vector, model, VECTOR_PATH, MODEL_PATH.
    """
    global vector, model, VECTOR_PATH, MODEL_PATH
    if pickle is None:
        app.logger.warning("pickle not available; cannot load models.")
        vector = None; model = None; VECTOR_PATH = None; MODEL_PATH = None
        return

    # vectorizer - try candidates in order
    vector = None; VECTOR_PATH = None
    for p in CANDIDATE_VECTOR_NAMES:
        obj, err = try_load_pickle(p)
        if obj is not None:
            vector = obj
            VECTOR_PATH = os.path.abspath(p)
            app.logger.info("Loaded vectorizer: %s", VECTOR_PATH)
            break
        else:
            app.logger.debug("Vectorizer candidate issue: %s", err)
    if vector is None:
        app.logger.warning("No vectorizer found. Candidates tried: %s", CANDIDATE_VECTOR_NAMES)

    # model - try candidates in order
    model = None; MODEL_PATH = None
    for p in CANDIDATE_MODEL_NAMES:
        obj, err = try_load_pickle(p)
        if obj is not None:
            model = obj
            MODEL_PATH = os.path.abspath(p)
            app.logger.info("Loaded model: %s", MODEL_PATH)
            break
        else:
            app.logger.debug("Model candidate issue: %s", err)
    if model is None:
        app.logger.warning("No model found. Candidates tried: %s", CANDIDATE_MODEL_NAMES)

# initial attempt to load at startup
find_and_load()

# -----------------------
# URL normalization
# -----------------------
def normalize_url_for_model(url: str):
    """Return (domain_only, domain_plus_path) from a URL-like input."""
    if not url or not isinstance(url, str):
        return ("", "")
    u = url.strip()
    try:
        u = unquote(u)
    except Exception:
        pass
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
        u = "http://" + u
    parsed = urlparse(u)
    netloc = parsed.netloc or ""
    if "@" in netloc:
        netloc = netloc.split("@", 1)[-1]
    domain = netloc.split(":", 1)[0].lower().strip()
    path = (parsed.path or "").rstrip("/")
    if path.startswith("/"):
        path = path[1:]
    if path:
        domain_plus_path = f"{domain}/{path}"
    else:
        domain_plus_path = domain
    domain = domain.strip(". ")
    domain_plus_path = domain_plus_path.strip(". ")
    return (domain, domain_plus_path)

# -----------------------
# Prediction interpretation
# -----------------------
def interpret_predictions(preds, proba=None, model_obj=None):
    """
    Map arbitrary model outputs to 'safe'/'malicious'/'unknown' and include details.
    """
    def map_label(lbl):
        s = str(lbl).lower()
        if s in ("0","good","safe","benign","legitimate","not_phishing","ham"):
            return "safe"
        if s in ("1","bad","malicious","phishing","suspicious","spam"):
            return "malicious"
        return "unknown"

    mapped = [map_label(p) for p in preds]
    details = {"mapped": mapped, "raw_preds": [str(p) for p in preds], "proba": None}

    if proba is not None:
        try:
            top_info = []
            for row in proba:
                if not hasattr(row, "__len__"):
                    top_info.append({"top_idx": None, "top_prob": None})
                    continue
                top_idx = int(max(range(len(row)), key=lambda i: row[i]))
                top_prob = float(row[top_idx])
                top_info.append({"top_idx": top_idx, "top_prob": top_prob, "probs": list(row)})
            details["proba"] = top_info
            cls = None
            if model_obj is not None and hasattr(model_obj, "classes_"):
                cls = list(map(str, model_obj.classes_))
            # prefer confident safe
            for i, info in enumerate(top_info):
                tp = info.get("top_prob")
                if tp is None: continue
                label = None
                if cls:
                    try:
                        raw_label = cls[info["top_idx"]]
                        label = map_label(raw_label)
                    except Exception:
                        label = mapped[i]
                else:
                    label = mapped[i]
                if tp >= 0.6 and label == "safe":
                    return "safe", details
            # then confident malicious
            for i, info in enumerate(top_info):
                tp = info.get("top_prob")
                if tp is None: continue
                label = None
                if cls:
                    try:
                        raw_label = cls[info["top_idx"]]
                        label = map_label(raw_label)
                    except Exception:
                        label = mapped[i]
                else:
                    label = mapped[i]
                if tp >= 0.6 and label == "malicious":
                    return "malicious", details
        except Exception as e:
            app.logger.exception("Error interpreting probabilities: %s", e)

    # fallback aggregated mapping
    if "safe" in mapped:
        return "safe", details
    if "malicious" in mapped:
        return "malicious", details
    return "unknown", details

# -----------------------
# Main predict function
# -----------------------
def predict_url(raw_input: str):
    if vector is None or model is None:
        return {"status": "error", "message": "Model or vectorizer not loaded. See server logs.", "css_class": "neutral"}

    domain_only, domain_plus_path = normalize_url_for_model(raw_input)
    candidates = []
    if domain_plus_path:
        candidates.append(domain_plus_path)
    if domain_only and domain_only != domain_plus_path:
        candidates.append(domain_only)
    # dedupe preserve order
    seen = set(); final = []
    for c in candidates:
        if c and c not in seen:
            seen.add(c); final.append(c)
    if not final:
        return {"status":"unknown", "message":"Could not parse a domain from the input.", "css_class":"neutral", "debug": {"domain_only": domain_only, "domain_plus_path": domain_plus_path}}

    try:
        X = vector.transform(final)
        preds = model.predict(X)
        proba = None
        if hasattr(model, "predict_proba"):
            try:
                proba = model.predict_proba(X)
            except Exception as e:
                app.logger.exception("predict_proba failed: %s", e)
                proba = None
    except Exception as e:
        app.logger.exception("Vectorize/predict failed: %s", e)
        # fallback: try single candidate raw_input
        try:
            X = vector.transform([raw_input])
            preds = model.predict(X)
            proba = model.predict_proba(X) if hasattr(model, "predict_proba") else None
            final = [raw_input]
        except Exception as e2:
            app.logger.exception("Fallback predict failed: %s", e2)
            return {"status":"error","message":f"Prediction errors: {e} / {e2}","css_class":"neutral"}

    status, details = interpret_predictions(preds, proba, model)
    if status == "safe":
        msg = "This website looks SAFE ✅"
        css = "good"
    elif status == "malicious":
        msg = "Warning — this looks like a PHISHING website! ⚠️"
        css = "bad"
    else:
        msg = "Model unable to determine safety."
        css = "neutral"
    return {"status": status, "message": msg, "css_class": css, "debug": {"candidates": final, "details": details}}

# -----------------------
# Chat handler (REPLACE your existing handle_chat_message with this)
# -----------------------
def handle_chat_message(msg: str):
    if not msg or not msg.strip():
        return "Please type something — I can explain phishing or check URLs."

    low = msg.lower().strip()
    # find URL-like substring (unchanged)
    m = re.search(r"(https?://[^\s]+)|(www\.[^\s]+)|([a-z0-9-]+\.[a-z]{2,6}[^\s]*)", msg, re.IGNORECASE)
    if m:
        url_like = m.group(0)
        pr = predict_url(url_like)
        if pr.get("status") == "error":
            return pr.get("message", "Prediction failed. Check server logs.")
        details = pr.get("debug", {}).get("details", {})
        reply = pr.get("message", "")
        if details and details.get("proba"):
            rows = details.get("proba")
            parts = []
            for i, r in enumerate(rows):
                topp = r.get("top_prob")
                if topp is None: continue
                label = None
                try:
                    if hasattr(model, "classes_"):
                        label = str(model.classes_[r["top_idx"]])
                except Exception:
                    label = None
                if label is None:
                    mapped = details.get("mapped", [])
                    label = mapped[i] if i < len(mapped) else "?"
                parts.append(f"{label}@{topp:.2f}")
            if parts:
                reply += " (confidence: " + ", ".join(parts) + ")"
        cand = pr.get("debug", {}).get("candidates")
        if cand:
            reply += f" — checked: {', '.join(cand)}"
        return reply

    # -----------------------
    # Inbuilt quick answers (grouped, markdown-style)
    # -----------------------
    quick_answers = {
        # General / Email
        "what is phishing": (
            "**What is phishing?**\n\n"
            "Phishing is a social-engineering attack where attackers impersonate trusted parties (email, websites, SMS, phone) "
            "to steal credentials, money, or personal data."
        ),
        "phishing signs in email": (
            "**Phishing signs in email**\n\n"
            "- Urgent / threatening language (e.g. 'act now')\n"
            "- Sender address doesn't match branding (hover to inspect)\n"
            "- Suspicious links or unexpected attachments\n"
            "- Poor grammar or odd salutations\n"
        ),
        "how to verify email sender": (
            "**How to verify the email sender**\n\n"
            "1. Check the full email address, not just the display name.\n"
            "2. Hover links to see the real destination.\n"
            "3. Look for slight misspellings in domain names.\n"
            "4. If in doubt, contact the organization via an official website/phone."
        ),
        "check suspicious attachments": (
            "**Check suspicious attachments**\n\n"
            "- Do not open attachments from unknown senders.\n"
            "- Scan attachments with antivirus.\n"
            "- Prefer previewing attachments in a sandbox or cloud preview.\n"
        ),

        # URLs & links
        "is this link safe": (
            "**Is this link safe?**\n\n"
            "Hover the link to preview the target. Watch for:\n"
            "- Misspelled domains\n- Unexpected top-level domains\n- IP address in place of domain\n- Shortened links (preview them first)\n"
        ),
        "how to verify a website": (
            "**How to verify a website**\n\n"
            "- Check for HTTPS (padlock) but remember padlock ≠ safe.\n"
            "- Confirm domain spelling and subdomain structure.\n"
            "- Use bookmarks for important logins and avoid links from email.\n"
        ),
        "check short links safely": (
            "**Check short links safely**\n\n"
            "Use a URL expander (online unshorteners) to reveal the real destination before clicking."
        ),
        "url red flags": (
            "**URL red flags**\n\n"
            "- Long random-looking path or query strings\n- Too many subdomains (e.g., bank.example.com.scam.com)\n- Misspellings and extra punctuation\n"
        ),

        # Banking & payments
        "bank fraud warning": (
            "**Bank fraud warning**\n\n"
            "Banks will never ask for your PIN, CVV, full password, or OTP over phone/email. If asked — it's a scam."
        ),
        "upi fraud signs": (
            "**UPI fraud signs**\n\n"
            "- Unexpected collect requests\n- Fake 'refund' or 'chargeback' requests\n- Screenshots claiming money was sent (can be faked)\n"
        ),
        "what to do if money sent": (
            "**What to do if money was sent to a scammer**\n\n"
            "1. Contact your bank immediately and lock the account if needed.\n"
            "2. Report to the cybercrime portal (https://cybercrime.gov.in) and local police.\n"
            "3. Save transaction IDs, screenshots and communications as evidence.\n"
        ),
        "fake payment requests": (
            "**Fake payment requests**\n\n"
            "If someone pressures you to approve a payment or scan a QR for receiving money, don't. Verify via official channels."
        ),

        # SMS / WhatsApp (smishing)
        "sms phishing signs": (
            "**SMS / WhatsApp phishing signs**\n\n"
            "- Unknown numbers\n- Links asking to 'verify' or 'claim' an offer\n- Requests for OTP or codes\n"
        ),
        "how to handle suspicious sms": (
            "**How to handle suspicious SMS**\n\n"
            "Do not click links. Block and report the sender. Verify the message via the official app or website."
        ),

        # Phone / vishing
        "fake customer support scams": (
            "**Fake customer support scams**\n\n"
            "Scammers impersonate support and ask for OTPs or remote access. Real support won't ask for OTP or passwords."
        ),
        "vishing (phone) scams": (
            "**Vishing (phone) scams**\n\n"
            "Don't provide OTPs or account details over the phone. Hang up and call the official number from the website."
        ),

        # Social media
        "social media hacking signs": (
            "**Social media hacking signs**\n\n"
            "- Unexpected posts/messages you didn't send\n- Password reset emails you didn't request\n- Login alerts from unknown devices\n"
        ),
        "recognize scam messages on social": (
            "**Recognize scam messages on social**\n\n"
            "Common patterns: links promising money, requests to visit third-party forms, impersonation of friends/accounts."
        ),

        # Job & recruitment scams
        "avoid fake job offers": (
            "**Avoid fake job offers**\n\n"
            "Red flags: asking for money to apply/training, guaranteed placement without interview, vague job details."
        ),
        "job scam red flags": (
            "**Job scam red flags**\n\n"
            "Look out for: no formal interview, payments required, non-corporate email domains from 'HR'."
        ),

        # Account security
        "safe password tips": (
            "**Safe password tips**\n\n"
            "- Use long, unique passwords for each site\n- Use a password manager\n- Prefer passphrases over single words\n"
        ),
        "two-factor auth": (
            "**Two-factor authentication (2FA)**\n\n"
            "2FA provides a second layer (SMS, authenticator app, or hardware key) and greatly reduces account takeover risk."
        ),
        "what to do if hacked": (
            "**What to do if hacked**\n\n"
            "1) Change passwords and enable 2FA\n2) Revoke unknown sessions\n3) Notify banks if financial data compromised\n4) Report incident with evidence"
        ),

        # Scams examples
        "common phishing examples": (
            "**Common phishing examples**\n\n"
            "- Fake bank login pages\n- Package delivery scams\n- Prize/lottery scams\n- Fake job offers\n- Romance scams"
        ),
        "ceo fraud / bec": (
            "**CEO fraud / Business Email Compromise (BEC)**\n\n"
            "Attackers impersonate executives to request urgent transfers—verify with a call before sending funds."
        ),
        "investment & refund scams": (
            "**Investment & refund scams**\n\n"
            "Scammers promise high returns or ask for 'processing fees' before releasing a refund—these are red flags."
        ),

        # Reporting & evidence
        "how to report cybercrime": (
            "**How to report cybercrime (India)**\n\n"
            "Report at https://cybercrime.gov.in or contact local police cyber cell. Include screenshots, transaction IDs and message headers."
        ),
        "evidence to collect": (
            "**Evidence to collect before reporting**\n\n"
            "- Screenshots, email headers, URLs, phone numbers, transaction references, timestamps."
        ),

        # Technical / model
        "how detection works": (
            "**How detection works**\n\n"
            "The detector analyses URL textual features (domain, path, tokens), known patterns and a trained model to estimate risk."
        ),
        "what the model checks": (
            "**What the model checks**\n\n"
            "- Domain length & spelling\n- Suspicious tokens\n- Subdomain patterns\n- Known blacklists (when available)"
        ),
        "why model might be wrong": (
            "**Why the model might be wrong**\n\n"
            "Attackers may mimic legitimate domains. Models are probabilistic and can be uncertain; always manually verify critical cases."
        ),

        # Misc tips
        "how to stay safe online": (
            "**How to stay safe online**\n\n"
            "- Don't click unknown links\n- Don't share OTP/passwords\n- Keep software updated\n- Use 2FA and unique passwords"
        ),
        "recognize scam messages": (
            "**Recognize scam messages**\n\n"
            "They often create urgency, ask for money, or request you to click unknown links—verify independently."
        ),
        "browser popups & qr scams": (
            "**Browser popups & QR code scams**\n\n"
            "Ignore urgent 'system' popups that ask for passwords. Only scan QR codes from trusted sources."
        ),

        # Extras (catch-alls)
        "what to do if you get a suspicious link": (
            "**If you receive a suspicious link**\n\n"
            "Do not click. Use a URL scanner or open in an isolated environment. Ask the sender if legitimate."
        ),
        "how to verify a caller": (
            "**How to verify a caller**\n\n"
            "Hang up and call the official number from the organization's website. Don't use phone numbers provided by the caller."
        ),
        "how to protect from phishing": (
            "**How to protect from phishing**\n\n"
            "Combination of vigilance, 2FA, unique passwords, email filters, and endpoint protection reduces risk."
        ),
        "who to contact for bank/fraud help": (
            "**Who to contact for bank/fraud help**\n\n"
            "Contact your bank's official fraud desk immediately and report the incident to cybercrime authorities."
        )
    }

    # Try to match any quick-answer key phrase (ordered keys)
    # Use simple substring containment in the incoming message
    for key, ans in quick_answers.items():
        if key in low:
            return ans

    # Keep original fallbacks / small FAQs (greetings, how it works, report)
    if any(x in low for x in ["what is phishing", "define phishing", "phishing meaning"]):
        return ("Phishing is a social-engineering attack where attackers trick victims into revealing credentials, "
                "clicking malicious links, or giving personal data — often via email, SMS or fake websites.")
    if any(x in low for x in ["how to protect", "prevent phishing", "protect from phishing"]):
        return ("To protect yourself: 1) don't click suspicious links, 2) verify sender addresses, 3) enable 2FA, "
                "4) inspect the URL before entering credentials, and 5) keep software updated.")
    if any(x in low for x in ["how to report", "report phishing", "report cybercrime"]):
        return ("If you're in India you can report to the cybercrime portal (cybercrime.gov.in) or your local police cyber cell. "
                "Save evidence (emails, screenshots) before reporting.")
    if any(g in low for g in ["hello","hi","hey"]):
        return "Hello — I'm Astral Assistant. Ask me about phishing, paste a URL to check, or ask how detection works."
    if "how" in low and "work" in low:
        model_type = "unknown model"
        try:
            model_type = type(model).__name__ if model is not None else "no model loaded"
        except Exception:
            pass
        return f"The detector uses a trained model ({model_type}) on URL textual features to decide if it looks malicious."
    return f"I heard: \"{msg}\" — I can explain phishing, how to protect, or check a URL if you paste one."


    # Non-url FAQ handling
    if any(x in low for x in ["what is phishing", "define phishing", "phishing meaning"]):
        return ("Phishing is a social-engineering attack where attackers trick victims into revealing credentials, "
                "clicking malicious links, or giving personal data — often via email, SMS or fake websites.")
    if any(x in low for x in ["how to protect", "prevent phishing", "protect from phishing"]):
        return ("To protect yourself: 1) don't click suspicious links, 2) verify sender addresses, 3) enable 2FA, "
                "4) inspect the URL before entering credentials, and 5) keep software updated.")
    if any(x in low for x in ["how to report", "report phishing", "report cybercrime"]):
        return ("If you're in India you can report to the cybercrime portal (cybercrime.gov.in) or your local police cyber cell. "
                "Save evidence (emails, screenshots) before reporting.")
    if any(g in low for g in ["hello","hi","hey"]):
        return "Hello — I'm Astral Assistant. Ask me about phishing, paste a URL to check, or ask how detection works."
    if "how" in low and "work" in low:
        model_type = "unknown model"
        try:
            model_type = type(model).__name__ if model is not None else "no model loaded"
        except Exception:
            pass
        return f"The detector uses a trained model ({model_type}) on URL textual features to decide if it looks malicious."
    return f"I heard: \"{msg}\" — I can explain phishing, how to protect, or check a URL if you paste one."

# -----------------------
# Admin endpoints (model info & reload)
# -----------------------
def get_model_info():
    info = {
        "vector_loaded": bool(vector),
        "model_loaded": bool(model),
        "vector_path": VECTOR_PATH,
        "model_path": MODEL_PATH,
        "meta": {}
    }
    try:
        if vector is not None:
            info["meta"]["vectorizer_type"] = type(vector).__name__
            try:
                if hasattr(vector, "vocabulary_"):
                    info["meta"]["vocab_size"] = len(getattr(vector, "vocabulary_", {}))
                elif hasattr(vector, "get_feature_names_out"):
                    info["meta"]["vocab_size"] = len(vector.get_feature_names_out())
            except Exception:
                app.logger.debug("Could not read vocab_size from vectorizer")
    except Exception:
        app.logger.exception("Error extracting vector meta")

    try:
        if model is not None:
            info["meta"]["model_type"] = type(model).__name__
            if hasattr(model, "classes_"):
                try:
                    info["meta"]["classes"] = list(map(str, model.classes_))
                except Exception:
                    pass
    except Exception:
        app.logger.exception("Error extracting model meta")

    return info

@app.route("/admin/model-info", methods=["GET"])
def admin_model_info():
    try:
        return jsonify(get_model_info()), 200
    except Exception as e:
        app.logger.exception("admin/model-info failed: %s", e)
        return jsonify({"error": "internal error", "details": str(e)}), 500

@app.route("/admin/reload-model", methods=["POST"])
def admin_reload_model():
    # token support: Authorization: Bearer <TOKEN> or ?token=...
    auth = request.headers.get("Authorization", "") or request.args.get("token", "")
    token = None
    if isinstance(auth, str) and auth.startswith("Bearer "):
        token = auth.split("Bearer ", 1)[1].strip()
    elif auth:
        token = auth.strip()
    if not token and "token" in request.args:
        token = request.args.get("token")

    admin_token = os.environ.get("ADMIN_TOKEN")
    if not admin_token:
        app.logger.warning("ADMIN_TOKEN not set; denying reload request.")
        return jsonify({"error": "server misconfiguration: ADMIN_TOKEN not set"}), 500

    if token != admin_token:
        return jsonify({"error": "unauthorized", "message": "invalid admin token"}), 401

    try:
        find_and_load()
        info = get_model_info()
        return jsonify({"ok": True, "reloaded": True, "info": info}), 200
    except Exception as e:
        app.logger.exception("admin/reload-model failed: %s", e)
        return jsonify({"error": "reload failed", "details": str(e)}), 500

# -----------------------
# Routes (UI + APIs)
# -----------------------
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if request.is_json:
            body = request.get_json(silent=True) or {}
            url = (body.get("url") or "").strip()
            if not url:
                return jsonify({"error":"Missing 'url' in JSON body"}), 400
            pr = predict_url(url)
            return jsonify(pr), 200
        url = request.form.get("url") or request.values.get("url") or ""
        if not url.strip():
            session['one_time_result'] = {"flash":{"category":"warning","message":"Please enter a URL before submitting."}}
            return redirect(url_for('index'))
        cleaned = re.sub(r"^https?://(www\.)?", "", url.strip(), flags=re.IGNORECASE).rstrip("/")
        if len(cleaned) < 3:
            session['one_time_result'] = {"flash":{"category":"warning","message":"Please enter a valid URL."}}
            return redirect(url_for('index'))
        result = predict_url(cleaned)
        session['one_time_result'] = {"result": result, "submitted_url": url}
        return redirect(url_for('index'))

    one_time = session.pop('one_time_result', None)
    predict = None; submitted_url = None; flash_obj = None
    if one_time:
        if 'result' in one_time:
            predict = one_time.get('result'); submitted_url = one_time.get('submitted_url')
        elif 'flash' in one_time:
            flash_obj = one_time.get('flash')
    resp = make_response(render_template("index8.html", predict=predict, submitted_url=submitted_url, flash=flash_obj))
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

@app.route("/interface", methods=["GET"])
def interface():
    return render_template("interface.html")

@app.route("/chat_api", methods=["POST", "GET"])
def chat_api():
    if request.method == "GET":
        msg = request.args.get("message", "") or ""
        return jsonify({"reply": handle_chat_message(msg)}), 200
    body = request.get_json(silent=True) or {}
    message = (body.get("message") or "").strip()
    if not message:
        return jsonify({"reply":"Please type a message."}), 200
    reply = handle_chat_message(message)
    return jsonify({"reply": reply}), 200

@app.route("/api/check_url", methods=["POST","GET"])
def api_check_url():
    if request.method == "GET":
        url = request.args.get("url","") or ""
        if not url:
            return jsonify({"error":"Provide ?url=..."}), 400
        pr = predict_url(url); return jsonify(pr), 200
    body = request.get_json(silent=True) or {}
    url = (body.get("url") or "").strip()
    if not url:
        return jsonify({"error":"Missing 'url' in body"}), 400
    pr = predict_url(url); return jsonify(pr), 200

@app.route("/debug_predict", methods=["POST"])
def debug_predict():
    body = request.get_json(silent=True) or {}
    url = (body.get("url") or "").strip()
    if not url:
        return jsonify({"error":"Missing 'url'"}), 400
    d_only, d_path = normalize_url_for_model(url)
    candidates = []
    if d_path: candidates.append(d_path)
    if d_only and d_only != d_path: candidates.append(d_only)
    out = {"domain_only": d_only, "domain_plus_path": d_path, "candidates": candidates, "vector_shape": None, "preds": None, "pred_proba": None, "notes": ""}
    if vector is None:
        out["notes"] = "Vectorizer not loaded."
        return jsonify(out), 200
    if model is None:
        out["notes"] = "Model not loaded."
        return jsonify(out), 200
    try:
        X = vector.transform(candidates if candidates else [url])
        try:
            out["vector_shape"] = [X.shape[0], X.shape[1]]
        except Exception:
            out["vector_shape"] = None
        preds = model.predict(X)
        out["preds"] = [str(p) for p in preds]
        if hasattr(model, "predict_proba"):
            try:
                proba = model.predict_proba(X)
                out["pred_proba"] = proba.tolist()
            except Exception as e:
                out["pred_proba"] = f"error computing proba: {e}"
    except Exception as e:
        out["notes"] = f"Error transforming/predicting: {e}"
    return jsonify(out), 200

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "vector_loaded": bool(vector), "model_loaded": bool(model)}), 200

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/home")
def home():
    return render_template("home.html")

@app.route("/chat")
def chat():
    return render_template("chat.html")

if __name__ == "__main__":
    app.logger.info("Starting app8.py. Vector loaded: %s, Model loaded: %s", bool(vector), bool(model))
    app.run(host="0.0.0.0", port=5000, debug=True)
