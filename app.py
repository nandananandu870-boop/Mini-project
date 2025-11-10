import os
import time
from flask import Flask, session, redirect, url_for, request, render_template, flash
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from rapidfuzz import fuzz
import httplib2

# --- CONFIGURATION ---
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
APP_SECRET_KEY = "replace-with-a-random-secret-key"
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
CLIENT_SECRETS_FILE = "client_secrets.json"
OAUTH2_CALLBACK = "http://localhost:5000/oauth2callback"

app = Flask(__name__)
app.secret_key = APP_SECRET_KEY


# --- HELPER FUNCTIONS ---
def creds_to_dict(creds: Credentials):
    return {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes,
    }


def creds_from_session():
    if "credentials" not in session:
        return None
    return Credentials(**session["credentials"])


def safe_build_service(creds, retries=3):
    """Retry Gmail API connection before failing."""
    for attempt in range(retries):
        try:
            service = build("gmail", "v1", credentials=creds)
            service.users().getProfile(userId="me").execute()
            return service
        except (httplib2.ServerNotFoundError, HttpError, Exception) as e:
            print(f"[GMAIL API ERROR] Attempt {attempt+1}/{retries}: {e}")
            if attempt < retries - 1:
                time.sleep(2)
            else:
                return None


def find_near_duplicates(emails, threshold=70):
    """Detect near-duplicates by comparing subjects with similarity 70–99%."""
    near_pairs = []
    n = len(emails)
    for i in range(n):
        s1 = emails[i]["subject"] or ""
        if not s1:
            continue
        for j in range(i + 1, n):
            s2 = emails[j]["subject"] or ""
            if not s2:
                continue
            sim = fuzz.token_sort_ratio(s1, s2)
            if threshold <= sim < 100:
                near_pairs.append({
                    "email1": emails[i],
                    "email2": emails[j],
                    "similarity": round(sim, 2)
                })
    return near_pairs


# ---------- LABEL HELPERS ----------
def get_or_create_label(service, label_name: str) -> str:
    """Return label ID; create label if it doesn't exist."""
    labels = service.users().labels().list(userId="me").execute().get("labels", [])
    for lbl in labels:
        if lbl.get("name", "").lower() == label_name.lower():
            return lbl["id"]
    body = {"name": label_name, "labelListVisibility": "labelShow", "messageListVisibility": "show"}
    created = service.users().labels().create(userId="me", body=body).execute()
    return created["id"]


def batch_add_label(service, ids, label_id):
    """Apply label to many messages at once."""
    if not ids:
        return
    body = {"ids": list(ids), "addLabelIds": [label_id], "removeLabelIds": []}
    service.users().messages().batchModify(userId="me", body=body).execute()


def batch_remove_label(service, ids, label_id):
    if not ids:
        return
    body = {"ids": list(ids), "addLabelIds": [], "removeLabelIds": [label_id]}
    service.users().messages().batchModify(userId="me", body=body).execute()


# --- ROUTES ---
@app.route("/")
def index():
    creds = creds_from_session()
    return render_template("index.html", signed_in=bool(creds and creds.valid))


@app.route("/authorize")
def authorize():
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=OAUTH2_CALLBACK)
    auth_url, state = flow.authorization_url(access_type="offline", include_granted_scopes="true", prompt="consent")
    session["state"] = state
    return redirect(auth_url)


@app.route("/oauth2callback")
def oauth2callback():
    state = session.get("state")
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, state=state, redirect_uri=OAUTH2_CALLBACK)
    flow.fetch_token(authorization_response=request.url)
    session["credentials"] = creds_to_dict(flow.credentials)
    flash("✅ Successfully signed in with Google!")
    return redirect(url_for("index"))


@app.route("/signout")
def signout():
    session.clear()
    flash("👋 You have been signed out.")
    return redirect(url_for("index"))

@app.route("/dedupe", methods=["POST"])
def dedupe():
    """
    Scan Gmail, detect exact and near duplicates (70–99% similarity),
    label them, and return accurate counts.
    Supports up to 2000 emails safely.
    """

    creds = creds_from_session()
    if not creds or not creds.valid:
        return redirect(url_for("index"))

    service = safe_build_service(creds)
    if not service:
        flash("❌ Could not reach Gmail servers. Please check internet or VPN.")
        return redirect(url_for("index"))

    # --- Label Setup ---
    lbl_duplicate_id = get_or_create_label(service, "DUPLICATE")
    lbl_near_id = get_or_create_label(service, "NEAR_DUPLICATE")

    # --- Fetch emails (default: 1000, max: 2000) ---
    max_emails = int(request.form.get("max_emails", 1000))
    max_emails = min(max_emails, 2000)

    all_emails = []
    page_token = None
    fetched = 0

    print(f"🔄 Fetching up to {max_emails} emails...")

    while fetched < max_emails:
        resp = service.users().messages().list(
            userId="me",
            maxResults=min(500, max_emails - fetched),
            pageToken=page_token
        ).execute()

        for m in resp.get("messages", []):
            try:
                msg = service.users().messages().get(
                    userId="me", id=m["id"], format="full"
                ).execute()

                headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
                ts = int(msg.get("internalDate", "0"))

                email = {
                    "id": m["id"],
                    "from": headers.get("From", "").strip(),
                    "subject": headers.get("Subject", "").strip(),
                    "date": headers.get("Date", ""),
                    "snippet": msg.get("snippet", ""),
                    "ts": ts
                }
                all_emails.append(email)
                fetched += 1

                if fetched >= max_emails:
                    break
            except Exception as e:
                print("⚠️ Error fetching message:", e)
                continue

        page_token = resp.get("nextPageToken")
        if not page_token or fetched >= max_emails:
            break

    print(f"✅ Total Emails Fetched: {fetched}")

    # --- Detect Exact Duplicates (From + Subject) ---
    groups_map = {}
    for e in all_emails:
        key = (e["from"], e["subject"])
        groups_map.setdefault(key, []).append(e)

    duplicate_groups = []
    for _, emails in groups_map.items():
        if len(emails) > 1:
            emails_sorted = sorted(emails, key=lambda x: x["ts"], reverse=True)
            duplicate_groups.append(emails_sorted)

    duplicates_flat = [e for grp in duplicate_groups for e in grp]
    duplicate_count = sum(max(0, len(grp) - 1) for grp in duplicate_groups)
    exact_copies = len(duplicates_flat)

    # Apply "DUPLICATE" label
    duplicate_ids = [e["id"] for e in duplicates_flat]
    batch_add_label(service, duplicate_ids, lbl_duplicate_id)

    # --- Detect Near Duplicates (Subject Similarity 70–99%) ---
    near_pairs = find_near_duplicates(all_emails, threshold=70)
    near_ids = set()

    for p in near_pairs:
        near_ids.add(p["email1"]["id"])
        near_ids.add(p["email2"]["id"])

    # Apply "NEAR_DUPLICATE" label
    if near_ids:
        batch_add_label(service, list(near_ids), lbl_near_id)

    # --- Compute Accurate Counts ---
    uniques_count = len(all_emails) - duplicate_count
    near_pairs_count = len(near_pairs)          # number of similarity pairs
    near_unique_count = len(near_ids)           # unique emails involved
    display_near_count = near_unique_count      # use unique email count in summary

    # --- Store Session Data for Smart Delete ---
    session["duplicate_groups"] = duplicate_groups
    session["dup_label_id"] = lbl_duplicate_id

    # --- Render Results ---
    return render_template(
        "results.html",
        fetched=fetched,
        uniques=uniques_count,
        duplicates=duplicates_flat,
        duplicate_groups=duplicate_groups,
        duplicate_count=duplicate_count,
        exact_copies=exact_copies,
        similars=near_pairs,
        near_pairs_count=near_pairs_count,
        near_unique_count=near_unique_count,
        display_near_count=display_near_count
    )

@app.route("/smart_delete", methods=["POST"])
def smart_delete():
    """Keep newest mail per group and permanently delete older duplicates."""
    creds = creds_from_session()
    if not creds or not creds.valid:
        return redirect(url_for("index"))

    service = safe_build_service(creds)
    duplicate_groups = session.get("duplicate_groups", [])
    dup_label_id = session.get("dup_label_id", None)

    deleted_mails = []
    kept_mails = []

    for group in duplicate_groups:
        if not group:
            continue
        keep = group[0]
        kept_mails.append(keep)
        if dup_label_id:
            try:
                batch_remove_label(service, [keep["id"]], dup_label_id)
            except Exception:
                pass
        for e in group[1:]:
            try:
                service.users().messages().delete(userId="me", id=e["id"]).execute()
                deleted_mails.append(e)
            except Exception as ex:
                print("Smart delete error:", ex)

    return render_template("deleted.html", kept_one=True, deleted_mails=deleted_mails, kept_mails=kept_mails)


if __name__ == "__main__":
    app.run("0.0.0.0", port=5000, debug=True)
