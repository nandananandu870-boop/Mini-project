import os
import time
from flask import Flask, session, redirect, url_for, request, render_template, flash
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from rapidfuzz import fuzz
import httplib2

<<<<<<< HEAD
# --- CONFIG ---
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # ok for localhost only
=======
# --- CONFIGURATION ---
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
>>>>>>> d6f3733 (all set)
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


<<<<<<< HEAD
def get_or_create_label(service, label_name: str) -> str:
    """Return label ID; create label if it doesn't exist."""
    labels = service.users().labels().list(userId="me").execute().get("labels", [])
    for lbl in labels:
        if lbl.get("name", "").lower() == label_name.lower():
            return lbl["id"]
    body = {
        "name": label_name,
        "labelListVisibility": "labelShow",
        "messageListVisibility": "show",
    }
    created = service.users().labels().create(userId="me", body=body).execute()
    return created["id"]


def batch_add_label(service, ids, label_id):
    if not ids:
        return
    body = {"ids": list(ids), "addLabelIds": [label_id], "removeLabelIds": []}
    service.users().messages().batchModify(userId="me", body=body).execute()


def batch_remove_label(service, ids, label_id):
    if not ids:
        return
    body = {"ids": list(ids), "addLabelIds": [], "removeLabelIds": [label_id]}
    service.users().messages().batchModify(userId="me", body=body).execute()


def find_near_pairs(emails, threshold=70):
    """Near-duplicates based on SUBJECT similarity (70–99%). Return list of pairs."""
    pairs = []
=======
def find_near_duplicates(emails, threshold=70):
    """Detect near-duplicates by comparing subjects with similarity 70–99%."""
    near_pairs = []
>>>>>>> d6f3733 (all set)
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
<<<<<<< HEAD
                pairs.append({
=======
                near_pairs.append({
>>>>>>> d6f3733 (all set)
                    "email1": emails[i],
                    "email2": emails[j],
                    "similarity": round(sim, 2)
                })
    return pairs


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
<<<<<<< HEAD
    """
    Scan Gmail, group exact duplicates (Sender + Subject),
    compute near duplicates (70–99%), label them,
    and show counts that match Gmail's label sidebar (conversation-based).
    """
=======
    """Scan Gmail, detect exact & near duplicates, and label them."""
>>>>>>> d6f3733 (all set)
    creds = creds_from_session()
    if not creds or not creds.valid:
        return redirect(url_for("index"))

    service = safe_build_service(creds)
    if not service:
        flash("❌ Could not reach Gmail servers. Please check your internet or VPN.")
        return redirect(url_for("index"))

<<<<<<< HEAD
    # Prepare labels (create if missing)
    lbl_dup = get_or_create_label(service, "DUPLICATE")
    lbl_near = get_or_create_label(service, "NEAR_DUPLICATE")

    max_emails = int(request.form.get("max_emails", 100))
=======
    lbl_duplicate_id = get_or_create_label(service, "DUPLICATE")
    lbl_near_id = get_or_create_label(service, "NEAR_DUPLICATE")
>>>>>>> d6f3733 (all set)

    max_emails = int(request.form.get("max_emails", 100))
    all_emails = []
    page_token = None
    fetched = 0

    while fetched < max_emails:
        resp = service.users().messages().list(
            userId="me", maxResults=min(100, max_emails - fetched), pageToken=page_token
        ).execute()

        for m in resp.get("messages", []):
            msg = service.users().messages().get(userId="me", id=m["id"], format="full").execute()
            headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
            ts = int(msg.get("internalDate", "0"))
            email = {
                "id": m["id"],
                "threadId": msg.get("threadId", ""),     # conversation id (matches Gmail label count)
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

        page_token = resp.get("nextPageToken")
        if not page_token:
            break

    # ---- EXACT DUPLICATES ----
    groups_map = {}
    for e in all_emails:
        key = (e["from"], e["subject"])
        groups_map.setdefault(key, []).append(e)

    duplicate_groups = []
    for _, emails in groups_map.items():
        if len(emails) > 1:
            duplicate_groups.append(sorted(emails, key=lambda x: x["ts"], reverse=True))

    # Flat list for table + label ids (messages)
    duplicates_flat = [e for grp in duplicate_groups for e in grp]
<<<<<<< HEAD
    duplicate_ids = [e["id"] for e in duplicates_flat]
    # Conversation-based count (matches Gmail label sidebar)
    duplicate_threads = sorted({e["threadId"] for e in duplicates_flat if e.get("threadId")})

    # Label all exact duplicates
    if duplicate_ids:
        batch_add_label(service, duplicate_ids, lbl_dup)

    # ---- NEAR DUPES (70–99% by subject) ----
    near_pairs = find_near_pairs(all_emails, threshold=70)

    # Unique message IDs & threads involved in near dupes
    near_ids = set()
    near_threads = set()
    for p in near_pairs:
        near_ids.add(p["email1"]["id"])
        near_ids.add(p["email2"]["id"])
        if p["email1"].get("threadId"):
            near_threads.add(p["email1"]["threadId"])
        if p["email2"].get("threadId"):
            near_threads.add(p["email2"]["threadId"])

    # Apply NEAR_DUPLICATE label
    if near_ids:
        batch_add_label(service, list(near_ids), lbl_near)

    # Save groups for Smart Delete; remember dup label id so we can remove from kept copy
    session["duplicate_groups"] = duplicate_groups
    session["dup_label_id"] = lbl_dup

    # Approx uniques (message-based): total - redundant copies
    redundant_copies = sum(max(0, len(grp) - 1) for grp in duplicate_groups)
    uniques_count = len(all_emails) - redundant_copies

    # COUNTS TO DISPLAY (conversation-based to match Gmail labels)
    exact_count_conversations = len(duplicate_threads)
    near_count_conversations = len(near_threads)
=======
    redundant_copies = sum(max(0, len(grp) - 1) for grp in duplicate_groups)
    duplicate_count = len(duplicates_flat)  # show all duplicates in summary

    duplicate_ids = [e["id"] for e in duplicates_flat]
    batch_add_label(service, duplicate_ids, lbl_duplicate_id)

    # ---- NEAR DUPLICATES ----
    near_pairs = find_near_duplicates(all_emails, threshold=70)
    near_ids = set()
    for p in near_pairs:
        near_ids.add(p["email1"]["id"])
        near_ids.add(p["email2"]["id"])
    if near_ids:
        batch_add_label(service, list(near_ids), lbl_near_id)

    session["duplicate_groups"] = duplicate_groups
    session["dup_label_id"] = lbl_duplicate_id

    uniques_count = len(all_emails) - redundant_copies
    near_pairs_count = len(near_pairs)
    near_unique_count = len(near_ids)
>>>>>>> d6f3733 (all set)

    return render_template(
        "results.html",
        fetched=fetched,
        uniques=uniques_count,
        # table data
        duplicates=duplicates_flat,
<<<<<<< HEAD
        # counts that match labels (conversation-based)
        exact_count=exact_count_conversations,
        near_count=near_count_conversations,
        # near pairs table
        similars=near_pairs
    )


@app.route("/delete", methods=["POST"])
def delete_duplicates():
    """Manual delete: send only the checked IDs to Trash (recoverable)."""
    creds = creds_from_session()
    if not creds or not creds.valid:
        return redirect(url_for("index"))

    service = safe_build_service(creds)
    if not service:
        flash("⚠️ Gmail delete request failed. Try again.")
        return redirect(url_for("index"))

    ids = request.form.getlist("ids")
    deleted_mails = []

    for message_id in ids:
        try:
            msg = service.users().messages().get(
                userId="me",
                id=message_id,
                format="metadata",
                metadataHeaders=["From", "Subject", "Date"]
            ).execute()
            headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
            deleted_mails.append({
                "id": message_id,
                "from": headers.get("From", ""),
                "subject": headers.get("Subject", ""),
                "date": headers.get("Date", "")
            })
            service.users().messages().trash(userId="me", id=message_id).execute()
        except Exception as e:
            print("Delete error:", e)

    return render_template("deleted.html", kept_one=False, deleted_mails=deleted_mails, kept_mails=[])


@app.route("/smart_delete", methods=["POST"])
def smart_delete():
    """
    KEEP the NEWEST (by internalDate) in each exact-duplicate group,
    PERMANENTLY delete the rest, and remove DUPLICATE label from the kept copy.
    """
=======
        duplicate_groups=duplicate_groups,
        duplicate_count=duplicate_count,
        redundant_copies=redundant_copies,
        similars=near_pairs,
        near_pairs_count=near_pairs_count,
        near_unique_count=near_unique_count
    )


@app.route("/smart_delete", methods=["POST"])
def smart_delete():
    """Keep newest mail per group and permanently delete older duplicates."""
>>>>>>> d6f3733 (all set)
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
<<<<<<< HEAD

        # newest first (already sorted in /dedupe)
        keep = group[0]
        kept_mails.append({
            "id": keep["id"],
            "from": keep["from"],
            "subject": keep["subject"],
            "date": keep["date"]
        })

        # Remove DUPLICATE label from the kept copy
=======
        keep = group[0]
        kept_mails.append(keep)
>>>>>>> d6f3733 (all set)
        if dup_label_id:
            try:
                batch_remove_label(service, [keep["id"]], dup_label_id)
            except Exception:
                pass
<<<<<<< HEAD

        # Permanently delete the older copies
        for e in group[1:]:
            try:
                service.users().messages().delete(userId="me", id=e["id"]).execute()
                deleted_mails.append({
                    "id": e["id"],
                    "from": e["from"],
                    "subject": e["subject"],
                    "date": e["date"]
                })
=======
        for e in group[1:]:
            try:
                service.users().messages().delete(userId="me", id=e["id"]).execute()
                deleted_mails.append(e)
>>>>>>> d6f3733 (all set)
            except Exception as ex:
                print("Smart delete error:", ex)

    return render_template("deleted.html", kept_one=True, deleted_mails=deleted_mails, kept_mails=kept_mails)


<<<<<<< HEAD
# --- RUN ---
=======
>>>>>>> d6f3733 (all set)
if __name__ == "__main__":
    app.run("0.0.0.0", port=5000, debug=True)
