# app.py
from flask import Flask, jsonify, render_template, request, redirect, url_for
from datetime import datetime
import db

# --- CONSTANTS ---
LARGE_AMOUNT_THRESHOLD = 100000.0        # Rule 1 — ₹1,00,000 
RISK_LARGE_AMOUNT   = 40                 # Rule 1 contributes up to 40%
RISK_RAPID_REPEAT   = 35                 # Rule 2 contributes up to 35%
RISK_CIRCULAR_PAIR  = 25                 # Rule 3 contributes up to 25%  
RAPID_WINDOW_SECONDS = 10 * 60           # Rule 2 (10 minutes)
RAPID_MIN_COUNT = 3                      # Rule 2 (3+ transactions)

app = Flask(__name__)

# --- DETECTION ENGINE ---
def detect_suspicious():
    """
    Returns (flagged_ids_set, findings, risk_by_id, rule_hits_by_id).
    """
    from datetime import datetime

    all_txns = db.get_all_transactions()
    flagged_ids = set()
    findings = []
    risk_by_id = {tx["id"]: 0 for tx in all_txns}
    rule_hits_by_id = {tx["id"]: [] for tx in all_txns}

    # --- Rule 1: Large amount ---
    for tx in all_txns:
        if tx["amount"] >= LARGE_AMOUNT_THRESHOLD:
            flagged_ids.add(tx["id"])
            risk_by_id[tx["id"]] += RISK_LARGE_AMOUNT
            rule_hits_by_id[tx["id"]].append("large_amount")
            findings.append({
                "transaction_id": tx["id"],
                "rule": "large_amount",
                "reason": f"Amount ₹{tx['amount']:,.2f} ≥ ₹{LARGE_AMOUNT_THRESHOLD:,.0f} threshold",
            })

    # --- Rule 2: Rapid repeats ---
    groups = db.get_transactions_grouped_by_pair()
    for (sender, receiver), txns in groups.items():
        if len(txns) < RAPID_MIN_COUNT:
            continue
        times = []
        for t in txns:
            try:
                times.append(datetime.fromisoformat(t["timestamp"]))
            except ValueError:
                times.append(None)
        for i in range(len(times) - RAPID_MIN_COUNT + 1):
            if times[i] is None:
                continue
            window_end = times[i].timestamp() + RAPID_WINDOW_SECONDS
            hit_ids = []
            for j in range(i, len(times)):
                if times[j] is None:
                    continue
                if times[j].timestamp() <= window_end:
                    hit_ids.append(txns[j]["id"])
                else:
                    break
            if len(hit_ids) >= RAPID_MIN_COUNT:
                for tid in hit_ids:
                    if "rapid_repeat" not in rule_hits_by_id[tid]:
                        risk_by_id[tid] += RISK_RAPID_REPEAT
                        rule_hits_by_id[tid].append("rapid_repeat")
                    if tid not in flagged_ids:
                        flagged_ids.add(tid)
                        findings.append({
                            "transaction_id": tid,
                            "rule": "rapid_repeat",
                            "reason": f"Rapid repeat: {sender} → {receiver} — {len(hit_ids)} transactions within {RAPID_WINDOW_SECONDS // 60} min",
                        })
                break

    # --- Rule 3: Circular pair ---
    bidir_groups = db.get_transactions_grouped_by_pair_bidirectional()
    for pair, txns in bidir_groups.items():
        senders = {t["sender"] for t in txns}
        if len(senders) < 2:
            continue
        for t in txns:
            if "circular_pair" not in rule_hits_by_id[t["id"]]:
                risk_by_id[t["id"]] += RISK_CIRCULAR_PAIR
                rule_hits_by_id[t["id"]].append("circular_pair")
            if t["id"] not in flagged_ids:
                flagged_ids.add(t["id"])
                findings.append({
                    "transaction_id": t["id"],
                    "rule": "circular_pair",
                    "reason": f"Circular pair: both-way transfers exist between {pair[0]} and {pair[1]}",
                })

    for tid in risk_by_id:
        risk_by_id[tid] = min(100, risk_by_id[tid])

    return flagged_ids, findings, risk_by_id, rule_hits_by_id


# --- ROUTES ---

@app.route("/")
@app.route("/dashboard")
def dashboard():
    all_txns = db.get_all_transactions()
    flagged_ids, findings, risk_by_id, rule_hits_by_id = detect_suspicious()
    
    rule_counts = {"large_amount": 0, "rapid_repeat": 0, "circular_pair": 0}
    for f in findings:
        if f["rule"] in rule_counts:
            rule_counts[f["rule"]] += 1

    unique_accounts = set()
    for tx in all_txns:
        unique_accounts.add(tx["sender"])
        unique_accounts.add(tx["receiver"])
        
    graph_elements_dummy = [{"data": {"id": acc}} for acc in unique_accounts]

    return render_template(
        "dashboard.html",
        transactions=all_txns,
        findings=findings,
        rule_counts=rule_counts,
        graph_elements=graph_elements_dummy
    )

@app.route("/investigate")
def investigate():
    all_txns = db.get_all_transactions()
    flagged_ids, findings, risk_by_id, rule_hits_by_id = detect_suspicious()
    reason_by_id = {f["transaction_id"]: f["reason"] for f in findings}

    # --- Build full graph ---
    flagged_accounts = set()
    for tx in all_txns:
        if tx["id"] in flagged_ids:
            flagged_accounts.add(tx["sender"])
            flagged_accounts.add(tx["receiver"])

    unique_accounts = set()
    for tx in all_txns:
        unique_accounts.add(tx["sender"])
        unique_accounts.add(tx["receiver"])

    nodes = [{"data": {"id": acc, "label": acc, "flagged": acc in flagged_accounts}}
             for acc in sorted(unique_accounts)]

    edges = [{"data": {
        "id": f"tx-{tx['id']}",
        "source": tx["sender"],
        "target": tx["receiver"],
        "amount": tx["amount"],
        "flagged": tx["id"] in flagged_ids,
        "tx_id": tx["id"],
        "risk": risk_by_id[tx["id"]],
    }} for tx in all_txns]

    graph_elements = nodes + edges

    # --- Build per-transaction history subgraph (2-hop around the two accounts) ---
    history_subgraphs = {}
    for tx in all_txns:
        center_accounts = {tx["sender"], tx["receiver"]}
        involved_accounts = set(center_accounts)
        involved_tx_ids = {tx["id"]}

        for center in center_accounts:
            frontier = {center}
            for _ in range(2):
                next_frontier = set()
                for other in all_txns:
                    if other["sender"] in frontier and other["receiver"] not in involved_accounts:
                        next_frontier.add(other["receiver"])
                        involved_accounts.add(other["receiver"])
                        involved_tx_ids.add(other["id"])
                    if other["receiver"] in frontier and other["sender"] not in involved_accounts:
                        next_frontier.add(other["sender"])
                        involved_accounts.add(other["sender"])
                        involved_tx_ids.add(other["id"])
                    if other["sender"] in frontier or other["receiver"] in frontier:
                        involved_tx_ids.add(other["id"])
                        involved_accounts.add(other["sender"])
                        involved_accounts.add(other["receiver"])
                frontier = next_frontier
                if not frontier:
                    break

        sub_nodes = [{"data": {
            "id": acc,
            "label": acc,
            "highlight": acc in center_accounts,
        }} for acc in sorted(involved_accounts)]

        sub_edges = []
        for other in all_txns:
            if other["id"] in involved_tx_ids:
                sub_edges.append({"data": {
                    "id": f"h-{tx['id']}-{other['id']}",
                    "source": other["sender"],
                    "target": other["receiver"],
                    "amount": other["amount"],
                    "is_current": other["id"] == tx["id"],
                    "flagged": other["id"] in flagged_ids,
                }})

        history_subgraphs[str(tx["id"])] = sub_nodes + sub_edges

    return render_template(
        "investigate.html",
        transactions=all_txns,
        flagged_ids=flagged_ids,
        findings=findings,
        reason_by_id=reason_by_id,
        risk_by_id=risk_by_id,
        rule_hits_by_id=rule_hits_by_id,
        graph_elements=graph_elements,
        history_subgraphs=history_subgraphs,
        findings_count=len(findings)
    )

@app.route("/alerts")
def alerts():
    all_txns = db.get_all_transactions()
    flagged_ids, findings, risk_by_id, rule_hits_by_id = detect_suspicious()
    
    unique_accounts = set()
    for tx in all_txns:
        unique_accounts.add(tx["sender"])
        unique_accounts.add(tx["receiver"])
    graph_elements_dummy = [{"data": {"id": acc}} for acc in unique_accounts]

    return render_template(
        "alerts.html", 
        findings=findings, 
        findings_count=len(findings), 
        graph_elements=graph_elements_dummy
    )

@app.route("/add", methods=["POST"])
def add_transaction():
    sender = request.form.get("sender", "").strip()
    receiver = request.form.get("receiver", "").strip()
    amount_raw = request.form.get("amount", "").strip()
    tx_type = request.form.get("tx_type", "Transfer").strip()
    location = request.form.get("location", "Unknown").strip() or "Unknown"

    if not sender or not receiver or not amount_raw:
        return redirect(url_for("investigate", error="All fields are required"))

    if sender.strip().lower() == receiver.strip().lower():
        return redirect(url_for("investigate", error="Sender and receiver cannot be the same account"))

    try:
        amount = float(amount_raw)
    except ValueError:
        return redirect(url_for("investigate", error="Amount must be a number"))

    if amount <= 0:
        return redirect(url_for("investigate", error="Amount must be greater than zero"))

    allowed_types = {"Transfer", "Deposit", "Withdrawal", "Refund"}
    if tx_type not in allowed_types:
        tx_type = "Transfer"

    timestamp = datetime.utcnow().isoformat()
    db.insert_transaction(sender, receiver, amount, timestamp, tx_type, location)
    return redirect(url_for("investigate", success="Transaction added"))

@app.route("/debug/seed")
def debug_seed():
    if db.count_transactions() > 0:
        return jsonify({
            "message": "Table already has rows; skipped seeding.",
            "row_count": db.count_transactions(),
        })

    from datetime import datetime, timedelta
    now = datetime.utcnow()
    def iso(dt): return dt.isoformat()

    samples = [
        ("ACC-1001", "ACC-1002", 1500.00,   iso(now - timedelta(hours=5)), "Transfer", "Delhi"),
        ("ACC-1002", "ACC-1003", 3205.00,   iso(now - timedelta(hours=4, minutes=55)), "Transfer", "Mumbai"),
        ("ACC-1003", "ACC-1004", 800.00,    iso(now - timedelta(hours=4, minutes=50)), "Deposit", "Bengaluru"),
        ("ACC-1004", "ACC-1005", 12000.00,  iso(now - timedelta(hours=3)), "Transfer", "Delhi"),
        ("ACC-2001", "ACC-2002", 125000.00, iso(now - timedelta(hours=2)), "Transfer", "Unknown"),
        ("ACC-2003", "ACC-2004", 180000.00, iso(now - timedelta(hours=1, minutes=50)), "Withdrawal", "Unknown"),
        ("ACC-3001", "ACC-3002", 4000.00,   iso(now - timedelta(minutes=40)), "Transfer", "Delhi"),
        ("ACC-3001", "ACC-3002", 4200.00,   iso(now - timedelta(minutes=38)), "Transfer", "Delhi"),
        ("ACC-3001", "ACC-3002", 4100.00,   iso(now - timedelta(minutes=36)), "Transfer", "Delhi"),
        ("ACC-3001", "ACC-3002", 4300.00,   iso(now - timedelta(minutes=34)), "Transfer", "Delhi"),
        ("ACC-4001", "ACC-4002", 8000.00,   iso(now - timedelta(minutes=20)), "Transfer", "Mumbai"),
        ("ACC-4002", "ACC-4001", 7900.00,   iso(now - timedelta(minutes=18)), "Transfer", "Mumbai"),
        ("ACC-5001", "ACC-5002", 600.00,    iso(now - timedelta(minutes=15)), "Transfer", "Pune"),
        ("ACC-5002", "ACC-5003", 2000.00,   iso(now - timedelta(minutes=12)), "Refund", "Pune"),
        ("ACC-5003", "ACC-5001", 900.00,    iso(now - timedelta(minutes=10)), "Transfer", "Pune"),
        ("ACC-6001", "ACC-6002", 15000.00,  iso(now - timedelta(minutes=8)), "Transfer", "Chennai"),
        ("ACC-6002", "ACC-6003", 17500.00,  iso(now - timedelta(minutes=6)), "Transfer", "Chennai"),
        ("ACC-6003", "ACC-6004", 22000.00,  iso(now - timedelta(minutes=4)), "Transfer", "Chennai"),
        ("ACC-6004", "ACC-6005", 31000.00,  iso(now - timedelta(minutes=2)), "Deposit", "Chennai"),
        ("ACC-6005", "ACC-6001", 28000.00,  iso(now), "Transfer", "Chennai"),
    ]

    for sender, receiver, amount, ts, tx_type, loc in samples:
        db.insert_transaction(sender, receiver, amount, ts, tx_type, loc)

    return redirect(url_for("dashboard", success="Sample data loaded successfully!"))

@app.route("/debug/reset")
def debug_reset():
    conn = db.get_connection()
    conn.execute("DELETE FROM transactions")
    conn.execute("DELETE FROM sqlite_sequence WHERE name='transactions'")
    conn.commit()
    conn.close()
    return redirect(url_for("dashboard", success="Database reset successfully!"))

@app.route("/transactions")
def list_transactions():
    return jsonify(db.get_all_transactions())

if __name__ == "__main__":
    db.init_db()
    app.run(debug=True)