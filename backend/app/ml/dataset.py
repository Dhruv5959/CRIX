"""Synthetic phishing / legitimate message corpus generator (documented as synthetic).

WHY SYNTHETIC: For a capstone we do not have a licensed, real phishing corpus we
can redistribute, and we will not fabricate "real" metrics. Instead we generate a
clearly-labeled synthetic corpus from templates and split it so that the TRAIN
and TEST sets use DISJOINT template families. Reported metrics therefore measure
generalization to unseen templates within a synthetic distribution — and are
labeled as such everywhere they surface.

The AI-vs-human dimension (§3.C) is likewise generated: "human" variants keep the
irregularities (typos, run-ons, inconsistent casing) while "AI" variants are
fluent, evenly structured and neatly formatted. This is a stylometric proxy, not
ground truth about any specific model.

A separate hand-authored held-out set (`HELD_OUT`) is used for the smoke check.
"""
from __future__ import annotations

import random

# --------------------------------------------------------------------------- #
# Template families. A-families train, B-families test (disjoint => no template
# leakage between train and split, so the metric is a real generalization test).
# --------------------------------------------------------------------------- #

PHISHING_TRAIN = [
    "Security alert: unusual activity on your {brand} account. Verify your identity "
    "at {link} to prevent lockout.",
    "Your {brand} password expires today. Reset it now by confirming your current "
    "password at {link}.",
    "New sign-in to your {brand} account. If this was not you, re-enter your password "
    "at {link} immediately to secure it.",
    "Your {brand} order is on hold pending payment. Confirm your card details at {link} "
    "to release it.",
    "A document was shared with you on {brand}. Sign in with your username and password "
    "at {link} to view it.",
    "Your {brand} account will be closed. Reply to this email with your password to keep "
    "it active.",
    "To receive your {brand} refund of {amount}, reply with your online banking PIN.",
    "Your {brand} invoice #{order} is overdue. Pay now at {link} to avoid suspension.",
    "Unusual login attempt. Confirm it was you by entering your password at {link}.",
    "Your {brand} wallet has been locked. Unlock it by confirming your seed phrase in "
    "reply to this message.",
]

LEGIT_TRAIN = [
    "Security alert: a sign-in attempt on your {brand} account was blocked. No action "
    "is required; you can review recent activity at {link}.",
    "Your {brand} password was changed successfully. If this was not you, review it at "
    "{link} or contact support from within the app.",
    "Your {brand} payment was processed successfully. Your receipt is available at {link} "
    "in the billing section.",
    "Your {brand} order #{order} has shipped. Track it from your orders page at {link}.",
    "A document was shared with you on {brand}. View it at {link}; we never ask for your "
    "password by email.",
    "Your {brand} account settings were updated. If you did not request this, review the "
    "change at {link}.",
    "Your {brand} refund of {amount} was issued to your original payment method. Details "
    "are at {link}.",
    "Your {brand} storage usage is nearing its limit. Review plans at {link} whenever you "
    "are ready.",
    "Your {brand} subscription renewed successfully this month. The invoice is at {link}.",
    "Two-factor authentication was enabled on your {brand} account. No verification is "
    "needed; you can review security settings at {link}.",
]

PHISHING_TEST = [
    "Unauthorized login to your {brand} was detected. Secure your account instantly by "
    "confirming your password at {link}.",
    "We are updating our records. Re-authenticate your {brand} account at {link} within "
    "24 hours or it will be deactivated.",
    "Your {brand} subscription could not be renewed. Confirm your payment method at "
    "{link} to continue.",
    "You have a pending refund of {amount}. Provide your bank login at {link} to receive it.",
    "Verify your {brand} account to avoid permanent deletion. Use this secure link: {link}.",
    "Your {brand} account is at risk. Reply with your current password so we can protect it.",
    "Your {brand} invoice #{order} is overdue. Pay immediately at {link} to prevent "
    "suspension of service.",
    "Quick favor — are you free to look at this document? Open it here {link} it's urgent.",
    "Your delivery is held. Confirm your address and card number in a reply to release it.",
]

LEGIT_TEST = [
    "The build is green on CI. Merging once the reviewer approves.",
    "Your package was delivered to the front desk. Details are at {link}.",
    "Security center: a suspicious sign-in attempt was blocked automatically. Review it "
    "at {link}; no action is required.",
    "Reminder to complete the annual account review. Open it at {link} from your "
    "bookmarks; we never ask for your password by email.",
    "Your subscription renewed successfully this month. The invoice is at {link}.",
    "Your refund has been issued to the original payment method. Status is at {link}.",
    "A colleague shared a document with you. Open it at {link}; no sign-in is needed.",
    "Your account details look complete. No further verification is required; review at "
    "{link} if you wish.",
    "Maintenance completed successfully. Status is posted at {link}.",
]

BRANDS = ["PayPal", "Amazon", "Google", "Microsoft", "Apple", "Netflix", "DHL",
          "Coinbase", "Instagram", "Bank of America", "Steam", "Dropbox"]
LINKS = ["http://secure-verify-{n}.tk/login", "http://{brand}-account-alert.xyz/verify",
         "https://bit.ly/3x{n}abc", "http://192.168.{n}.1/portal"]
PRIZES = ["iPhone 16 Pro", "$5,000 gift card", "free 12-month subscription", "laptop"]
NAMES = ["Priya", "Alex", "Sam", "Jordan", "Taylor", "Morgan", "Riya", "Chris"]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]

# Hand-authored held-out examples (not from any template pool).
HELD_OUT: list[tuple[str, int]] = [
    ("Your account has been locked due to suspicious activity. Click here to unlock: "
     "http://tinyurl.com/unlock-now", 1),
    ("URGENT!! Confirm your bank password immediately or your funds will be frozen.", 1),
    ("Please find attached the agenda for Monday's planning session.", 0),
    ("Hey, are we still on for lunch tomorrow? No rush, just checking.", 0),
]


def _fill(template: str, rng: random.Random) -> str:
    brand = rng.choice(BRANDS)
    n = rng.randint(1, 99)
    return template.format(
        brand=brand,
        link=rng.choice(LINKS).format(n=n, brand=brand.lower().replace(" ", "-")),
        prize=rng.choice(PRIZES),
        name=rng.choice(NAMES),
        day=rng.choice(DAYS),
        order=rng.randint(1000, 99999),
        amount=f"${rng.randint(20, 900)}.{rng.randint(10, 99)}",
    )


def _humanize(text: str, rng: random.Random) -> str:
    """Introduce human-style irregularities for the 'human-written' class."""
    text = text.strip()
    if rng.random() < 0.5:
        text = text.lower()
    if rng.random() < 0.4:
        # drop a comma / add a run-on
        text = text.replace(", ", " ")
    if rng.random() < 0.3 and len(text) > 20:
        text = text[:-1] + rng.choice(["..", "!", ""])
    return text


def _ai_smooth(text: str) -> str:
    """Produce a fluent, neatly-structured 'AI-written' variant."""
    body = text.strip()
    return f"Hello,\n\nI hope this message finds you well. {body}\n\nBest regards,\nSupport Team"


def _style_variant(text: str, ai: bool, rng: random.Random) -> str:
    """Apply a writing-style variant with intentional overlap between classes.

    Real AI output is not always peppered with filler, and real humans sometimes
    write cleanly. We preserve that overlap so the detector is a genuine
    statistical task rather than a trivial separator.
    """
    if ai:
        # Some AI output is plain and fluent with no giveaway markers.
        return text.strip() if rng.random() < 0.35 else _ai_smooth(text)
    # Some humans write cleanly; others are messy.
    return text.strip() if rng.random() < 0.30 else _humanize(text, rng)


def generate_corpus(seed: int = 1234) -> dict[str, list[dict]]:
    """Return {'train': [...], 'test': [...], 'heldout': [...]} records.

    Each record: text, phishing (0/1), ai_generated (0/1, only in train/test).
    """
    rng = random.Random(seed)
    train: list[dict] = []
    test: list[dict] = []

    for template in PHISHING_TRAIN:
        for _ in range(rng.randint(8, 14)):
            text = _fill(template, rng)
            ai = rng.random() < 0.5
            train.append({
                "text": _style_variant(text, ai, rng),
                "phishing": 1, "ai_generated": int(ai), "family": "phish_train",
            })
    for template in LEGIT_TRAIN:
        for _ in range(rng.randint(8, 14)):
            text = _fill(template, rng)
            ai = rng.random() < 0.5
            train.append({
                "text": _style_variant(text, ai, rng),
                "phishing": 0, "ai_generated": int(ai), "family": "legit_train",
            })

    for template in PHISHING_TEST:
        for _ in range(rng.randint(6, 10)):
            text = _fill(template, rng)
            ai = rng.random() < 0.5
            test.append({
                "text": _style_variant(text, ai, rng),
                "phishing": 1, "ai_generated": int(ai), "family": "phish_test",
            })
    for template in LEGIT_TEST:
        for _ in range(rng.randint(6, 10)):
            text = _fill(template, rng)
            ai = rng.random() < 0.5
            test.append({
                "text": _style_variant(text, ai, rng),
                "phishing": 0, "ai_generated": int(ai), "family": "legit_test",
            })

    heldout = [{"text": t, "phishing": label, "family": "heldout"} for t, label in HELD_OUT]
    rng.shuffle(train)
    rng.shuffle(test)
    return {"train": train, "test": test, "heldout": heldout}