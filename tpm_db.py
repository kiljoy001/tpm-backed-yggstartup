#!/usr/bin/env python3
import sqlite3
import argparse
import json
import sys
import os
import subprocess
import hashlib
import binascii
import base64
import getpass
import shutil
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Default DB path
DB_PATH = os.environ.get("TPM_DB_PATH", "/var/lib/yggdrasil/tpm_state.db")

# --- YubiKey / Nitrokey Integration ---

def check_yubikey_tools():
    return shutil.which("ykchalresp") is not None

def get_yubikey_challenge_response(salt_hex):
    """
    Sends the salt (challenge) to the YubiKey (Slot 2 by default)
    and gets the response. This response effectively becomes the password.
    """
    if not check_yubikey_tools():
        raise RuntimeError("YubiKey tools ('ykchalresp') not found in PATH.")

    try:
        # We use the salt as the challenge.
        # ykchalresp expects hex input.
        cmd = ["ykchalresp", "-2", "-x", salt_hex]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        response = result.stdout.strip()
        if not response:
            raise ValueError("Empty response from YubiKey. Is it plugged in?")
        return response
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"YubiKey error: {e.stderr}")

# --- BIP-39 Implementation ---
WORDLIST = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become", "beef", "before", "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit", "best", "bet", "better", "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry", "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog", "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child", "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle", "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog", "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut", "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come", "comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress", "connect", "consider", "control", "convince", "cook", "cool", "copper", "copy", "coral", "core", "corn", "corner", "correct", "cost", "cotton", "couch", "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle", "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream", "create", "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard", "curious", "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad", "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december", "decide", "decline", "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay", "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend", "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk", "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display", "distance", "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft", "dragon", "drama", "draw", "dream", "dress", "drift", "drill", "drink", "drip", "drive", "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo", "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either", "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else", "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable", "enact", "end", "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode", "equal", "equip", "era", "erase", "erode", "erosion", "error", "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil", "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend", "extra", "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame", "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female", "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure", "file", "film", "filter", "final", "find", "fine", "finger", "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash", "flat", "flavor", "flee", "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly", "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot", "force", "forest", "forget", "fork", "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile", "frame", "frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown", "frozen", "fruit", "fuel", "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy", "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp", "gate", "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance", "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue", "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green", "grid", "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "handle", "hang", "happen", "happy", "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health", "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen", "hero", "hidden", "high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow", "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host", "hotel", "hour", "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify", "idle", "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune", "impact", "impose", "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate", "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial", "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane", "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest", "invite", "involve", "iron", "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge", "juice", "jump", "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know", "lab", "label", "labor", "ladder", "lady", "lake", "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law", "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture", "left", "leg", "legal", "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty", "library", "license", "life", "lift", "light", "like", "limb", "limit", "link", "lion", "liquid", "list", "listen", "liter", "little", "live", "liver", "load", "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop", "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet", "maid", "mail", "main", "major", "make", "mammal", "man", "manage", "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine", "market", "marriage", "mask", "mass", "master", "match", "material", "math", "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media", "melody", "melt", "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry", "mesh", "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind", "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed", "mixture", "mobile", "model", "modify", "mom", "moment", "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning", "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie", "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music", "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin", "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative", "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral", "never", "news", "next", "nice", "night", "noble", "noise", "nominee", "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice", "novel", "now", "nuclear", "number", "nurse", "nut", "oak", "obey", "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean", "october", "odor", "off", "offer", "office", "often", "oil", "okay", "old", "olive", "olympic", "omit", "once", "one", "onion", "online", "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit", "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich", "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over", "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper", "parade", "parent", "park", "parrot", "party", "pass", "patch", "path", "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper", "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical", "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play", "please", "pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar", "pole", "police", "pond", "pony", "pool", "popular", "portion", "position", "possible", "post", "potato", "pottery", "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare", "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority", "prison", "private", "prize", "problem", "process", "produce", "profit", "program", "project", "promote", "proof", "property", "prosper", "protect", "proud", "provide", "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle", "pyramid", "quality", "quantum", "quarter", "question", "quick", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail", "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid", "rare", "rate", "rather", "raven", "raw", "reach", "react", "read", "real", "realm", "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle", "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject", "relax", "release", "relief", "rely", "remain", "remember", "remind", "remove", "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "reply", "report", "rescue", "resemble", "resist", "resource", "response", "result", "retire", "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib", "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket", "romance", "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say", "scale", "scan", "scare", "scatter", "scene", "scheme", "school", "science", "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea", "search", "season", "seat", "second", "secret", "section", "security", "seed", "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence", "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft", "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine", "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side", "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar", "simple", "since", "sing", "siren", "sister", "sit", "six", "size", "skate", "sketch", "ski", "skill", "skin", "skirt", "skull", "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan", "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social", "sock", "soft", "solar", "soldier", "solid", "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup", "source", "south", "space", "spare", "speak", "special", "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay", "steak", "steel", "stem", "step", "stereo", "stick", "still", "sting", "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street", "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject", "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun", "sunny", "sunset", "super", "supply", "supreme", "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain", "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup", "system", "table", "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target", "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten", "tenant", "tennis", "tent", "term", "test", "text", "thank", "that", "theme", "then", "theory", "there", "they", "thing", "this", "thought", "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger", "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco", "today", "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top", "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist", "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic", "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree", "trend", "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck", "true", "truly", "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle", "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical", "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo", "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown", "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge", "usage", "use", "used", "useful", "useless", "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley", "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle", "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel", "veteran", "viable", "vibrant", "vicious", "victory", "video", "view", "village", "vintage", "violin", "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal", "voice", "void", "volcano", "volume", "vote", "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut", "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave", "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "week", "weird", "welcome", "west", "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip", "whisper", "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing", "wink", "winner", "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder", "wood", "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year", "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo"]

def bytes_to_mnemonic(data_bytes):
    if len(data_bytes) % 4 != 0:
        raise ValueError("Data length in bits must be divisible by 32")

    bits = "".join([bin(b)[2:].zfill(8) for b in data_bytes])

    h = hashlib.sha256(data_bytes).hexdigest()
    checksum_bits = bin(int(h, 16))[2:].zfill(256)[:len(data_bytes) * 8 // 32]

    all_bits = bits + checksum_bits
    chunks = [all_bits[i:i+11] for i in range(0, len(all_bits), 11)]

    return " ".join([WORDLIST[int(chunk, 2)] for chunk in chunks])

def mnemonic_to_bytes(mnemonic_str):
    words = mnemonic_str.strip().lower().split()
    if len(words) not in [12, 15, 18, 21, 24]:
        raise ValueError("Invalid mnemonic length")

    bits = ""
    for w in words:
        if w not in WORDLIST:
            raise ValueError(f"Unknown word: {w}")
        idx = WORDLIST.index(w)
        bits += bin(idx)[2:].zfill(11)

    divider_index = (len(bits) // 33) * 32
    entropy_bits = bits[:divider_index]
    checksum_bits = bits[divider_index:]

    entropy_bytes = int(entropy_bits, 2).to_bytes(len(entropy_bits) // 8, byteorder='big')

    h = hashlib.sha256(entropy_bytes).hexdigest()
    calculated_checksum = bin(int(h, 16))[2:].zfill(256)[:len(entropy_bytes) * 8 // 32]

    if checksum_bits != calculated_checksum:
        raise ValueError("Invalid checksum")

    return entropy_bytes

# --- Artifact Encryption ---

def derive_key(secret, salt):
    # This secret is either a password OR the hex response from YubiKey
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=300000,
    )
    return base64.urlsafe_b64encode(kdf.derive(secret.encode()))

def encrypt_artifact(key_hex, secret, use_yubikey=False):
    salt = os.urandom(16)

    if use_yubikey:
        print("Insert YubiKey and press button (if configured)...")
        # Challenge is the hex representation of the salt
        challenge = salt.hex()
        secret = get_yubikey_challenge_response(challenge)
        print("YubiKey response received.")

    key = derive_key(secret, salt)
    f = Fernet(key)
    encrypted = f.encrypt(key_hex.encode())

    return {
        "version": 1,
        "type": "yubikey" if use_yubikey else "password",
        "salt": base64.b64encode(salt).decode(),
        "data": base64.b64encode(encrypted).decode()
    }

def decrypt_artifact(json_data, secret=None, use_yubikey=False):
    if json_data.get("version") != 1:
        raise ValueError("Unsupported artifact version")

    salt = base64.b64decode(json_data["salt"])
    encrypted = base64.b64decode(json_data["data"])

    artifact_type = json_data.get("type", "password")

    if artifact_type == "yubikey" or use_yubikey:
        if not check_yubikey_tools():
             raise RuntimeError("Artifact requires YubiKey, but ykchalresp not found.")
        print("Insert YubiKey for decryption...")
        challenge = salt.hex()
        secret = get_yubikey_challenge_response(challenge)
    elif secret is None:
        raise ValueError("Password required for password-type artifact")

    key = derive_key(secret, salt)
    f = Fernet(key)
    return f.decrypt(encrypted).decode()

# --- Database Logic ---

def get_db():
    db_dir = os.path.dirname(DB_PATH)
    if not os.path.exists(db_dir):
        try:
            os.makedirs(db_dir, exist_ok=True)
        except OSError as e:
            fallback = os.path.join(os.getcwd(), "tpm_state.db")
            print(f"Warning: Could not create {db_dir}: {e}. Using {fallback}", file=sys.stderr)
            return sqlite3.connect(fallback)
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS handles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    primary_handle TEXT NOT NULL,
                    key_handle TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    active BOOLEAN DEFAULT 1
                )''')
    conn.commit()
    conn.close()
    if os.path.exists(DB_PATH):
        try:
            os.chmod(DB_PATH, 0o600)
        except: pass

def add_handles(primary, key):
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE handles SET active = 0 WHERE active = 1")
    c.execute("INSERT INTO handles (primary_handle, key_handle) VALUES (?, ?)", (primary, key))
    conn.commit()
    conn.close()
    print(json.dumps({"status": "success", "primary": primary, "key": key}))

def get_active():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT primary_handle, key_handle, created_at FROM handles WHERE active = 1 ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    conn.close()
    if row:
        print(json.dumps({
            "found": True,
            "primary_handle": row[0],
            "key_handle": row[1],
            "created_at": row[2]
        }))
    else:
        print(json.dumps({"found": False}))

def mark_inactive(primary):
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE handles SET active = 0 WHERE primary_handle = ?", (primary,))
    conn.commit()
    conn.close()
    print(json.dumps({"status": "marked_inactive"}))

def get_all_tracked():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT primary_handle, key_handle, active FROM handles")
    rows = c.fetchall()
    conn.close()
    return [{"primary": r[0], "key": r[1], "active": bool(r[2])} for r in rows]

def check_tpm_handles():
    try:
        result = subprocess.run(["tpm2_getcap", "handles-persistent"], capture_output=True, text=True)
        if result.returncode != 0: return []
        handles = []
        for line in result.stdout.splitlines():
            parts = line.split()
            for p in parts:
                if p.startswith("0x"):
                    handles.append(p.lower())
        return handles
    except FileNotFoundError:
        return []

def garbage_collect():
    tracked = get_all_tracked()
    # Create a set of all handles that SHOULD exist (active or inactive records in DB)
    known_handles = set()
    for item in tracked:
        known_handles.add(item['primary'].lower())
        known_handles.add(item['key'].lower())

    tpm_handles = check_tpm_handles()
    tpm_handles_norm = [h.lower() for h in tpm_handles]

    evicted_count = 0
    errors = []

    # 1. Evict anything in TPM that is NOT in our DB at all (Orphans)
    for h in tpm_handles_norm:
        if h not in known_handles:
            print(f"GC: Evicting orphan handle {h}...", file=sys.stderr)
            try:
                subprocess.run(["sudo", "tpm2_evictcontrol", "-C", "o", "-c", h], check=True, capture_output=True)
                evicted_count += 1
            except subprocess.CalledProcessError as e:
                errors.append(f"Failed to evict orphan {h}: {e}")

    # 2. Evict things we know about but marked as inactive
    for item in tracked:
        if not item['active']:
            for h in [item['primary'].lower(), item['key'].lower()]:
                if h in tpm_handles_norm:
                    print(f"GC: Evicting inactive handle {h}...", file=sys.stderr)
                    try:
                        subprocess.run(["sudo", "tpm2_evictcontrol", "-C", "o", "-c", h], check=True, capture_output=True)
                        evicted_count += 1
                    except subprocess.CalledProcessError as e:
                        errors.append(f"Failed to evict {h}: {e}")

    print(json.dumps({"status": "gc_complete", "evicted": evicted_count, "errors": errors}))

# --- Command Handler ---

def hex_to_mnemonic(hex_str):
    try:
        data = bytes.fromhex(hex_str)
        if len(data) not in [16, 20, 24, 28, 32]:
            print(json.dumps({"error": f"Invalid key length: {len(data)} bytes. Expected 16, 20, 24, 28, or 32."}))
            return
        words = bytes_to_mnemonic(data)
        print(json.dumps({"mnemonic": words}))
    except Exception as e:
        print(json.dumps({"error": str(e)}))

def mnemonic_to_hex(mnemonic_str):
    try:
        data = mnemonic_to_bytes(mnemonic_str)
        print(json.dumps({"hex": data.hex()}))
    except Exception as e:
        print(json.dumps({"error": str(e)}))

def sign_artifact_gpg(filename, key_id=None):
    """Signs the file using GPG (works with YubiKey/Nitrokey smart cards)."""
    if shutil.which("gpg") is None:
        print(json.dumps({"error": "GPG not found. Install gnupg to use signing."}))
        return False

    sig_file = filename + ".asc"
    cmd = ["gpg", "--armor", "--detach-sign", "--output", sig_file]

    if key_id and key_id != "default":
        cmd.extend(["--default-key", key_id])

    cmd.append(filename)

    try:
        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def verify_artifact_gpg(filename):
    """Verifies the detached signature of the file."""
    if shutil.which("gpg") is None:
        print("Warning: GPG not found, cannot verify signature.")
        return False

    sig_file = filename + ".asc"
    if not os.path.exists(sig_file):
        return False

    cmd = ["gpg", "--verify", sig_file, filename]

    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False

def handle_export(hex_key, filename, use_yubikey, sign_key=None):
    password = None
    if not use_yubikey:
        print("Enter a strong password to encrypt the backup artifact:")
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm: ")
        if password != confirm:
            print(json.dumps({"error": "Passwords do not match"}))
            return

    try:
        artifact = encrypt_artifact(hex_key, password, use_yubikey)
        with open(filename, 'w') as f:
            json.dump(artifact, f, indent=2)

        mnemonic = bytes_to_mnemonic(bytes.fromhex(hex_key))

        msg = "Backup saved."
        if use_yubikey:
            msg += " Encrypted with YubiKey HMAC-SHA1."
        else:
            msg += " Encrypted with password."

        if sign_key:
            print("Signing artifact with GPG (Insert Nitrokey/YubiKey if needed)...", file=sys.stderr)
            if sign_artifact_gpg(filename, sign_key):
                msg += " GPG Signature attached."
            else:
                msg += " GPG Signing FAILED."

        print(json.dumps({
            "status": "success",
            "artifact_file": filename,
            "mnemonic": mnemonic,
            "message": msg
        }))
    except Exception as e:
        print(json.dumps({"error": str(e)}))

def handle_import(filename):
    if not os.path.exists(filename):
        print(json.dumps({"error": "File not found"}))
        return

    # Check for signature
    if os.path.exists(filename + ".asc"):
        print("Found GPG signature. Verifying...", file=sys.stderr)
        if verify_artifact_gpg(filename):
            print("✅ Signature VERIFIED.", file=sys.stderr)
        else:
            print("❌ Signature VERIFICATION FAILED! Aborting import.", file=sys.stderr)
            return

    # Peek at file to see type
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
    except:
        print(json.dumps({"error": "Invalid JSON file"}))
        return

    is_yubikey = data.get("type") == "yubikey"
    password = None

    print(f"Decrypting artifact {filename}...")

    if not is_yubikey:
        password = getpass.getpass("Password: ")

    try:
        hex_key = decrypt_artifact(data, password, is_yubikey)
        mnemonic = bytes_to_mnemonic(bytes.fromhex(hex_key))

        print(json.dumps({
            "status": "success",
            "hex_key": hex_key,
            "mnemonic": mnemonic,
            "message": "Key decrypted successfully."
        }))
    except Exception as e:
        print(json.dumps({"error": f"Decryption failed: {str(e)}"}))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--init", action="store_true", help="Initialize DB")
    parser.add_argument("--get-active", action="store_true", help="Get currently active handles")
    parser.add_argument("--add", nargs=2, metavar=('PRIMARY', 'KEY'), help="Add new active handles")
    parser.add_argument("--mark-inactive", metavar='PRIMARY', help="Mark a primary handle set as inactive")
    parser.add_argument("--gc", action="store_true", help="Garbage collect inactive handles from TPM")
    parser.add_argument("--to-mnemonic", metavar='HEX', help="Convert HEX key to BIP-39 mnemonic")
    parser.add_argument("--from-mnemonic", metavar='WORDS', help="Convert BIP-39 mnemonic to HEX key")

    parser.add_argument("--export-artifact", nargs=2, metavar=('HEX_KEY', 'FILENAME'), help="Encrypt and save key to JSON")
    parser.add_argument("--import-artifact", metavar='FILENAME', help="Decrypt key from JSON")

    parser.add_argument("--use-yubikey", action="store_true", help="Use YubiKey HMAC-SHA1 for encryption/decryption instead of password")
    parser.add_argument("--sign", nargs='?', const="default", metavar="KEY_ID", help="Sign output artifact with GPG (YubiKey/Nitrokey)")

    args = parser.parse_args()

    init_db()

    if args.get_active:
        get_active()
    elif args.add:
        add_handles(args.add[0], args.add[1])
    elif args.mark_inactive:
        mark_inactive(args.mark_inactive)
    elif args.gc:
        garbage_collect()
    elif args.to_mnemonic:
        hex_to_mnemonic(args.to_mnemonic)
    elif args.from_mnemonic:
        mnemonic_to_hex(args.from_mnemonic)
    elif args.export_artifact:
        handle_export(args.export_artifact[0], args.export_artifact[1], args.use_yubikey, args.sign)
    elif args.import_artifact:
        handle_import(args.import_artifact)

if __name__ == "__main__":
    main()
