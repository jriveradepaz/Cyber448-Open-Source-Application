import os
import json
import argparse
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

MALSHARE_API_KEY = os.getenv("MALSHARE_API_KEY", "4ddbba3649a21f53adfd28a7205c9b99266baf28e9c5fe499b90b1192e1453a3")
BASE_URL = "https://malshare.com/api.php"
REQUEST_TIMEOUT = 10


def _make_session(retries: int = 2, backoff_factor: float = 0.5) -> requests.Session:
	s = requests.Session()
	retry = Retry(total=retries, backoff_factor=backoff_factor, status_forcelist=(429, 500, 502, 503, 504))
	adapter = HTTPAdapter(max_retries=retry)
	s.mount("https://", adapter)
	s.mount("http://", adapter)
	return s


def get_malshare_info(api_key: Optional[str] = None, file_hash: Optional[str] = None, save_path: str = "data.json"):
	"""
	Query MalShare for a given file hash and save the raw response to `save_path`.

	- `api_key`: optional override; if not provided uses env var or constant.
	- `file_hash`: optional override; if not provided the user is prompted.
	"""

	key = api_key or MALSHARE_API_KEY
	if not key or "YOUR_MALSHARE_API_KEY_HERE" in key:
		print("[Error] MALSHARE_API_KEY is not set. Set MALSHARE_API_KEY environment variable or pass api_key.")
		return

	if not file_hash:
		file_hash = input("Enter the file hash to check (MD5 / SHA1 / SHA256): ").strip()

	if not file_hash:
		print("No hash entered, aborting.")
		return

	params = {"api_key": key, "action": "getinfo", "hash": file_hash}

	print(f"\nQuerying MalShare for hash: {file_hash}")
	session = _make_session()

	try:
		resp = session.get(BASE_URL, params=params, timeout=REQUEST_TIMEOUT)
		resp.raise_for_status()
		text = resp.text.strip()

		if not text:
			print("[Error] MalShare returned an empty response.")
			return

		if text.lower().startswith("error"):
			print(f"[Error] MalShare response: {text}")
			# still save the raw response so caller can inspect
			_save_result(save_path, file_hash, text)
			return

		# Try to parse the response as JSON (MalShare returns JSON-like text in many cases)
		parsed = None
		try:
			parsed = json.loads(text)
		except Exception:
			parsed = None

		print("\n=== MalShare Result ===")
		if parsed is not None:
			# pretty-print parsed JSON
			print(json.dumps(parsed, indent=4))
		else:
			print(text)

		_save_result(save_path, file_hash, text, parsed)
		print(f"\nResult saved to {save_path}")

	except requests.exceptions.RequestException as e:
		print(f"[Error] MalShare request failed: {e}")


def _save_result(path: str, file_hash: str, raw_text: str, parsed: Optional[dict] = None):
	payload = {"hash": file_hash, "raw": raw_text}
	if parsed is not None:
		payload["parsed"] = parsed

	try:
		with open(path, "w", encoding="utf-8") as f:
			json.dump(payload, f, indent=4)
	except TypeError:
		# Fallback if some value is not serializable
		with open(path, "w", encoding="utf-8") as f:
			json.dump({"hash": file_hash, "raw": str(raw_text)}, f, indent=4)


def _cli():
	p = argparse.ArgumentParser(description="Query MalShare for a file hash and save the response.")
	p.add_argument("--hash", "-s", help="File hash (MD5/SHA1/SHA256)")
	p.add_argument("--api-key", help="MalShare API key (overrides env var)")
	p.add_argument("--out", "-o", default="data.json", help="Output JSON file path")
	args = p.parse_args()
	get_malshare_info(api_key=args.api_key, file_hash=args.hash, save_path=args.out)


if __name__ == "__main__":
	_cli()

