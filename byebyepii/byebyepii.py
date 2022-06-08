import json
import hashlib


def hashString(s: str) -> str:
    """
    Hash a string using SHA256

    Args:
        s: string to hash

    Returns:
        hashed string
    """
    if s:
        return hashlib.sha256(s.encode("utf-8")).hexdigest()
    return None


def byeByePii(pii_dict: dict, keys_to_hash: list, subkeys_to_hash: list) -> dict:
    """
    Hash the PII in the given dictionary.

    Args:
        pii_dict: The dictionary to hash.
        keys_to_hash: The keys to hash.

    Returns:
        A dictionary with the hashed PII.
    """
    if keys_to_hash:
        for key in keys_to_hash:
            if key in pii_dict:
                if isinstance(pii_dict[key], dict):
                    for subkey in subkeys_to_hash:
                        if subkey in pii_dict[key]:
                            pii_dict[key][subkey] = hashString(
                                json.dumps(pii_dict[key][subkey])
                            )
                else:
                    pii_dict[key] = hashString(json.dumps(pii_dict[key]))
    return pii_dict
