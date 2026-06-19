"""
mapper.py

Maps Windows Event IDs to MITRE ATT&CK techniques.
"""

MITRE_MAPPING = {
    4625: {
        "technique": "T1110",
        "name": "Brute Force"
    },

    4624: {
        "technique": "T1078",
        "name": "Valid Accounts"
    },

    4720: {
        "technique": "T1136",
        "name": "Create Account"
    }
}


def map_event(event_id):
    """
    Return MITRE ATT&CK mapping information.

    Args:
        event_id (int)

    Returns:
        dict
    """

    return MITRE_MAPPING.get(
        event_id,
        {
            "technique": "Unknown",
            "name": "Unknown Event"
        }
    )
