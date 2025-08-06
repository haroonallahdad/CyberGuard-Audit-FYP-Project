# phone_tracker.py
# Updated with detailed exception logging to help diagnose intermittent failures.

import sys
import json
import phonenumbers
from phonenumbers import geocoder, carrier, timezone

def track_phone_number(phone_number_str):
    """
    Parses a phone number and attempts to retrieve publicly available information
    like country, carrier, and timezones.

    Args:
        phone_number_str (str): The phone number to check, e.g., '+15551234567'.

    Returns:
        A dictionary of results, including validation status, country, carrier,
        timezones, and an error message if an exception occurs.
    """
    results = {
        "input_number": phone_number_str,
        "is_valid": False,
        "is_possible": False,
        "country": "N/A",
        "carrier": "N/A",
        "timezones": [],
        "associated_accounts_simulated": [],  # Simulated data for demonstration
        "location_simulated": "N/A",  # Simulated data for demonstration
        "error": None
    }

    try:
        # It's good practice to provide a default region code if the number
        # doesn't start with a '+' for international format.
        # For general international numbers, the '+' is crucial.
        parsed_number = phonenumbers.parse(phone_number_str, None)

        results["is_valid"] = phonenumbers.is_valid_number(parsed_number)
        results["is_possible"] = phonenumbers.is_possible_number(parsed_number)

        if results["is_valid"]:
            # Get country
            country_name = geocoder.description_for_number(parsed_number, "en")
            results["country"] = country_name

            # Get carrier
            carrier_name = carrier.name_for_number(parsed_number, "en")
            results["carrier"] = carrier_name

            # Get timezones
            timezones_list = list(timezone.time_zones_for_number(parsed_number))
            if timezones_list:
                results["timezones"] = timezones_list

            # --- Simulated Data for Demonstration
            # IMPORTANT: The following are simulated and cannot be obtained
            # through simple OSINT for a generic phone number due to privacy.
            if "1234567890" in phone_number_str or "5551234567" in phone_number_str:
                results["associated_accounts_simulated"] = ["dummy_social_1", "dummy_app_user"]
                results["location_simulated"] = "Simulated: New York, USA (approximate city based on number prefix)"
            elif results["country"] != "N/A":
                results["associated_accounts_simulated"] = [f"simulated_account_{username.lower()}" for username in ["user1", "user2"]]
                results["location_simulated"] = f"Simulated: General area in {results['country']}"
            # --- End Simulated Data
    
    except Exception as e:
        # This is the new, more detailed logging for the backend.
        # It will print the full exception to your server console.
        print(f"Error processing number '{phone_number_str}': {e}", file=sys.stderr)
        results["error"] = f"Error processing number: {str(e)}"

    return results

if __name__ == '__main__':
    # This block allows the script to be run directly from the command line
    # It expects the phone number as the first command-line argument
    if len(sys.argv) > 1:
        phone_num = sys.argv[1]
        output = track_phone_number(phone_num)
        # Print the results as JSON to standard output
        print(json.dumps(output, indent=2))
