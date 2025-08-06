# osint_checker.py
import requests
import sys
import json
import phonenumbers

def check_username(username, socketio=None):
    """
    Checks for the existence of a username on a few popular social media sites.
    Returns a dictionary of results.

    Args:
        username (str): The username to check
        socketio: Optional Flask-SocketIO instance for progress updates
    """
    results = {}

    # Define sites to check and their URL patterns
    # {username} will be replaced by the actual username
    sites = {
        "GitHub": "https://github.com/{username}",
        "Twitter": "https://twitter.com/{username}",
        "Instagram": "https://instagram.com/{username}",
        "LinkedIn": "https://www.linkedin.com/in/{username}",
        "Reddit": "https://www.reddit.com/user/{username}",
        "Pinterest": "https://www.pinterest.com/{username}/",
        "Facebook": "https://facebook.com/{username}",
        "TikTok": "https://tiktok.com/@{username}",
        "YouTube": "https://youtube.com/@{username}",
        "Medium": "https://medium.com/@{username}",
        "Dev.to": "https://dev.to/{username}",
        "Behance": "https://behance.net/{username}",
        "Dribbble": "https://dribbble.com/{username}",
        "GitLab": "https://gitlab.com/{username}",
        "Stack Overflow": "https://stackoverflow.com/users/{username}",
        "Twitch": "https://twitch.tv/{username}",
        "Steam": "https://steamcommunity.com/id/{username}",
        "Vimeo": "https://vimeo.com/{username}",
        "Spotify": "https://open.spotify.com/user/{username}",
        "Telegram": "https://t.me/{username}"
    }

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    total_sites = len(sites)
    sites_checked = 0
    socketio = None  # Will be set by app.py when calling this function

    for site, url_pattern in sites.items():
        if socketio:
            progress = int((sites_checked / total_sites) * 100)
            socketio.emit('osint_progress', {'progress': progress})
        url = url_pattern.format(username=username)
        try:
            # Make a GET request to the site
            response = requests.get(url, headers=headers, timeout=10) # 10-second timeout

            # Check status code for existence
            # 200 OK generally means the page exists
            # 404 Not Found generally means the page does not exist
            # Some sites might return 200 but with a "User not found" message in content
            if response.status_code == 200:
                # Basic content check for common "not found" scenarios
                # This is a simple check; more robust checks would involve parsing HTML
                if "Page Not Found" in response.text or "This page doesn't exist" in response.text or "Sorry, this page isn't available." in response.text:
                    results[site] = {"found": False, "url": url, "status_code": response.status_code, "message": "Page exists but user not found (content check)"}
                else:
                    results[site] = {"found": True, "url": url, "status_code": response.status_code}
            elif response.status_code == 404:
                results[site] = {"found": False, "url": url, "status_code": response.status_code}
            else:
                # Other status codes (e.g., 302 redirect, 500 server error)
                results[site] = {"found": "unknown", "url": url, "status_code": response.status_code, "message": f"Unexpected status code: {response.status_code}"}

        except requests.exceptions.Timeout:
            results[site] = {"found": "unknown", "url": url, "message": "Request timed out"}
        except requests.exceptions.ConnectionError:
            results[site] = {"found": "unknown", "url": url, "message": "Connection error (site unreachable)"}
        except Exception as e:
            results[site] = {"found": "unknown", "url": url, "message": f"An unexpected error occurred: {str(e)}"}
        
        sites_checked += 1
        if socketio:
            progress = int((sites_checked / total_sites) * 100)
            socketio.emit('osint_progress', {'progress': progress})
    
    # Ensure we show 100% at the end
    if socketio:
        socketio.emit('osint_progress', {'progress': 100})
    
    return results

def validate_number(number, country='PK'):
    try:
        parsed = phonenumbers.parse(number, country)
        if not phonenumbers.is_possible_number(parsed):
            return False, "Number is not possible for this country."
        if not phonenumbers.is_valid_number(parsed):
            return False, "Number is not valid for this country."
        # Additional: check length for Pakistan
        if country == 'PK' and len(str(parsed.national_number)) != 10:
            return False, "Pakistani numbers must have exactly 10 digits after country code."
        return True, ""
    except Exception as e:
        return False, str(e)

if __name__ == '__main__':
    # This block allows the script to be run directly from the command line
    # It expects the username as the first command-line argument
    if len(sys.argv) > 1:
        username_to_check = sys.argv[1]
        output = check_username(username_to_check)
        # Print the results as JSON to standard output
        print(json.dumps(output, indent=2))
    else:
        print(json.dumps({"error": "No username provided. Usage: python osint_checker.py <username>"}))

