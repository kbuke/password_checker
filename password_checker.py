# check if your password has been hacked

import requests # allows us to make a request
import hashlib
import sys

def request_api_date(query_char): #where query_char is the hashed func
    url = 'https://api.pwnedpasswords.com/range/' + query_char # this is the API url
    # This API needs it password to be hashed (hence CBFDA)
    # It uses technique called K-Anonymity (know key info about you, but not who u r)
    # The CBFDA above is just the first 5 digits of our hashed password, it is NOT the whole thing
    resp = requests.get(url)
    if resp.status_code != 200:
        raise RuntimeError(f"Error fetching: {resp.status_code}, check api and try again")
    return resp

# def read_response(response):
#     print(response.text) # this shows all the hashes that match the beginning of our password, after colon shows how many times hacked

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes: # remember we are splitting the tuple hence two for h and count
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    # check password if it exists in API response
    # need to ensure all chars are uppercase as well as per rules of API
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper() #sha1 is the hashing lib
    # need to send this to the request_api_date funct
    # get first 5 chars
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_date(first5_char)
    # return read_response(response)
    return get_password_leaks_count(response, tail)

# request_api_date("123")
# pwned_api_check("hi there")

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count: 
            print(f"{password} was found {count} times.... you should probably change your password")
        else:
            print(f"{password} was not found. Carry on")
    return "Done"

if __name__ == "__main__":
    main(sys.argv[1:]) # accept any number of args
