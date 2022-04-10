import requests
import hashlib
import sys

#In the following function, we are going to turn our clear-text password into a SHA1 hash.
def pwned_api_check(password):
    #In the following line, the hash will be made.
    #The reason that we make it upper-case is that the hashlib class will return the hash
    #in lower-case format. So we should upper it manually.
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    #You must bare this into your mind that we don't want to send the entire hash to the
    #mentioned web-site for the sake of security. Maybe that website will store it in it's database !
    #So we will break it into two sections.( Notice it's totally up to you that how many characters
    #you want to send to the website, I chose 5. You can choose more, but choosing less characters
    #won't make sense. Because there could be thousands of passwords that have the same first 5 characters
    #and we want to make it as precise as possible ).
    first5_chars, tail = sha1password[:5], sha1password[5:]
    #Now, we will send the first 5 characters to the website.
    response = request_api_data(first5_chars)
    return get_password_leaks_count(response, tail)

#The $query_char is equal to our hash first 5 characters.
def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    #In the following lines, if the response will equal to 200, it means that the request has been
    #sent successfully. Other codes usually represent errors. So if the request wasn't successful,
    #we will raise a manual error for the sake of logging.
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetched: {res.status_code}")
    else:
        pass
    return res

#The mentioned website will return the results in this format:
#hashed_characters:{counts}
#The $counts represents how many times that hash is used.
#So we're going to split the result into two sections respectively,$h and $count.
def get_password_leaks_count(hashes, hash_to_check):
    #The $hashes variable is from the requests library. This library will make us
    #to get the text of our request.
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        #Now, if $h is equal to the rest of our hash characters which is $hash_to_check
        # ( from the fifth character to end ), it means our password has been pwned
        # based on the website's database.
        if h == hash_to_check:
            #The following line will return how many times the password has been used.
            return count
    return 0

def main(password_list_path):
    #We are oppening the file that contains the list of our passwords in clear-text.
    with open(password_list_path) as passwords:
        for each_password in passwords:
            #Because our passwords have been separated by \n in our file,
            #we are removing the \n for the sake of simplicity.
            each_password = each_password.strip("\n")
            count = pwned_api_check(each_password)
            if count:
                print(f"{each_password} was found {count} times. You should probably change it.")
            else:
                print(f"Nothing found about {each_password}, You're all good !")
    return "DONE !"

#The sys.exit method will end the app.
sys.exit(main(input("Type the password list path: ")))

