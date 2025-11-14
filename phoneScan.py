import requests
import json
import os

def get_phone_number():

    file_path = 'data.json'
    #filepath for where data is stored after being checked
    phone = input('Enter phone number: ')
    CC = input('Enter default country code (optional): ')
    url = 'https://api.veriphone.io/v2/verify?phone=' + phone + '&country_code=' + CC + '&key=DD0982B23C8641CC97CEF6682591574C'
    #url for veriphone API and necessary fields asking for user input
    
    try:
        response = requests.get(url)
        
        if response.status_code == 200:
            posts = response.json()
            print(posts)
        else:
            print('Error:', response.status_code)
    except Exception as e:
        print('An error occurred:', str(e))
        #sends request to veriphone API if successful the data is printed, if there is an error it prints it
        
    finally:
        #at the end of the main function for the user the data is then stored onto a json file
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as file:
                try:
                    data = json.load(file)
                except json.JSONDecodeError:
                    data = []
                    # attempts to load the file, if there is an error it is printed
        else:
            data = []
            #creates an array if the file does not exist
        data.append(posts)
        with open(file_path, 'w', encoding='utf-8') as file:
            json.dump(data, file, indent=4, ensure_ascii=False)
        print(f'Data added to {file_path} successfully.')
        #adds the data onto the json file and confirms to the user that it was successful
        
            
            