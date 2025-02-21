from typing import Counter
from flask import Flask, request
import pickle
from urllib.parse import urlparse
import re
from datetime import datetime
import requests
import whois
import datetime
from csv import reader
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
model = pickle.load(open('combined_model.pkl', 'rb'))

def get_domain_registration_length(domain_url):
    try:
        domain_info = whois.whois(domain_url)
        if domain_info.creation_date and domain_info.expiration_date:
            # Handle cases where creation_date/expiration_date might be a list
            creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            expiration_date = domain_info.expiration_date[0] if isinstance(domain_info.expiration_date, list) else domain_info.expiration_date

            registration_length = (expiration_date - creation_date).days
            return registration_length
        else:
            return -1  # Data not available
    except Exception as e:
        return -1

def get_domain_age(domain_url):
    try:
        domain_info = whois.whois(domain_url)
        if domain_info.creation_date:
            # Handle cases where creation_date might be a list
            creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            current_date = datetime.datetime.now()

            domain_age = (current_date - creation_date).days
            return 1 <domain_age
        else:
            return -1  # Data not available
    except Exception as e:
        return -1

#Extra feature checks url exists in popular websites data
def checkCSV(url):
  flag=0
  try:
    checkURL=urlparse(url).netloc
  except:
    return 1
  with open('Web_Scrapped_websites.csv', 'r') as read_obj:
    csv_reader = reader(read_obj)
    for row in csv_reader:
        if row[0]==checkURL:
            flag=0
            break
        else:
            flag=1
  if flag==0:
      return 0
  else:
      return 1

def has_tld_in_path(url):
    print("Feature Extraction at : 34 ", datetime.datetime.now())
    tlds = ['.com', '.net', '.org', '.info'] 
    return 1 if any(tld in url for tld in tlds) else 0

def  submit_email(url):
    print("Feature Extraction at 63 : ", datetime.datetime.now())
    if re.search(r'mailto:', requests.get(url).text):
      return 1
    else:
      return 0

def has_domain_in_brand(hostname):
    print("Feature Extraction at 57 : ", datetime.datetime.now())
    brand_list = [
        'google', 'facebook', 'amazon', 'microsoft', 'apple',
        'twitter', 'linkedin', 'instagram', 'netflix', 'github',
        'walmart', 'ebay', 'paypal', 'airbnb', 'snapchat',
        'youtube', 'pinterest', 'tiktok', 'spotify', 'salesforce',
        'oracle', 'zoom', 'reddit', 'dropbox', 'wordpress',
        'tesla', 'uber', 'lyft', 'square', 'adobe',
        'vimeo', 'shopify', 'slack', 'atlassian', 'zoominfo',
        'paypal', 'stripe', 'shopify', 'hubspot', 't-mobile',
        'verizon', 'spotify', 'discord', 'ticktock', 'snap', 'preinsta', 
        'snapchat', 'wordpress', 'hubspot', 'microsoft', 'twitch'
    ]
    return 1 if any(brand in hostname for brand in brand_list) else 0

def onmouseover(url):
  print("Feature Extraction at : 68 ", datetime.datetime.now())
  if re.search(r'onmouseover=', requests.get(url).text):
      return 1
  else:
      return 0
  
def whois_registered_domain(hostname):
    print("Feature Extraction at last... ", datetime.datetime.now())
    try:
      if whois.whois(hostname).domain_name:
        return 0
      else:
        return 1
    except:
       return 1

def featureExtraction(url):
    # Parse the URL
    if not url.startswith(('http://', 'https://','www.')):
        return 0
    print("Feature Extraction Started : ", datetime.datetime.now())

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ""
    path = parsed_url.path or ""

    # Feature extraction from URL components
    features = {
        'length_url': len(url),
        'length_hostname': len(hostname),
        'ip': 1 if re.match(r"\d+\.\d+\.\d+\.\d+", hostname) else 0,
        'nb_dots': url.count('.'),
        'nb_hyphens': url.count('-'),
        'nb_at': url.count('@'),
        'nb_qm': url.count('?'),
        'nb_and': url.count('&'),
        'nb_or': url.count('|'),
        'nb_eq': url.count('='),
        'nb_underscore': url.count('_'),
        'nb_tilde': url.count('~'),
        'nb_percent': url.count('%'),
        'nb_slash': url.count('/'),
        'nb_star': url.count('*'),
        'nb_colon': url.count(':'),
        'nb_comma': url.count(','),
        'nb_semicolumn': url.count(';'),
        'nb_dollar': url.count('$'),
        'nb_space': url.count(' '),
        'nb_www': url.count('www'),
        'nb_com': url.count('.com'),
        'nb_dslash': url.count('//'),
        'http_in_path': 1 if 'http' in path else 0,
        'https_token': 1 if 'https' in path else 0,
        'ratio_digits_url': sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0,
        'ratio_digits_host': sum(c.isdigit() for c in hostname) / len(hostname) if len(hostname) > 0 else 0,
        'punycode': 1 if 'xn--' in url else 0,
        'port': parsed_url.port or 0,
        'tld_in_path': has_tld_in_path(path), ####at 34 ---debugging
        'tld_in_subdomain': 1 if '.com' in parsed_url.netloc else 0,
        'abnormal_subdomain': 0 if re.search(r"[^a-zA-Z0-9-]", parsed_url.netloc) else 1,
        'nb_subdomains': len(parsed_url.netloc.split('.')) - 2,
        'prefix_suffix': 1 if '-' in parsed_url.netloc else 0,
        'random_domain': 1 if re.match(r'\b\w{10,}\b', parsed_url.netloc) else 0,
        'shortening_service': 1 if re.search(r'bit\.ly|t\.co|goo\.gl', parsed_url.netloc) else 0,
        'path_extension': 1 if re.search(r"\.\w+$", path) else 0,
        'nb_redirection': url.count('//') - 1,
        'nb_external_redirection': 1 if url.startswith('http') and not url.startswith('https') else 0,
        'length_words_raw': len(re.findall(r'\w+', url)),
        'char_repeat': max([url.count(char) for char in set(url)]),
        'shortest_words_raw': min([len(word) for word in re.findall(r'\w+', url)]) if re.findall(r'\w+', url) else 0,
        'shortest_word_host': min([len(word) for word in hostname.split('.')]) if hostname else 0,
        'shortest_word_path': min([len(word) for word in path.split('/')]) if path else 0,
        'longest_words_raw': max([len(word) for word in re.findall(r'\w+', url)]) if re.findall(r'\w+', url) else 0,
        'longest_word_host': max([len(word) for word in hostname.split('.')]) if hostname else 0,
        'longest_word_path': max([len(word) for word in path.split('/')]) if path else 0,
        'avg_words_raw': sum(len(word) for word in re.findall(r'\w+', url)) / len(re.findall(r'\w+', url)) if re.findall(r'\w+', url) else 0,
        'avg_word_host': sum(len(word) for word in hostname.split('.')) / len(hostname.split('.')) if hostname else 0,
        'avg_word_path': sum(len(word) for word in path.split('/')) / len(path.split('/')) if path else 0,
        'phish_hints': 1 if re.search(r'free|login|secure|bank', url.lower()) else 0,
        'domain_in_brand': has_domain_in_brand   (hostname), ##at 56 ---debugging
        'brand_in_subdomain': has_domain_in_brand(parsed_url.netloc),
        'brand_in_path': has_domain_in_brand(path),
        'suspecious_tld': 1 if re.search(r'.xyz|.top|.win|.download|.bid|.club|.click', hostname) else 0,
        #-----'statistical_report': 0,  # Placeholder: Requires external API or DB lookup
        #-----'nb_hyperlinks': len(re.findall(r'<a\s+(?:[^>]*?\s+)?href=([\"\'])(.*?)\1', requests.get(url).text)),
        #-----'ratio_intHyperlinks': 0,  # Placeholder: External link count logic
        #-----'ratio_extHyperlinks': 0,  # Placeholder: External link count logic
        #-----'ratio_nullHyperlinks': 0,  # Placeholder: Null link count logic
        #-----'nb_extCSS': 0,  # Placeholder: External CSS count logic
        #-----'ratio_intRedirection': 0,  # Placeholder: Redirection logic
        #-----'ratio_extRedirection': 0,  # Placeholder: Redirection logic
        #-----'ratio_intErrors': 0,  # Placeholder: Internal errors logic
        #-----'ratio_extErrors': 0,  # Placeholder: External errors logic
        'login_form': 0 if re.search(r'<form', requests.get(url).text) else 1,
        'external_favicon': 0,  # Placeholder
        'links_in_tags': 100,  # Placeholder
        'submit_email': submit_email(url), ####at 63 ---debugging
        #-----'ratio_intMedia': 0,  # Placeholder
        #-----'ratio_extMedia': 0,  # Placeholder
        'sfh': 0 if "about:blank" in url or urlparse(url).netloc in url else 1, 
        'iframe': 0 if re.search(r'<iframe', requests.get(url).text) else 1,
        'popup_window': 0 if re.search(r'window\.open', requests.get(url).text) else 1,
        'safe_anchor': 30 if re.search(r'<a\s+(?:[^>]*?\s+)?href=([\"\'])(.*?)\1', requests.get(url).text) else 0,
        'onmouseover': onmouseover(url),###at 68 ---debugging
        'right_clic': 0,  # Placeholder
        'empty_title': 0, #Placeholder
        'domain_in_title': 1 if hostname in requests.get(url).text else 0,
        'domain_with_copyright': 1 if 'copyright' in requests.get(url).text else 0, 
        'whois_registered_domain':  whois_registered_domain(hostname),#at last ---debugging
        'domain_registration_length': get_domain_registration_length(url),  
        'domain_age': get_domain_age(url),  
        #-----'web_traffic': 0,  
        'dns_record': 1 if whois.whois(hostname).status else 0,
        #-----'google_index': 0,  
        #-----'page_rank': 0,  
    }
    print("Feature Extraction Completed:", datetime.datetime.now())
    print(features)
    return list(features.values())


@app.route('/post', methods=['POST'])
def predict():
    url = request.form['URL']
    print("Input URL Received...", datetime.datetime.now())
    # Initialize dataPhish
    dataPhish = checkCSV(url) 

    if dataPhish == 0:
        print("Safe")
        return "0"
    
    # Extract features
    features = featureExtraction(url)
    if features == 0:
        print("Invalid URL")
        return "0"
    
    # Transform the extracted features using PCA 
    try:
        pca_features = model['pca'].transform([features])
    except KeyError:
        return "Error: PCA transformer not found in the model"
    except Exception as e:
        return f"Error in PCA transformation: {str(e)}"

    predictions = []
    # Iterate through the models for predictions
    for model_name, trained_model in model['models'].items():
        try:
            # Predict using the model and the transformed PCA features
            prediction = trained_model.predict(pca_features) 
            predictions.append(prediction[0])
        except Exception as e:
            return f"Error in model prediction with {model_name}: {str(e)}"

    # Perform majority voting on the collected predictions
    if not predictions:
        return "Error: No predictions made."

    # Get the most common prediction and its count
    prediction_counts = Counter(predictions)
    majority_prediction, majority_count = prediction_counts.most_common(1)[0]
    legit=0
    if(predictions[3]=='legitimate'):
       legit=legit+1
    if(predictions[2]=='legitimate'):
       legit=legit+1

    print("Predictions from all models: ", predictions)
    print("Majority Prediction: ", majority_prediction)
    print("Dataphish: ", dataPhish)

    # Check the new conditions for a safe result
    if dataPhish == 1 and majority_prediction == 'legitimate' and legit==2 and majority_count >= 3:
        print("Safe")
        return "0"  # Safe

    # Original phishing check
    elif majority_prediction == 'phishing' and dataPhish == 1:
        print("Phishing")
        return "-1"  # Phishing

    # Suspicious as a fallback
    else:
        print("Suspicious")
        return "1"

if __name__ == "__main__":
    app.run(debug=True)  