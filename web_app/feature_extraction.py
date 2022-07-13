from pandas.core.arrays.numeric import T
from math import log
from re import compile
from urllib.parse import urlparse
from socket import gethostbyname
from pyquery import PyQuery
from requests import get
from json import dump
from string import ascii_lowercase
from numpy import array, log
from string import punctuation
import pandas as pd


class LexicalURLFeature:

    """

    ## extract lexical features for benign and malware dataframes
    
    """

    def __init__(self, url):
        self.description = 'blah'
        self.url = url
        self.urlparse = urlparse(self.url)
        # self.host = self.__get_ip()


    def __get_entropy(self, text):
        text = text.lower()
        probs = [text.count(c) / len(text) for c in set(text)]
        entropy = -sum([p * log(p) / log(2.0) for p in probs])
        return entropy

    def __get_ip(self):
        try:
            ip = self.urlparse.netloc if self.url_host_is_ip() else gethostbyname(self.urlparse.netloc)
            return ip
        except:
            return None

    # extract lexical features
    def url_scheme(self):
        return self.urlparse.scheme

    def url_length(self):
        return len(self.url)

    def url_path_length(self):
        return len(self.urlparse.path)

    def url_host_length(self):
        return len(self.urlparse.netloc)

    def url_host_is_ip(self):
        host = self.urlparse.netloc
        pattern = compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        match = pattern.match(host)
        return match is not None

    def url_has_port_in_string(self):
        has_port = self.urlparse.netloc.split(':')
        return len(has_port) > 1 and has_port[-1].isdigit()

    def number_of_digits(self):
        digits = [i for i in self.url if i.isdigit()]
        return len(digits)

    def number_of_parameters(self):
        params = self.urlparse.query
        return 0 if params == '' else len(params.split('&'))

    def number_of_fragments(self):
        frags = self.urlparse.fragment
        return len(frags.split('#')) - 1 if frags == '' else 0

    def is_encoded(self):
        return '%' in self.url.lower()

    def num_encoded_char(self):
        encs = [i for i in self.url if i == '%']
        return len(encs)

    def url_string_entropy(self):
        return self.__get_entropy(self.url)

    def number_of_subdirectories(self):
        d = self.urlparse.path.split('/')
        return len(d)

    def number_of_periods(self):
        periods = [i for i in self.url if i == '.']
        return len(periods)

    def has_client_in_string(self):
        return 'client' in self.url.lower()

    def has_admin_in_string(self):
        return 'admin' in self.url.lower()

    def has_server_in_string(self):
        return 'server' in self.url.lower()

    def has_login_in_string(self):
        return 'login' in self.url.lower()
        
    def get_tld(self):
      return self.urlparse.netloc.split('.')[-1].split(':')[0]


def extract_lexical_features(url):
  sample = dict()
  feature_extractor = LexicalURLFeature(url)
  sample["url_scheme"] = feature_extractor.url_scheme()
  sample["url_length"] = feature_extractor.url_length()
  sample["url_path_length"] = feature_extractor.url_path_length()
  sample["url_host_length"] = feature_extractor.url_host_length()
  sample["url_host_is_ip"] = feature_extractor.url_host_is_ip()
  sample["url_has_port_in_string"] = feature_extractor.url_has_port_in_string()
  sample["number_of_digits"] = feature_extractor.number_of_digits()
  sample["number_of_parameters"] = feature_extractor.number_of_parameters()
  sample["number_of_fragments"] = feature_extractor.number_of_fragments()
  sample["is_encoded"] = feature_extractor.is_encoded()
  sample["num_encoded_char"] = feature_extractor.num_encoded_char()
  sample["url_string_entropy"] = feature_extractor.url_string_entropy()
  sample["number_of_subdirectories"] = feature_extractor.number_of_subdirectories()
  sample["number_of_periods"] = feature_extractor.number_of_periods()
  sample["has_client_in_string"] = feature_extractor.has_client_in_string()
  sample["has_admin_in_string"] = feature_extractor.has_admin_in_string()
  sample["has_server_in_string"] = feature_extractor.has_server_in_string()
  sample["has_login_in_string"] = feature_extractor.has_login_in_string()
  sample["tld"] = feature_extractor.get_tld()
  return pd.DataFrame([sample])

if __name__ == "__main__":
    # test
    import joblib
    import numpy as np
    model = joblib.load('deploheroku\logreg.pkl')
    preprocessing = joblib.load('deploheroku\pipeline.pkl')    
    url = "https://youtube.com"
    features = extract_lexical_features(url)
    preprocessed_features = preprocessing.transform(features)
    model_pred = model.predict_proba(preprocessed_features)
    print(np.argmax(model_pred))


