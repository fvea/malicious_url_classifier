# Malicious URL Classifier

## Resources:
* https://github.com/NakulLakhotia/deploheroku (web app inspiration)
* https://towardsdatascience.com/extracting-feature-vectors-from-url-strings-for-malicious-url-detection-cbafc24737a (feature extraction)
* https://www.unb.ca/cic/datasets/url-2016.html (training data)

## Project Preview
![caption](https://github.com/fvea/malicious_url_classifier/blob/main/demo_Trim.gif)

## Installation Steps
<br/>
<b>Step 1.</b> Clone this repository through git.
<pre>
git clone https://github.com/fvea/malicious_url_classifier.git
</pre> 
<br/>
<b>Step 2.</b> Create a new virtual environment.
<pre>
python -m venv url
</pre> 
<br/>
<b>Step 3.</b> Activate your virtual environment
<pre>
source tfod/bin/activate # Linux
.\url\Scripts\activate # Windows 
</pre>
<br/>
<b>Step 4.</b> Install dependencies.
<pre>
python -m pip install --upgrade pip
pip install -r requirements.txt
</pre>