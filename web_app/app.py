#import libraries
import numpy as np
from flask import Flask, request, jsonify, render_template
import pickle
import joblib
from feature_extraction import extract_lexical_features


#Initialize the flask App
app = Flask(__name__)
model = joblib.load('deploheroku\logreg.pkl')
preprocessing = joblib.load('deploheroku\pipeline.pkl')  

#default page of our web-app
@app.route('/')
def home():
    return render_template('index.html')


#To use the predict button in our web-app
@app.route('/predict',methods=['POST'])
def predict():
    '''
    For rendering results on HTML GUI
    '''
    url = [str(x) for x in request.form.values()][0]
    features = extract_lexical_features(url)
    features_preprocessed = preprocessing.transform(features)
    raw_preds = model.predict_proba(features_preprocessed)
    class_label = np.argmax(raw_preds)
    confidence = round(raw_preds[0][class_label] * 100, 2)
    class_label = "Malicious link" if class_label == 1 else "Safe link"

    return render_template('index.html', prediction_text='Class Prediction: {}'.format(class_label), confidence_text='Confidence: {}%'.format(confidence))

if __name__ == "__main__":
    app.run(debug=True)