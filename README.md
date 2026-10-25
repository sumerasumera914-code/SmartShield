# 🛡️ SmartShield — Scam Message and Suspicious Link Detector

SmartShield is a small educational web app (built with Streamlit) that helps users spot warning signs in
**scam messages** and **suspicious links**.

> ⚠️ **Disclaimer:** This is a student prototype. It cannot detect every scam and it can make mistakes.
> "Not Flagged" does **not** mean a message or link is safe.

## Features

| Feature | How it works | Type |
|---|---|---|
| Message Checker | TF-IDF text features + Logistic Regression, trained on a labelled SMS dataset | **Machine Learning** |
| Link Checker | Python rules look at the *text* of a URL (length, IP address, subdomains, shorteners, keywords, HTTPS...) | **Rule-based (not ML)** |
| Optional reputation check | Google Safe Browsing lookup, only if you provide your own API key | Optional online service |

The link is **never opened or visited**. The app works fully offline without any API key.

## Technologies
Python, Pandas, Scikit-learn, Streamlit, Joblib, Requests, Git/GitHub

## Project structure
```
smartshield-scam-detector/
├── app.py            # Streamlit web app
├── train_model.py    # trains and evaluates the message model
├── url_checker.py    # rule-based URL analysis (+ optional Safe Browsing)
├── text_utils.py     # text cleaning shared by training and the app
├── requirements.txt
├── README.md
└── .gitignore
```
`data/` and `model/` are created on your computer and are not uploaded to GitHub.

## Installation (Windows, VS Code terminal)
```
python --version
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```
If PowerShell blocks activation, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` and activate again.

## Get the dataset
This project uses the **SMS Spam Collection** dataset (UCI Machine Learning Repository, by Almeida & Hidalgo).
Please check the licence shown on the dataset page before reuse.

1. Open: https://archive.ics.uci.edu/dataset/228/sms+spam+collection
2. Click **Download** and extract the zip file.
3. Create a folder named `data` inside the project.
4. Copy the file named `SMSSpamCollection` (no extension) into `data/`.

## Train the model
```
python train_model.py
```
This prints precision, recall, F1-score and a confusion matrix for a held-out 20% test set, saves the model to
`model/scam_model.joblib`, and writes `model/evaluation_report.txt`.

### My evaluation results
*(Paste the output of `python train_model.py` from your own computer here.)*

## Run the app
```
streamlit run app.py
```
It opens at http://localhost:8501

## Optional: Safe Browsing check
Get a free Google Safe Browsing API key and paste it into the app's expander, or set the environment variable
`SAFE_BROWSING_API_KEY`. Never put your key in the code or upload it to GitHub. When a key is used, the URL text is
sent to Google (the link itself is still not opened by this app).

## Limitations
- The dataset is an older collection of English SMS messages. It may miss modern scams (UPI, KYC, OTP, courier, job scams) or messages in other languages.
- Normal messages with prize or offer words may be wrongly flagged.
- URL rules only read the text of a link. Safe-looking links can be dangerous and odd-looking links can be harmless.
- The model's percentage is its own estimate, not a guarantee.

## Future improvements
- Add newer and local-language scam examples to the training data
- Try other models and compare them
- Show which words influenced the prediction
- Add a larger URL dataset and train a URL model

## AI tools disclosure
*(Write here how you used AI tools to help build this project, as per your course guidelines.)*
