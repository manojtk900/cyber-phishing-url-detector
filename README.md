




Cyber Phishing URL Detection Using Machine Learning
Abstract

Cyber phishing is a major cybersecurity threat in which attackers create fraudulent websites that closely resemble legitimate ones to steal sensitive information such as usernames, passwords, and financial details. With the rapid growth of online services, phishing attacks have become more frequent and sophisticated, making manual detection difficult.
This project presents a Machine Learning–based Cyber Phishing URL Detection System that automatically classifies URLs as legitimate or phishing by analyzing their structural and lexical patterns. The proposed system demonstrates how machine learning techniques can be effectively applied to enhance web security and protect users from malicious online activities.

1. Introduction

Phishing attacks exploit human trust by disguising malicious websites as trusted entities such as banks, e-commerce platforms, and social networks. Traditional phishing detection techniques rely heavily on blacklists and rule-based systems, which are ineffective against newly generated or previously unseen phishing URLs.

Machine learning provides a scalable and adaptive solution by learning patterns from historical phishing and legitimate URLs. This project focuses on URL-based phishing detection, which does not require webpage content or third-party services, making the system lightweight and efficient.

2. Problem Statement

Existing phishing detection systems suffer from the following limitations:

Dependence on manually maintained blacklists

Inability to detect newly created phishing URLs

High false-positive rates in rule-based approaches

There is a need for an automated system that can intelligently classify URLs using learned patterns rather than static rules.

3. Proposed Solution

The proposed system uses supervised machine learning algorithms to classify URLs based on their textual and structural features. By applying TF-IDF–based feature extraction and trained classification models, the system predicts whether a given URL is phishing or legitimate in real time.

The solution is implemented as a web-based application to provide easy accessibility and practical usability.

4. System Architecture

The system follows a modular architecture consisting of:

User Interface
A web interface where users input URLs for analysis.

Preprocessing Module
Cleans and normalizes URLs to remove noise and standardize input.

Feature Extraction Module
Converts URLs into numerical feature vectors using TF-IDF.

Machine Learning Model
A trained classification model that predicts the URL category.

Result Display Module
Displays prediction results as SAFE or PHISHING.

5. Methodology

Data Collection
Datasets containing both phishing and legitimate URLs are collected from publicly available sources.

Data Preprocessing
URLs are cleaned, tokenized, and normalized to remove irrelevant characters.

Feature Engineering
TF-IDF vectorization is applied to extract meaningful character-level features from URLs.

Model Training
Supervised learning algorithms such as Logistic Regression, Naive Bayes, and Random Forest are trained and evaluated.

Model Deployment
The best-performing model is integrated into a Flask-based web application.

6. Technologies Used

Programming Language: Python

Machine Learning Library: scikit-learn

Web Framework: Flask

Frontend: HTML, CSS, JavaScript, Tailwind CSS

Model Serialization: Pickle


cyber-phishing-url-detector/
│
├── app8.py                 # Main Flask application
├── test_model.py           # Model testing script
├── templates/              # HTML templates
├── static/                 # Static assets (CSS, JS)
├── .gitignore              # Ignored large files
└── README.md               # Documentation


8. Execution Details

To execute the project:
Ensure Python 3.8 or higher is installed.
Install required dependencies.

Place trained machine learning model and vectorizer files (.pkl) in the project directory.

Run the Flask application and access the local server through a web browser.

9. Results and Observations

The system successfully classifies URLs with high accuracy and provides instant predictions. The experimental results demonstrate that machine learning–based approaches outperform traditional blacklist-based methods, especially for detecting previously unseen phishing URLs.

10. Limitations

Detection accuracy depends on the quality and diversity of training data.

The system analyzes only URL features and does not inspect webpage content.

Advanced phishing techniques may still evade detection.

11. Future Scope

Integration of deep learning models for improved accuracy

Browser extension implementation

Real-time URL scanning in emails and messages

Cloud-based deployment for scalability

12. Disclaimer

This project is developed strictly for academic and educational purposes.
While it enhances phishing awareness, it does not guarantee complete protection against all phishing attacks.


----------------------------------------------------------------------------------------------------------------------



Note:
Due to GitHub file size limits, trained machine learning model files (.pkl),
datasets (.csv), and result plots are not included in this repository.
Please place the required model and vectorizer files in the project
directory before running the application.
