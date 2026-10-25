"""Small text-cleaning helper used by BOTH train_model.py and app.py.

It lives in its own file so the saved model can always find it.
"""
import re

URL_PATTERN = re.compile(r"(https?://\S+|www\.\S+)", re.IGNORECASE)
NUMBER_PATTERN = re.compile(r"\d+")


def clean_text(text):
    """Make a message easier for the model to learn from.

    - turns everything to lowercase
    - replaces links with the word 'urltoken'
    - replaces numbers with the word 'numtoken'
    - removes extra spaces
    """
    if text is None:
        return ""
    text = str(text).lower()
    text = URL_PATTERN.sub(" urltoken ", text)
    text = NUMBER_PATTERN.sub(" numtoken ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text
