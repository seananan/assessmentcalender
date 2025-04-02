from flask import Flask, render_template, request, redirect, session
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt

app = Flask(__name__)


@app.route('/')
def render_homepage():  # put application's code here
    return render_template('home.html')


if __name__ == '__main__':
    app.run()
